// Copyright 2024 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"compress/gzip"
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/alphadose/haxmap"
	"github.com/fsnotify/fsnotify"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

type (
	pcapEvent string

	fsnEvent struct {
		Event  pcapEvent `json:"event,omitempty"`
		Source string    `json:"source,omitempty"`
		Target string    `json:"target,omitempty"`
		Bytes  int64     `json:"bytes,omitempty"`
	}
)

const (
	PCAP_FSNINI pcapEvent = "PCAP_FSNINI"
	PCAP_FSNEND pcapEvent = "PCAP_FSNEND"
	PCAP_FSNERR pcapEvent = "PCAP_FSNERR"
	PCAP_CREATE pcapEvent = "PCAP_CREATE"
	PCAP_EXPORT pcapEvent = "PCAP_EXPORT"
	PCAP_QUEUED pcapEvent = "PCAP_QUEUED"
	PCAP_OSWMEM pcapEvent = "PCAP_OSWMEM"
	PCAP_SIGNAL pcapEvent = "PCAP_SIGNAL"
)

const (
	cgroupMemoryUtilization       = "/sys/fs/cgroup/memory/memory.usage_in_bytes"
	dockerCgroupMemoryUtilization = "/sys/fs/cgroup/memory.current"
	procSysVmDropCaches           = "/proc/sys/vm/drop_caches"
)

const watchdogInterval = 60 * time.Second

var (
	src_dir    = flag.String("src_dir", "/pcap-tmp", "pcaps source directory")
	gcs_dir    = flag.String("gcs_dir", "/pcap", "pcaps destination directory")
	pcap_ext   = flag.String("pcap_ext", "pcap", "pcap files extension")
	gzip_pcaps = flag.Bool("gzip", false, "compress pcap files")
	gcp_gae    = flag.Bool("gae", false, "define serverless execution environment")
)

var (
	projectID  string   = os.Getenv("PROJECT_ID")
	gcpRegion  string   = os.Getenv("GCP_REGION")
	service    string   = os.Getenv("APP_SERVICE")
	version    string   = os.Getenv("APP_VERSION")
	sidecar    string   = os.Getenv("APP_SIDECAR")
	instanceID string   = os.Getenv("INSTANCE_ID")
	module     string   = os.Getenv("PROC_NAME")
	gcpGAE     string   = os.Getenv("PCAP_GAE")
	tags       []string = []string{projectID, service, gcpRegion, version, instanceID}
)

var logger, _ = zap.Config{
	Encoding:    "json",
	Level:       zap.NewAtomicLevelAt(zapcore.DebugLevel),
	OutputPaths: []string{"stdout"},
	EncoderConfig: zapcore.EncoderConfig{
		MessageKey:  "message",
		LevelKey:    "severity",
		EncodeLevel: zapcore.CapitalLevelEncoder,
		TimeKey:     "time",
		EncodeTime:  zapcore.ISO8601TimeEncoder,
	},
}.Build()
var sugar = logger.Sugar()

var (
	counters *haxmap.Map[string, *atomic.Uint64]
	lastPcap *haxmap.Map[string, string]
	isActive atomic.Bool
)

func logFsEvent(level zapcore.Level, message string, event pcapEvent, src, tgt string, by int64) {
	sugar.Logw(level, message, "sidecar", sidecar, "module", module, "tags", tags,
		"data", fsnEvent{Event: event, Source: src, Target: tgt, Bytes: by})
}

func movePcapToGcs(pcap *uint64, srcPcap *string, dstDir *string, compress, clean bool) (*string, *int64, error) {
	// Define name of destination PCAP file, prefixed by its ordinal and destination directory
	pcapName := fmt.Sprintf("%d_%s", *pcap, filepath.Base(*srcPcap))
	tgtPcap := filepath.Join(*dstDir, pcapName)
	// If compressing PCAP files is enabled, add `gz` siffux to the destination PCAP file path
	if compress {
		tgtPcap = fmt.Sprintf("%s.gz", tgtPcap)
	}

	var (
		err                   error
		inputPcap, outputPcap *os.File
		pcapBytes             int64 = 0
	)

	// Open source PCAP file: the one thas is being moved to the destination directory
	inputPcap, err = os.Open(*srcPcap)
	if err != nil {
		logFsEvent(zapcore.ErrorLevel, fmt.Sprintf("%s", err), PCAP_EXPORT, *srcPcap, tgtPcap, 0)
		return &tgtPcap, &pcapBytes, fmt.Errorf("failed to open source pcap: %s", *srcPcap)
	}

	// Create destination PCAP file ( export to the GCS Bucket )
	outputPcap, err = os.Create(tgtPcap)
	if err != nil {
		logFsEvent(zapcore.ErrorLevel, fmt.Sprintf("%s", err), PCAP_EXPORT, *srcPcap, tgtPcap, 0)
		return &tgtPcap, &pcapBytes, fmt.Errorf("failed to create destination pcap: %s", tgtPcap)
	}
	defer outputPcap.Close()

	// Copy source PCAP into destination PCAP, compressing destination PCAP is optional
	if compress {
		gzipPcap := gzip.NewWriter(outputPcap)
		pcapBytes, err = io.Copy(gzipPcap, inputPcap)
		gzipPcap.Flush()
		gzipPcap.Close()
	} else {
		pcapBytes, err = io.Copy(outputPcap, inputPcap)
	}
	inputPcap.Close()
	if err != nil {
		logFsEvent(zapcore.ErrorLevel, fmt.Sprintf("%s", err), PCAP_EXPORT, *srcPcap, tgtPcap, 0)
		return &tgtPcap, &pcapBytes, fmt.Errorf("failed to copy '%s' into '%s'", *srcPcap, tgtPcap)
	}

	if clean {
		// remove the source PCAP file if copying is sucessful
		os.Remove(*srcPcap)
	}

	return &tgtPcap, &pcapBytes, nil
}

func getCurrentMemoryUtilization(isGAE bool) (uint64, error) {
	var err error
	var memoryUtilizationFilePath string

	if isGAE {
		memoryUtilizationFilePath = dockerCgroupMemoryUtilization
	} else {
		memoryUtilizationFilePath = cgroupMemoryUtilization
	}

	memoryUtilizationFile, err := os.OpenFile(memoryUtilizationFilePath, os.O_RDONLY, 0o444 /* -r--r--r-- */)
	if err != nil {
		return 0, err
	}

	var memoryUtilization int
	_, err = fmt.Fscanf(memoryUtilizationFile, "%d\n", &memoryUtilization)
	if err != nil {
		if err == io.EOF {
			return uint64(memoryUtilization), nil
		}
		return 0, err
	}
	return uint64(memoryUtilization), nil
}

func flushBuffers() (int, error) {
	cmd := exec.Command("sync")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Run()
	// see: https://www.kernel.org/doc/Documentation/sysctl/vm.txt
	fd, err := os.OpenFile(procSysVmDropCaches,
		os.O_WRONLY|os.O_TRUNC, 0o200 /* --w------- */)
	if err != nil {
		return 0, err
	}
	defer fd.Close()
	return fmt.Fprintln(fd, "3")
}

func exportPcapFile(wg *sync.WaitGroup, pcapDotExt *regexp.Regexp, srcFile *string, flush bool) bool {
	defer wg.Done()

	// `flushing` is only allowed when FS watcher is not avtive.
	if flush && isActive.Load() {
		logFsEvent(zapcore.WarnLevel, fmt.Sprintf("flushing while active is not allowed:  %s", *srcFile), PCAP_FSNERR, *srcFile, "" /* target PCAP file */, 0)
		return false
	}

	rMatch := pcapDotExt.FindStringSubmatch(*srcFile)

	iface := fmt.Sprintf("%s:%s", rMatch[1], rMatch[2])
	ext := rMatch[3]
	key := strings.Join(rMatch[1:], "/")

	counter, _ := counters.GetOrCompute(key,
		func() *atomic.Uint64 {
			return new(atomic.Uint64)
		})
	iteration := (*counter).Add(1)
	index := iteration - 1

	// `flushing` is the only thread-safe PCAP export operation.
	if flush {
		defer lastPcap.Set(key, "")
		logFsEvent(zapcore.InfoLevel, fmt.Sprintf("flushing PCAP file: [%s] (%s/%s/%d) %s", key, ext, iface, iteration, *srcFile), PCAP_EXPORT, *srcFile, "" /* target PCAP file */, 0)
		tgtPcapFileName, pcapBytes, moveErr := movePcapToGcs(&index, srcFile, gcs_dir, false, false) /* compression & deletion are disabled when flushing to speed up the process */
		if moveErr != nil {
			logFsEvent(zapcore.ErrorLevel, fmt.Sprintf("failed to flush PCAP file: (%s/%s/%d) %s: %v", ext, iface, index, *srcFile, moveErr), PCAP_FSNERR, *srcFile, *tgtPcapFileName /* target PCAP file */, 0)
			return false
		}
		logFsEvent(zapcore.InfoLevel, fmt.Sprintf("flushed PCAP file: (%s/%s/%d) %s", ext, iface, index, *tgtPcapFileName), PCAP_EXPORT, *srcFile, *tgtPcapFileName, *pcapBytes)
		return true
	}

	logFsEvent(zapcore.InfoLevel, fmt.Sprintf("new PCAP file detected: [%s] (%s/%s/%d) %s", key, ext, iface, iteration, *srcFile), PCAP_CREATE, *srcFile, "" /* target PCAP file */, 0)

	// Skip 1st PCAP, start moving PCAPs as soon as TCPDUMP rolls over into the 2nd file.
	// The outcome of this implementation is that the directory in which TCPDUMP writes
	// PCAP files will contain at most 2 files, the current one, and the one being moved
	// into the destination directory ( `gcs_dir` ). Otherwise it will contain all PCAPs.
	if iteration == 1 {
		lastPcap.Set(key, *srcFile)
		return true
	}

	srcPcapFileName, loaded := lastPcap.Get(key)
	if !loaded || srcPcapFileName == "" {
		lastPcap.Set(key, *srcFile)
		logFsEvent(zapcore.ErrorLevel, fmt.Sprintf("PCAP file [%s] (%s/%s/%d) unavailable", key, ext, iface, index), PCAP_EXPORT, "" /* source PCAP File */, *srcFile /* target PCAP file */, 0)
		return false
	}

	// move non-current PCAP file into `gcs_dir` which means that:
	// 1. the GCS Bucket should have already been mounted
	// 2. the directory hierarchy to store PCAP files already exists
	tgtPcapFileName, pcapBytes, moveErr := movePcapToGcs(&index, &srcPcapFileName, gcs_dir, *gzip_pcaps, true)
	if moveErr == nil {
		logFsEvent(zapcore.InfoLevel, fmt.Sprintf("exported PCAP file: (%s/%s/%d) %s", ext, iface, index, *tgtPcapFileName), PCAP_EXPORT, srcPcapFileName, *tgtPcapFileName, *pcapBytes)
	} else {
		logFsEvent(zapcore.ErrorLevel, fmt.Sprintf("failed to export PCAP file: (%s/%s/%d) %s: %v", ext, iface, index, srcPcapFileName, moveErr), PCAP_EXPORT, srcPcapFileName, *tgtPcapFileName /* target PCAP file */, 0)
	}

	// current PCAP file is the next one to be moved
	if !lastPcap.CompareAndSwap(key, srcPcapFileName, *srcFile) {
		logFsEvent(zapcore.ErrorLevel, fmt.Sprintf("leaked PCAP file: [%s] (%s/%s/%d) %s", key, ext, iface, iteration, *srcFile), PCAP_FSNERR, *srcFile, "" /* target PCAP file */, 0)
		lastPcap.Set(key, *srcFile)
	}
	logFsEvent(zapcore.InfoLevel, fmt.Sprintf("queued PCAP file: (%s/%s/%d) %s", ext, iface, iteration, *srcFile), PCAP_QUEUED, *srcFile, "" /* target PCAP file */, 0)

	return moveErr == nil
}

func flushSrcDir(wg *sync.WaitGroup, pcapDotExt *regexp.Regexp) uint32 {
	pendingPcapFiles := uint32(0)
	flushBuffers() // run `sync` to flush OS write buffers
	filepath.WalkDir(*src_dir, func(path string, d os.DirEntry, err error) error {
		if d.IsDir() {
			return nil
		}
		if err != nil {
			logFsEvent(zapcore.ErrorLevel, fmt.Sprintf("%v", err), PCAP_FSNERR, path, "" /* target PCAP file */, 0)
			return nil
		}
		pendingPcapFiles += 1
		wg.Add(1)
		go exportPcapFile(wg, pcapDotExt, &path, true /* flush */)
		return nil
	})
	return pendingPcapFiles
}

func main() {
	isActive.Store(false)

	flag.Parse()

	defer logger.Sync()

	counters = haxmap.New[string, *atomic.Uint64]()
	lastPcap = haxmap.New[string, string]()

	isGAE, isGAEerr := strconv.ParseBool(gcpGAE)
	isGAE = (isGAEerr == nil && isGAE) || *gcp_gae

	ext := strings.Join(strings.Split(*pcap_ext, ","), "|")
	pcapDotExt := regexp.MustCompile(`^` + *src_dir + `/part__(\d+?)_(.+?)__\d{8}T\d{6}\.(` + ext + `)$`)

	args := map[string]interface{}{
		"src_dir":  *src_dir,
		"gcs_dir":  *gcs_dir,
		"pcap_ext": pcapDotExt,
		"gzip":     *gzip_pcaps,
	}
	initEvent := map[string]interface{}{"event": PCAP_FSNINI}

	sugar.Infow("starting PCAP filesystem watcher", "args", args, "data", initEvent,
		"sidecar", sidecar, "module", module, "tags", tags, "rgx", pcapDotExt.String())

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGTERM, syscall.SIGINT, syscall.SIGHUP, syscall.SIGQUIT)

	// Create new watcher.
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		sugar.Fatalw(fmt.Sprintf("failed to create FS watcher: %v", err),
			"sidecar", sidecar, "module", module, "tags", tags,
			"data", map[string]interface{}{
				"event": PCAP_FSNINI,
				"error": err.Error(),
			})
		os.Exit(1)
	}
	defer watcher.Close()

	ctx, cancel := context.WithCancel(context.Background())

	var wg sync.WaitGroup
	ticker := time.NewTicker(watchdogInterval)

	// Watch the PCAP files source directory for FS events.
	if isActive.CompareAndSwap(false, true) {
		if err = watcher.Add(*src_dir); err != nil {
			sugar.Fatalw(fmt.Sprintf("failed to watch directory '%s': %v", *src_dir, err),
				"sidecar", sidecar, "module", module, "tags", tags,
				"data", map[string]interface{}{
					"event": PCAP_FSNERR,
					"error": err.Error(),
				})
			isActive.Store(false)
			os.Exit(2)
		}
	}

	// Start listening for FS events at PCAP files source directory.
	go func(wg *sync.WaitGroup, ticker *time.Ticker) {
		for isActive.Load() {
			select {

			case signal := <-sigChan:
				sugar.Infow(fmt.Sprintf("signaled: %v", signal),
					"sidecar", sidecar, "module", module, "tags", tags,
					"data", map[string]interface{}{
						"event":  PCAP_SIGNAL,
						"signal": signal,
					})
				if isActive.CompareAndSwap(true, false) {
					watcher.Remove(*src_dir)
					watcher.Close()
					ticker.Stop()
				}
				cancel()
				return

			case event, ok := <-watcher.Events:
				if !ok || !isActive.Load() {
					continue
				}
				// Skip events which are not CREATE, and all which are not related to PCAP files
				if !event.Has(fsnotify.Create) || !pcapDotExt.MatchString(event.Name) {
					continue
				}
				wg.Add(1)
				exportPcapFile(wg, pcapDotExt, &event.Name, false /* flush */)

			case fsnErr, ok := <-watcher.Errors:
				sugar.Fatalw(fmt.Sprintf("%v", fsnErr),
					"sidecar", sidecar, "module", module, "tags", tags,
					"data", map[string]interface{}{
						"event": PCAP_FSNERR,
						"error": fsnErr.Error(),
					})
				if !ok {
					cancel()
					watcher.Close()
					ticker.Stop()
					os.Exit(3)
				}

			case <-ticker.C:
				// packet capturing is write intensive
				// OS buffers memory must be fluhsed often to prevent memory saturation
				// flushing OS file write buffers is safe: 'non-destructive operation and will not free any dirty objects'
				// additionally, PCAP files are [write|append]-only
				memoryBefore, _ := getCurrentMemoryUtilization(isGAE)
				_, memFlushErr := flushBuffers()
				memoryAfter, _ := getCurrentMemoryUtilization(isGAE)
				if memFlushErr != nil {
					sugar.Warnw(fmt.Sprintf("failed to flush OS file write buffers: [memory=%d] | %+v", memoryAfter, memFlushErr),
						"sidecar", sidecar, "module", module, "tags", tags,
						"data", map[string]interface{}{
							"event": PCAP_OSWMEM,
							"error": memFlushErr.Error(),
						})
					continue
				}
				releasedMemory := int64(memoryBefore) - int64(memoryAfter)
				sugar.Infow(fmt.Sprintf("flushed OS file write buffers: memory[before=%d|after=%d] / released=%d", memoryBefore, memoryAfter, releasedMemory),
					"sidecar", sidecar, "module", module, "tags", tags,
					"data", map[string]interface{}{
						"event":    PCAP_OSWMEM,
						"before":   memoryBefore,
						"after":    memoryAfter,
						"released": releasedMemory,
					})

			}
		}
	}(&wg, ticker)

	if err == nil {
		sugar.Infow(fmt.Sprintf("watching directory: %s", *src_dir),
			"data", initEvent, "sidecar", sidecar, "module", module, "tags", tags)
	} else {
		sugar.Fatalw(fmt.Sprintf("error at initialization: %v", err),
			"sidecar", sidecar, "module", module, "tags", tags,
			"data", map[string]interface{}{
				"event": PCAP_FSNINI,
				"error": err.Error(),
			})
		ticker.Stop()
		watcher.Close()
		cancel()
	}

	<-ctx.Done() // wait for context to be cancelled

	// flush remaining PCAP files after context is done
	flushStart := time.Now()
	pendingPcapFiles := flushSrcDir(&wg, pcapDotExt)
	sugar.Infow(fmt.Sprintf("waiting for %d PCAP files to be flushed", pendingPcapFiles),
		"sidecar", sidecar, "module", module, "tags", tags, "data",
		map[string]interface{}{
			"event":     PCAP_FSNEND,
			"files":     pendingPcapFiles,
			"timestamp": flushStart.Format(time.RFC3339Nano),
		})

	wg.Wait() // wait for remaining PCAP failes to be flushed
	flushLatency := time.Since(flushStart)

	sugar.Infow(fmt.Sprintf("flushed %d PCAP files: %v", pendingPcapFiles, flushLatency),
		"sidecar", sidecar, "module", module, "tags", tags,
		"data", map[string]interface{}{
			"event":   PCAP_FSNEND,
			"files":   pendingPcapFiles,
			"latency": flushLatency.String(),
		})
}
