package main

import (
	"compress/gzip"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/fsnotify/fsnotify"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

var (
	src_dir    = flag.String("src_dir", "/pcap-tmp", "pcaps source directory")
	gcs_dir    = flag.String("gcs_dir", "/pcap", "pcaps destination directory")
	pcap_ext   = flag.String("pcap_ext", "pcap", "pcap files extension")
	gzip_pcaps = flag.Bool("gzip", false, "compress pcap files")
)

var (
	projectID  string   = os.Getenv("PROJECT_ID")
	gcpRegion  string   = os.Getenv("GCP_REGION")
	service    string   = os.Getenv("APP_SERVICE")
	version    string   = os.Getenv("APP_VERSION")
	sidecar    string   = os.Getenv("APP_SIDECAR")
	instanceID string   = os.Getenv("INSTANCE_ID")
	module     string   = os.Getenv("PROC_NAME")
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
	PCAP_FSNERR pcapEvent = "PCAP_FSNERR"
	PCAP_CREATE pcapEvent = "PCAP_CREATE"
	PCAP_EXPORT pcapEvent = "PCAP_EXPORT"
	PCAP_QUEUED pcapEvent = "PCAP_QUEUED"
)

var counters, lastPcap sync.Map

func logFsEvent(level zapcore.Level, message string, event pcapEvent, src, tgt string, by int64) {
	sugar.Logw(level, message, "sidecar", sidecar, "module", module, "tags", tags,
		"data", fsnEvent{Event: event, Source: src, Target: tgt, Bytes: by})
}

func movePcapToGcs(pcap *uint64, srcPcap *string, dstDir *string, compress *bool) (*string, *int64, error) {
	// Define name of destination PCAP file, prefixed by its ordinal and destination directory
	pcapName := fmt.Sprintf("%d_%s", *pcap, filepath.Base(*srcPcap))
	tgtPcap := filepath.Join(*dstDir, pcapName)
	// If compressing PCAP files is enabled, add `gz` siffux to the destination PCAP file path
	if *compress {
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
	if *compress {
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

	// remove the source PCAP file if copying is sucessful
	os.Remove(*srcPcap)

	return &tgtPcap, &pcapBytes, nil
}

func main() {
	flag.Parse()

	defer logger.Sync()

	ext := strings.Join(strings.Split(*pcap_ext, ","), "|")
	fmt.Println(ext)
	pcapDotExt := regexp.MustCompile(`^` + *src_dir + `/part__(\d+?)_(.+?)__\d{8}_\d{6}\.(` + ext + `)$`)

	args := map[string]interface{}{
		"src_dir":  *src_dir,
		"gcs_dir":  *gcs_dir,
		"pcap_ext": pcapDotExt,
		"gzip":     *gzip_pcaps,
	}
	initEvent := map[string]interface{}{"event": PCAP_FSNINI}

	sugar.Infow("starting PCAP filesystem watcher", "args", args,
		"data", initEvent, "sidecar", sidecar, "module", module, "tags", tags)

	// Create new watcher.
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		log.Fatal(err)
	}
	defer watcher.Close()

	// Start listening for FS events at PCAP files source directory.
	go func() {
		// [ToDo]: implement fast-pcap-export
		// using a short timeout for `tcpdumnp` and long periods between executions may cause orphaned PCAPs;
		// implement a validation to confirm that `tcpdump` is not running while PCAP files are available.
		for {
			select {
			case event, ok := <-watcher.Events:
				if !ok {
					return
				}
				// Skip events which are not CREATE, and all which are not related to PCAP files
				if !event.Has(fsnotify.Create) || !pcapDotExt.MatchString(event.Name) {
					break
				}

				rMatch := pcapDotExt.FindStringSubmatch(event.Name)

				iface := fmt.Sprintf("%s:%s", rMatch[1], rMatch[2])
				ext := rMatch[3]
				key := strings.Join(rMatch[1:], "/")

				var counter *atomic.Uint64
				if c, ok := counters.Load(key); !ok {
					c = new(atomic.Uint64)
					c, _ = counters.LoadOrStore(key, c)
					counter = c.(*atomic.Uint64)
				} else {
					counter = c.(*atomic.Uint64)
				}
				iteration := (*counter).Add(1)

				logFsEvent(zapcore.InfoLevel, fmt.Sprintf("new PCAP file: [%s] (%s/%s/%d) %s", key, ext, iface, iteration, event.Name), PCAP_CREATE, event.Name, "" /* target PCAP file */, 0)

				// Skip 1st PCAP, start moving PCAPs as soon as TCPDUMP rolls over into the 2nd file.
				// The outcome of this implementation is that the directory in which TCPDUMP writes
				// PCAP files will contain at most 2 files, the current one, and the one being moved
				// into the destination directory ( `gcs_dir` ). Otherwise it will contain all PCAPs.
				if iteration == 1 {
					lastPcap.Store(key, event.Name)
					break
				}

				index := iteration - 1

				pcapFile, loaded := lastPcap.Load(key)
				if !loaded {
					logFsEvent(zapcore.ErrorLevel, fmt.Sprintf("PCAP file [%s] (%s/%s/%d) unavailable/leaked", key, ext, iface, index), PCAP_EXPORT, "" /* source PCAP File */, "" /* target PCAP file */, 0)
				}
				srcPcapFileName := pcapFile.(string)

				// move non-current PCAP file into `gcs_dir` which means that:
				// 1. the GCS Bucket should have already been mounted
				// 2. the directory hierarchy to store PCAP files already exists
				tgtPcapFileName, pcapBytes, moveErr := movePcapToGcs(&index, &srcPcapFileName, gcs_dir, gzip_pcaps)
				if moveErr != nil {
					logFsEvent(zapcore.ErrorLevel, fmt.Sprintf("(%s/%s/%d) %s: %v", ext, iface, index, srcPcapFileName, moveErr), PCAP_EXPORT, srcPcapFileName, *tgtPcapFileName /* target PCAP file */, 0)
				}
				logFsEvent(zapcore.InfoLevel, fmt.Sprintf("exported PCAP file: (%s/%s/%d) %s", ext, iface, index, *tgtPcapFileName), PCAP_EXPORT, srcPcapFileName, *tgtPcapFileName, *pcapBytes)

				// current PCAP file is the next one to be moved
				if lastPcap.CompareAndSwap(key, srcPcapFileName, event.Name) {
					logFsEvent(zapcore.InfoLevel, fmt.Sprintf("queued PCAP file: (%s/%s/%d) %s", ext, iface, iteration, event.Name), PCAP_QUEUED, event.Name, "" /* target PCAP file */, 0)
				} else {
					logFsEvent(zapcore.ErrorLevel, fmt.Sprintf("leaked PCAP file: [%s] (%s/%s/%d) %s", key, ext, iface, iteration, event.Name), PCAP_QUEUED, event.Name, "" /* target PCAP file */, 0)
				}
			case fsnErr, ok := <-watcher.Errors:
				if !ok {
					return
				}
				logFsEvent(zapcore.ErrorLevel, fmt.Sprintf("%v", fsnErr), PCAP_FSNERR, "" /* source PCAP file */, "" /* target PCAP file */, 0)
			}
		}
	}()

	// Watch the PCAP files source directory for FS events.
	err = watcher.Add(*src_dir)
	if err != nil {
		sugar.Fatalw(fmt.Sprintf("%v", err),
			"sidecar", sidecar, "module", module, "tags", tags,
			"data", map[string]interface{}{"event": PCAP_FSNERR})
	}

	sugar.Infow(fmt.Sprintf("watching directory: %s", *src_dir),
		"data", initEvent, "sidecar", sidecar, "module", module, "tags", tags)

	// Block main goroutine forever.
	<-make(chan struct{})
}
