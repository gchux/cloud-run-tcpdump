package main

import (
    "os"
    "io"
    "strings"
    "fmt"
    "log"
    "flag"
    "path/filepath"
    "compress/gzip"

    "go.uber.org/zap"
    "go.uber.org/zap/zapcore"
    "github.com/fsnotify/fsnotify"
)

var project_id  string   = os.Getenv("PROJECT_ID")
var gcp_region  string   = os.Getenv("GCP_REGION")
var service     string   = os.Getenv("RUN_SERVICE")
var sidecar     string   = os.Getenv("RUN_SIDECAR")
var version     string   = os.Getenv("RUN_REVISION")
var instance_id string   = os.Getenv("INSTANCE_ID")
var module      string   = os.Getenv("PROC_NAME")
var tags        []string = []string{project_id, service, gcp_region, version, instance_id}

var logger, _ = zap.Config{
    Encoding:    "json",
    Level:       zap.NewAtomicLevelAt(zapcore.DebugLevel),
    OutputPaths: []string{"stdout"},
    EncoderConfig: zapcore.EncoderConfig{  
        MessageKey: "message",
        LevelKey:   "severity",
        EncodeLevel: zapcore.CapitalLevelEncoder,
        TimeKey:    "time",
        EncodeTime: zapcore.ISO8601TimeEncoder,
    },
}.Build()
var sugar = logger.Sugar()

type jLogLevel string
const (
  INFO  jLogLevel = "INFO"
  ERROR jLogLevel = "ERROR"
)

type pcapEvent string
const (
  PCAP_FSNINI pcapEvent = "PCAP_FSNINI"
  PCAP_FSNERR pcapEvent = "PCAP_FSNERR"
  PCAP_CREATE pcapEvent = "PCAP_CREATE"
  PCAP_EXPORT pcapEvent = "PCAP_EXPORT"
)

type fsnEvent struct {
  Event  pcapEvent `json:"event,omitempty"`
  Source string    `json:"source,omitempty"`
  Target string    `json:"target,omitempty"`
  Bytes  int64     `json:"bytes,omitempty"`
}

func logFsEvent(level zapcore.Level, message string, event pcapEvent, src, tgt string, by int64) {
  sugar.Logw(zapcore.InfoLevel, message,
    "sidecar", sidecar, "module", module, "tags", tags,
    "data", fsnEvent{Event: event, Source: src, Target: tgt, Bytes: by})
}

func movePcapToGcs(pcap *int64, src_pcap *string, dst_dir *string, compress *bool) error {

    // Define name of destination PCAP file, prefixed by its ordinal and destination directory
    pcap_name := fmt.Sprintf("%d_%s", *pcap, filepath.Base(*src_pcap))
    tgt_pcap := filepath.Join(*dst_dir, pcap_name)
    // If compressing PCAP files is enabled, add `gz` siffux to the destination PCAP file path
    if *compress {
        tgt_pcap = fmt.Sprintf("%s.gz", tgt_pcap)
    }

    var err error
    var input_pcap, output_pcap *os.File

    // Open source PCAP file: the one thas is being moved to the destination directory
    input_pcap, err = os.Open(*src_pcap)
    if err != nil {
        logFsEvent(zapcore.ErrorLevel, fmt.Sprintf("%s", err), PCAP_EXPORT, *src_pcap, tgt_pcap, 0)
        return fmt.Errorf("failed to open source pcap: %s", *src_pcap)
    }

    // Create destination PCAP file ( export to the GCS Bucket )
    output_pcap, err = os.Create(tgt_pcap)
    if err != nil {
        logFsEvent(zapcore.ErrorLevel, fmt.Sprintf("%s", err), PCAP_EXPORT, *src_pcap, tgt_pcap, 0)
        return fmt.Errorf("failed to create destination pcap: %s", tgt_pcap)
    }
    defer output_pcap.Close()

    // Copy source PCAP into destination PCAP, compressing destination PCAP is optional
    var pcap_bytes int64
    if *compress {
        gzip_pcap := gzip.NewWriter(output_pcap)
        pcap_bytes, err = io.Copy(gzip_pcap, input_pcap)
        gzip_pcap.Flush()
        gzip_pcap.Close()
    } else {
        pcap_bytes, err = io.Copy(output_pcap, input_pcap)
    }
    input_pcap.Close()
    if err != nil {
        logFsEvent(zapcore.ErrorLevel, fmt.Sprintf("%s", err), PCAP_EXPORT, *src_pcap, tgt_pcap, 0)
        return fmt.Errorf("failed to copy '%s' into '%s'", *src_pcap, tgt_pcap)
    }
    
    // remove the source PCAP file if copying is sucessful
    os.Remove(*src_pcap)
    
    logFsEvent(zapcore.InfoLevel, "exported PCAP file", PCAP_EXPORT, *src_pcap, tgt_pcap, pcap_bytes)

    return nil
}

func main() {

    src_dir    := flag.String("src_dir",  "/pcap-tmp", "pcaps source directory")
    gcs_dir    := flag.String("gcs_dir",  "/pcap",     "pcaps destination directory")
    pcap_ext   := flag.String("pcap_ext", "pcap",      "pcap files extension")
    gzip_pcaps := flag.Bool("gzip",       false,       "compress pcap files")

    flag.Parse()

    defer logger.Sync()

    pcap_dot_ext := fmt.Sprintf(".%s", *pcap_ext)
    
    args := map[string]interface{}{
      "src_dir":  *src_dir,
      "gcs_dir":  *gcs_dir,
      "pcap_ext": pcap_dot_ext,
      "gzip":     *gzip_pcaps,
    }
    init_event := map[string]interface{}{"event": PCAP_FSNINI}

    sugar.Infow("starting PCAP filesystem watcher", "args", args,
      "data", init_event, "sidecar", sidecar, "module", module, "tags", tags)

    // Create new watcher.
    watcher, err := fsnotify.NewWatcher()
    if err != nil {
        log.Fatal(err)
    }
    defer watcher.Close()

    // Start listening for FS events at PCAP files source directory.
    go func() {

        var iteration int64 = 0;
        last_pcap := "";
        
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
                    if !(event.Has(fsnotify.Create) && strings.HasSuffix(event.Name, pcap_dot_ext)) {
                        break
                    }
                    logFsEvent(zapcore.InfoLevel, "new PCAP file", PCAP_CREATE, event.Name, "", 0)

                    // Skip 1st PCAP, start moving PCAPs as soon as TCPDUMP rolls over into the 2nd file.
                    // The outcome of this implementation is that the directory in which TCPDUMP writes
                    // PCAP files will contain at most 2 files, the current one, and the one being moved
                    // into the destination directory ( `gcs_dir` ). Otherwise it will contain all PCAPs.
                    if iteration == 0 {
                        last_pcap = event.Name
                        iteration += 1
                        break
                    }
                    // move non-current PCAP file into `gcs_dir` which means that:
                    // 1. the GCS Bucket should have already been mounted
                    // 2. the directory hierarchy to store PCAP files already exists
                    err = movePcapToGcs(&iteration, &last_pcap, gcs_dir, gzip_pcaps);
                    if err != nil {
                        logFsEvent(zapcore.ErrorLevel, fmt.Sprintf("%v", err), PCAP_EXPORT, last_pcap, "", 0)
                    }
                    // current PCAP file is the next one to be moved
                    last_pcap = event.Name
                    iteration += 1
                case err, ok := <-watcher.Errors:
                    if !ok {
                        return
                    }
                    logFsEvent(zapcore.ErrorLevel, fmt.Sprintf("%v", err), PCAP_FSNERR, last_pcap, "", 0)
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
      "data", init_event, "sidecar", sidecar, "module", module, "tags", tags)

    // Block main goroutine forever.
    <-make(chan struct{})
}
