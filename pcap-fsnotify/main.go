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

    "github.com/fsnotify/fsnotify"
)

func movePcapToGcs(pcap *int64, src_pcap *string, dst_dir *string, compress *bool) error {

    // Define name of destination PCAP file, prefixed by its ordinal and destination directory
    pcap_name := fmt.Sprintf("%d_%s", *pcap, filepath.Base(*src_pcap))
    dest_pcap := filepath.Join(*dst_dir, pcap_name)
    // If compressing PCAP files is enabled, add `gz` siffux to the destination PCAP file path
    if *compress {
        dest_pcap = fmt.Sprintf("%s.gz", dest_pcap)
    }

    var err error
    var input_pcap  *os.File
    var output_pcap *os.File

    // Open source PCAP file: the one thas is being moved to the destination directory
    input_pcap, err = os.Open(*src_pcap)
    if err != nil {
        log.Println(err)
        return fmt.Errorf("failed to open source pcap: %s", *src_pcap)
    }

    // Create destination PCAP file
    output_pcap, err = os.Create(dest_pcap)
    if err != nil {
        log.Println(err)
        return fmt.Errorf("failed to create destination pcap: %s", dest_pcap)
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
        log.Println(err)
        return fmt.Errorf("failed to copy '%s' to '%s'", *src_pcap, dest_pcap)
    }
    
    // remove the source PCAP file if copying is sucessful
    os.Remove(*src_pcap)
    
    log.Printf("[INFO] - last pcap [bytes:%d]: %s", pcap_bytes, dest_pcap)

    return nil
}

func main() {

    src_dir    := flag.String("src", "/pcap-tmp", "pcaps source directory")
    dst_dir    := flag.String("dst", "/pcap",     "pcaps destination directory")
    pcap_ext   := flag.String("ext", "pcap",      "pcap files extension")
    gzip_pcaps := flag.Bool("gzip",  false,       "compress pcap files")

    flag.Parse()

    pcap_dot_ext := fmt.Sprintf(".%s", *pcap_ext)

    log.Println("[INFO] - PCAPs source directory: ",      *src_dir)
    log.Println("[INFO] - PCAPs destination directory: ", *dst_dir)
    log.Println("[INFO] - PCAPs expected extension: ",    pcap_dot_ext)
    log.Println("[INFO] - Compress PCAP files: ",         *gzip_pcaps)

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
                    log.Println("[INFO] - new pcap: ", event.Name)
                    // Skip 1st PCAP, start moving PCAPs as soon as TCPDUMP rolls over into the 2nd file.
                    // The outcome of this implementation is that the directory in which TCPDUMP writes
                    // PCAP files will contain at most 2 files, the current one, and the one being moved
                    // into the destination directory ( `dst_dir` ). Otherwise it will contain all PCAPs.
                    if iteration == 0 {
                        last_pcap = event.Name
                        iteration += 1
                        break
                    }
                    // move non-current PCAP file into `dst_dir`
                    movePcapToGcs(&iteration, &last_pcap, dst_dir, gzip_pcaps);
                    // current PCAP file is the next one to be moved
                    last_pcap = event.Name
                    iteration += 1
                case err, ok := <-watcher.Errors:
                    if !ok {
                        return
                    }
                    log.Println("error:", err)
            }
        }
    }()

    // Watch the PCAP files source directory for FS events.
    err = watcher.Add(*src_dir)
    if err != nil {
        log.Fatal(err)
    }

    // Block main goroutine forever.
    <-make(chan struct{})
}
