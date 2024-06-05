package main

import (
  "os"
  "fmt"
  "log"
  "flag"
  "time"
  "errors"
  "regexp"
  "context"
  "syscall"
  "os/signal"

  "github.com/gchux/cloud-run-tcpdump/pcap-writer/pkg/pcap"
)

var engine    = flag.String("eng",     "google",  "Engine to use for capturing packets: tcpdump or google")
var iface     = flag.String("i",       "any",     "Interface to read packets from")
var snaplen   = flag.Int("s",          0,         "Snap length (number of bytes max to read per packet")
var writeTo   = flag.String("w",       "stdout",  "Where to write packet capture to: stdout, stderr, file_path")
var tsType    = flag.String("ts_type", "",        "Type of timestamps to use")
var promisc   = flag.Bool("promisc",   true,      "Set promiscuous mode")
var format    = flag.String("fmt",     "default", "Set the output format: default, text or json")
var filter    = flag.String("bpf",     "",        "Set BPF filter to be used")
var timeout   = flag.Int("timeout",    0,         "Set packet capturing total duration in seconds")
var interval  = flag.Int("interval",   0,         "Set packet capture file rotation interval in seconds")
var extension = flag.String("ext",     "",        "Set pcap files extension: pcap, json, txt")
var stdout    = flag.Bool("stdout",    false,     "Log translation to standard output; only if 'w' is not 'stdout'")

var logger = log.New(os.Stderr, "[pcap] - ", log.LstdFlags)

func handleError(err error) {

  if errors.Is(err, context.Canceled) {
    logger.Println("execution cancelled")
    os.Exit(1)
  }

  if errors.Is(err, context.DeadlineExceeded) {
    logger.Println("execution complete")
  }
}

func newPcapEngine(engine *string, config *pcap.PcapConfig) (pcap.PcapEngine, error) {

  pcapEngine := *engine

  switch pcapEngine {
  case "google":
    return pcap.NewPcap(config)
  case "tcpdump":
    return pcap.NewTcpdump(config)
  default:
    /* no-go */
  }

  return nil, fmt.Errorf("unavailable: %s", pcapEngine)
}

func main() {

  flag.Parse()

  config := &pcap.PcapConfig{
    Promisc:   *promisc,
    Iface:     *iface,
    Snaplen:   *snaplen,
    TsType:    *tsType,
    Format:    *format,
    Filter:    *filter,
    Output:    *writeTo,
    Interval:  *interval,
    Extension: *extension,
  }

  exp, _  := regexp.Compile(fmt.Sprintf("^(?:ipvlan-)?%s.*", *iface))
  devs, _ := pcap.FindDevicesByRegex(exp)
  logger.Printf("device: %v\n", devs)


  var err error
  var pcapEngine pcap.PcapEngine

  pcapEngine, err = newPcapEngine(engine, config)
  if err != nil {
    log.Fatalf("%s", err)
    return
  }

  var pcapWriter pcap.PcapWriter
  pcapWriter, err = pcap.NewPcapWriter(writeTo, extension, *interval)
  if err != nil {
    pcapWriter = os.Stdout
  }

  var ctx context.Context = context.Background()
  var cancel context.CancelFunc
  
  if *timeout > 0 {
    ctx, cancel = context.WithTimeout(ctx, time.Duration(*timeout) * time.Second)
  } else {
    ctx, cancel = context.WithCancel(ctx)
  }

  signals := make(chan os.Signal)
  signal.Notify(signals, os.Interrupt, syscall.SIGTERM, syscall.SIGINT)
  go func() {
    <-signals
    cancel() 
  }()

  pcapWriters := []pcap.PcapWriter{pcapWriter}
  if *stdout && config.Output != "stdout" {
    pcapWriters = append(pcapWriters, os.Stdout)
  }

  err = pcapEngine.Start(ctx, pcapWriters)
  if err != nil {
    handleError(err)
  }

}
