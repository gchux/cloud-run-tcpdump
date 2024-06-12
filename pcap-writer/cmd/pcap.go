package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"regexp"
	"syscall"
	"time"

	"github.com/google/uuid"
	"github.com/gchux/cloud-run-tcpdump/pcap-writer/pkg/pcap"
)

var (
	engine    = flag.String("eng", "google", "Engine to use for capturing packets: tcpdump or google")
	iface     = flag.String("i", "any", "Interface to read packets from")
	snaplen   = flag.Int("s", 0, "Snap length (number of bytes max to read per packet")
	writeTo   = flag.String("w", "stdout", "Where to write packet capture to: stdout, stderr, file_path")
	tsType    = flag.String("ts_type", "", "Type of timestamps to use")
	promisc   = flag.Bool("promisc", true, "Set promiscuous mode")
	format    = flag.String("fmt", "default", "Set the output format: default, text or json")
	filter    = flag.String("bpf", "", "Set BPF filter to be used")
	timeout   = flag.Int("timeout", 0, "Set packet capturing total duration in seconds")
	interval  = flag.Int("interval", 0, "Set packet capture file rotation interval in seconds")
	extension = flag.String("ext", "", "Set pcap files extension: pcap, json, txt")
	stdout    = flag.Bool("stdout", false, "Log translation to standard output; only if 'w' is not 'stdout'")
	ordered   = flag.Bool("ordered", false, "write translation in the order in which packets were captured")
)

var logger = log.New(os.Stderr, "[pcap] - ", log.LstdFlags)

func handleError(prefix *string, err error) {
	if errors.Is(err, context.Canceled) {
		logger.Printf("%s cancelled\n", *prefix)
		os.Exit(1)
	}

	if errors.Is(err, context.DeadlineExceeded) {
		logger.Printf("%s complete\n", *prefix)
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
		Ordered:   *ordered,
	}

	exp, _ := regexp.Compile(fmt.Sprintf("^(?:ipvlan-)?%s.*", *iface))
	devs, _ := pcap.FindDevicesByRegex(exp)
	logger.Printf("device: %v\n", devs)

	var err error
	var pcapEngine pcap.PcapEngine

	pcapEngine, err = newPcapEngine(engine, config)
	if err != nil {
		log.Fatalf("%s", err)
		return
	}

	var ctx context.Context = context.Background()
	var cancel context.CancelFunc

	id := fmt.Sprintf("cli/%s", uuid.New())
	ctx = context.WithValue(ctx, "id", id)

	if *timeout > 0 {
		ctx, cancel = context.WithTimeout(ctx, time.Duration(*timeout)*time.Second)
	} else {
		ctx, cancel = context.WithCancel(ctx)
	}

	if *writeTo == "stdout" {
		*stdout = true
	}

	pcapWriters := []pcap.PcapWriter{}

	if *engine == "google" && *stdout {
		pcapWriter, err := pcap.NewStdoutPcapWriter()
		if err == nil {
			pcapWriters = append(pcapWriters, pcapWriter)
		}
	}

	if *engine == "google" && *writeTo != "stdout" {
		pcapWriter, err := pcap.NewPcapWriter(writeTo, extension, *interval)
		if err == nil {
			pcapWriters = append(pcapWriters, pcapWriter)
		}
  }

	signals := make(chan os.Signal)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		<-signals
		cancel()
	}()

	prefix := fmt.Sprintf("execution '%s'", id)
	logger.Printf("%s started", prefix)
	// this is a blocking call
	err = pcapEngine.Start(ctx, pcapWriters)
	if err != nil {
		handleError(&prefix, err)
	}

}
