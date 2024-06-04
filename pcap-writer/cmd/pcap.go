package main

import (
  "log"
  "flag" 

  "github.com/gchux/cloud-run-tcpdump/pcap-writer/pkg/pcap"
)

var iface   = flag.String("i", "any", "Interface to read packets from")
var snaplen = flag.Int("s", 0, "Snap length (number of bytes max to read per packet")
var writeTo = flag.String("w", "/dev/stdout", "where to write packet capture to")
var tsType  = flag.String("ts_type", "", "Type of timestamps to use")
var promisc = flag.Bool("promisc", true, "Set promiscuous mode")
var format  = flag.String("fmt", "default", "Set the output format: default, text or json")
var filter  = flag.String("bpf", "", "Set BPF filter to be used")

func main() {

  flag.Parse()

  config := &pcap.PcapConfig{
    Promisc: *promisc,
    Iface:   *iface,
    Snaplen: *snaplen,
    TsType:  *tsType,
    Format:  *format,
    Filter:  *filter,
  }

  var engine pcap.PcapEngine
  var err error

  engine, err = pcap.NewPcap(config)
  if err != nil {
    log.Fatalf("%s", err)
    return
  }

  err = engine.Start()
  if err != nil {
    log.Fatalf("error: %s", err)
  }
}
