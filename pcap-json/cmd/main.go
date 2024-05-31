package main

import (
  "log"
  "flag"
  "strings"

  "github.com/gchux/cloud-run-tcpdump/pcap-json/pkg/transformer"
)

func main() {
  
  pcapFileArg := flag.String("pcap", "", "absolute path of PCAP file to be transformed")

  flag.Parse()

  pcapFile := strings.TrimSpace(*pcapFileArg)

  if len(pcapFile) == 0 {
    log.Fatalln("invalid argument 'pcap'")
    return
  }

  transformer.PcapToJson(pcapFile)
}
