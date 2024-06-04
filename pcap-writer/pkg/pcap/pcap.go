package pcap

import (
  "sync/atomic"

  gpcap "github.com/google/gopacket/pcap"
  "github.com/gchux/cloud-run-tcpdump/pcap-writer/pkg/transformer"
)

type PcapConfig struct{
  Promisc   bool
  Iface     string
  Snaplen   int
  TsType    string
  Format    string
  Filter    string
}

type PcapEngine interface{
  Start()    error
  IsActive() bool
}

type Pcap struct{
  config         *PcapConfig
  activeHandle   *gpcap.Handle
  inactiveHandle *gpcap.InactiveHandle
  outStream      string
  isActive       atomic.Bool // should be atomic.Bool
  fn             transformer.IPcapTransformer
}

type Tcpdump struct{
}
