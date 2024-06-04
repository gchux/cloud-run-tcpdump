package pcap

import (
  "context"
  "sync/atomic"

  gpcap "github.com/google/gopacket/pcap"
  "github.com/gchux/cloud-run-tcpdump/pcap-writer/pkg/transformer"
)

type PcapConfig struct{
  Promisc bool
  Iface   string
  Snaplen int
  TsType  string
  Format  string
  Filter  string
  Output  string
}

type PcapEngine interface{
  Start(context.Context) error
  IsActive() bool
}

type Pcap struct{
  config         *PcapConfig
  activeHandle   *gpcap.Handle
  inactiveHandle *gpcap.InactiveHandle
  isActive       atomic.Bool
  fn             transformer.IPcapTransformer
}

type Tcpdump struct{
  config *PcapConfig
}
