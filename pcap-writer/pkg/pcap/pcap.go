package pcap

import (
  "regexp"
  "context"
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
  Output    string
  Extension string
  Interval  int
}

type PcapEngine interface{
  Start(context.Context, PcapWriter) error
  IsActive() bool
}

type Pcap struct {
  config         *PcapConfig
  isActive       atomic.Bool
  activeHandle   *gpcap.Handle
  inactiveHandle *gpcap.InactiveHandle
  fn             transformer.IPcapTransformer
}

type Tcpdump struct {
  config   *PcapConfig
  isActive atomic.Bool
}

func FindDevicesByRegex(exp *regexp.Regexp) ([]string, error) {

  devices, err := gpcap.FindAllDevs()
  if err != nil {
    return nil, err
  }

  var devs []string

  for _, device := range devices {
    if exp.MatchString(device.Name) {
      devs = append(devs, device.Name)
    }
  }

  return devs, nil
}
