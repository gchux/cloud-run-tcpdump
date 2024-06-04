package pcap

import (
  "fmt"
  "log"
  "time"
  "sync/atomic"

  "github.com/google/gopacket"
  gpcap "github.com/google/gopacket/pcap"
  "github.com/google/gopacket/dumpcommand"
  "github.com/gchux/cloud-run-tcpdump/pcap-json/pkg/transformer"
)

func (p *Pcap) IsActive() bool {
  return p.isActive.Load()
}

func (p *Pcap) Start() error {

  if !p.isActive.CompareAndSwap(false, true) {
    return fmt.Errorf("already started")
  }

  var err error
  var handle *gpcap.Handle

  inactiveHandle := p.inactiveHandle
  defer inactiveHandle.CleanUp()

  if handle, err = inactiveHandle.Activate(); err != nil {
    p.isActive.Store(false)
    return fmt.Errorf("failed to activate: %s", err)
  }
  defer handle.Close()

  p.activeHandle = handle

  config := *p.config

  var filter string = config.Filter
  if filter != "" {
    if err = handle.SetBPFFilter(filter); err != nil {
      return fmt.Errorf("BPF filter error: %s", err)
    }
  }

  var format string = config.Format
  if format == "default" {
    dumpcommand.Run(handle) // `gopacket` default implementation
    return nil
  }

  fn, err := transformer.NewTransformer(&format)
  if err != nil {
    return fmt.Errorf("invalid format: %s", err)
  }

  p.fn = fn

  source := gopacket.NewPacketSource(handle, handle.LinkType())
  
  source.Lazy = false
  source.NoCopy = true
  source.DecodeStreamsAsDatagrams = true

  for packet := range source.Packets() {
    fn.Apply(&packet)
    // use `packet.Data()` to write bytes to a PCAP file
  }

  return nil
}

func NewPcap(config *PcapConfig) (PcapEngine, error) {

  cfg := *config

  var err error

  inactiveHandle, err := gpcap.NewInactiveHandle(cfg.Iface)
  if err != nil {
    log.Fatalf("could not create: %v", err)
  }

  if err = inactiveHandle.SetSnapLen(cfg.Snaplen); err != nil {
    log.Fatalf("could not set snap length: %v", err)
    return nil, err
  }

  if err = inactiveHandle.SetPromisc(cfg.Promisc); err != nil {
    log.Fatalf("could not set promisc mode: %v", err)
    return nil, err
  }

  if err = inactiveHandle.SetTimeout(time.Second); err != nil {
    log.Fatalf("could not set timeout: %v", err)
    return nil, err
  }

  if cfg.TsType != "" {
    if t, err := gpcap.TimestampSourceFromString(cfg.TsType); err != nil {
      log.Fatalf("Supported timestamp types: %v", inactiveHandle.SupportedTimestamps())
      return nil, err
    } else if err := inactiveHandle.SetTimestampSource(t); err != nil {
      log.Fatalf("Supported timestamp types: %v", inactiveHandle.SupportedTimestamps())
      return nil, err
    }
  }

  var isActive atomic.Bool
  isActive.Store(false)
  
  pcap := Pcap{config: config, inactiveHandle: inactiveHandle, isActive: isActive}
  return &pcap, nil
}
