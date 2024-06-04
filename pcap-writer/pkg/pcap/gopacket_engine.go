package pcap

import (
  "fmt"
  "log"
  "time"
  "context"
  "sync/atomic"

  "github.com/google/gopacket"
  gpcap "github.com/google/gopacket/pcap"
  "github.com/google/gopacket/dumpcommand"
  "github.com/gchux/cloud-run-tcpdump/pcap-writer/pkg/transformer"
)

func (p *Pcap) IsActive() bool {
  return p.isActive.Load()
}

func (p *Pcap) Start(ctx context.Context) error {

  // atomically activate the packet capture
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
  p.activeHandle = handle
  defer handle.Close()

  cfg := *p.config

  // set packet capture filter; i/e: `tcp port 443`
  var filter string = cfg.Filter
  if filter != "" {
    if err = handle.SetBPFFilter(filter); err != nil {
      return fmt.Errorf("BPF filter error: %s", err)
    }
  }

  // if format is `default` output is similar to `tcpdump`
  var format string = cfg.Format
  if format == "default" {
    dumpcommand.Run(handle) // `gopacket` default implementation
    return nil
  }

  source := gopacket.NewPacketSource(handle, handle.LinkType())
  source.Lazy = false
  source.NoCopy = true
  source.DecodeStreamsAsDatagrams = true

  // create new transformer for the specified output format
  fn, err := transformer.NewTransformer(ctx, &cfg.Output, &format)
  if err != nil {
    return fmt.Errorf("invalid format: %s", err)
  }
  p.fn = fn

  // `fn.Apply` is non-blocking
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
