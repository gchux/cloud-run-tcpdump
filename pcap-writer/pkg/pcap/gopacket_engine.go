package pcap

import (
  "os"
  "io"
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

func (p *Pcap) newPcap() (*gpcap.InactiveHandle, error) {

  cfg := *p.config

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

  p.inactiveHandle = inactiveHandle

  return inactiveHandle, nil
}

func (p *Pcap) Start(ctx context.Context, writers []PcapWriter) error {

  // atomically activate the packet capture
  if !p.isActive.CompareAndSwap(false, true) {
    return fmt.Errorf("already started")
  }

  var err error
  var handle *gpcap.Handle

  inactiveHandle, err := p.newPcap()
  if err != nil {
    return err
  }
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

  numWriters := len(writers)
  // saving buffered writers in advance
  pcapWriters := []*pcapWriter{}
  // `io.Writer` is what `fmt.Fprintf` requires 
  ioWriters := make([]io.Writer, numWriters, numWriters)
  for i, writer := range writers {
    ioWriters[i] = writer
    // except for `stdout` all other writers are buffered
    if writer != os.Stdout {
      pcapWriters = append(pcapWriters, writer.(*pcapWriter))
    }
  }
  // create new transformer for the specified output format
  fn, err := transformer.NewTransformer(ctx, ioWriters, &format)
  if err != nil {
    return fmt.Errorf("invalid format: %s", err)
  }
  p.fn = fn

  for {
    select {
    case packet := <-source.Packets():
      // non-blocking operation
      fn.Apply(&packet)
    case <-ctx.Done():
      // do not close engine's writers until `stop` is called
      // if the context is done, simply rotate the curren Pcap file
      // PCAP file rotation includes: flush and sync
      for _, writer := range pcapWriters {
        writer.rotate()
      }
      p.isActive.Store(false)
      return ctx.Err()
    }
  }
}

func NewPcap(config *PcapConfig) (PcapEngine, error) {

  var isActive atomic.Bool
  isActive.Store(false)
  
  pcap := Pcap{config: config, isActive: isActive}
  return &pcap, nil
}
