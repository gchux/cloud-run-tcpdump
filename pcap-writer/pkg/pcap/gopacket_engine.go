package pcap

import (
	"context"
	"fmt"
	"io"
	"log"
	"os"
	"sync/atomic"
	"time"

	"github.com/gchux/cloud-run-tcpdump/pcap-writer/pkg/transformer"
	"github.com/google/gopacket"
	"github.com/google/gopacket/dumpcommand"
	gpcap "github.com/google/gopacket/pcap"
)

var gopacketLogger = log.New(os.Stderr, "[gopacket] - ", log.LstdFlags)

func (p *Pcap) IsActive() bool {
	return p.isActive.Load()
}

func (p *Pcap) newPcap(ctx context.Context) (*gpcap.InactiveHandle, error) {
	cfg := *p.config

	var err error

	inactiveHandle, err := gpcap.NewInactiveHandle(cfg.Iface)
	if err != nil {
		gopacketLogger.Fatalf("could not create: %v\n", err)
	}

	if err = inactiveHandle.SetSnapLen(cfg.Snaplen); err != nil {
		gopacketLogger.Fatalf("could not set snap length: %v\n", err)
		return nil, err
	}

	if err = inactiveHandle.SetPromisc(cfg.Promisc); err != nil {
		gopacketLogger.Fatalf("could not set promisc mode: %v\n", err)
		return nil, err
	}

	if err = inactiveHandle.SetTimeout(100 * time.Millisecond); err != nil {
		gopacketLogger.Fatalf("could not set timeout: %v\n", err)
		return nil, err
	}

	if cfg.TsType != "" {
		if t, err := gpcap.TimestampSourceFromString(cfg.TsType); err != nil {
			gopacketLogger.Fatalf("Supported timestamp types: %v\n", inactiveHandle.SupportedTimestamps())
			return nil, err
		} else if err := inactiveHandle.SetTimestampSource(t); err != nil {
			gopacketLogger.Fatalf("Supported timestamp types: %v\n", inactiveHandle.SupportedTimestamps())
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

	inactiveHandle, err := p.newPcap(ctx)
	if err != nil {
		return err
	}

	if handle, err = inactiveHandle.Activate(); err != nil {
		p.isActive.Store(false)
		return fmt.Errorf("failed to activate: %s", err)
	}
	p.activeHandle = handle

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

	// intentionally not using `io.MultiWriter`
	pcapWriters := []PcapWriter{}
	// `io.Writer` is what `fmt.Fprintf` requires
	ioWriters := make([]io.Writer, len(writers))
	for i, writer := range writers {
		ioWriters[i] = writer
		pcapWriters = append(pcapWriters, writer.(PcapWriter))
	}

	// create new transformer for the specified output format
	var fn transformer.IPcapTransformer
	if cfg.Ordered {
		fn, err = transformer.NewOrderedTransformer(ctx, ioWriters, &format)
	} else {
		fn, err = transformer.NewTransformer(ctx, ioWriters, &format)
	}
	if err != nil {
		return fmt.Errorf("invalid format: %s", err)
	}
	p.fn = fn

	var packetsCounter atomic.Int64
	for {
		select {
		case packet := <-source.Packets():
			serial := packetsCounter.Add(1)
			// non-blocking operation
			if err := fn.Apply(ctx, &packet, &serial); err != nil {
				gopacketLogger.Fatalf("[%d] – failed to translate: %s\n", serial, packet)
			}
		case <-ctx.Done():
			inactiveHandle.CleanUp()
			handle.Close()
			fn.WaitDone()
			// do not close engine's writers until `stop` is called
			// if the context is done, simply rotate the curren Pcap file
			// PCAP file rotation includes: flush and sync
			for _, writer := range pcapWriters {
				writer.rotate()
			}
			gopacketLogger.Printf("total packets: %d\n", packetsCounter.Load())
			p.isActive.Store(false)
			return ctx.Err()
		}
	}
}

func NewPcap(config *PcapConfig) (PcapEngine, error) {
	var isActive atomic.Bool
	isActive.Store(false)

	pcap := Pcap{config: config, isActive: &isActive}
	return &pcap, nil
}
