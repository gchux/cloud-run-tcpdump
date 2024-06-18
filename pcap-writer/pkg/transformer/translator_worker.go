package transformer

import (
	"context"
	"fmt"
	"sync"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// Create a type based on your input to the work function
type pcapTranslatorWorker struct {
	serial     *int64
	packet     *gopacket.Packet
	translator PcapTranslator
}

//go:generate stringer -type=PcapTranslatorFmt
const (
	TEXT PcapTranslatorFmt = iota
	JSON
)

var pcapTranslatorFmts = map[string]PcapTranslatorFmt{
	"json": JSON,
	"text": TEXT,
}

func (w pcapTranslatorWorker) pkt() gopacket.Packet {
	return *w.packet
}

func (w pcapTranslatorWorker) asLayer(layer gopacket.LayerType) gopacket.Layer {
	return w.pkt().Layer(layer)
}

func (w pcapTranslatorWorker) translateEthernetLayer(ctx context.Context) fmt.Stringer {
	ethernetLayer := w.asLayer(layers.LayerTypeEthernet)
	if ethernetLayer != nil {
		ethernetPacket, _ := ethernetLayer.(*layers.Ethernet)
		return w.translator.translateEthernetLayer(ctx, ethernetPacket)
	}
	return nil
}

func (w pcapTranslatorWorker) translateIPv4Layer(ctx context.Context) fmt.Stringer {
	ipLayer := w.asLayer(layers.LayerTypeIPv4)
	if ipLayer != nil {
		ipPacket, _ := ipLayer.(*layers.IPv4)
		return w.translator.translateIPv4Layer(ctx, ipPacket)
	}
	return nil
}

func (w pcapTranslatorWorker) translateIPv6Layer(ctx context.Context) fmt.Stringer {
	ipLayer := w.asLayer(layers.LayerTypeIPv6)
	if ipLayer != nil {
		ipPacket, _ := ipLayer.(*layers.IPv6)
		return w.translator.translateIPv6Layer(ctx, ipPacket)
	}
	return nil
}

func (w pcapTranslatorWorker) translateUDPLayer(ctx context.Context) fmt.Stringer {
	tcpLayer := w.asLayer(layers.LayerTypeUDP)
	if tcpLayer != nil {
		tcpPacket, _ := tcpLayer.(*layers.UDP)
		return w.translator.translateUDPLayer(ctx, tcpPacket)
	}
	return nil
}

func (w pcapTranslatorWorker) translateTCPLayer(ctx context.Context) fmt.Stringer {
	tcpLayer := w.asLayer(layers.LayerTypeTCP)
	if tcpLayer != nil {
		tcpPacket, _ := tcpLayer.(*layers.TCP)
		return w.translator.translateTCPLayer(ctx, tcpPacket)
	}
	return nil
}

// The work that needs to be performed
// The input type should implement the WorkFunction interface
func (w pcapTranslatorWorker) Run(ctx context.Context) interface{} {
	buffer := w.translator.next(ctx, w.serial)

	translators := []packetLayerTranslator{
		w.translateEthernetLayer,
		w.translateIPv4Layer,
		w.translateIPv6Layer,
		w.translateUDPLayer,
		w.translateTCPLayer,
	}

	numLayers := len(translators)
	translations := make(chan fmt.Stringer, numLayers)
	var wg sync.WaitGroup
	wg.Add(numLayers) // number of layers to be translated

	for _, translator := range translators {
		go func(translator packetLayerTranslator) {
			translations <- translator(ctx)
			wg.Done()
		}(translator)
	}

	go func() {
		wg.Wait()
		close(translations)
	}()

	for translation := range translations {
		// translations are `nil` if layer is not available
		if translation != nil {
			buffer, _ = w.translator.merge(ctx, buffer, translation)
		}
	}

	// translate more layers

	return &buffer
}
