package transformer

import (
	"context"
	"fmt"
	"strings"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type TextPcapTranslator struct{}

func (t *TextPcapTranslator) next(ctx context.Context, serial *int64) fmt.Stringer {
	var text strings.Builder
	text.WriteString("[ctx=")
	text.WriteString(fmt.Sprintf("%s", ctx.Value("id")))
	text.WriteString("|num=")
	text.WriteString(fmt.Sprintf("%d", serial))
	text.WriteString("]")
	return &text
}

func (t *TextPcapTranslator) translate(packet *gopacket.Packet) error {
	p := *packet

	ipLayer := p.Layer(layers.LayerTypeIPv4)
	if ipLayer != nil {
		fmt.Println("IPv4 layer detected.")
		ip, _ := ipLayer.(*layers.IPv4)

		// IP layer variables:
		// Version (Either 4 or 6)
		// IHL (IP Header Length in 32-bit words)
		// TOS, Length, Id, Flags, FragOffset, TTL, Protocol (TCP?),
		// Checksum, SrcIP, DstIP
		fmt.Printf("From %s to %s\n", ip.SrcIP, ip.DstIP)
		fmt.Println("Protocol: ", ip.Protocol)
		fmt.Println()
	}

	tcpLayer := p.Layer(layers.LayerTypeTCP)
	if tcpLayer != nil {
		fmt.Println("TCP layer detected.")
		tcp, _ := tcpLayer.(*layers.TCP)

		// TCP layer variables:
		// SrcPort, DstPort, Seq, Ack, DataOffset, Window, Checksum, Urgent
		// Bool flags: FIN, SYN, RST, PSH, ACK, URG, ECE, CWR, NS
		fmt.Printf("From port %d to %d\n", tcp.SrcPort, tcp.DstPort)
		fmt.Println("Sequence number: ", tcp.Seq)
		fmt.Println()
	}

	// Iterate over all layers, printing out each layer type
	fmt.Println("All packet layers:")
	for _, layer := range p.Layers() {
		fmt.Println("- ", layer.LayerType())
	}

	// Check for errors
	if err := p.ErrorLayer(); err != nil {
		fmt.Println("Error decoding some part of the packet:", err)
	}
	return nil
}

func (t *TextPcapTranslator) asText(buffer fmt.Stringer) *strings.Builder {
	return buffer.(*strings.Builder)
}

func (t *TextPcapTranslator) translateEthernetLayer(ctx context.Context, packet *layers.Ethernet, buffer fmt.Stringer) {
	text := t.asText(buffer)

	text.WriteString("[L2(")
	text.WriteString(packet.EthernetType.String())
	text.WriteString(") | ")
	text.WriteString(fmt.Sprintf("src=%s", packet.SrcMAC.String()))
	text.WriteString(" > ")
	text.WriteString(fmt.Sprintf("src=%s", packet.DstMAC.String()))
	text.WriteString("]")
}

func newTextPcapTranslator() *TextPcapTranslator {
	return &TextPcapTranslator{}
}
