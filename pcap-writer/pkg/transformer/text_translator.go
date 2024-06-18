package transformer

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type (
	TextPcapTranslator struct{}
	textPcapTranslator struct {
		index   int
		builder *strings.Builder
	}
	iTextPcapTranslator interface {
		fmt.Stringer
	}
	textPcapTranslators map[int]*textPcapTranslator
)

func (tt *textPcapTranslator) String() string {
	return tt.builder.String()
}

func (tt *textPcapTranslators) String() string {
	keys := make([]int, 0)
	for key := range *tt {
		keys = append(keys, key)
	}
	sort.Ints(keys)
	var packetStr strings.Builder
	for _, key := range keys {
		builder := (*tt)[key].builder
		if key > 0 {
			packetStr.WriteString("\n - ")
		}
		packetStr.WriteString(builder.String())
	}
	return packetStr.String()
}

func (t *TextPcapTranslator) next(ctx context.Context, serial *int64) fmt.Stringer {
	var text strings.Builder
	text.WriteString("[ctx=")
	text.WriteString(fmt.Sprintf("%s", ctx.Value("id")))
	text.WriteString("|num=")
	text.WriteString(fmt.Sprintf("%d", *serial))
	text.WriteString("]")
	return &textPcapTranslator{0, &text}
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

func (t *TextPcapTranslator) translateEthernetLayer(ctx context.Context, packet *layers.Ethernet) fmt.Stringer {
	var text strings.Builder

	text.WriteString("[L2=")
	text.WriteString(packet.EthernetType.String())
	text.WriteString("|")
	text.WriteString(fmt.Sprintf("src=%s", packet.SrcMAC.String()))
	text.WriteString("|")
	text.WriteString(fmt.Sprintf("dst=%s", packet.DstMAC.String()))
	text.WriteString("]")

	return &textPcapTranslator{1, &text}
}

func (t *TextPcapTranslator) translateIPv4Layer(ctx context.Context, packet *layers.IPv4) fmt.Stringer {
	return &textPcapTranslator{2, new(strings.Builder)}
}

func (t *TextPcapTranslator) translateTCPLayer(ctx context.Context, packet *layers.TCP) fmt.Stringer {
	return &textPcapTranslator{3, new(strings.Builder)}
}

func (t *TextPcapTranslator) merge(ctx context.Context, tgt fmt.Stringer, src fmt.Stringer) (fmt.Stringer, error) {
	switch typedObj := tgt.(type) {
	case *textPcapTranslators:
		(*typedObj)[src.(*textPcapTranslator).index] = src.(*textPcapTranslator)
	case *textPcapTranslator:
		tgt = &textPcapTranslators{
			typedObj.index: typedObj, src.(*textPcapTranslator).index: src.(*textPcapTranslator),
		}
	}
	return tgt, nil
}

func newTextPcapTranslator() *TextPcapTranslator {
	return &TextPcapTranslator{}
}
