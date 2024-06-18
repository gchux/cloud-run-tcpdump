package transformer

import (
	"context"
	"fmt"

	"github.com/Jeffail/gabs/v2"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type JsonPcapTranslator struct{}

func (t *JsonPcapTranslator) translate(packet *gopacket.Packet) error {
	return fmt.Errorf("not implemented")
}

// return pointer to `struct` `gabs.Container`
func (t *JsonPcapTranslator) next(ctx context.Context, serial *int64) fmt.Stringer {
	json := gabs.New()
	json.Set(ctx.Value("id"), "ctx")
	json.Set(*serial, "num")
	return json
}

func (t *JsonPcapTranslator) asJson(buffer fmt.Stringer) *gabs.Container {
	return buffer.(*gabs.Container)
}

func (t *JsonPcapTranslator) translateEthernetLayer(ctx context.Context, eth *layers.Ethernet) fmt.Stringer {
	json := gabs.New()

	json.SetP(eth.EthernetType.String(), "L2.type")
	json.SetP(eth.SrcMAC.String(), "L2.src")
	json.SetP(eth.DstMAC.String(), "L2.dst")

	return json
}

func (t *JsonPcapTranslator) translateIPv4Layer(ctx context.Context, ip *layers.IPv4) fmt.Stringer {
	json := gabs.New()

	json.SetP(ip.Protocol.String(), "L3.proto")
	json.SetP(ip.TTL, "L3.ttl")
	json.SetP(ip.SrcIP, "L3.src")
	json.SetP(ip.DstIP, "L3.dst")

	return json
}

func (t *JsonPcapTranslator) translateTCPLayer(ctx context.Context, tcp *layers.TCP) fmt.Stringer {
	json := gabs.New()

	json.SetP(tcp.SrcPort, "L4.src.port")
	json.SetP(tcp.DstPort, "L4.dst.port")
	json.SetP(tcp.Seq, "L4.seq")
	json.SetP(tcp.Ack, "L4.ack")
	json.SetP(tcp.SYN, "L4.flags.SYN")
	json.SetP(tcp.ACK, "L4.flags.ACK")
	json.SetP(tcp.PSH, "L4.flags.PSH")
	json.SetP(tcp.FIN, "L4.flags.FIN")
	json.SetP(tcp.RST, "L4.flags.RST")

	if name, ok := layers.TCPPortNames[tcp.SrcPort]; ok {
		json.SetP(name, "L4.src.proto")
	}

	if name, ok := layers.TCPPortNames[tcp.DstPort]; ok {
		json.SetP(name, "L4.dst.proto")
	}

	return json
}

func (t *JsonPcapTranslator) merge(ctx context.Context, tgt fmt.Stringer, src fmt.Stringer) (fmt.Stringer, error) {
	return tgt, t.asJson(tgt).Merge(t.asJson(src))
}

func newJsonPcapTranslator() *JsonPcapTranslator {
	return &JsonPcapTranslator{}
}
