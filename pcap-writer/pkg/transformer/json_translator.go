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

func (t *JsonPcapTranslator) translateEthernetLayer(ctx context.Context, packet *layers.Ethernet, buffer fmt.Stringer) {
	json := t.asJson(buffer)

	json.SetP(packet.EthernetType.String(), "L2.type")
	json.SetP(packet.SrcMAC.String(), "L2.src")
	json.SetP(packet.DstMAC.String(), "L2.dst")
}

func newJsonPcapTranslator() *JsonPcapTranslator {
	return &JsonPcapTranslator{}
}
