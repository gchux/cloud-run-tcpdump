package transformer

import (
  "fmt"

  "github.com/Jeffail/gabs/v2"
  "github.com/google/gopacket"
  "github.com/google/gopacket/layers"
)

type JsonPcapTranslator struct{}

func (t *JsonPcapTranslator) translate(packet *gopacket.Packet) error {
  return fmt.Errorf("not implemented")
} 

func (t *JsonPcapTranslator) next() fmt.Stringer {
  return gabs.New()
}

func (t *JsonPcapTranslator) translateEthernetLayer(packet *layers.Ethernet, buffer fmt.Stringer) {
  jsonObj := buffer.(*gabs.Container)
  jsonObj.Set(packet.EthernetType.String(), "L2", "type")
  jsonObj.Set(packet.SrcMAC.String(), "L2", "src")
  jsonObj.Set(packet.DstMAC.String(), "L2", "dst")
}

func newJsonPcapTranslator() *JsonPcapTranslator {
  return &JsonPcapTranslator{}
}
