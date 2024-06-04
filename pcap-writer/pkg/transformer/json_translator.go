package transformer

import (
  "io"
  "fmt"

  "github.com/google/gopacket"
  "github.com/google/gopacket/layers"
)

type JsonPcapTranslator struct{}

func (t *JsonPcapTranslator) translate(packet *gopacket.Packet) error {
  return fmt.Errorf("not implemented")
} 

func (t *JsonPcapTranslator) next(stream io.Writer) {}

func (t *JsonPcapTranslator) translateEthernetLayer(packet *layers.Ethernet) {}

func newJsonPcapTranslator() *JsonPcapTranslator {
  return nil
}
