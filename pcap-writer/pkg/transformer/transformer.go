package transformer

import (
  "io"
  "os"
  "fmt"

  "github.com/google/gopacket"
  "github.com/google/gopacket/layers"
)

type PcapTranslator interface{
  translate(packet *gopacket.Packet) error
  next(stream io.Writer)
  translateEthernetLayer(packet *layers.Ethernet)
}

type PcapTransformer struct{
  translator PcapTranslator
  output string
}

type IPcapTransformer interface{
  Apply(packet *gopacket.Packet) error
}

func (t *PcapTransformer) Apply(packet *gopacket.Packet) error {
  
  translator := t.translator
  translator.next(os.Stdout)

  p := *packet
  
  ethernetLayer := p.Layer(layers.LayerTypeEthernet)
  if ethernetLayer != nil {
    ethernetPacket, _ := ethernetLayer.(*layers.Ethernet)
    translator.translateEthernetLayer(ethernetPacket)
  }

  // translate more layers

  return nil
}

func NewTransformer(format *string) (IPcapTransformer, error) {

  var translator PcapTranslator = newTranslator(format)

  if translator == nil {
    return nil, fmt.Errorf("not available: %s", *format)
  }

  // same transformer, multiple strategies
  return &PcapTransformer{translator: translator}, nil
}

func newTranslator(format *string) PcapTranslator {

  switch f := *format; f {
  case "json":
    return newJsonPcapTranslator()
  case "text":
    return newTextPcapTranslator()
  default:
    /* no-go */
  }

  return nil
}

