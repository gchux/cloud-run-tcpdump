package transformer

import (
  "fmt"

  "github.com/google/gopacket"
)

type PcapTransformer struct{
  Output string
}

type JsonPcapTransformer struct{
  PcapTransformer
}

type TextPcapTransformer struct {
  PcapTransformer
}

type IPcapTransformer interface{
  Apply(packet gopacket.Packet) error
}

func NewTransformer(format *string) (IPcapTransformer, error) {

  switch f := *format; f {
  case "json":
    return new(JsonPcapTransformer), nil
  case "text":
    return new(TextPcapTransformer), nil
  default:
    /* no-go */
  }

  return nil, fmt.Errorf("not available: %s", *format)
}

