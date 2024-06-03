package transformer

import (
  "fmt"

  "github.com/google/gopacket"
)

func (t *JsonPcapTransformer) Apply(packet gopacket.Packet) error {
  return fmt.Errorf("not implemented")
} 
