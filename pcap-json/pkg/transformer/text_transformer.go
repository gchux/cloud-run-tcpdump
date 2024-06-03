package transformer

import (
  "fmt"

  "github.com/google/gopacket"
  "github.com/google/gopacket/layers"
)

func (t *TextPcapTransformer) Apply(packet gopacket.Packet) error {
  ethernetLayer := packet.Layer(layers.LayerTypeEthernet)

  if ethernetLayer != nil {
    fmt.Println("Ethernet layer detected.")
    ethernetPacket, _ := ethernetLayer.(*layers.Ethernet)
    fmt.Println("Source MAC: ", ethernetPacket.SrcMAC)
    fmt.Println("Destination MAC: ", ethernetPacket.DstMAC)
    fmt.Println("Ethernet type: ", ethernetPacket.EthernetType)
    fmt.Println()
  }

  ipLayer := packet.Layer(layers.LayerTypeIPv4)
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

  tcpLayer := packet.Layer(layers.LayerTypeTCP)
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
  for _, layer := range packet.Layers() {
    fmt.Println("- ", layer.LayerType())
  }

  // Check for errors
  if err := packet.ErrorLayer(); err != nil {
    fmt.Println("Error decoding some part of the packet:", err)
  }
  return nil
} 
