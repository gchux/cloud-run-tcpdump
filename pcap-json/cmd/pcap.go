package main

import (
  "os"
  "fmt"
  "log"
  "flag"
  "time"
  "strings"

  "github.com/google/gopacket"
  "github.com/google/gopacket/pcap"
  "github.com/google/gopacket/layers"
  // "github.com/google/gopacket/dumpcommand"
)

var iface = flag.String("i", "any", "Interface to read packets from")
var fname = flag.String("r", "", "Filename to read from, overrides -i")
var snaplen = flag.Int("s", 0, "Snap length (number of bytes max to read per packet")
var tstype = flag.String("timestamp_type", "", "Type of timestamps to use")
var promisc = flag.Bool("promisc", true, "Set promiscuous mode")

func main() {
  flag.Parse()

  var handle *pcap.Handle
  var err error

  inactive, err := pcap.NewInactiveHandle(*iface)
  if err != nil {
    log.Fatalf("could not create: %v", err)
  }
  defer inactive.CleanUp()

  if err = inactive.SetSnapLen(*snaplen); err != nil {
    log.Fatalf("could not set snap length: %v", err)
  } else if err = inactive.SetPromisc(*promisc); err != nil {
    log.Fatalf("could not set promisc mode: %v", err)
  } else if err = inactive.SetTimeout(time.Second); err != nil {
    log.Fatalf("could not set timeout: %v", err)
  }
  if *tstype != "" {
    if t, err := pcap.TimestampSourceFromString(*tstype); err != nil {
      log.Fatalf("Supported timestamp types: %v", inactive.SupportedTimestamps())
    } else if err := inactive.SetTimestampSource(t); err != nil {
      log.Fatalf("Supported timestamp types: %v", inactive.SupportedTimestamps())
    }
  }
  
  if handle, err = inactive.Activate(); err != nil {
    log.Fatal("PCAP Activate error:", err)
  }
  defer handle.Close()

  if len(flag.Args()) > 0 {
    bpffilter := strings.Join(flag.Args(), " ")
    fmt.Fprintf(os.Stderr, "Using BPF filter %q\n", bpffilter)
    if err = handle.SetBPFFilter(bpffilter); err != nil {
      log.Fatal("BPF filter error:", err)
    }
  }

  // dumpcommand.Run(handle)
  source := gopacket.NewPacketSource(handle, handle.LinkType())
  source.Lazy = false
  source.NoCopy = true
  source.DecodeStreamsAsDatagrams = true
  for packet := range source.Packets() {
    printPacketInfo(packet)
    // use `packet.Data()` to write bytes to a PCAP file
  }
}

func printPacketInfo(packet gopacket.Packet) {
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
}
