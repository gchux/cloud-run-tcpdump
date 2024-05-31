package transformer

import (
  "log"

  "github.com/google/gopacket"
  "github.com/google/gopacket/pcap"
)

func PcapToJson(pcapFile string) {

  handle, err := pcap.OpenOffline(pcapFile)
  if err != nil {
    log.Fatal(err)
  }

  defer handle.Close()

  packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

  for packet := range packetSource.Packets() {
    log.Println(packet.String())
  }

}
