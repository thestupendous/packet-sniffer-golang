package main

import (
    "fmt"
    "github.com/google/gopacket"
    "github.com/google/gopacket/pcap"
    _ "github.com/google/gopacket/layers"

    "log"
    "time"
)

var (
    device       string = "wlp0s20f3"
    snapshot_len int32  = 1024
    promiscuous  bool   = false
    err          error
    timeout      time.Duration = 1 * time.Second
    handle       *pcap.Handle
)

func main() {
    // Open device
    handle, err = pcap.OpenLive(device, snapshot_len, promiscuous, timeout)
    if err != nil {log.Fatal(err) }
    defer handle.Close()

    // Set filter
    var filter string = "tcp"
    err = handle.SetBPFFilter(filter)
    if err != nil {
        log.Fatal(err)
    }
    fmt.Println("Only capturing TCP port 80 packets.")

    // Use the handle as a packet source to process all packets
    packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
    for packet := range packetSource.Packets() {
        // Process packet here
        // fmt.Println(packet)
        for _, layer := range packet.Layers() {
            fmt.Println("- ", layer.LayerType())
        }
        fmt.Println("*************************************************")
    }
}
