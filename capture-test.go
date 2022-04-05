package main

import (
    "fmt"
    "github.com/google/gopacket"
    "github.com/google/gopacket/layers"
    "github.com/google/gopacket/pcap"
    "log"
    "strings"
    "time"
    "os"
)


var (
    Counter int	= 0
    osInfo = map[string]NodeInfo{}
    device      string = "wlp0s20f3"
    snapshotLen int32  = 1024
    promiscuous bool   = false
    err         error
    timeout     time.Duration = 1 * time.Second
    handle      *pcap.Handle
)

type NodeInfo struct {
    Mac string
    OsString string
}

func main() {
    fmt.Println("started")
    // Open device
    handle, err = pcap.OpenLive(device, snapshotLen, promiscuous, timeout)
    if err != nil {log.Fatal(err) }
    defer handle.Close()

	// Set filter
    var filter string = "tcp port 80"
    err = handle.SetBPFFilter(filter)
    if err != nil {
        log.Fatal(err)
    }
    fmt.Println("Only capturing TCP port 80 packets.")


    fmt.Println("started")

    packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
    for packet := range packetSource.Packets() {
        printPacketInfo(packet)
    }
}

func printPacketInfo(packet gopacket.Packet) {
    // Let's see if the packet is an ethernet packet
    ethernetLayer := packet.Layer(layers.LayerTypeEthernet)
    if ethernetLayer != nil {
        fmt.Println("Ethernet layer detected.")
        ethernetPacket, _ := ethernetLayer.(*layers.Ethernet)
        fmt.Println("Source MAC: ", ethernetPacket.SrcMAC)
        fmt.Println("Destination MAC: ", ethernetPacket.DstMAC)
        // Ethernet type is typically IPv4 but could be ARP or other
        fmt.Println("Ethernet type: ", ethernetPacket.EthernetType)
        fmt.Println()
    }

    // Let's see if the packet is IP (even though the ether type told us)
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

    // Let's see if the packet is TCP
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

    // // Iterate over all layers, printing out each layer type
    // fmt.Println("All packet layers:")
    // for _, layer := range packet.Layers() {
    //     fmt.Println("- ", layer.LayerType())
    // }

    // When iterating through packet.Layers() above,
    // if it lists Payload layer then that is the same as
    // this applicationLayer. applicationLayer contains the payload
    applicationLayer := packet.ApplicationLayer()
    if applicationLayer != nil {
        fmt.Println("Application layer/Payload found.")
		
        fmt.Printf("\n------[%s]--------\n", applicationLayer.Payload())

        payloadString := string(applicationLayer.Payload())
        // Search for a string inside the payload
        if strings.Contains(payloadString,"User-Agent") {
            fmt.Println("????????????????????????????????????????????\n\t$$$$ FOUND OS HEADER $$$$$ !! !!")
            Counter++


            //adding the detected os and client info to map
            ipLayer := packet.Layer(layers.LayerTypeIPv4)
            ip, _ := ipLayer.(*layers.IPv4)
            ethernetLayer := packet.Layer(layers.LayerTypeEthernet)
            ethernetPacket, _ := ethernetLayer.(*layers.Ethernet)
            var osString string
            
            osString = "os info"

            if _ , ok := osInfo[string(ip.SrcIP)]; !ok {
                //extracting os data string from payload
                idx := strings.Index(payloadString, "User-Agent")
                idy := strings.Index(payloadString[idx:],"\n")
                // fmt.Println("\t\tx: %T  y: %d\t++++++++++++",idx,idy,payloadString[idx:idy])
                tempStr := fmt.Sprintf("idx: %d, idy: %d\n\t%s]\n",idx,idy,payloadString[idx:idy])



                //appending found record to file
                textForFile := fmt.Sprintf("%s > %s > %s\n",ip.SrcIP,ethernetPacket.SrcMAC,osString)
                filename := "os-info-golang.txt"
                f, err := os.OpenFile(filename, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0600)
                if err != nil {
                    panic(err)
                }
                defer f.Close()
                _ = textForFile
                if _, err = f.WriteString(tempStr); err != nil {
                    panic(err)
                }
            }
            osInfo[string(ip.SrcIP)] = NodeInfo{string(ethernetPacket.SrcMAC),osString}
            
        }
    }

    // Check for errors
    if err := packet.ErrorLayer(); err != nil {
        fmt.Println("Error decoding some part of the packet:", err)
    }

	fmt.Println("**********************************************",Counter,len(osInfo))
}