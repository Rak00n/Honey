package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"strings"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

func main() {
	interfaceToListen := "E0-2E-0B-31-B1-8B"
	portsToListen := []int{80, 443, 22}
	interfaceToListen = strings.ReplaceAll(interfaceToListen, "-", ":")
	interfaceToListen = strings.ToLower(interfaceToListen)
	// Open the device for capturing
	fmt.Println("Listing all network interfaces...")
	ifaces, err := net.Interfaces()
	if err == nil {
		for _, iface := range ifaces {
			fmt.Println(iface.HardwareAddr.String())
			if iface.HardwareAddr.String() == interfaceToListen {
				fmt.Println("Found interface", iface.Name)
			}
		}
	}
	fmt.Println(portsToListen)
	os.Exit(1)
	devs, err := pcap.FindAllDevs()
	for _, dev := range devs {
		fmt.Println(dev.Name)
		fmt.Println(dev.Addresses)
		fmt.Println(dev.Description)
	}
	//fmt.Println(devs)

	handle, err := pcap.OpenLive("\\Device\\NPF_{F727CFFF-1919-434B-A395-F7CA0A2954AD}", 1600, true, pcap.BlockForever)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	var filter string = "tcp"
	err = handle.SetBPFFilter(filter)
	if err != nil {
		log.Fatal(err)
	}

	// Use the handle as a packet source to process all packets
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		// Process packet here
		// Check for the TCP layer
		tcpLayer := packet.Layer(layers.LayerTypeTCP)
		if tcpLayer != nil {
			tcp, _ := tcpLayer.(*layers.TCP)

			// Print TCP information
			log.Printf("From src port: %d to dst port: %d\n", tcp.SrcPort, tcp.DstPort)
			log.Printf("Sequence number: %d\n", tcp.Seq)

			// If there's payload, print it as a string
			if len(tcp.Payload) > 0 {
				log.Printf("Payload: %s\n", string(tcp.Payload))
			}
		}
	}
}
