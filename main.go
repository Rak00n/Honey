package main

import (
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"log"
	"os"
	"strings"
)

func portInList(port string, listOfPorts []string) bool {
	for _, portItem := range listOfPorts {
		if portItem == port {
			return true
		}
	}
	return false
}

func addressInList(ip string, listOfIPs []string) bool {
	for _, ipItem := range listOfIPs {
		if ipItem == ip {
			return true
		}
	}
	return false
}

func main() {
	//interfaceMAC := "E0:2E:0B:31:B1:8B"
	interfaceMAC := "00:15:5D:4F:2E:7A"
	portsToListen := []string{"80", "443", "22"}

	deviceToCapture, ipsToCapture := getInterfaceAndIPs(interfaceMAC)
	if deviceToCapture == "" {
		fmt.Println("No device to capture")
		os.Exit(1)
	}
	fmt.Println("Device MAC: " + interfaceMAC)
	fmt.Println("Device IPs: " + strings.Join(ipsToCapture, " "))
	fmt.Println("Honeypot launched on " + deviceToCapture)
	handle, err := pcap.OpenLive(deviceToCapture, 1600, true, pcap.BlockForever)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	var filter string = "tcp"
	err = handle.SetBPFFilter(filter)
	if err != nil {
		log.Fatal(err)
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		networkLevel := packet.NetworkLayer().NetworkFlow()
		if addressInList(networkLevel.Dst().String(), ipsToCapture) {
			tcpLayer := packet.Layer(layers.LayerTypeTCP)
			if tcpLayer != nil {
				tcp, _ := tcpLayer.(*layers.TCP)
				dstPortSlice := strings.Split(tcp.DstPort.String(), "(")
				dstPort := dstPortSlice[0]
				if portInList(dstPort, portsToListen) {
					fmt.Println("Alert! Packet to: ", dstPort)
				}
			}
		}

	}
}
