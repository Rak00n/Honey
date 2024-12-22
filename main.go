package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"io/ioutil"
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

type conf struct {
	InterfaceMAC     string   `json:"interfaceMAC"`
	TelegramBotToken string   `json:"telegramBotToken"`
	PortsToListen    []string `json:"honeypotPorts"`
	TelegramChatIDs  []int64  `json:"telegramChatIDs"`
}

var runningConfig conf
var configPath string

func init() {
	flag.StringVar(&configPath, "config", "config.json", "path to config file")
	flag.Parse()
}

func main() {
	configFile, err := ioutil.ReadFile(configPath)

	if err := json.Unmarshal(configFile, &runningConfig); err != nil {
		panic(err)
	}

	deviceToCapture, ipsToCapture := getInterfaceAndIPs(runningConfig.InterfaceMAC)
	if deviceToCapture == "" {
		fmt.Println("No device to capture")
		os.Exit(1)
	}
	fmt.Println("Device MAC: " + runningConfig.InterfaceMAC)
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
				if portInList(dstPort, runningConfig.PortsToListen) {
					fmt.Println("Alert! Packet to: ", dstPort)
					sendTelegramCommand("Alert! Packet from: " + networkLevel.Src().String() + " to port " + dstPort)
				}
			}
		}

	}
}
