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
	"runtime"
	"strings"
	"time"
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

func logMessage(message string) {
	f, err := os.OpenFile("./honey.log",
		os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Println(err)
	}
	defer f.Close()

	t := time.Now()

	timestamp := t.Format("2006-01-02 15:04:05")

	if _, err := f.WriteString(timestamp + " " + message + newLineSeparator); err != nil {
		log.Println(err)
	}
}

type conf struct {
	HoneypotName     string   `json:"honeypotName"`
	InterfaceMAC     string   `json:"interfaceMAC"`
	TelegramBotToken string   `json:"telegramBotToken"`
	PortsToListen    []string `json:"honeypotPorts"`
	TelegramChatIDs  []int64  `json:"telegramChatIDs"`
}

var runningConfig conf
var configPath string
var newLineSeparator string

func init() {
	flag.StringVar(&configPath, "config", "config.json", "path to config file")
	flag.Parse()
	if runtime.GOOS == "windows" {
		newLineSeparator = "\r\n"
	} else {
		newLineSeparator = "\n"
	}
}

func main() {
	configFile, err := ioutil.ReadFile(configPath)

	if err := json.Unmarshal(configFile, &runningConfig); err != nil {
		fmt.Println("Error reading config file")
		os.Exit(1)
	}

	deviceToCapture, ipsToCapture := getInterfaceAndIPs(runningConfig.InterfaceMAC)
	if deviceToCapture == "" {
		fmt.Println("No device to capture")
		os.Exit(1)
	}
	fmt.Println("Honeypot Name: " + runningConfig.HoneypotName)
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
					logMessage("Honeypot: " + runningConfig.HoneypotName + ". Packet from: " + networkLevel.Src().String() + " to port " + dstPort)
					sendTelegramCommand("Alert! Honeypot: " + runningConfig.HoneypotName + ". Packet from: " + networkLevel.Src().String() + " to port " + dstPort)
				}
			}
		}

	}
}
