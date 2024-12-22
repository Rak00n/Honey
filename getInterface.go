package main

import (
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strings"
)

func checkIPAddress(ip string) bool {
	if net.ParseIP(ip) == nil {
		return false
	} else {
		return true
	}
}

func getInterfaceAndIPs(macAddress string) (string, []string) {
	detectedDevice := ""
	detectedIPs := []string{}
	if runtime.GOOS == "windows" {
		//macAddressUC := strings.ToUpper(strings.ReplaceAll(macAddress, "-", ":"))
		macAddressUH := strings.ToUpper(strings.ReplaceAll(macAddress, ":", "-"))
		macAddressLC := strings.ToLower(strings.ReplaceAll(macAddress, "-", ":"))
		//macAddressLH := strings.ToLower(strings.ReplaceAll(macAddress, ":", "-"))
		result, err := exec.Command("cmd", "/C", "getmac").Output()
		if err != nil {
			fmt.Println("Something went wrong: ", err)
			os.Exit(1)
		} else {
			resultSlice := strings.Split(string(result), "\r\n")
			for _, v := range resultSlice {
				//fmt.Println(v)
				if strings.Contains(v, macAddressUH) {
					v = strings.ReplaceAll(v, " ", "")
					detectedDevice = strings.ReplaceAll(v, macAddressUH, "")
					detectedDevice = strings.ReplaceAll(detectedDevice, "Tcpip_{", "NPF_{")
					break
				}
			}
		}
		interfaces, _ := net.Interfaces()
		for _, v := range interfaces {
			testMAC := v.HardwareAddr.String()
			if testMAC == macAddressLC {
				ips, _ := v.Addrs()
				for _, ip := range ips {
					ipSlice := strings.Split(ip.String(), "/")
					tempIP := ipSlice[0]
					detectedIPs = append(detectedIPs, tempIP)
				}
			}
		}
		//os.Exit(1)
	} else {
		macAddressLC := strings.ToLower(strings.ReplaceAll(macAddress, "-", ":"))
		files, err := ioutil.ReadDir("/sys/class/net/")
		if err != nil {
			fmt.Println("Something went wrong: ", err)
			os.Exit(1)
		}

		for _, file := range files {
			//fmt.Println(file.Name())
			//fmt.Println(macAddressLC)
			dat, _ := os.ReadFile("/sys/class/net/" + file.Name() + "/address")
			if strings.Contains(string(dat), macAddressLC) {
				detectedDevice = file.Name()
				break
			}
			//fmt.Print(string(dat))

		}
		result, err := exec.Command("/bin/sh", "-c", "hostname --all-ip-addresses").Output()
		if err != nil {
			fmt.Println("Something went wrong: ", err)
			os.Exit(1)
		} else {
			resultSlice := strings.Split(string(result), " ")
			for _, v := range resultSlice {
				vTemp := strings.Trim(v, " ")
				if checkIPAddress(vTemp) {
					detectedIPs = append(detectedIPs, vTemp)
				}
			}
		}
	}
	//fmt.Println(detectedIPs)
	return detectedDevice, detectedIPs
}
