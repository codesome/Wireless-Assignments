package main

import (
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"time"
)

// sudo iw phy phy0 interface add mon0 type monitor
// sudo iw dev wlp2s0 del
// sudo ifconfig mon0 up
// sudo iw dev mon0 set freq 2437

// sudo iw phy phy0 interface add wlp2s0 type managed
// sudo iw dev mon0 del
// sudo ifconfig wlp2s0 up

const (
	// Time to sniff each channel (in seconds)
	sniffDuration = 1
)

func handleErr(err error) {
	if err != nil {
		panic(err)
	}
}

func createHotspot(intf, ssid, channel, password string) {
	fmt.Printf("Starting hotspot: INTERFACE=%q, SSID=%q, CHANNEL=%q\n", intf, ssid, channel)
	handleErr(exec.Command("nmcli", "dev", "wifi", "hotspot", "ifname", intf, "ssid", ssid, "band", "bg", "channel", channel, "password", password).Run())
}

func connectToSSID(device, ssid string) {
	fmt.Printf("Connecting to %q...\n", ssid)
	commands := []string{"con", "up", ssid}
	handleErr(exec.Command("nmcli", commands...).Run())
}

func main() {

	if len(os.Args) != 2 || (os.Args[1] != "hotspot" && os.Args[1] != "connect") {
		fmt.Printf("Usage: %s hotspot|connect\n", os.Args[0])
		return
	}
	hotspot := os.Args[1] == "hotspot"

	// Creating new sniffer.
	s := NewSniffer("wlp2s0", "mon0", 30*time.Second)

	// Starting the sniffer (monitor mode)
	handleErr(s.StartSniffer())

	// We parse the packet differently for creating hotspot and
	// connecting to an AP.
	var packetHandler PacketHandler
	if hotspot {
		packetHandler = s.StatsCollectorForHotspot()
	} else {
		packetHandler = s.StatsCollectorForConnection()
	}

	// We sniff and collect stats from required channels.
	channelsToTest := []int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11}
	for _, i := range channelsToTest {
		handleErr(s.Sniff(i, sniffDuration, packetHandler, handleErr))
	}
	fmt.Printf("Total Packets: %d, Total Info Elements: %d\n", s.TotalPacketCount, s.TotalInfoElementCount)

	// Sniffing over. Stop the sniffer and restore the WLAN settings.
	handleErr(s.StopSniffer())

	if hotspot {
		// Get the least utilized orthogonal channel and start hotspot
		// on that channel.
		c := s.LeastUtilizedOrthogonalChan()
		fmt.Println("Selected Channel:", c)
		createHotspot(s.Device, "CS15BTECH11018", strconv.Itoa(c), "secretpassword")
	} else {
		// Get the SSID with least station count and connect to it.
		ssid := s.LeastStationCountSSID()
		if ssid == "" {
			fmt.Println("Sorry! None of the APs broadcasted Station Counts.")
		}
		fmt.Println("Selected SSID:", ssid)

		// Connect.
		connectToSSID(s.Device, ssid)
	}
}
