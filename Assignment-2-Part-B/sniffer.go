package main

import (
	"bufio"
	"errors"
	"fmt"
	"math"
	"os"
	"os/exec"
	"os/signal"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/olekukonko/tablewriter"
	"golang.org/x/crypto/ssh/terminal"
)

// sudo iw phy phy0 interface add mon0 type monitor
// sudo iw dev wlp2s0 del
// sudo ifconfig mon0 up
// sudo iw dev mon0 set freq 2437

// sudo iw phy phy0 interface add wlp2s0 type managed
// sudo iw dev mon0 del
// sudo ifconfig wlp2s0 up

const (
	sniffDuration = 5 // time in seconds
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

func connectToSSID(device, ssid, username, password string) {
	fmt.Printf("Connecting to %q...\n", ssid)
	commands := []string{"dev", "wifi", "connect", ssid, "ifname", device}
	if password != "" {
		if username != "" {
			commands = append(commands, "name", username)
		}
		commands = append(commands, "password", password)
	}
	handleErr(exec.Command("nmcli", commands...).Run())
}

func main() {

	if len(os.Args) != 2 || (os.Args[1] != "hotspot" && os.Args[1] != "connect") {
		fmt.Printf("Usage: %s hotspot|connect\n", os.Args[0])
		return
	}

	hotspot := os.Args[1] == "hotspot"

	s := NewSniffer("wlp2s0", "mon0", 30*time.Second)
	s.SetInterruptHandler()

	handleErr(s.StartSniffer())

	var packetHandler PacketHandler
	if hotspot {
		packetHandler = s.StatsForHotspot()
	} else {
		packetHandler = s.StatsForConnection()
	}

	channelsToTest := []int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11}
	for _, i := range channelsToTest {
		handleErr(s.Sniff(i, sniffDuration, packetHandler, handleErr))
		fmt.Println(i, s.count, s.beaconCount)
	}

	handleErr(s.StopSniffer())
	if hotspot {
		c := s.LeastUtilizedOrthogonalChan()
		fmt.Println("Selected Channel:", c)
		createHotspot(s.device, "CS15BTECH11018", strconv.Itoa(c), "secretpassword")
	} else {
		ssid := s.LeastStationCountSSID()
		fmt.Println("Selected SSID:", ssid)
		reader := bufio.NewReader(os.Stdin)
		fmt.Printf("Enter username %s ([Enter] if N/A):", ssid)
		username, err := reader.ReadString('\n')
		handleErr(err)
		fmt.Printf("Enter password for %s ([Enter] if N/A):", ssid)
		bytePassword, err := terminal.ReadPassword(0)
		fmt.Println()
		handleErr(err)
		connectToSSID(s.device, ssid, username[:len(username)-1], string(bytePassword))
	}
}

var (
	channelFreqMap = map[int]string{
		1: "2412", 2: "2417", 3: "2422", 4: "2427", 5: "2432",
		6: "2437", 7: "2442", 8: "2447", 9: "2452", 10: "2457",
		11: "2462", 12: "2467", 13: "2472", 14: "2484",
	}
	freqChanMap = map[uint16]int{
		2412: 1, 2417: 2, 2422: 3, 2427: 4, 2432: 5,
		2437: 6, 2442: 7, 2447: 8, 2452: 9, 2457: 10,
		2462: 11, 2467: 12, 2472: 13, 2484: 14,
	}
	snapshotLen = int32(65536)
)

type PacketHandler func(packet gopacket.Packet) error

type sniffer struct {
	monitorStarted        bool
	SIGINT                chan os.Signal
	mtx                   sync.Mutex
	device, monitorDevice string
	timeout               time.Duration
	infoPacketCount       map[int]int64

	channelUtilization map[int]*utilization
	channelUniqueMacs  map[int]map[string]struct{}
	ssidStationCount   map[string]*utilization

	// temp
	count       int
	beaconCount int
}

type utilization struct {
	totalValue int64
	count      int64
}

func NewSniffer(device, monitorDevice string, timeout time.Duration) *sniffer {
	s := &sniffer{
		SIGINT:             make(chan os.Signal, 1),
		device:             device,
		monitorDevice:      monitorDevice,
		timeout:            timeout,
		channelUtilization: make(map[int]*utilization),
		channelUniqueMacs:  make(map[int]map[string]struct{}),
		infoPacketCount:    make(map[int]int64),
		ssidStationCount:   make(map[string]*utilization),
	}
	for i := 0; i <= 11; i++ {
		s.channelUtilization[i] = &utilization{}
		s.channelUniqueMacs[i] = make(map[string]struct{})
		s.infoPacketCount[i] = 0
	}
	return s
}

func (s *sniffer) SetInterruptHandler() {
	signal.Notify(s.SIGINT, os.Interrupt)
	go func() {
		<-s.SIGINT
		s.mtx.Lock()
		defer s.mtx.Unlock()
		if s.monitorStarted {
			s.StopSniffer()
		}
		os.Exit(1)
	}()
}

func (s *sniffer) StartSniffer() error {
	s.mtx.Lock()
	defer s.mtx.Unlock()
	if err := s.removeCurrentWireless(); err != nil {
		return err
	}
	if err := s.startMonitor(); err != nil {
		return err
	}
	s.monitorStarted = true
	return nil
}

func (s *sniffer) StopSniffer() error {
	s.mtx.Lock()
	defer s.mtx.Unlock()
	if err := s.endMonitor(); err != nil {
		return err
	}
	if err := s.resetDefaultWireless(); err != nil {
		return err
	}
	s.monitorStarted = false
	return nil
}

func (s *sniffer) removeCurrentWireless() error {
	return exec.Command("sudo", "iw", "dev", s.device, "del").Run()
}

func (s *sniffer) resetDefaultWireless() error {
	if err := exec.Command("sudo", "iw", "phy", "phy0", "interface", "add", s.device, "type", "managed").Run(); err != nil {
		return err
	}
	return exec.Command("sudo", "ifconfig", s.device, "up").Run()
}

func (s *sniffer) startMonitor() error {
	if err := exec.Command("sudo", "iw", "phy", "phy0", "interface", "add", s.monitorDevice, "type", "monitor").Run(); err != nil {
		return err
	}
	return exec.Command("sudo", "ifconfig", s.monitorDevice, "up").Run()
}

func (s *sniffer) endMonitor() error {
	return exec.Command("sudo", "iw", "dev", s.monitorDevice, "del").Run()
}

func (s *sniffer) setMonitorFreq(freq string) error {
	return exec.Command("sudo", "iw", "dev", s.monitorDevice, "set", "freq", freq).Run()
}

func (s *sniffer) captureFilename(channel int) string {
	return fmt.Sprintf("capture_chan%d.pcapng", channel)
}

func (s *sniffer) Sniff(channel int, sniffDur int, packetHandler PacketHandler, errorHandler func(err error)) error {
	s.mtx.Lock()
	defer s.mtx.Unlock()
	if !s.monitorStarted {
		return errors.New("Sniffer not started")
	}

	fmt.Printf("Analysing channel %d (for %d seconds)...\n", channel, sniffDur)
	s.setMonitorFreq(channelFreqMap[channel])
	filename := s.captureFilename(channel)
	// if err := exec.Command("tshark", "-i", s.monitorDevice, "-a", "duration:"+strconv.Itoa(sniffDur), "-w", filename).Run(); err != nil {
	// 	return err
	// }

	// filename = "/home/codesome/IITH/Assignments/CS15BTECH11018_IITH_802_11.pcapng"

	handle, err := pcap.OpenOffline(filename)
	// handle, err := pcap.OpenLive(s.monitorDevice, snapshotLen, false, s.timeout)
	if err != nil {
		return err
	}
	// go func() {
	// 	<-time.After(sniffDur)
	// 	handle.Close()
	// }()

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		if err := packetHandler(packet); err != nil {
			errorHandler(err)
		}
	}

	return nil
}

func (s *sniffer) updateAPs(channel int, packet gopacket.Packet) {
	if l := packet.Layer(layers.LayerTypeDot11); l != nil {
		pkt := l.(*layers.Dot11)

		typesForSender := []gopacket.LayerType{layers.LayerTypeDot11MgmtAssociationResp, layers.LayerTypeDot11CtrlCTS,
			layers.LayerTypeDot11MgmtReassociationResp, layers.LayerTypeDot11MgmtBeacon}
		for _, t := range typesForSender {
			if l := packet.Layer(t); l != nil {
				s.channelUniqueMacs[channel][pkt.Address2.String()] = struct{}{}
				return
			}
		}

		typesForReceiver := []gopacket.LayerType{layers.LayerTypeDot11MgmtAssociationReq, layers.LayerTypeDot11CtrlRTS,
			layers.LayerTypeDot11MgmtReassociationReq}
		for _, t := range typesForReceiver {
			if l := packet.Layer(t); l != nil {
				s.channelUniqueMacs[channel][pkt.Address1.String()] = struct{}{}
				return
			}
		}
	}
}

type result struct {
	id                string
	totalValue, count int64
	avg               float64
}

func NewResult(id string, totalValue, count int64, avg float64) result {
	return result{
		id:         id,
		totalValue: totalValue,
		count:      count,
		avg:        avg,
	}
}

func (s *sniffer) sortAndAppend(table *tablewriter.Table, results []result, utilisation bool) {
	sort.Slice(results, func(i, j int) bool {
		if results[i].avg == results[j].avg {
			return results[i].id < results[j].id
		}
		return results[i].avg < results[j].avg
	})
	if utilisation {
		for i, r := range results {
			table.Append([]string{strconv.Itoa(i + 1), r.id, strconv.Itoa(int(r.totalValue)), strconv.Itoa(int(r.count)), fmt.Sprintf("%.2f(%.2f%%)", r.avg, (r.avg*100)/255)})
		}
	} else {
		for i, r := range results {
			table.Append([]string{strconv.Itoa(i + 1), r.id, strconv.Itoa(int(r.totalValue)), strconv.Itoa(int(r.count)), fmt.Sprintf("%.2f", r.avg)})
		}
	}
}

func (s *sniffer) LeastUtilizedOrthogonalChan() int {
	notExistCount := 0
	leastVal := math.MaxFloat64
	leastUtilizedChan := 1
	fmt.Println("\n\nCHANNEL UTILISATION")
	table := tablewriter.NewWriter(os.Stdout)
	table.SetHeader([]string{"SL.NO.", "CHANNEL", "TOTAL UTILISATION COUNT", "NUM COUNTS", "AVG UTILISATION"})
	var results []result
	for c, ut := range s.channelUtilization {
		avg := float64(0)
		if ut.count != 0 {
			avg = float64(ut.totalValue) / float64(ut.count)
		}
		results = append(results, NewResult(strconv.Itoa(c), ut.totalValue, ut.count, avg))
		if (c == 1 || c == 6 || c == 11) && avg < leastVal {
			if s.infoPacketCount[c] == 0 && ut.totalValue == 0 {
				notExistCount++
			}
			leastUtilizedChan = c
			leastVal = avg
		}
	}

	s.sortAndAppend(table, results, true)
	table.Render()

	if notExistCount > 1 {
		fmt.Println("ATTENTION: SELECTING BASED ON TOTLA UNIQUE AP FOR EVERY CHANNEL, AS WE DID NOT GET BEACONS IN ALL ORTHOGONAL CHANNELS")
		leastUtilizedChan = 1
		minc := len(s.channelUniqueMacs[1])
		if len(s.channelUniqueMacs[6]) < minc {
			leastUtilizedChan = 6
		}
		if len(s.channelUniqueMacs[11]) < minc {
			leastUtilizedChan = 11
		}

		table := tablewriter.NewWriter(os.Stdout)
		table.SetHeader([]string{"SL.NO.", "CHANNEL", "TOTAL UNIQUE APs"})
		results = results[:0]
		for k1, v := range s.channelUniqueMacs {
			results = append(results, NewResult(strconv.Itoa(k1), 0, int64(len(v)), 0))
		}
		sort.Slice(results, func(i, j int) bool {
			if results[i].count == results[j].count {
				v1, _ := strconv.Atoi(results[i].id)
				v2, _ := strconv.Atoi(results[j].id)
				return v1 < v2
			}
			return results[i].count < results[j].count
		})
		for i, r := range results {
			table.Append([]string{strconv.Itoa(i + 1), r.id, strconv.Itoa(int(r.count))})
		}
		table.Render()
	}

	return leastUtilizedChan
}

func (s *sniffer) LeastStationCountSSID() string {
	hasNonZeroChar := func(s string) bool {
		for _, c := range s {
			if c != 0 {
				return true
			}
		}
		return false
	}
	selectedSSID := ""
	leastCount := math.MaxFloat64
	fmt.Println("\n\nSTATION COUNT")
	const padding = 3
	table := tablewriter.NewWriter(os.Stdout)
	table.SetHeader([]string{"SL.NO.", "SSID", "TOTAL STA COUNT", "NUM COUNTS", "AVG STA COUNT"})
	var results []result
	for ssid, ut := range s.ssidStationCount {
		avg := float64(ut.totalValue) / float64(ut.count)
		if avg < leastCount && hasNonZeroChar(ssid) {
			leastCount = avg
			selectedSSID = ssid
		}
		results = append(results, NewResult(ssid, ut.totalValue, ut.count, avg))
	}
	s.sortAndAppend(table, results, false)
	table.Render()
	return selectedSSID
}

func (s *sniffer) StatsForHotspot() PacketHandler {
	return func(packet gopacket.Packet) error {
		s.count++
		for _, l := range packet.Layers() {
			if l.LayerType() == layers.LayerTypeDot11InformationElement {
				// Getting radio.
				var radio *layers.RadioTap
				if l := packet.Layer(layers.LayerTypeRadioTap); l != nil {
					radio = l.(*layers.RadioTap)
					if !radio.Present.Channel() || !radio.ChannelFlags.Ghz2() {
						continue
					}
				} else {
					continue
				}

				// Getting channel.
				ch := freqChanMap[uint16(radio.ChannelFrequency)]
				s.infoPacketCount[ch]++
				s.updateAPs(ch, packet)

				pkt := l.(*layers.Dot11InformationElement)
				if pkt.ID == layers.Dot11InformationElementIDQBSSLoadElem {
					if ut, ok := s.channelUtilization[ch]; ok {
						ut.count++
						ut.totalValue += int64(pkt.Info[2])
					} else {
						handleErr(fmt.Errorf("Frequency not found in channelUtilization map: %d", radio.ChannelFrequency))
					}
					s.beaconCount++
					break
				}
			}
		}

		return nil
	}
}

func (s *sniffer) getSSID(packet gopacket.Packet) string {
	for _, l := range packet.Layers() {
		if l.LayerType() == layers.LayerTypeDot11InformationElement {
			pkt := l.(*layers.Dot11InformationElement)
			if pkt.ID == layers.Dot11InformationElementIDSSID {
				return string(pkt.Info)
			}
		}
	}
	return ""
}

func (s *sniffer) StatsForConnection() PacketHandler {

	return func(packet gopacket.Packet) error {
		s.count++
		ssid := s.getSSID(packet)
		if ssid == "" {
			return nil
		}
		for _, l := range packet.Layers() {
			if l.LayerType() == layers.LayerTypeDot11InformationElement {
				// Getting radio.
				var radio *layers.RadioTap
				if l := packet.Layer(layers.LayerTypeRadioTap); l != nil {
					radio = l.(*layers.RadioTap)
					if !radio.Present.Channel() || !radio.ChannelFlags.Ghz2() {
						continue
					}
				} else {
					continue
				}

				// Getting channel.
				ch := freqChanMap[uint16(radio.ChannelFrequency)]
				s.infoPacketCount[ch]++
				s.updateAPs(ch, packet)

				pkt := l.(*layers.Dot11InformationElement)
				if pkt.ID == layers.Dot11InformationElementIDQBSSLoadElem {

					ut, ok := s.ssidStationCount[ssid]
					if !ok {
						ut = &utilization{}
						s.ssidStationCount[ssid] = ut
					}
					ut.count++
					val := int64(pkt.Info[1]) << 8
					val += int64(pkt.Info[0])
					ut.totalValue += val

					s.beaconCount++
					break
				}
			}
		}

		return nil
	}
}
