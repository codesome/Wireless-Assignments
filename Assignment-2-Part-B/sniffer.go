package main

import (
	"errors"
	"fmt"
	"math"
	"os"
	"os/exec"
	"os/signal"
	// "strconv"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// sudo iw phy phy0 interface add mon0 type monitor
// sudo iw dev wlp2s0 del
// sudo ifconfig mon0 up
// sudo iw dev mon0 set freq 2437

// sudo iw phy phy0 interface add wlp2s0 type managed
// sudo iw dev mon0 del
// sudo ifconfig wlp2s0 up

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

const (
	sniffDuration = 15 // time in seconds
)

func handleErr(err error) {
	if err != nil {
		panic(err)
	}
}

func main() {

	s := NewSniffer("wlp2s0", "mon0", 30*time.Second)
	s.SetInterruptHandler()

	handleErr(s.StartSniffer())

	// channelsToTest := []int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11}
	channelsToTest := []int{6}
	for _, i := range channelsToTest {
		count := 0
		beaconCount := 0
		handleErr(s.Sniff(i, sniffDuration, func(packet gopacket.Packet) {
			count++
			for _, l := range packet.Layers() {
				if l.LayerType() == layers.LayerTypeDot11InformationElement {
					var radio *layers.RadioTap
					if l := packet.Layer(layers.LayerTypeRadioTap); l != nil {
						radio = l.(*layers.RadioTap)
						if !radio.Present.Channel() || !radio.ChannelFlags.Ghz2() {
							continue
						}
					} else {
						continue
					}
					pkt := l.(*layers.Dot11InformationElement)
					if pkt.ID == layers.Dot11InformationElementIDQBSSLoadElem {
						if ut, ok := s.channelUtilization[freqChanMap[uint16(radio.ChannelFrequency)]]; ok {
							ut.count++
							ut.totalValue += int64(pkt.Info[2])
						} else {
							handleErr(fmt.Errorf("Frequency not found in channelUtilization map: %d", radio.ChannelFrequency))
						}
						// fmt.Println(int(pkt.Info[2]), radio.ChannelFrequency)
						beaconCount++
						break
					}
				}
			}
		}, handleErr))
		fmt.Println(i, count, beaconCount)
	}

	handleErr(s.StopSniffer())
	fmt.Println(s.LeastUtilizedOrthogonalChan())

}

type sniffer struct {
	monitorStarted        bool
	SIGINT                chan os.Signal
	mtx                   sync.Mutex
	device, monitorDevice string
	timeout               time.Duration

	channelUtilization map[int]*utilization
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
	}
	for i := 0; i <= 11; i++ {
		s.channelUtilization[i] = &utilization{}
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
	// if err := s.removeCurrentWireless(); err != nil {
	// 	return err
	// }
	// if err := s.startMonitor(); err != nil {
	// 	return err
	// }
	s.monitorStarted = true
	return nil
}

func (s *sniffer) StopSniffer() error {
	s.mtx.Lock()
	defer s.mtx.Unlock()
	// if err := s.endMonitor(); err != nil {
	// 	return err
	// }
	// if err := s.resetDefaultWireless(); err != nil {
	// 	return err
	// }
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

func (s *sniffer) Sniff(channel int, sniffDur int, packetHandler func(packet gopacket.Packet), errorHandler func(err error)) error {
	s.mtx.Lock()
	defer s.mtx.Unlock()
	if !s.monitorStarted {
		return errors.New("Sniffer not started")
	}

	fmt.Println(channelFreqMap[channel])
	s.setMonitorFreq(channelFreqMap[channel])
	filename := s.captureFilename(channel)
	// if err := exec.Command("tshark", "-i", s.monitorDevice, "-a", "duration:"+strconv.Itoa(sniffDur), "-w", filename).Run(); err != nil {
	// 	return err
	// }

	filename = "/home/codesome/IITH/Assignments/CS15BTECH11018_IITH_802_11.pcapng"

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
		packetHandler(packet)
	}

	return nil
}

func (s *sniffer) LeastUtilizedOrthogonalChan() int {
	leastVal := math.MaxFloat64
	leastUtilizedChan := 1
	for c, ut := range s.channelUtilization {
		avg := float64(0)
		if ut.count != 0 {
			avg = float64(ut.totalValue) / float64(ut.count)
		}
		fmt.Println(c, "#", ut.totalValue, "#", ut.count, "#", avg)
		if (c == 1 || c == 6 || c == 11) && avg < leastVal {
			leastUtilizedChan = c
		}
	}
	return leastUtilizedChan
}
