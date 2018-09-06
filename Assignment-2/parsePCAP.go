/*
* Script to parse PCAP file and output stats.
*
* Author: Ganesh Vernekar
*
* Prereq:
* $ sudo apt-get install libpcap-dev
* $ go get github.com/google/gopacket
*
* To run this script
* 1. Change the file path in `func main()`.
* 2. `go build parsePCAP.go`
* 3. `./parsePCAP` (or `sudo ./parsePCAP` if file is protected).
* The stats and the exported values for the graphs will be writte out in the same directory
*                               (with prefix as the second argument in `pcapInfo` function).
**/

package main

import (
	"encoding/csv"
	"fmt"
	"math"
	"os"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

func handleErr(err error) {
	if err != nil {
		panic(err)
	}
}

type result struct {
	prefix string

	packets     int
	infopackets int

	ssids map[string]struct{}

	protectedFrames int
	typeCounts      map[layers.Dot11Type]int
	subTypeCounts   map[layers.Dot11Type]int

	packetSizeHistogram map[int]int
	dataRateHistogram   map[uint8]int

	packetSizeChan chan gopacket.Packet
	radioLayerChan chan gopacket.Packet

	minRTSDataPacketSize int

	files   []*os.File
	writers []*csv.Writer

	wg sync.WaitGroup
}

func newResult(prefix string) *result {
	return &result{
		prefix:               prefix,
		ssids:                make(map[string]struct{}),
		typeCounts:           make(map[layers.Dot11Type]int),
		subTypeCounts:        make(map[layers.Dot11Type]int),
		packetSizeHistogram:  make(map[int]int),
		dataRateHistogram:    make(map[uint8]int),
		minRTSDataPacketSize: math.MaxInt32,
	}
}

func (res *result) updateAPs(packet gopacket.Packet) {
	if l := packet.Layer(layers.LayerTypeDot11); l != nil {
		pkt := l.(*layers.Dot11)

		typesForSender := []gopacket.LayerType{layers.LayerTypeDot11MgmtAssociationResp, layers.LayerTypeDot11CtrlCTS,
			layers.LayerTypeDot11MgmtReassociationResp, layers.LayerTypeDot11MgmtBeacon}
		for _, t := range typesForSender {
			if l := packet.Layer(t); l != nil {
				res.ssids[pkt.Address2.String()] = struct{}{}
				return
			}
		}

		typesForReceiver := []gopacket.LayerType{layers.LayerTypeDot11MgmtAssociationReq, layers.LayerTypeDot11CtrlRTS,
			layers.LayerTypeDot11MgmtReassociationReq}
		for _, t := range typesForReceiver {
			if l := packet.Layer(t); l != nil {
				res.ssids[pkt.Address1.String()] = struct{}{}
				return
			}
		}
	}
}

func (res *result) updateTypeCounts(pkt *layers.Dot11) {
	if pkt != nil {
		res.typeCounts[pkt.Type.MainType()] = res.typeCounts[pkt.Type.MainType()] + 1
		res.subTypeCounts[pkt.Type] = res.subTypeCounts[pkt.Type] + 1
	}
}

func (res *result) updateProtected(pkt *layers.Dot11) {
	if pkt.Flags.WEP() {
		res.protectedFrames++
	}
}

func (res *result) updateMinDataWithRTS(packet gopacket.Packet) {
	types := []gopacket.LayerType{layers.LayerTypeDot11DataQOSData, layers.LayerTypeDot11DataQOSDataCFAck,
		layers.LayerTypeDot11DataQOSDataCFPoll, layers.LayerTypeDot11DataQOSDataCFAckPoll, layers.LayerTypeDot11DataQOSNull,
		layers.LayerTypeDot11DataQOSCFPollNoData, layers.LayerTypeDot11DataQOSCFAckPollNoData}
	for _, t := range types {
		if l := packet.Layer(t); l != nil {
			if len(packet.Data()) < res.minRTSDataPacketSize {
				res.minRTSDataPacketSize = len(packet.Data())
				break
			}
		}
	}
}

func (res *result) newTSVWriter(filename string) *csv.Writer {
	file, err := os.Create(res.prefix + "_" + filename)
	if err != nil {
		panic(err)
	}
	writer := csv.NewWriter(file)

	res.files = append(res.files, file)
	res.writers = append(res.writers, writer)
	writer.Comma = '\t'

	return writer
}

func (res *result) write(writer *csv.Writer, data []string) {
	err := writer.Write(data)
	if err != nil {
		panic(err)
	}
}

func (res *result) packetSizeExporter() {
	writer := res.newTSVWriter("packetSizePlot.tsv")
	res.write(writer, []string{"Time (mins)", "Avg Size (bytes)"})

	writer2 := res.newTSVWriter("packetRatePlot.tsv")
	res.write(writer2, []string{"Time (mins)", "Packets/sec"})

	var startTS, ts time.Time
	interval := 1 * time.Minute

	packetCount := 0
	size := 0
	mins := 0

	dump := func() {
		var avgSize float64
		if packetCount != 0 {
			avgSize = float64(size) / float64(packetCount)
		}
		mins++

		res.write(writer, []string{strconv.Itoa(mins), fmt.Sprintf("%f", avgSize)})
		res.write(writer2, []string{strconv.Itoa(mins), fmt.Sprintf("%f", float64(packetCount)/(float64(ts.Sub(startTS))/float64(time.Second)))})

		startTS = startTS.Add(interval)
		packetCount = 0
		size = 0
	}

	for packet := range res.packetSizeChan {
		ts = packet.Metadata().Timestamp
		if startTS.IsZero() {
			startTS = ts
		}
		for ts.Sub(startTS) > interval {
			dump()
		}
		size += len(packet.Data())
		res.packetSizeHistogram[len(packet.Data())]++
		packetCount++
	}
	if packetCount > 0 {
		dump()
	}

	histWriter := res.newTSVWriter("packetSizeHistogram.tsv")
	res.write(histWriter, []string{"Packet Size (bytes)", "Count"})
	var keys []int
	for k := range res.packetSizeHistogram {
		keys = append(keys, k)
	}
	sort.Ints(keys)
	for _, r := range keys {
		res.write(histWriter, []string{strconv.Itoa(r), strconv.Itoa(res.packetSizeHistogram[r])})
	}

	res.wg.Done()
}

func (res *result) radioLayerExporter() {
	phyDataRateWriter := res.newTSVWriter("phyDataRatePlot.tsv")
	res.write(phyDataRateWriter, []string{"Time (mins)", "Avg Data Rate (Mb/s)"})

	rssiDataRateWriter := res.newTSVWriter("rssiDataRatePlot.tsv")
	res.write(rssiDataRateWriter, []string{"Time (mins)", "Avg Signal Strength (dBm)"})

	var startTS time.Time
	interval := 1 * time.Minute

	packetCount1 := 0
	packetCount2 := 0
	dataRate := uint32(0)
	signalStrength := 0
	mins := 0

	dump := func() {
		mins++
		var rateAvg, strengthAvg float64
		if packetCount1 != 0 {
			rateAvg = float64(dataRate) / float64(packetCount1)
		}
		if packetCount2 != 0 {
			strengthAvg = float64(signalStrength) / float64(packetCount2)
		}
		res.write(phyDataRateWriter, []string{strconv.Itoa(mins), fmt.Sprintf("%f", rateAvg)})
		res.write(rssiDataRateWriter, []string{strconv.Itoa(mins), fmt.Sprintf("%f", strengthAvg)})

		startTS = startTS.Add(interval)
		packetCount1 = 0
		packetCount2 = 0
		dataRate = 0
		signalStrength = 0
	}
	for packet := range res.radioLayerChan {
		ts := packet.Metadata().Timestamp
		if startTS.IsZero() {
			startTS = ts
		}
		var radio *layers.RadioTap
		if l := packet.Layer(layers.LayerTypeRadioTap); l != nil {
			radio = l.(*layers.RadioTap)
		}
		for ts.Sub(startTS) > interval {
			dump()
		}
		if radio == nil {
			continue
		}

		if radio.Present.Rate() {
			dataRate += uint32(radio.Rate)
			res.dataRateHistogram[uint8(radio.Rate)]++
			packetCount1++
		}
		if radio.Present.DBMAntennaSignal() {
			signalStrength += int(radio.DBMAntennaSignal)
			packetCount2++
		}

	}

	if packetCount1 > 0 || packetCount2 > 0 {
		dump()
	}

	histWriter := res.newTSVWriter("dataRateHistogram.tsv")
	res.write(histWriter, []string{"Data Rate (Mb/s)", "Count"})
	var keys []uint8
	for k := range res.dataRateHistogram {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })
	for _, r := range keys {
		res.write(histWriter, []string{strconv.Itoa(int(r)), strconv.Itoa(res.dataRateHistogram[r])})
	}

	res.wg.Done()
}

func (res *result) initPlotsExport() {
	res.wg.Add(2)
	res.packetSizeChan = make(chan gopacket.Packet, 100)
	res.radioLayerChan = make(chan gopacket.Packet, 100)
	go res.packetSizeExporter()
	go res.radioLayerExporter()
}

func (res *result) updatePlotExport(packet gopacket.Packet) {
	res.packetSizeChan <- packet
	res.radioLayerChan <- packet
}

func (res *result) closePlotsExport() {
	close(res.packetSizeChan)
	close(res.radioLayerChan)
	res.wg.Wait()
}

func (res *result) closeFiles() {
	for _, w := range res.writers {
		w.Flush()
	}
	for _, f := range res.files {
		f.Close()
	}
}

func pcapInfo(filename string, prefix string) {
	res := newResult(prefix)

	handleRead, err := pcap.OpenOffline(filename)
	handleErr(err)
	res.initPlotsExport()
	packetSource := gopacket.NewPacketSource(handleRead, handleRead.LinkType())
	for packet := range packetSource.Packets() {
		res.updatePlotExport(packet)
		res.updateMinDataWithRTS(packet)
		res.updateAPs(packet)
		res.packets++
		l := packet.Layer(layers.LayerTypeDot11)
		if l == nil {
			continue
		}
		pkt := l.(*layers.Dot11)
		res.updateTypeCounts(pkt)
		res.updateProtected(pkt)
	}
	res.closePlotsExport()

	stats := res.newTSVWriter("stats.tsv")
	res.write(stats, []string{"Packets", strconv.Itoa(res.packets)})
	res.write(stats, []string{})
	res.write(stats, []string{"Num APs", strconv.Itoa(len(res.ssids))})
	res.write(stats, []string{})
	res.write(stats, []string{"Num Protected Frames", strconv.Itoa(res.protectedFrames)})
	res.write(stats, []string{})
	res.write(stats, []string{"Min Data Size with RTS", strconv.Itoa(res.minRTSDataPacketSize)})
	res.write(stats, []string{})
	res.write(stats, []string{})
	res.write(stats, []string{})
	res.write(stats, []string{"Types"})
	for k, v := range res.typeCounts {
		res.write(stats, []string{k.String(), strconv.Itoa(v)})
	}
	res.write(stats, []string{})
	res.write(stats, []string{"SubTypes"})
	for k, v := range res.subTypeCounts {
		res.write(stats, []string{k.String(), strconv.Itoa(v)})
	}

	res.closeFiles()
}

func main() {
	pcapInfo("/home/codesome/CS15BTECH11018_IITH_802_11.pcapng", "mess")
	pcapInfo("/home/codesome/Wireshark_802_11.pcap", "online")
}
