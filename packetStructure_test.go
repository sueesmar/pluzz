package main

import (
	"bytes"
	"encoding/hex"
	"log"
	"net"
	"reflect"
	"strconv"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// TestInitEmptyPacketStructure tests the initialization of the empty packet structure.
func TestInitEmptyPacketStructure(t *testing.T) {
	InitEmptyPacketStructure()

	// Check main fields from ethernet layer
	if !bytes.Equal(ethernetLayer.DstMAC, net.HardwareAddr{}) {
		t.Error("Expected:", net.HardwareAddr{}, "Got:", ethernetLayer.DstMAC)
	}
	if !bytes.Equal(ethernetLayer.SrcMAC, net.HardwareAddr{}) {
		t.Error("Expected:", net.HardwareAddr{}, "Got:", ethernetLayer.SrcMAC)
	}
	if ethernetLayer.EthernetType != 0 {
		t.Error("Expected:", 0, "Got:", ethernetLayer.EthernetType)
	}
	if ethernetLayer.Length != 0 {
		t.Error("Expected:", 0, "Got:", ethernetLayer.Length)
	}
	// Check main fields from ip layer
	if !bytes.Equal(ipLayer.DstIP, net.IP{}) {
		t.Error("Expected:", net.IP{}, "Got:", ipLayer.DstIP)
	}
	if !bytes.Equal(ipLayer.SrcIP, net.IP{}) {
		t.Error("Expected:", net.IP{}, "Got:", ipLayer.SrcIP)
	}
	if ipLayer.Length != 0 {
		t.Error("Expected:", 0, "Got:", ipLayer.Length)
	}
	if ipLayer.TTL != 0 {
		t.Error("Expected:", 0, "Got:", ipLayer.TTL)
	}
	if ipLayer.TOS != 0 {
		t.Error("Expected:", 0, "Got:", ipLayer.TOS)
	}
	if ipLayer.Version != 0 {
		t.Error("Expected:", 0, "Got:", ipLayer.Version)
	}
	if ipLayer.Protocol != 0 {
		t.Error("Expected:", 0, "Got:", ipLayer.Protocol)
	}
	if ipLayer.Options != nil {
		t.Error("Expected:", nil, "Got:", ipLayer.Options)
	}
	// Check main fields from udp layer
	if udpLayer.DstPort != 0 {
		t.Error("Expected:", 0, "Got:", udpLayer.DstPort)
	}
	if udpLayer.SrcPort != 0 {
		t.Error("Expected:", 0, "Got:", udpLayer.SrcPort)
	}
	if udpLayer.Length != 0 {
		t.Error("Expected:", 0, "Got:", udpLayer.Length)
	}
	if udpLayer.Checksum != 0 {
		t.Error("Expected:", 0, "Got:", udpLayer.Checksum)
	}
}

type InitBasePacketTestStruct struct {
	targetIP      net.IP
	localIP       net.IP
	targetMACAddr net.HardwareAddr
	localMACAddr  net.HardwareAddr
	targetPort    uint
	localPort     uint
}

// TestInitBasePacketStructure tests the initialization of the base packet layers without shimlayer.
func TestInitBasePacketStructure(t *testing.T) {

	var testcases = []InitBasePacketTestStruct{
		{net.IP{192, 168, 181, 133}, net.IP{192, 168, 181, 132}, net.HardwareAddr{0x00, 0x0c, 0x29, 0xec, 0x31, 0xfa}, net.HardwareAddr{0x00, 0x0c, 0x29, 0xc7, 0x6d, 0xb9}, 9999, 10000},
	}

	for _, testcase := range testcases {
		InitBasePacketStructure(testcase.targetIP, testcase.localIP, testcase.targetMACAddr, testcase.localMACAddr, testcase.targetPort, testcase.localPort)

		// Check main fields from ethernet layer
		if !bytes.Equal(ethernetLayer.DstMAC, testcase.targetMACAddr) {
			t.Error("Expected:", testcase.targetMACAddr, "Got:", ethernetLayer.DstMAC)
		}
		if !bytes.Equal(ethernetLayer.SrcMAC, testcase.localMACAddr) {
			t.Error("Expected:", testcase.localMACAddr, "Got:", ethernetLayer.SrcMAC)
		}
		if ethernetLayer.EthernetType != layers.EthernetTypeIPv4 {
			t.Error("Expected:", layers.EthernetTypeIPv4, "Got:", ethernetLayer.EthernetType)
		}

		// Check main fields from ip layer
		if !bytes.Equal(ipLayer.DstIP, testcase.targetIP) {
			t.Error("Expected:", testcase.targetIP, "Got:", ipLayer.DstIP)
		}
		if !bytes.Equal(ipLayer.SrcIP, testcase.localIP) {
			t.Error("Expected:", testcase.localIP, "Got:", ipLayer.SrcIP)
		}
		if ipLayer.TTL != 64 {
			t.Error("Expected:", 64, "Got:", ipLayer.TTL)
		}
		if ipLayer.TOS != 0 {
			t.Error("Expected:", 0, "Got:", ipLayer.TOS)
		}
		if ipLayer.Version != 4 {
			t.Error("Expected:", 4, "Got:", ipLayer.Version)
		}
		if ipLayer.Protocol != layers.IPProtocolUDP {
			t.Error("Expected:", layers.IPProtocolUDP, "Got:", ipLayer.Protocol)
		}
		// Check main fields from udp layer
		if udpLayer.DstPort != layers.UDPPort(testcase.targetPort) {
			t.Error("Expected:", testcase.targetPort, "Got:", udpLayer.DstPort)
		}
		if udpLayer.SrcPort != layers.UDPPort(testcase.localPort) {
			t.Error("Expected:", testcase.localPort, "Got:", udpLayer.SrcPort)
		}
	}
}

//TestInitShimLayer tests the initialization of the shimlayer.
func TestInitShimLayer(t *testing.T) {

	InitShimLayer()

	resultLayerType := shimLayer.LayerType()

	// Check LayerType
	if resultLayerType != layers.ShimLayerType {
		t.Error("Expected:", layers.ShimLayerType, "Got:", resultLayerType)
	}
	// Check basic payload
	if !bytes.Equal(*payload, []byte{0x7a, 0x68, 0x61, 0x77, 0x2d, 0x70, 0x6c, 0x75, 0x7a, 0x7a, 0x20, 0x74, 0x6f, 0x20, 0x66, 0x75, 0x7a, 0x7a, 0x20, 0x61, 0x20, 0x73, 0x68, 0x69, 0x6d, 0x20, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x63, 0x6f, 0x6c, 0x2d, 0x7a, 0x68, 0x61, 0x77}) {
		t.Error("Expected:", []byte{0x7a, 0x68, 0x61, 0x77, 0x2d, 0x70, 0x6c, 0x75, 0x7a, 0x7a, 0x20, 0x74, 0x6f, 0x20, 0x66, 0x75, 0x7a, 0x7a, 0x20, 0x61, 0x20, 0x73, 0x68, 0x69, 0x6d, 0x20, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x63, 0x6f, 0x6c, 0x2d, 0x7a, 0x68, 0x61, 0x77}, "Got:", *payload)
	}
}

// TestDecodePacket tests the implementation of decoding a packet.
// It uses a real pcap file from the testdata and decodes the first packet.
func TestDecodePacket(t *testing.T) {
	InitEmptyPacketStructure()
	InitShimLayer()

	expectedEthernetPayload, err := hex.DecodeString("450000947e7340004011cf8ac0a8b584c0a8b5852710270f0080ececd8007ff0342f1403bb44df81ad3b1bd10000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000065666768")
	expectedIPPayload, err := hex.DecodeString("2710270f0080ececd8007ff0342f1403bb44df81ad3b1bd10000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000065666768")
	expectedUDPPayload, err := hex.DecodeString("d8007ff0342f1403bb44df81ad3b1bd10000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000065666768")
	expectedShimPayload, err := hex.DecodeString("00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000065666768")

	*destIP = "192.168.181.133"
	*targetPort = 9999
	pcapTestFile := "testdata/plus_debug_original_trace.pcapng"

	// fileHandle is the handle to the pcap file with the saved packets.
	fileHandle, err := pcap.OpenOffline(pcapTestFile)
	if err != nil {
		log.Fatal(err)
	}
	// Only read the packets of the specific protocol and direction from the file.
	fileHandle.SetBPFFilter("dst host " + *destIP + " and dst port " + strconv.Itoa(int(*targetPort)))
	defer fileHandle.Close()

	// layerValReflect represents the layer by dynamically examining the fields via reflection
	layerValReflect := reflect.ValueOf(shimLayer).Elem()

	packetSource := gopacket.NewPacketSource(fileHandle, fileHandle.LinkType())

	packet, err := packetSource.NextPacket()
	if err != nil {
		t.Errorf("Error in getting Packet from PCAP file %s.\n", pcapTestFile)
	}

	DecodePacket(packet, &layerValReflect)

	// Check main fields from ethernet layer
	if !bytes.Equal(ethernetLayer.DstMAC, net.HardwareAddr{0x00, 0x0c, 0x29, 0xec, 0x31, 0xfa}) {
		t.Error("Expected:", net.HardwareAddr{0x00, 0x0c, 0x29, 0xec, 0x31, 0xfa}, "Got:", ethernetLayer.DstMAC)
	}
	if !bytes.Equal(ethernetLayer.SrcMAC, net.HardwareAddr{0x00, 0x0c, 0x29, 0xc7, 0x6d, 0xb9}) {
		t.Error("Expected:", net.HardwareAddr{0x00, 0x0c, 0x29, 0xc7, 0x6d, 0xb9}, "Got:", ethernetLayer.SrcMAC)
	}
	if ethernetLayer.EthernetType != layers.EthernetTypeIPv4 {
		t.Error("Expected:", layers.EthernetTypeIPv4, "Got:", ethernetLayer.EthernetType)
	}
	if !bytes.Equal(ethernetLayer.Payload, expectedEthernetPayload) {
		t.Error("Expected:", expectedEthernetPayload, "Got:", ethernetLayer.Payload)
	}

	// Check main fields from ip layer
	if !bytes.Equal(ipLayer.DstIP, net.IP{192, 168, 181, 133}) {
		t.Error("Expected:", net.IP{192, 168, 181, 133}, "Got:", ipLayer.DstIP)
	}
	if !bytes.Equal(ipLayer.SrcIP, net.IP{192, 168, 181, 132}) {
		t.Error("Expected:", net.IP{192, 168, 181, 132}, "Got:", ipLayer.SrcIP)
	}
	if ipLayer.TTL != 64 {
		t.Error("Expected:", 64, "Got:", ipLayer.TTL)
	}
	if ipLayer.IHL != 5 {
		t.Error("Expected:", 5, "Got:", ipLayer.IHL)
	}
	if ipLayer.TOS != 0 {
		t.Error("Expected:", 0, "Got:", ipLayer.TOS)
	}
	if ipLayer.Version != 4 {
		t.Error("Expected:", 4, "Got:", ipLayer.Version)
	}
	if ipLayer.Checksum != 53130 {
		t.Error("Expected:", 53130, "Got:", ipLayer.Checksum)
	}
	if ipLayer.Protocol != layers.IPProtocolUDP {
		t.Error("Expected:", layers.IPProtocolUDP, "Got:", ipLayer.Protocol)
	}
	if ipLayer.Id != 32371 {
		t.Error("Expected:", 32371, "Got:", ipLayer.Id)
	}
	if ipLayer.Length != 148 {
		t.Error("Expected:", 148, "Got:", ipLayer.Length)
	}
	if ipLayer.Flags != layers.IPv4DontFragment {
		t.Error("Expected:", layers.IPv4DontFragment, "Got:", ipLayer.Flags)
	}
	if !bytes.Equal(ipLayer.Payload, expectedIPPayload) {
		t.Error("Expected:", expectedIPPayload, "Got:", ipLayer.Payload)
	}

	// Check main fields from udp layer
	if udpLayer.DstPort != layers.UDPPort(9999) {
		t.Error("Expected:", layers.UDPPort(9999), "Got:", udpLayer.DstPort)
	}
	if udpLayer.SrcPort != layers.UDPPort(10000) {
		t.Error("Expected:", layers.UDPPort(10000), "Got:", udpLayer.SrcPort)
	}
	if udpLayer.Checksum != 60652 {
		t.Error("Expected:", 60652, "Got:", udpLayer.Checksum)
	}
	if udpLayer.Length != 128 {
		t.Error("Expected:", 128, "Got:", udpLayer.Length)
	}
	if !bytes.Equal(udpLayer.Payload, expectedUDPPayload) {
		t.Error("Expected:", expectedUDPPayload, "Got:", udpLayer.Payload)
	}

	// Check main field from shim layer
	if shimLayer.Magic.Value != 0x0d8007ff {
		t.Error("Expected:", 0x0d8007ff, "Got:", shimLayer.Magic.Value)
	}
	if shimLayer.LFlag.Value != false {
		t.Error("Expected:", 0, "Got:", shimLayer.LFlag.Value)
	}
	if shimLayer.RFlag.Value != false {
		t.Error("Expected:", false, "Got:", shimLayer.RFlag.Value)
	}
	if shimLayer.SFlag.Value != false {
		t.Error("Expected:", false, "Got:", shimLayer.SFlag.Value)
	}
	if shimLayer.XFlag.Value != false {
		t.Error("Expected:", false, "Got:", shimLayer.XFlag.Value)
	}
	if shimLayer.CAT.Value != 3760246220136963969 {
		t.Error("Expected:", 3760246220136963969, "Got:", shimLayer.CAT.Value)
	}
	if shimLayer.PSN.Value != 2906332113 {
		t.Error("Expected:", 2906332113, "Got:", shimLayer.PSN.Value)
	}
	if shimLayer.PSE.Value != 0 {
		t.Error("Expected:", 0, "Got:", shimLayer.PSN.Value)
	}
	if !bytes.Equal(*payload, expectedShimPayload) {
		t.Error("Expected:", expectedShimPayload, "Got:", *payload)
	}
}
