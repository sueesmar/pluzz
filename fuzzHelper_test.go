package main

import (
	"bytes"
	"net"
	"os"
	"strconv"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

func TestMain(m *testing.M) {
	// Init code
	InitLog(os.Stderr, os.Stdout, os.Stdout)

	// Run other tests
	runTests := m.Run()

	os.Exit(runTests)
}

type ReplayFilenameTestStruct struct {
	filepath        string
	replayFilenames []string
}

// TestReplayFilenames tests the method of getting the filenames for replay pcap files.
func TestReplayFilenames(t *testing.T) {
	// Only one file should be get back, event there are following ones.
	var testsWithoutFollowing = []ReplayFilenameTestStruct{
		{filepath: "testdata/fuzz-send-20180305193851-0.pcap", replayFilenames: []string{"testdata/fuzz-send-20180305193851-0.pcap"}},
		{filepath: "testdata/plus_debug_original_trace.pcapng", replayFilenames: []string{"testdata/plus_debug_original_trace.pcapng"}},
		{filepath: "testdata/fuzz-send-20180305193851-99.pcap", replayFilenames: []string{"testdata/fuzz-send-20180305193851-99.pcap"}},
		{filepath: "testdata/fuzz-send-20180305193851-100.pcap", replayFilenames: []string{"testdata/fuzz-send-20180305193851-100.pcap"}},
	}

	// If there are following ones, they should be returned. if one is missing e.g. -3, it should stop at the last available.
	var testsWithFollowing = []ReplayFilenameTestStruct{
		{filepath: "testdata/fuzz-send-20180305193851-4.pcap", replayFilenames: []string{"testdata/fuzz-send-20180305193851-4.pcap"}},
		{filepath: "testdata/plus_debug_original_trace.pcapng", replayFilenames: []string{"testdata/plus_debug_original_trace.pcapng"}},
		{filepath: "testdata/fuzz-send-20180305193851-0.pcap", replayFilenames: []string{"testdata/fuzz-send-20180305193851-0.pcap", "testdata/fuzz-send-20180305193851-1.pcap", "testdata/fuzz-send-20180305193851-2.pcap"}},
		{filepath: "testdata/fuzz-send-20180305193851-99.pcap", replayFilenames: []string{"testdata/fuzz-send-20180305193851-99.pcap", "testdata/fuzz-send-20180305193851-100.pcap"}},
	}

	// Testing with replayFollowing set to false
	for _, replayFilename := range testsWithoutFollowing {
		result, err := ReplayFilenames(replayFilename.filepath)
		if err == nil {
			if len(result) != len(replayFilename.replayFilenames) {
				t.Error("Given Input:", replayFilename.filepath, "Expected length:", len(replayFilename.replayFilenames), "Got length:", len(result))
			} else {
				for i := 0; i < len(result); i++ {
					if result[i] != replayFilename.replayFilenames[i] {
						t.Error("Expected: ", replayFilename.replayFilenames, "Got:", result)
					}
				}
			}
		} else {
			if result[0] != replayFilename.replayFilenames[0] {
				t.Error("Expected: ", replayFilename.replayFilenames, "Got:", result)
			}
		}
	}

	// Testing with replayFollowing set to true
	*replayFollowing = true
	for _, replayFilename := range testsWithFollowing {
		result, err := ReplayFilenames(replayFilename.filepath)
		if err == nil {
			if len(result) != len(replayFilename.replayFilenames) {
				t.Error("Given Input:", replayFilename.filepath, "Expected length:", len(replayFilename.replayFilenames), "Got length:", len(result))
			} else {
				for i := 0; i < len(result); i++ {
					if result[i] != replayFilename.replayFilenames[i] {
						t.Error("Expected: ", replayFilename.replayFilenames, "Got:", result)
					}
				}
			}
		} else {
			if result[0] != replayFilename.replayFilenames[0] {
				t.Error("Expected: ", replayFilename.replayFilenames, "Got:", result)
			}
		}
	}
}

type localIPAddressTestStruct struct {
	dev  string
	ip   net.IP
	mask net.IPMask
	net  *net.IPNet
}

// TestLocalIPAddress tests the recognition of the local ip address of the system.
// The test cases have to be adapted with the current ip addresses.
func TestLocalIPAddress(t *testing.T) {

	// Insert the config from your local network interface
	var testsLocalIP = []localIPAddressTestStruct{
		{"ens33", net.IP{192, 168, 181, 137}, net.IPMask{255, 255, 255, 0}, &net.IPNet{IP: net.IP{192, 168, 181, 0}, Mask: net.IPMask{255, 255, 255, 0}}},
		{"lo", net.IP{127, 0, 0, 1}, net.IPMask{255, 0, 0, 0}, &net.IPNet{IP: net.IP{127, 0, 0, 0}, Mask: net.IPMask{255, 0, 0, 0}}},
	}

	// Loop through all the testcases and check the results
	for _, testcase := range testsLocalIP {
		resultIP, resultMask, resultNet := localIPAddress(testcase.dev)
		if !resultIP.Equal(testcase.ip) {
			t.Error("Expected:", testcase.ip, "Got:", resultIP)
		}
		if !net.IP(resultMask).Equal(net.IP(testcase.mask)) {
			t.Error("Expected:", testcase.mask, "Got:", resultMask)
		}
		if !resultNet.IP.Equal(testcase.net.IP) || !net.IP(resultNet.Mask).Equal(net.IP(testcase.net.Mask)) {
			t.Error("Expected:", testcase.net, "Got:", resultNet)
		}
	}
}

type localMacAddressTestStruct struct {
	dev string
	mac net.HardwareAddr
}

// TestLocalMacAddress tests the resolution of the local mac address of the system.
// You have to change the address to your local address.
func TestLocalMacAddress(t *testing.T) {

	var testcases = []localMacAddressTestStruct{
		{"ens33", net.HardwareAddr{0x00, 0x0C, 0x29, 0xC7, 0x6D, 0xB9}},
	}

	for _, testcase := range testcases {
		result := localMACAddress(testcase.dev)
		// if result.String() != testcase.mac.String() {
		// 	t.Error("Expected:", testcase.mac, "Got:", result)
		// }
		if !bytes.Equal(result, testcase.mac) {
			t.Error("Expected:", testcase.mac, "Got:", result)
		}
	}
}

type remoteMACAddressTestStruct struct {
	targetIP net.IP
	localNet *net.IPNet
	mac      string
}

// TestRemoteMACAddress tests getting the mac address for the target system.
// Because of missing root rights, the ping command can't be executed.
func TestRemoteMACAddress(t *testing.T) {

	var testcases = []remoteMACAddressTestStruct{
		// {net.IP{192, 168, 181, 132}, &net.IPNet{IP: net.IP{192, 168, 181, 0}, Mask: net.IPMask{255, 255, 255, 0}}, "00:0c:29:c7:6d:b9"}, // local addres not found in arp cache
		{net.IP{192, 168, 181, 133}, &net.IPNet{IP: net.IP{192, 168, 181, 0}, Mask: net.IPMask{255, 255, 255, 0}}, "00:0c:29:ec:31:fa"}, // IP in local subnet
		{net.IP{8, 8, 8, 8}, &net.IPNet{IP: net.IP{192, 168, 181, 0}, Mask: net.IPMask{255, 255, 255, 0}}, "00:50:56:ee:c6:46"},         // IP in remote subnet
		{net.IP{192, 168, 181, 2}, &net.IPNet{IP: net.IP{192, 168, 181, 0}, Mask: net.IPMask{255, 255, 255, 0}}, "00:50:56:ee:c6:46"},   // Gateway
		{net.IP{195, 186, 1, 162}, &net.IPNet{IP: net.IP{192, 168, 181, 0}, Mask: net.IPMask{255, 255, 255, 0}}, "00:50:56:ee:c6:46"},   // Another IP in remote subnet
		{net.IP{192, 168, 10, 71}, &net.IPNet{IP: net.IP{192, 168, 181, 0}, Mask: net.IPMask{255, 255, 255, 0}}, "00:50:56:ee:c6:46"},   // Another IP in remote subnet
	}

	for _, testcase := range testcases {
		result, err := remoteMACAddress(testcase.targetIP, testcase.localNet)
		if err != nil {
			t.Error("Error returned:", err)
		} else {
			if result != testcase.mac {
				t.Error("Expected:", testcase.mac, "Got:", result)
			}
		}
	}
}

type RotatePCAPFileTestStruct struct {
	pcapFileSize       int
	maxStorageCapacity int
	pcapPathSend       string
	filenames          []string
}

// TestRotatePCAPFile tests the rotation of the pcap file
// with maximum file size and maximum storage capacity.
func TestRotatePCAPFile(t *testing.T) {

	var testcases = []RotatePCAPFileTestStruct{
		{20, 40, "testdata/test-rotate-2040.pcap", []string{
			"testdata/test-rotate-2040-15.pcap",
			"testdata/test-rotate-2040-16.pcap"}},
		{10, 40, "testdata/test-rotate-1040.pcap", []string{
			"testdata/test-rotate-1040-29.pcap",
			"testdata/test-rotate-1040-30.pcap",
			"testdata/test-rotate-1040-31.pcap",
			"testdata/test-rotate-1040-32.pcap"}},
		{50, 0, "testdata/test-rotate-500.pcap", []string{
			"testdata/test-rotate-500-0.pcap",
			"testdata/test-rotate-500-1.pcap",
			"testdata/test-rotate-500-2.pcap",
			"testdata/test-rotate-500-3.pcap",
			"testdata/test-rotate-500-4.pcap",
			"testdata/test-rotate-500-5.pcap",
			"testdata/test-rotate-500-6.pcap"}},
	}

	var snapshotLen int32 = 65535
	// Testdata size 162bytes
	var testdata = []byte{0x00, 0x0c, 0x29, 0xec, 0x31, 0xfa, 0x00, 0x0c, 0x29, 0xc7, 0x6d, 0xb9, 0x08, 0x00, 0x45, 0x00, 0x00, 0x94, 0x7e, 0x73, 0x40, 0x00, 0x40, 0x11, 0xcf, 0x8a, 0xc0, 0xa8, 0xb5, 0x84, 0xc0, 0xa8, 0xb5, 0x85, 0x27, 0x10, 0x27, 0x0f, 0x00, 0x80, 0xec, 0xec, 0xd8, 0x00, 0x7f, 0xf0, 0x34, 0x2f, 0x14, 0x03, 0xbb, 0x44, 0xdf, 0x81, 0xad, 0x3b, 0x1b, 0xd1, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x65, 0x66, 0x67, 0x68}

	for _, testcase := range testcases {

		// pcapWriterSend is the writer to save the packets into the pcap file.
		var pcapWriterSend *pcapgo.Writer
		// pcapFileSend is the file to write the sent packets to.
		var pcapFileSend *os.File

		var packetBytesCountSend int
		var fileCountPcapSend int
		var keepNPCAPFiles int
		if testcase.maxStorageCapacity != 0 {
			if testcase.pcapFileSize < testcase.maxStorageCapacity {
				keepNPCAPFiles = testcase.maxStorageCapacity / testcase.pcapFileSize
			} else {
				Error.Fatal("Maximum storage capacity has to be larger than " + strconv.Itoa(testcase.pcapFileSize) + " kilo bytes.")
			}
		}

		pcapWriterSend, pcapFileSend = RotatePCAPFile(&fileCountPcapSend, testcase.pcapPathSend, snapshotLen, keepNPCAPFiles, testcase.maxStorageCapacity)

		for i := 0; i < 2000; i++ {
			// Check file size to rotate it. Factor 1000 is because of kilo bytes.
			if packetBytesCountSend >= testcase.pcapFileSize*1000 {
				pcapFileSend.Close()
				pcapWriterSend, pcapFileSend = RotatePCAPFile(&fileCountPcapSend, testcase.pcapPathSend, snapshotLen, keepNPCAPFiles, testcase.maxStorageCapacity)
				packetBytesCountSend = 0
			}
			defer pcapFileSend.Close()

			// packet is the packet, which was sent on the wire to the target.
			// A packet in pcap format is created from the raw bytes to save it to the file.
			packet := gopacket.NewPacket(testdata, layers.LayerTypeEthernet, gopacket.Default)

			// We have to set the packet metadata manually, because we don't read the packet data from a handle.
			// Otherwise, the packet isn't saved to file.
			// The CaptureLength and the Length of the metadata are the length of the byte slice from the outgoing packet.
			packet.Metadata().CaptureLength = len(testdata)
			packet.Metadata().Length = len(testdata)

			// Update number of bytes sent so far to check maximum file size
			packetBytesCountSend += len(testdata)

			// Write packet to the pcap file.
			err := pcapWriterSend.WritePacket(packet.Metadata().CaptureInfo, packet.Data())
			if err != nil {
				Error.Fatal(err)
			}
		}

		for _, filename := range testcase.filenames {
			if _, err := os.Stat(filename); err == nil {
				// do nothing
			} else {
				t.Error("Expected:", filename, "Got:", err)
			}
		}

	}

	// Delete the testfiles after testing.
	for _, removeTestcase := range testcases {
		for _, filename := range removeTestcase.filenames {
			err := os.Remove(filename)
			if err != nil {
				t.Error("Couldn't delete the testfiles after testing.")
			}
		}
	}
}

// TestMandatoryShimLayerFieldsExist tests the mandatory fields in the struct of the Shim Layer.
func TestMandatoryShimLayerFieldsExist(t *testing.T) {
	var shimLayer = layers.ShimLayer{}
	shimLayer.Contents.Value = []byte{0x00}
	shimLayer.Payload.Value = []byte{0x00}

	if !bytes.Equal(shimLayer.Contents.Value, []byte{0x00}) {
		// Is not reached, if the field isn't available, but use it to check it nevertheless
		t.Error("Shimlayer doesn't contain mandadory field Contents.")
	}
	if !bytes.Equal(shimLayer.Payload.Value, []byte{0x00}) {
		// Is not reached, if the field isn't available, but use it to check it nevertheless
		t.Error("Shimlayer doesn't contain mandadory field Payload.")
	}
}

type CountPacketsTestStruct struct {
	filename    string
	packetCount int
	destIP      string
	targetPort  uint
}

// TestCountPackets tests the counting of packets in pcap files.
func TestCountPackets(t *testing.T) {
	var testcases = []CountPacketsTestStruct{
		{"testdata/fuzz-send-20180305193851-0.pcap", 138, "192.168.181.133", 9999},
		{"testdata/fuzz-send-20180305193851-1.pcap", 45, "192.168.181.133", 9999},
		{"testdata/fuzz-send-20180305193851-2.pcap", 45, "192.168.181.133", 9999},
		{"testdata/plus_debug_original_trace.pcapng", 99, "192.168.181.133", 9999},
	}

	for _, testcase := range testcases {
		*destIP = testcase.destIP
		*targetPort = testcase.targetPort
		result, err := CountPackets(testcase.filename)
		if err != nil {
			t.Error("Error in counting packets.")
		}
		if result != testcase.packetCount {
			t.Error("Expected:", testcase.packetCount, "Got:", result)
		}
	}
}
