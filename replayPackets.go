package main

import (
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

// ReplayPackets takes a pcap file and sends the packets again.
// The method uses the raw bytes from the pcap file and doesn't decode the packet data.
// It is the faster method than FuzzCapturedPackets() although the two can do nearly the same.
// This method takes all packets from the pcap (no filter) and process and send them out the network interface.
// Use this method to replay saved packets of a fuzzing process from this application.
// To replay an original pcap file, use the method FuzzCapturedPackets().
func ReplayPackets(fuzzingRoundDone chan bool) {

	// snapshotLen specifies the maximum length of the packet to read.
	var snapshotLen int32 = 65535
	// promiscious sets/unsets the promisious mode of the network interface.
	promiscious := true
	// timeout sets the interval, after that packets get send/read from the network interface to the application.
	// Use a negative value to immediately send or receive it.
	timeout := -1 * time.Second
	// err contains the error value, if one occurs.
	var err error
	// sendHandle is the reference to the pcap stream. It is used to write to the network interface.
	var sendHandle *pcap.Handle
	// recvHandle is the reference to the pcap stream. It is used to read from the network interface.
	var recvHandle *pcap.Handle
	// fileHandle is the reference to the pcap file for replay. It is used to read from file.
	var fileHandle *pcap.Handle
	// replayBuffer is the packet buffer, which holds the raw bytes for sending them to the network interface.
	var replayBuffer gopacket.SerializeBuffer
	// options for the packet sending. Because of replay, we don't have to fix length or calculate checksums.
	var options gopacket.SerializeOptions
	// packetCountSend is a counter for the packets sent.
	var packetCountSend int
	// replayFilenames is a slice which holds the filenames to replay.
	var replayFilenames []string

	WriteReplayLogHeader()

	Info.Println("Start of replay of packets from pcap file", *pcapPathReplay)

	// Open network device for sending packets
	sendHandle, err = pcap.OpenLive(*device, snapshotLen, promiscious, timeout)
	if err != nil {
		Error.Fatalln(err.Error())
	}
	defer sendHandle.Close()

	// Open network device for receiving packets
	recvHandle, err = pcap.OpenLive(*device, snapshotLen, promiscious, timeout)
	if err != nil {
		Error.Fatalln(err.Error())
	}
	// Set Berkley Packet Filter to just search for ICMP unreachable packets with code "port unreachable"
	recvHandle.SetBPFFilter("src host " + *destIP + " and icmp[icmptype]==icmp-unreach and icmp[icmpcode]==3")
	defer recvHandle.Close()

	// Start server (SUT) on target
	if *sshCommand != "" {
		sendSSHCommand(*destIP+":22", *sshCommand, *sshUsername, *sshPassword)
	}

	// Channel for communication with CheckCrash goroutine
	quitCheckCrash := make(chan bool)

	// Receive incomming packets and check for ICMP Port uncreachable
	go CheckCrash(recvHandle, &packetCountSend, nil, quitCheckCrash)

	replayFilenames, err = ReplayFilenames(*pcapPathReplay)
	if err != nil {
		Error.Fatal(err)
	}
	Log.Println("Files for replay:", replayFilenames)

	// numPacketsInFiles holds the packets of the pcap files.
	var numPacketsInFiles int
	for i := 0; i < len(replayFilenames); i++ {
		packetCount, err := CountPackets(replayFilenames[i])
		if err != nil {
			Error.Fatal(err)
		}
		numPacketsInFiles += packetCount
		if *verbose {
			Info.Printf("Number of packets in %s: %d\n", replayFilenames[i], packetCount)
		}
	}

	// Initialize buffer
	replayBuffer = gopacket.NewSerializeBuffer()

	// Loop through all the files to replay
	for i := 0; i < len(replayFilenames); i++ {

		// fileHandle is the handle to the pcap file with the saved packets.
		fileHandle, err = pcap.OpenOffline(replayFilenames[i])
		if err != nil {
			Error.Fatal(err)
		}
		defer fileHandle.Close()

		Info.Println("Replay packets from", replayFilenames[i])
		Log.Println("Replay packets from", replayFilenames[i])

		packetSource := gopacket.NewPacketSource(fileHandle, fileHandle.LinkType())
		// Loop through packets in file
		for packet := range packetSource.Packets() {

			// Show the packet
			if *verbose {
				Info.Printf("Packet from file to replay:\n%v\n\n", packet)
			}

			// Serialize the packet for sending the byte stream
			err = gopacket.SerializePacket(replayBuffer, options, packet)
			if err != nil {
				Error.Fatal(err)
			}
			// outgoingPacket is the byte stream for sending it on the wire.
			outgoingPacket := replayBuffer.Bytes()

			// Send the packet to the pcap handle to the wire
			err = sendHandle.WritePacketData(outgoingPacket)
			if err != nil {
				Error.Fatal(err)
			}

			// Increment counter to get number of packets sent so far.
			packetCountSend++
			if packetCountSend%10 == 0 {
				Info.Printf("%d packets sent. (%.2f %%)\n", packetCountSend, float64(packetCountSend)*100.0/float64(numPacketsInFiles))
			}

			// Insert a pause interval between to packets
			time.Sleep(time.Duration(*packetSendInterval) * time.Millisecond)
		}
	}

	Info.Println("Waiting 2 seconds to looking for ICMP unreachable packets...")
	time.Sleep(2 * time.Second)

	// End the goroutine for checking for crashes.
	quitCheckCrash <- true

	Info.Printf("All %d packets replayed without crash.\n", packetCountSend)
	Log.Printf("All %d packets replayed without crash.\n", packetCountSend)
	fuzzingRoundDone <- true
}
