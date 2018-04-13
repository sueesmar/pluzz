package main

import (
	"math/rand"
	"net"
	"os"
	"reflect"
	"strconv"
	"time"

	fuzz "github.com/google/gofuzz"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
)

// SendPackets generates fuzzed packets and send them out to the wire.
func SendPackets(fuzzingRoundDone chan bool) {

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
	// buffer is the packet buffer, which holds the raw bytes for sending them to the network interface.
	var buffer gopacket.SerializeBuffer
	// options serves for setting additional options for packet processing like
	// calculation of checksum or calculation of length fields in packet headers like UDP or IP
	var options gopacket.SerializeOptions

	// Initialize the random generator with the given seed.
	// Without this, each fuzzer of the same type gets the same value.
	randSource := rand.NewSource(*fuzzerSeed)
	randFuzzGen := rand.New(randSource)

	WriteFuzzLogHeader()

	// packetBytesCountSend is a counter for the bytes sent.
	var packetBytesCountSend int
	// packetCountSend is a counter for the packets sent.
	var packetCountSend int
	// fileCountPcapSend is a counter for the amount of files to save the packets sent.
	var fileCountPcapSend int
	// keepNPCAPFiles is the amount of pcap files to store.
	var keepNPCAPFiles int
	if *maxStorageCapacity != 0 {
		if *pcapFileSize < *maxStorageCapacity {
			keepNPCAPFiles = *maxStorageCapacity / *pcapFileSize
		} else {
			Error.Fatal("Maximum storage capacity has to be larger than " + strconv.Itoa(*pcapFileSize) + " kilo bytes.")
		}
	}

	// pcapWriterSend is the writer to save the packets into the pcap file.
	var pcapWriterSend *pcapgo.Writer
	// pcapFileSend is the file to write the sent packets to.
	var pcapFileSend *os.File

	// Create file to save the sent packets, if enabled
	if *savePackets {
		pcapWriterSend, pcapFileSend = RotatePCAPFile(&fileCountPcapSend, *pcapPathSend, snapshotLen, keepNPCAPFiles, *maxStorageCapacity)
	}

	// Get and set the local/target IP and local MAC address of the fuzzing process
	targetIP := net.ParseIP(*destIP)
	if targetIP == nil {
		Error.Fatal(targetIP, " isn't a valid value. Set a correct IP address.")
	}
	localIP, _, localNetwork := localIPAddress(*device)
	localMACAddr := localMACAddress(*device)

	// Get the MAC address of the target from the IP address
	// TargetMAC is either the MAC address of the target IP address
	// or the MAC address of the Default Gateway.
	targetMAC, err := remoteMACAddress(targetIP, localNetwork)
	if err != nil {
		Error.Fatalln(err.Error())
	}
	targetMACAddr, err := net.ParseMAC(targetMAC)
	if err != nil {
		Error.Fatalln(err.Error())
	}

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
	recvHandle.SetBPFFilter("src host " + targetIP.String() + " and icmp[icmptype]==icmp-unreach and icmp[icmpcode]==3")
	defer recvHandle.Close()

	// Initialize the packet structure and prepares them with the local and target addresses.
	// The packet structure with their layers can be defined in the "packetStructure.go".
	InitBasePacketStructure(targetIP, localIP, targetMACAddr, localMACAddr, *targetPort, *localPort)
	InitShimLayer()

	// Set options to compute the checksums and length of the headers correct
	options.ComputeChecksums = true
	options.FixLengths = true

	// Create fuzzer for payload (application data), if fuzzing of payload is required
	var payloadFuzzer *fuzz.Fuzzer
	if *fuzzPayload {
		randSeed := randFuzzGen.Int63n(4294967296) // Get a random number to seed the fuzzer
		payloadFuzzer = fuzz.New().NilChance(0).NumElements(*minPayloadLen, *maxPayloadLen).RandSource(rand.NewSource(randSeed)).Funcs(fuzzFuncs...)
	}

	// layerValReflect represents the layer by dynamically examining the fields via reflection
	layerValReflect := reflect.ValueOf(shimLayer).Elem()

	// Log the protocol structure and their fuzzing parameters.
	// The json encoding is to pretty print the struct.
	PrettyPrintProtocolStructure(shimLayer)

	// fuzzers contains a pointer to the fuzzing function for each field of the protocol
	var fuzzers []*fuzz.Fuzzer
	// Go through the protocol structure and get the min an max value for the fuzzer.
	// Add the fuzzer for each protocol field to the struct, for later fuzzing.
	// The last two fields Contents and Payload aren't necessary and therefore,
	// minus 2 at the fields is used.
	// Each fuzzer is initialized with a random seed to get different numbers for the same data type.
	if *fuzzFields {
		for i := 0; i < layerValReflect.NumField()-2; i++ {
			minLen := int(layerValReflect.Field(i).FieldByName("MinLen").Int())
			maxLen := int(layerValReflect.Field(i).FieldByName("MaxLen").Int())
			randSeed := randFuzzGen.Int63n(4294967296)                                                                                              // Get a random number to seed the fuzzer
			fuzzers = append(fuzzers, fuzz.New().NilChance(0).NumElements(minLen, maxLen).RandSource(rand.NewSource(randSeed)).Funcs(fuzzFuncs...)) // Initialize each fuzzer with a separate rand source, but deterministic with the fuzzerSeed
		}
	}

	// Start server (SUT) on target
	if *sshCommand != "" {
		sendSSHCommand(*destIP+":22", *sshCommand, *sshUsername, *sshPassword)
	}

	// Channel for communication with CheckCrash goroutine
	quitCheckCrash := make(chan bool)

	// Receive incomming packets and check for ICMP Port uncreachable
	go CheckCrash(recvHandle, &packetCountSend, pcapFileSend, quitCheckCrash)

	// Initialize packet buffer to send it out the wire
	buffer = gopacket.NewSerializeBuffer()

	// layerStack holds the stack of the layers, how a packet should be constructed
	var layerStack []gopacket.SerializableLayer

	// Send the packets out
	for i := int64(0); i < *numPacketsToFuzz; i++ {

		// Fuzz struct fields (when enabled) with access via reflection to protocol layer and slice of fuzzers
		if *fuzzFields {
			for j := 0; j < len(fuzzers); j++ {
				// Check, if field should be fuzzed, otherwise you
				// can set it manually in packetStructure.go or it will use the "zero" value
				if layerValReflect.Field(j).FieldByName("FuzzIt").Bool() {
					// addressToField is the address to the specific type given to the function
					addressToField := getAddressFromReflect(layerValReflect.Field(j).FieldByName("Value"))
					if addressToField != nil {
						fuzzers[j].Fuzz(addressToField)
					} else {
						Error.Fatal("Address to the struct field can't be resolved. Probably you haven't added the type for the field ", layerValReflect.Type().Field(j).Name, " to the function getAddressFromReflect().")
					}
				}
			}
		}

		// Fuzz the payload, if set to true in "FuzzIt" of packetStructure.go
		if *fuzzPayload {
			payloadFuzzer.Fuzz(&payload)
		}

		// Print Shimlayer data
		if *verbose {
			Info.Printf("ShimLayer after fuzzing the fields:\n%+v\n\n", shimLayer)
		}

		// Get the layer stack of the packetStructure.go to compose the packet so send over the wire.
		layerStack = getLayerStack()
		gopacket.SerializeLayers(buffer, options,
			layerStack...,
		)

		// outgoingPackets are the raw bytes to send over the wire.
		outgoingPacket := buffer.Bytes()

		// Send the packet to the pcap handle to the wire
		err = sendHandle.WritePacketData(outgoingPacket)
		if err != nil {
			Error.Fatal(err)
		}

		// Save the packets only to file, if enabled
		if *savePackets {

			// Check file size to rotate it. Factor 1000 is because of kilo bytes.
			if packetBytesCountSend >= *pcapFileSize*1000 {
				pcapFileSend.Close()
				pcapWriterSend, pcapFileSend = RotatePCAPFile(&fileCountPcapSend, *pcapPathSend, snapshotLen, keepNPCAPFiles, *maxStorageCapacity)
				packetBytesCountSend = 0
			}
			defer pcapFileSend.Close()

			// packet is the packet, which was sent on the wire to the target.
			// A packet in pcap format is created from the raw bytes to save it to the file.
			packet := gopacket.NewPacket(outgoingPacket, layers.LayerTypeEthernet, gopacket.Default)

			// Print packet to StdOut
			if *verbose {
				Info.Printf("Packet to save to file:\n%v\n\n", packet)
			}

			// We have to set the packet metadata manually, because we don't read the packet data from a handle.
			// Otherwise, the packet isn't saved to file.
			// The CaptureLength and the Length of the metadata are the length of the byte slice from the outgoing packet.
			packet.Metadata().CaptureLength = len(outgoingPacket)
			packet.Metadata().Length = len(outgoingPacket)

			// Update number of bytes sent so far to check maximum file size
			packetBytesCountSend += len(outgoingPacket)

			// Write packet to the pcap file.
			err = pcapWriterSend.WritePacket(packet.Metadata().CaptureInfo, packet.Data())
			if err != nil {
				Error.Fatal(err)
			}
		}
		// Check for any error
		if err != nil {
			Error.Fatalln(err.Error())
		}

		// Increment Counter to get number of packets sent so far.
		packetCountSend++
		if packetCountSend%10 == 0 {
			Info.Printf("%d packets sent. (%.2f %%)\n", packetCountSend, float64(packetCountSend)*100.0/float64(*numPacketsToFuzz))
		}

		// Insert a pause interval between to packets
		time.Sleep(time.Duration(*packetSendInterval) * time.Millisecond)
	}

	Info.Println("Waiting 2 seconds to looking for ICMP unreachable packets...")
	time.Sleep(2 * time.Second)

	// End the goroutine for checking for crashes.
	quitCheckCrash <- true

	Info.Printf("All %d packets sent without crash.\n", packetCountSend)
	Log.Printf("All %d packets sent without crash.\n", packetCountSend)
	fuzzingRoundDone <- true
}
