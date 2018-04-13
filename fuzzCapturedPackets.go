package main

import (
	"log"
	"math/rand"
	"reflect"
	"strconv"
	"time"

	fuzz "github.com/google/gofuzz"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

// FuzzCapturedPackets takes an existing pcap packet capture and replays and optionally fuzzes the containing packets.
// The packet capture can contain other packets, because a filter is set to only take the needed packets to interesting port and target ip.
// Therefore it decodes the packets of the ShimLayer and fuzz it with the fuzz functions defined in fuzzFunctions.go.
func FuzzCapturedPackets(fuzzingRoundDone chan bool) {
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
	// buffer is the packet buffer, which holds the raw bytes for sending them to the network interface.
	var buffer gopacket.SerializeBuffer
	// options for the packet sending. Because of replay, we don't have to fix length or calculate checksums.
	var options gopacket.SerializeOptions
	// packetCountSend is a counter for the packets sent.
	var packetCountSend int
	// replayFilenames is a slice which holds the filenames to replay.
	var replayFilenames []string

	// Initialize the random generator with the given seed.
	// Without this, each fuzzer of the same type gets the same value.
	randSource := rand.NewSource(*fuzzerSeed)
	randFuzzGen := rand.New(randSource)

	WriteFuzzReplayLogHeader()

	Info.Println("Start of fuzzing packets from pcap file", *pcapPathFuzz)

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

	// Set options to compute the checksums and length of the headers correct
	options.ComputeChecksums = true
	options.FixLengths = true

	// Initialize the ShimLayer
	InitEmptyPacketStructure()
	InitShimLayer()

	// Create fuzzer for payload (application data), if fuzzing of payload is required
	var payloadFuzzer *fuzz.Fuzzer
	if *fuzzPayload {
		randSeed := randFuzzGen.Int63n(4294967296) // Get a random number to seed the fuzzer
		payloadFuzzer = fuzz.New().NilChance(0).NumElements(*minPayloadLen, *maxPayloadLen).RandSource(rand.NewSource(randSeed)).Funcs(fuzzFuncs...)
	}

	// layerValReflect represents the layer by dynamically examining the fields via reflection
	layerValReflect := reflect.ValueOf(shimLayer).Elem()

	// Log the protocol structure and their fuzzing parameters.
	PrettyPrintProtocolStructure(shimLayer)

	// fuzzers contains a pointer to the fuzzing function for each field of the protocol
	var fuzzers []*fuzz.Fuzzer
	// Go through the protocol structure and get the min an max value for the fuzzer.
	// Add the fuzzer for each protocol field to the struct, for later fuzzing.
	// The last two fields Contents and Payload aren't necessary and therefore,
	// minus 2 at the fields is used
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
	go CheckCrash(recvHandle, &packetCountSend, nil, quitCheckCrash)

	replayFilenames, err = ReplayFilenames(*pcapPathFuzz)
	if err != nil {
		Error.Fatal(err)
	}
	Log.Println("Files for replay and fuzz:", replayFilenames)

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

	// Loop through all the files for replay
	for i := 0; i < len(replayFilenames); i++ {

		// fileHandle is the handle to the pcap file with the saved packets.
		fileHandle, err = pcap.OpenOffline(replayFilenames[i])
		if err != nil {
			log.Fatal(err)
		}
		// Only read the packets of the specific protocol and direction from the file.
		fileHandle.SetBPFFilter("dst host " + *destIP + " and dst port " + strconv.Itoa(int(*targetPort)))
		defer fileHandle.Close()

		Info.Println("Replay and fuzz packets from", replayFilenames[i])
		Log.Println("Replay and fuzz packets packets from", replayFilenames[i])

		packetSource := gopacket.NewPacketSource(fileHandle, fileHandle.LinkType())
		// Loop through packets in file
		for packet := range packetSource.Packets() {

			// Decode the packet, which fills the different layers.
			DecodePacket(packet, &layerValReflect)

			// Initialize packet buffer to send it out the wire
			buffer = gopacket.NewSerializeBuffer()

			// layerStack holds the stack of the layers, how a packet should be constructed
			var layerStack []gopacket.SerializableLayer

			// Fuzz struct fields (when enabled) with access via reflection to protocol layer and slice of fuzzers
			if *fuzzFields {
				for j := 0; j < len(fuzzers); j++ {
					// Check, if field should be fuzzed, otherwise you
					// can set it manually in packetStructure.go or it will use the "zero" value
					if layerValReflect.Field(j).FieldByName("FuzzIt").Bool() {
						// fmt.Printf("Address of shimlayer: %p\n", &shimLayer.PSN.Value) // Check address for specific Value
						// fmt.Printf("Address of reflect to shim: %p\n", getAddressFromReflect(layerValReflect.Field(j).FieldByName("Value"))) // Check address via reflection
						if *verbose {
							Info.Println("Value of", layerValReflect.Type().Field(j).Name, "before fuzzing:", layerValReflect.Field(j).FieldByName("Value").Interface())
						}
						// addressToField is the address to the specific type given to the function
						addressToField := getAddressFromReflect(layerValReflect.Field(j).FieldByName("Value"))
						if addressToField != nil {
							fuzzers[j].Fuzz(addressToField)
						} else {
							Error.Fatal("Address to the struct field can't be resolved. Probably you haven't added the type for the field ", layerValReflect.Type().Field(j).Name, " to the function getAddressFromReflect().")
						}
						if *verbose {
							Info.Println("Value of", layerValReflect.Type().Field(j).Name, "after fuzzing:", layerValReflect.Field(j).FieldByName("Value").Interface())
						}
					}
				}
			}

			// Print values of the shimlayer to check them after fuzzing
			// for i := 0; i < layerValReflect.NumField()-2; i++ {
			// 	fmt.Println(i, ":", layerValReflect.Field(i).FieldByName("Value").Interface())
			// }

			// Fuzz the payload, if set to true in "FuzzIt" of packetStructure.go
			if *fuzzPayload {
				payloadFuzzer.Fuzz(&payload)
			}

			// Print Shimlayer data
			if *verbose {
				Info.Printf("Shimlayer after fuzzing:\n%+v\n\n", shimLayer)
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
