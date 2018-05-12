package main

import (
	"bytes"
	"encoding/binary"
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
	"github.com/malfunkt/arpfox/arp"
	"github.com/malfunkt/iprange"
)

// FuzzMITM captures the original packets from the network interface,
// fuzzes them according to the fuzzing functions and sends them out the network interface.
// This mode allows to fuzz the protocol in a man-in-the-middle method between original endpoints.
func FuzzMITM(fuzzingRoundDone chan bool) {
	// snapshotLen specifies the maximum length of the packet to read.
	var snapshotLen int32 = 65535
	// promiscious unsets the promisious mode of the network interface.
	promiscious := false
	// timeout sets the interval, after that packets get send/read from the network interface to the application.
	// Use a negative value to immediately send or receive it.
	timeout := -1 * time.Second
	// err contains the error value, if one occurs.
	var err error
	// sendHandle is the reference to the pcap stream. It is used to write to the network interface.
	var sendHandle *pcap.Handle
	// crashHandle is the reference to the pcap stream. It is used to read from the network interface and listens for icmp packets.
	var crashHandle *pcap.Handle
	// recvHandle is the reference to the pcap stream. It is used to read packets from the interface in man-in-the-middle-mode.
	var recvHandle *pcap.Handle
	// buffer is the packet buffer, which holds the raw bytes for sending them to the network interface.
	var buffer gopacket.SerializeBuffer
	// options for the packet sending. Because of replay, we don't have to fix length or calculate checksums.
	var options gopacket.SerializeOptions
	// packetCountSend is a counter for the packets sent.
	var packetCountSend int

	// Initialize the random generator with the given seed.
	// Without this, each fuzzer of the same type gets the same value.
	randSource := rand.NewSource(*fuzzerSeed)
	randFuzzGen := rand.New(randSource)

	WriteFuzzMITMLogHeader()

	Info.Println("Start of fuzzing packets with a man-in-the-middle attack of original source", *srcIP)

	// Get the local MAC address of the own interface for later use in BPF filter.
	localMACAddr := localMACAddress(*device)

	// Open network device for sending packets
	sendHandle, err = pcap.OpenLive(*device, snapshotLen, promiscious, timeout)
	if err != nil {
		Error.Fatalln(err.Error())
	}
	defer sendHandle.Close()

	// Open network device for receiving packets for crash detection
	crashHandle, err = pcap.OpenLive(*device, snapshotLen, promiscious, timeout)
	if err != nil {
		Error.Fatalln(err.Error())
	}
	// Set Berkley Packet Filter to just search for ICMP unreachable packets with code "port unreachable"
	crashHandle.SetBPFFilter("src host " + *destIP + " and icmp[icmptype]==icmp-unreach and icmp[icmpcode]==3")
	defer crashHandle.Close()

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

	// Channel for communication with CheckCrash goroutine
	quitCheckCrash := make(chan bool)

	// Receive incomming packets and check for ICMP Port uncreachable
	go CheckCrash(crashHandle, &packetCountSend, nil, quitCheckCrash)

	// recvHandle is the handle for receiving the packets on the interface in man-in-the-middle mode.
	recvHandle, err = pcap.OpenLive(*device, snapshotLen, promiscious, timeout)
	if err != nil {
		Error.Fatal(err)
	}
	// Only read the packets of the specific protocol and direction from the interface. Consider the destination MAC address,
	// otherwise each packet sent in the man-in-the-middle mode is received again from this handle and process hangs in an infinite loop.
	recvHandle.SetBPFFilter("dst host " + *destIP + " and dst port " + strconv.Itoa(int(*targetPort)) + " and ether dst " + localMACAddr.String())
	defer recvHandle.Close()

	// Get the original destination IP and MAC addresses to set them later in the packet.
	origDestIP := net.ParseIP(*destIP)
	origDestMAC, err := arp.Lookup(binary.BigEndian.Uint32(origDestIP[12:16]))
	if err != nil {
		Error.Fatalf("Unable to lookup hw address for %s: %v", origDestIP, err)
	}

	packetSource := gopacket.NewPacketSource(recvHandle, recvHandle.LinkType())
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

		// Change destination MAC address of received packet to real destination MAC
		ethernetLayer.DstMAC = origDestMAC.HardwareAddr

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
			Info.Printf("%d packets sent.\n", packetCountSend)
		}

		// Insert a pause interval between to packets
		time.Sleep(time.Duration(*packetSendInterval) * time.Millisecond)
	}

	Info.Println("Waiting 2 seconds to looking for ICMP unreachable packets...")
	time.Sleep(2 * time.Second)

	// End the goroutine for checking for crashes.
	quitCheckCrash <- true

	Info.Printf("All %d packets replayed without crash.\n", packetCountSend)
	Log.Printf("All %d packets replayed without crash.\n", packetCountSend)
	fuzzingRoundDone <- true
}

// ARPPoison poisons the ARP cache of the original sender to act as a man-in-the-middle.
// Code comes from José Nieto, https://menteslibres.net/malfunkt
func ARPPoison() {

	// waitInterval is the timeout between to two broadcast packets.
	waitInterval := 0.1

	if *srcIP == "" {
		Error.Fatal("Missing target (-t 192.168.1.7).")
	}

	iface, err := net.InterfaceByName(*device)
	if err != nil {
		Error.Fatalf("Could not use interface %s: %v", *device, err)
	}

	handler, err := pcap.OpenLive(iface.Name, 65535, true, pcap.BlockForever)
	if err != nil {
		Error.Fatal(err)
	}
	defer handler.Close()

	var ifaceAddr *net.IPNet
	ifaceAddrs, err := iface.Addrs()
	if err != nil {
		Error.Fatal(err)
	}

	for _, addr := range ifaceAddrs {
		if ipnet, ok := addr.(*net.IPNet); ok {
			if ip4 := ipnet.IP.To4(); ip4 != nil {
				ifaceAddr = &net.IPNet{
					IP:   ip4,
					Mask: net.IPMask([]byte{0xff, 0xff, 0xff, 0xff}),
				}
				break
			}
		}
	}
	if ifaceAddr == nil {
		Error.Fatal("Could not get interface address.")
	}

	var targetAddrs []net.IP
	if *srcIP != "" {
		addrRange, err := iprange.ParseList(*srcIP)
		if err != nil {
			Error.Fatal("Wrong format for target.")
		}
		targetAddrs = addrRange.Expand()
		if len(targetAddrs) == 0 {
			Error.Fatalf("No valid targets given.")
		}
	}

	hostIP := net.ParseIP(*destIP)

	if hostIP == nil {
		Error.Fatalf("Wrong format for host IP.")
	}
	hostIP = hostIP.To4()

	stop := make(chan struct{}, 2)

	// Disabled in this code, because man-in-the-middle mode stops as soon as fuzzer stopps.
	// Waiting for ^C
	// c := make(chan os.Signal)
	// signal.Notify(c, os.Interrupt)
	// go func() {
	// 	for {
	// 		select {
	// 		case <-c:
	// 			log.Println("'stop' signal received; stopping...")
	// 			close(stop)
	// 			return
	// 		}
	// 	}
	// }()

	go readARP(handler, stop, iface)

	// Get original source
	origSrc, err := arp.Lookup(binary.BigEndian.Uint32(hostIP))
	if err != nil {
		Error.Fatalf("Unable to lookup hw address for %s: %v", hostIP, err)
	}

	fakeSrc := arp.Address{
		IP:           hostIP,
		HardwareAddr: iface.HardwareAddr,
	}

	<-writeARP(handler, stop, targetAddrs, &fakeSrc, time.Duration(waitInterval*1000.0)*time.Millisecond)

	<-cleanUpAndReARP(handler, targetAddrs, origSrc)

	os.Exit(0)
}

// Code comes from José Nieto, https://menteslibres.net/malfunkt
func cleanUpAndReARP(handler *pcap.Handle, targetAddrs []net.IP, src *arp.Address) chan struct{} {
	Info.Printf("Cleaning up and re-ARPing targets...")

	stopReARPing := make(chan struct{})
	go func() {
		t := time.NewTicker(time.Second * 5)
		<-t.C
		close(stopReARPing)
	}()

	return writeARP(handler, stopReARPing, targetAddrs, src, 500*time.Millisecond)
}

// Code comes from José Nieto, https://menteslibres.net/malfunkt
func writeARP(handler *pcap.Handle, stop chan struct{}, targetAddrs []net.IP, src *arp.Address, waitInterval time.Duration) chan struct{} {
	stoppedWriting := make(chan struct{})
	go func(stoppedWriting chan struct{}) {
		t := time.NewTicker(waitInterval)
		for {
			select {
			case <-stop:
				stoppedWriting <- struct{}{}
				return
			default:

				/*
				*  this is done to ensure there aren't
				*  two channels ready to receive at the same
				*  time, possibly ignoring the stop signal,
				*  but ensuring the loop is executed at least
				*  once, to guarantee proper reARPing
				 */

				<-t.C
				for _, ip := range targetAddrs {
					arpAddr, err := arp.Lookup(binary.BigEndian.Uint32(ip))
					if err != nil {
						Error.Printf("Could not retrieve %v's MAC address: %v", ip, err)
						continue
					}
					dst := &arp.Address{
						IP:           ip,
						HardwareAddr: arpAddr.HardwareAddr,
					}
					buf, err := arp.NewARPRequest(src, dst)
					if err != nil {
						Error.Print("NewARPRequest: ", err)
						continue
					}
					if err := handler.WritePacketData(buf); err != nil {
						Error.Print("WritePacketData: ", err)
					}
				}
			}
		}
	}(stoppedWriting)
	return stoppedWriting
}

// Code comes from José Nieto, https://menteslibres.net/malfunkt
func readARP(handle *pcap.Handle, stop chan struct{}, iface *net.Interface) {
	src := gopacket.NewPacketSource(handle, layers.LayerTypeEthernet)
	in := src.Packets()
	for {
		var packet gopacket.Packet
		select {
		case <-stop:
			return
		case packet = <-in:
			arpLayer := packet.Layer(layers.LayerTypeARP)
			if arpLayer == nil {
				continue
			}
			packet := arpLayer.(*layers.ARP)
			if !bytes.Equal([]byte(iface.HardwareAddr), packet.SourceHwAddress) {
				continue
			}
			if packet.Operation == layers.ARPReply {
				arp.Add(net.IP(packet.SourceProtAddress), net.HardwareAddr(packet.SourceHwAddress))
			}
			Info.Printf("ARP packet (%d): %v (%v) -> %v (%v)", packet.Operation, net.IP(packet.SourceProtAddress), net.HardwareAddr(packet.SourceHwAddress), net.IP(packet.DstProtAddress), net.HardwareAddr(packet.DstHwAddress))
		}
	}
}
