package main

import (
	"math/rand"
	"net"
	"reflect"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// Layer of the packet.
// To add additional layers, add them here and set the default
// values in the InitBasePacketStructure and InitShimLayer method.
var (
	ethernetLayer *layers.Ethernet
	ipLayer       *layers.IPv4
	udpLayer      *layers.UDP
	shimLayer     *layers.ShimLayer
	payload       *layers.Payload
)

// InitEmptyPacketStructure initializes an empty packet structure with the layers needed.
// For other layers change them here.
func InitEmptyPacketStructure() {
	// Create empty ethernet layer.
	ethernetLayer = &layers.Ethernet{}

	// Create empty IP layer.
	ipLayer = &layers.IPv4{}

	// Create empty UDP layer.
	udpLayer = &layers.UDP{}

	// Define the layer, which has to be considered for checksum calculation on transport layer
	err := udpLayer.SetNetworkLayerForChecksum(ipLayer)
	if err != nil {
		Error.Fatal(err)
	}
}

// InitBasePacketStructure initializes the packet structure and their layers of the base packet
// without the shimlayer.
// The initial values for the fields are set and prepared for fuzzing.
// To add additional layers, you have to insert them here and add the layer
// on top of this file.
func InitBasePacketStructure(targetIP net.IP, localIP net.IP, targetMACAddr net.HardwareAddr, localMACAddr net.HardwareAddr, targetPort uint, localPort uint) {

	// Initialize a random generator. It is used in the IP header,
	// because some applications doesn't accept packets without random ID field.

	seedSource := rand.NewSource(time.Now().UnixNano())
	randomGenerator := rand.New(seedSource)

	// Create ethernet header and set the target and source MAC address.
	ethernetLayer = &layers.Ethernet{
		DstMAC:       targetMACAddr, // Remote System
		SrcMAC:       localMACAddr,  // Local System
		EthernetType: layers.EthernetTypeIPv4,
	}

	// Create IP header and set the default values.
	// Most important are the destination and source addresses.
	ipLayer = &layers.IPv4{
		DstIP:      targetIP, // Remote System
		SrcIP:      localIP,  // Local System
		Version:    4,
		IHL:        5,
		Protocol:   layers.IPProtocolUDP,
		TTL:        64,
		Id:         uint16(randomGenerator.Intn(65535)),
		FragOffset: 0,
		TOS:        0,
		Flags:      layers.IPv4DontFragment,
	}

	// Create UDP header and set the default values.
	udpLayer = &layers.UDP{
		DstPort: layers.UDPPort(targetPort),
		SrcPort: layers.UDPPort(localPort),
	}

	// Define the layer, which has to be considered for checksum calculation on transport layer
	err := udpLayer.SetNetworkLayerForChecksum(ipLayer)
	if err != nil {
		Error.Fatal(err)
	}

}

// InitShimLayer initializes the shimlayer and sets the metadata for the single fields.
// Here, you define the values of each field and set if the field should be fuzzed or not.
func InitShimLayer() {

	// Create the shimLayer
	shimLayer = new(layers.ShimLayer)

	// Setting the metadata of the Shimlayer. Here we can set the min an max length of each field.
	// You can also set a fixed value for the "Value" struct field and define, if it should be fuzzed.
	// The MinLen and MaxLen fields could be set to fuzz slices or maps with different lengths.
	// The length is then choosen random for each packet.
	// For single values you should set the MinLen and MaxLen to 1.

	// plusLayer implementation
	// Change to your needs
	shimLayer.CAT.MinLen = 1
	shimLayer.CAT.MaxLen = 1
	shimLayer.CAT.FuzzIt = false
	shimLayer.CAT.Value = 1986
	shimLayer.Magic.MinLen = 1
	shimLayer.Magic.MaxLen = 1
	shimLayer.Magic.Value = 0xd8007ff // == 226494463 (decimal)
	shimLayer.LFlag.MinLen = 1
	shimLayer.LFlag.MaxLen = 1
	shimLayer.LFlag.FuzzIt = true
	shimLayer.RFlag.MinLen = 1
	shimLayer.RFlag.MaxLen = 1
	shimLayer.RFlag.FuzzIt = true
	shimLayer.SFlag.MinLen = 1
	shimLayer.SFlag.MaxLen = 1
	shimLayer.SFlag.FuzzIt = true
	shimLayer.XFlag.MinLen = 1
	shimLayer.XFlag.MaxLen = 1
	shimLayer.XFlag.FuzzIt = false
	shimLayer.PSE.MinLen = 1
	shimLayer.PSE.MaxLen = 1
	shimLayer.PSE.FuzzIt = true
	shimLayer.PSN.MinLen = 1
	shimLayer.PSN.MaxLen = 1
	shimLayer.PSN.FuzzIt = true
	shimLayer.PCFType.MinLen = 1
	shimLayer.PCFType.MaxLen = 1
	shimLayer.PCFType.FuzzIt = true
	shimLayer.PCFIntegrity.MinLen = 1
	shimLayer.PCFIntegrity.MaxLen = 1
	shimLayer.PCFIntegrity.FuzzIt = true
	shimLayer.PCFValue.MinLen = 0
	shimLayer.PCFValue.MaxLen = 63
	shimLayer.PCFValue.FuzzIt = true
	shimLayer.PCFLen.MinLen = 1
	shimLayer.PCFLen.MaxLen = 1
	shimLayer.PCFLen.FuzzIt = true

	// Setting the application data as byte slice.
	// You can set it to a fixed value or define it to be fuzzed with the command line arguments.
	payload = &layers.Payload{0x7a, 0x68, 0x61, 0x77, 0x2d, 0x70, 0x6c, 0x75, 0x7a, 0x7a, 0x20, 0x74, 0x6f, 0x20, 0x66, 0x75, 0x7a, 0x7a, 0x20, 0x61, 0x20, 0x73, 0x68, 0x69, 0x6d, 0x20, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x63, 0x6f, 0x6c, 0x2d, 0x7a, 0x68, 0x61, 0x77}
}

// getLayerStack returns the stack of the network packet.
// You can define the stack with one layer after another.
// The packet is built from top to down. Adapt the order
// of the layers for your needs.
func getLayerStack() []gopacket.SerializableLayer {

	// layerStack sets the layer stack for creating a packet.
	var layerStack = []gopacket.SerializableLayer{
		ethernetLayer,
		ipLayer,
		udpLayer,
		shimLayer,
		gopacket.Payload(*payload),
	}

	return layerStack
}

// DecodePacket decodes the packet in its different layers.
// Change the function to your needs and the layers in the interesting packets.
// Use the layers from the global variables on top of this file.
// No auto resolving of the including layers possible at the moment,
// because of the needed type assertion for the layer.
func DecodePacket(packet gopacket.Packet, layerValReflect *reflect.Value) {

	// Add every layer here and save the packet data of
	// the layer to the corresponding layer as global variable,
	// found on top of this file.
	ethernet := packet.Layer(layers.LayerTypeEthernet)
	if ethernet != nil {
		ethernetLayer, _ = ethernet.(*layers.Ethernet)
	}

	ip := packet.Layer(layers.LayerTypeIPv4)
	if ip != nil {
		ipLayer, _ = ip.(*layers.IPv4)
	}

	udp := packet.Layer(layers.LayerTypeUDP)
	if udp != nil {
		udpLayer, _ = udp.(*layers.UDP)
	}

	// shimLayerDecoded is a helper variable to store the decoded data.
	// If we decode the data direct to the shimLayer, we loose the metadata of the structure.
	var shimLayerDecoded *layers.ShimLayer
	// shimLayerDecodedReflect is a helper variable for the shimlayer.
	// It gets the data from the shimLayerDecoded by reflection. This is used to make the code
	// more generalized for changes at the ShimLayer.
	var shimLayerDecodedReflect reflect.Value
	// shim is the Shimlayer of the received packet.
	shim := packet.Layer(layers.ShimLayerType)
	if shim != nil {
		// Get the data from the packet and decode it to the shimLayerDecoded.
		// If we use here the original shimLayer, we loose the metadata such as MinLen, MaxLen and FuzzIt.
		shimLayerDecoded, _ = shim.(*layers.ShimLayer)
		shimLayerDecodedReflect = reflect.ValueOf(shimLayerDecoded).Elem()
		// Loop through the reflect variable of the decoded shimLayer (shimLayerDecoded)
		// and set the values of the original shimlayer (layerValReflect) with the values from the decoded shimLayer
		// (shimLayerDecodedReflect)
		for i := 0; i < layerValReflect.NumField()-2; i++ {
			// fmt.Println(i, ":", shimLayerDecodedReflect.Field(i).FieldByName("Value").Interface()) // Print values of the decoded shimlayer
			layerValReflect.Field(i).FieldByName("Value").Set(shimLayerDecodedReflect.Field(i).FieldByName("Value"))
		}
	}

	applicationLayer := packet.ApplicationLayer()
	if applicationLayer != nil {
		*payload = applicationLayer.Payload()
	}

	// Check for errors
	if err := packet.ErrorLayer(); err != nil {
		Error.Fatal("Error decoding some part of the packet:", err)
	}

	// Define the layer, which has to be considered for checksum calculation on transport layer
	// Needed, because the decoding function creates new ethernetLayer, udpLayer and ipLayer.
	err := udpLayer.SetNetworkLayerForChecksum(ipLayer)
	if err != nil {
		Error.Fatal(err)
	}

	// Print layer content for testing
	if *verbose {
		Info.Printf("\nEthernet layer: %+v\n\n", ethernetLayer)
		Info.Printf("\nIP layer: %+v\n\n", ipLayer)
		Info.Printf("\nUDP layer: %+v\n\n", udpLayer)
		Info.Printf("\nShimLayer after decode: %+v\n\n", shimLayer)
	}

}
