package main

// package layers

// import (
// 	"encoding/binary"

// 	"github.com/google/gopacket"
// )

// //====================================================================
// //
// // Instructions:
// // Uncomment the whole code and move the this file to the
// // gopacket/layers package. Then define the protocol structure with
// // all the fields in the section below, between the "Start of
// // implementing..." and "Stop of implementing..." section. Also
// // implement the SerializeTo() and DecodeFromBytes() functions.
// // The rest should normally be unchanged, but read the comments.
// //
// //====================================================================
// // Start of implementing layer specifc functions

// // Define custom types for the protocol fields of the shim layer. This allows you
// // to fuzz the fields with individual random values or define specific fuzzing
// // functions for each field.
// // Name the fields in capital letter, because otherwise they aren't public and
// // can't be fuzzed.
// // Examples:

// type MyBoolProtocolFieldType bool

// type MyUInt32ProtocolFieldType uint32

// type MyByteSliceProtocolFieldType []byte

// type MyByteProtocolFieldType byte

// // ShimLayer defines the structure of the custom network layer.
// // The layer is a struct of structs in a specific and mandatory structure.
// // Each protocol field gets its own struct with the subfields "MinLen, MaxLen, Value, FuzzIt".
// // "MinLen and MaxLen" defines the minimal length of the field in bytes. It is used for
// // maps or slices to fuzz them with random length.
// // To fix it to one length or for the other types, use 1 for MinLen and MaxLen.
// // The "Value" holds the real data. It can be fixed in packetStructure.go or it will be fuzzed,
// // according to the boolean value of "FuzzIt".
// // Fields depending on another field of the struct (like length) have to be placed at the end of the structure.
// // All fields have to be initialized in packetStructure.go.
// // The last two struct fields Payload and Contents are mandatory and used for decoding.
// // If you want to fuzz specific fields with custom functions, you can define custom field types in the ShimLayer (see above).
// // If you define your types, you have to add them in fuzzHelper.go in the getAddressFromReflect() function.
// type ShimLayer struct {
// 	BoolProtocolField struct {
// 		MinLen int
// 		MaxLen int
// 		Value  MyBoolProtocolFieldType
// 		FuzzIt bool
// 	}
// 	UInt32ProtocolField struct {
// 		MinLen int
// 		MaxLen int
// 		Value  MyUInt32ProtocolFieldType
// 		FuzzIt bool
// 	}
// 	ByteSliceProtocolField struct {
// 		MinLen int
// 		MaxLen int
// 		Value  MyByteSliceProtocolFieldType
// 		FuzzIt bool
// 	}
// 	ByteProtocolField struct {
// 		MinLen int
// 		MaxLen int
// 		Value  MyByteProtocolFieldType
// 		FuzzIt bool
// 	}
// 	// Payload is the set of bytes contained by (but not part of) this
// 	// Layer.  Again, to take Ethernet as an example, this would be the
// 	// set of bytes encapsulated by the Ethernet protocol.
// 	Payload struct {
// 		MinLen int
// 		MaxLen int
// 		Value  []byte
// 		FuzzIt bool
// 	}
// 	// Contents is the set of bytes that make up this layer.  IE: for an
// 	// Ethernet packet, this would be the set of bytes making up the
// 	// Ethernet frame.
// 	Contents struct {
// 		MinLen int
// 		MaxLen int
// 		Value  []byte
// 		FuzzIt bool
// 	}
// }

// // DecodeFromBytes analyses a byte slice and attempts to decode it as a ShimLayer
// // record of a packet. Thanks to Roman Muentener from ZHAW for this function.
// // You have to implement the decoding by getting the data from the byte slice and save it to the corresponding fields.
// // Use "l.<subfield>.Value = binary.BigEndian.UintXY(data[<startByte>:<endByte>])" for fields with Int values more than one byte.
// // Use "l.<subfield>.Value = data[<startByte>:<endByte>]" for byte fields of any length.
// func (l *ShimLayer) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {

// 	l.BoolProtocolField.Value = MyBoolProtocolFieldType(toBool(data[0]))
// 	l.UInt32ProtocolField.Value = MyUInt32ProtocolFieldType(binary.BigEndian.Uint32(data[1:]))
// 	l.ByteSliceProtocolField.Value = MyByteSliceProtocolFieldType(data[5:11])
// 	l.ByteProtocolField.Value = MyByteProtocolFieldType(data[11])

// 	return nil
// }

// // SerializeTo writes the serialized form of this layer into the
// // SerializationBuffer, implementing gopacket.SerializableLayer.
// // See the docs for gopacket.SerializableLayer for more info.
// // You have to implement the serialization of the fields to write them to bytes slice.
// func (l *ShimLayer) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {

// 	var bytes []byte
// 	var err error

// // Insert 12 bytes to get space for header
// 	bytes, err = b.PrependBytes(12)
// 	if err != nil {
// 		panic(err.Error())
// 	}

// 	// Write fields to buffer.
// 	bytes[0] = byte(boolToInt(bool(l.BoolProtocolField.Value)))
// 	binary.BigEndian.PutUint32(bytes[1:], uint32(l.UInt32ProtocolField.Value))
// 	copy(bytes[5:], l.ByteSliceProtocolField.Value)
// 	bytes[11] = byte(l.ByteProtocolField.Value)

// 	return nil
// }

// // End of change and implementing layer specific functions.
// //====================================================================
// // Normally, you can let the following functions unchanged.

// // ShimLayerType is  to register the layer type so we can use it.
// // The first argument is an ID. Use negative
// // or 2000+ for custom layers. It must be unique.
// // If ID isn't used otherwise, you can let this function unchanged.
// var ShimLayerType = gopacket.RegisterLayerType(
// 	2018,
// 	gopacket.LayerTypeMetadata{
// 		Name:    "ShimLayerType",
// 		Decoder: gopacket.DecodeFunc(decodeShimLayer),
// 	},
// )

// // LayerType is for implementing the interface and it returns our custom layer
// // You can let this method unchanged.
// func (l *ShimLayer) LayerType() gopacket.LayerType {
// 	return ShimLayerType
// }

// // LayerContents returns the information that our layer
// // provides. In this case it is a header layer so
// // we return the header information.
// // Normally, you can let this method unchanged.
// func (l *ShimLayer) LayerContents() []byte {
// 	return l.Contents.Value
// }

// // LayerPayload is mandatory to implement the interface.
// // It returns the subsequent layer built
// // on top of our layer or raw payload as byte slice.
// // Normally, yu can let this method unchanged.
// func (l *ShimLayer) LayerPayload() []byte {
// 	return l.Payload.Value
// }

// // decodeShimLayer ist the custom decode function.
// // When the layer is registered we tell it to use this decode function.
// // Normally, you can let this function unchanged.
// func decodeShimLayer(data []byte, p gopacket.PacketBuilder) error {

// 	// Attempt to decode the byte slice.
// 	s := &ShimLayer{}
// 	err := s.DecodeFromBytes(data, p)
// 	if err != nil {
// 		return err
// 	}

// 	// AddLayer appends to the list of layers that the packet has
// 	p.AddLayer(s)

// 	// The return value tells the packet what layer to expect
// 	// with the rest of the data. It could be another header layer,
// 	// nothing, or a payload layer.

// 	// nil means this is the last layer. No more decoding
// 	// return nil

// 	// Returning another layer type tells it to decode
// 	// the next layer with that layer's decoder function
// 	// return p.NextDecoder(layers.LayerTypeEthernet)
// 	// return p.NextDecoder(layers.LayerTypeUDP)

// 	// Returning payload type means the rest of the data
// 	// is raw payload. It will set the application layer
// 	// contents with the payload
// 	return p.NextDecoder(gopacket.LayerTypePayload)
// }

// // boolToInt is a utility function for converting bool -> 0/1
// // during serialization/decoding
// func boolToInt(b bool) uint32 {
// 	if b {
// 		return 1
// 	}
// 	return 0
// }

// // toBool is a utility function for converting 0/1 -> bool
// // during serialization/decoding
// func toBool(v byte) bool {
// 	if v == 0 {
// 		return false
// 	}
// 	return true
// }
