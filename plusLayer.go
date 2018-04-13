package main

// package layers

// import (
// 	"encoding/binary"

// 	"github.com/google/gopacket"
// )

// //====================================================================
// //
// // Instructions:
// // Uncomment the whole code and move this file to the
// // gopacket/layers package. This implements the PLUS shim layer.
// //
// // To get the decoding of PLUS packets to work, change the function
// // NextLayerType() in file udp.go in gopacket/layers package as follows:
// // func (u *UDP) NextLayerType() gopacket.LayerType {
// // 	// Check for magic of ShimLayer at fixed position
// // 	// and set the next layer according to that.
// //	if len(u.Payload) >= 4 {
// //	magic := binary.BigEndian.Uint32(u.Payload[0:4]) >> 4
// //	expected := uint32(0xd8007ff)
// //		if magic == expected {
// //			return ShimLayerType
// //		}
// //	}
// //	... rest of the function unchanged
// // }
// //
// //====================================================================

// // SFLAG is a custom SFLAG field for fuzzing it explicitly with a custom function
// type SFLAG bool

// // RFLAG is a custom RFLAG field for fuzzing it explicitly with a custom function
// type RFLAG bool

// // LFLAG is a custom LFLAG field for fuzzing it explicitly with a custom function
// type LFLAG bool

// // XFLAG is a custom XFLAG field for fuzzing it explicitly with a custom function
// type XFLAG bool

// // PCFLen is a custom PCFLen field for fuzzing it explicitly with a custom function
// type PCFLen int8

// // PCFIntegrity is a custom PCFIntegrity field for fuzzing it explicitly with a custom function
// type PCFIntegrity int8

// // PCFType is a custom PCFType field for fuzzing it explicitly with a custom function
// type PCFType int32

// // PCFValue is a custom PCFValue field for fuzzing it explicitly with a custom function
// type PCFValue []byte

// // PSN is a custom PSN field for fuzzing it explicitly with a custom function
// type PSN uint32

// // PSE is a custom PSE field for fuzzing it explicitly with a custom function
// type PSE uint32

// // CAT is a custom CAT field for fuzzing it explicitly with a custom function
// type CAT uint64

// // Magic is a custom Magic field for fuzzing it explicitly with a custom function
// type Magic uint32

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
// // If you want to fuzz specific fields with custom functions, you can define custom field types in the ShimLayer.
// // If you define your types, you have to add them in fuzzHelper.go in the getAddressFromReflect() function.
// type ShimLayer struct {
// 	SFlag struct {
// 		MinLen int
// 		MaxLen int
// 		Value  SFLAG
// 		FuzzIt bool
// 	}
// 	RFlag struct {
// 		MinLen int
// 		MaxLen int
// 		Value  RFLAG
// 		FuzzIt bool
// 	}
// 	LFlag struct {
// 		MinLen int
// 		MaxLen int
// 		Value  LFLAG
// 		FuzzIt bool
// 	}
// 	XFlag struct {
// 		MinLen int
// 		MaxLen int
// 		Value  XFLAG
// 		FuzzIt bool
// 	}
// 	CAT struct {
// 		MinLen int
// 		MaxLen int
// 		Value  CAT
// 		FuzzIt bool
// 	}
// 	PSN struct {
// 		MinLen int
// 		MaxLen int
// 		Value  PSN
// 		FuzzIt bool
// 	}
// 	PSE struct {
// 		MinLen int
// 		MaxLen int
// 		Value  PSE
// 		FuzzIt bool
// 	}
// 	PCFIntegrity struct {
// 		MinLen int
// 		MaxLen int
// 		Value  PCFIntegrity
// 		FuzzIt bool
// 	}
// 	PCFType struct {
// 		MinLen int
// 		MaxLen int
// 		Value  PCFType
// 		FuzzIt bool
// 	}
// 	PCFValue struct {
// 		MinLen int
// 		MaxLen int
// 		Value  PCFValue
// 		FuzzIt bool
// 	}
// 	Magic struct {
// 		MinLen int
// 		MaxLen int
// 		Value  Magic
// 		FuzzIt bool
// 	}
// 	PCFLen struct {
// 		MinLen int
// 		MaxLen int
// 		Value  PCFLen
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

// // ShimLayerType is  to register the layer type so we can use it.
// // The first argument is an ID. Use negative
// // or 2000+ for custom layers. It must be unique.
// var ShimLayerType = gopacket.RegisterLayerType(
// 	2018,
// 	gopacket.LayerTypeMetadata{
// 		Name:    "ShimLayerType",
// 		Decoder: gopacket.DecodeFunc(decodeShimLayer),
// 	},
// )

// // LayerType is for implementing the interface and it returns our custom layer
// // You can let it be as it is.
// func (l *ShimLayer) LayerType() gopacket.LayerType {
// 	return ShimLayerType
// }

// // LayerContents returns the information that our layer
// // provides. In this case it is a header layer so
// // we return the header information.
// // You will have to implement this function according to the protocol header.
// // You should fill the buffer with each protocol field in the right order.
// // Use the "binary.BigEndian.PutXY(buf, l.<subfield>.Value)" for fields larger one byte.
// // Use buf[z] = l.<subfield>.Value for one byte fields.
// // Use "copy(dst, src)" for multi byte slices.
// func (l *ShimLayer) LayerContents() []byte {
// 	return l.Contents.Value
// }

// // LayerPayload is mandatory to implement the interface.
// // It returns the subsequent layer built
// // on top of our layer or raw payload as byte slice.
// func (l *ShimLayer) LayerPayload() []byte {
// 	return l.Payload.Value
// }

// // decodeShimLayer ist the custom decode function.
// // When the layer is registered we tell it to use this decode function.
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

// // DecodeFromBytes analyses a byte slice and attempts to decode it as an ShimLayer
// // record of a packet. Thanks to Roman Muentener from ZHAW for this function.
// // You have to implement the decoding by getting the data from the byte slice and save it to the corresponding fields.
// // Use "l.<subfield>.Value = binary.BigEndian.UintXY(data[<startByte>:<endByte>])" for fields with Int values more than one byte.
// // Use "l.<subfield>.Value = data[<startByte>:<endByte>]" for byte fields of any length.
// func (l *ShimLayer) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {

// 	magicAndFlags := data[0:4]

// 	p := l

// 	p.Magic.Value = Magic(binary.BigEndian.Uint32(magicAndFlags) >> uint32(4))
// 	p.XFlag.Value = XFLAG(toBool(data[3] & 0x01))
// 	p.LFlag.Value = LFLAG(toBool((data[3] >> 3) & 0x01))
// 	p.RFlag.Value = RFLAG(toBool((data[3] >> 2) & 0x01))
// 	p.SFlag.Value = SFLAG(toBool((data[3] >> 1) & 0x01))

// 	p.CAT.Value = CAT(binary.BigEndian.Uint64(data[4:]))
// 	p.PSN.Value = PSN(binary.BigEndian.Uint32(data[12:]))
// 	p.PSE.Value = PSE(binary.BigEndian.Uint32(data[16:]))

// 	if !p.XFlag.Value {
// 		p.PCFIntegrity.Value = -1
// 		p.PCFLen.Value = -1
// 		p.PCFType.Value = -1
// 		p.PCFValue.Value = nil
// 		p.Payload.Value = data[20:]
// 		p.Contents.Value = data[:20]

// 		return nil
// 	} else {
// 		nindex := 20

// 		if data[nindex] == 0x00 {
// 			p.PCFType.Value = PCFType(uint16(data[nindex+1]) << uint16(8))
// 			nindex += 2
// 		} else {
// 			p.PCFType.Value = PCFType(data[nindex])
// 			nindex++
// 		}

// 		if p.PCFType.Value == 0xFF {
// 			p.PCFLen.Value = -1
// 			p.PCFType.Value = -1
// 			p.PCFValue.Value = nil
// 			p.Contents.Value = data[:nindex]
// 			return nil
// 		}

// 		pcfLenI := data[nindex]

// 		p.PCFLen.Value = PCFLen(uint8(pcfLenI) >> uint8(2))
// 		p.PCFIntegrity.Value = PCFIntegrity(pcfLenI & 0x03)

// 		nindex++

// 		p.PCFValue.Value = data[nindex : nindex+int(p.PCFLen.Value)]
// 		p.Payload.Value = data[nindex+int(p.PCFLen.Value):]

// 		nindex += int(p.PCFLen.Value)

// 		p.Contents.Value = data[:nindex]

// 		return nil
// 	}
// }

// // SerializeTo writes the serialized form of this layer into the
// // SerializationBuffer, implementing gopacket.SerializableLayer.
// // See the docs for gopacket.SerializableLayer for more info.
// // You have to implement the serialization of the fields to write them to bytes slice.
// func (l *ShimLayer) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {

// 	var bytes []byte
// 	var err error
// 	var lengthAndIntegrity int8

// 	if l.XFlag.Value {
// 		//Extended Header
// 		bytes, err = b.PrependBytes(22 + len(l.PCFValue.Value))
// 		// Generate length and integrity field, because they are 1 byte together.
// 		lengthAndIntegrity = int8(l.PCFLen.Value)<<2 | int8(l.PCFIntegrity.Value)
// 	} else {
// 		// Basic Header
// 		bytes, err = b.PrependBytes(20)
// 	}
// 	if err != nil {
// 		return err
// 	}

// 	// Generate magic and flags in one uint32 value, because magic and flags share 4 bytes. We get the magic and shift it 4 bits to add the flags by shifting them
// 	// in the correct order.
// 	magicAndFlags := ((((uint32(l.Magic.Value) << 4) | (boolToInt(bool(l.LFlag.Value)) << 3)) | (boolToInt(bool(l.RFlag.Value)) << 2)) | (boolToInt(bool(l.SFlag.Value)) << 1)) | boolToInt(bool(l.XFlag.Value))
// 	// fmt.Println("Magic: ", p.Magic<<4)
// 	// fmt.Println("LFlag: ", boolToInt(p.LFlag)<<3)
// 	// fmt.Println("RFlag: ", boolToInt(p.RFlag)<<2)
// 	// fmt.Println("SFlag: ", boolToInt(p.SFlag)<<1)
// 	// fmt.Println("XFlag: ", boolToInt(p.XFlag))
// 	// fmt.Println(magicAndFlags)
// 	binary.BigEndian.PutUint32(bytes, uint32(magicAndFlags))
// 	binary.BigEndian.PutUint64(bytes[4:], uint64(l.CAT.Value))
// 	binary.BigEndian.PutUint32(bytes[12:], uint32(l.PSN.Value))
// 	binary.BigEndian.PutUint32(bytes[16:], uint32(l.PSE.Value))

// 	// Write fields of extended Header only if XFlag is set.
// 	if l.XFlag.Value {
// 		bytes[20] = uint8(l.PCFType.Value)
// 		bytes[21] = uint8(lengthAndIntegrity)
// 		copy(bytes[22:], l.PCFValue.Value)
// 	}

// 	return nil
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
