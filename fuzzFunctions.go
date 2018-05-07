package main

import (
	"bytes"
	"crypto/md5"
	"encoding/binary"
	"math/rand"
	"net"
	"time"

	fuzz "github.com/google/gofuzz"
	"github.com/google/gopacket/layers"
)

// FuzzHardwareAddrValidFix sets the MAC address to a static value
func FuzzHardwareAddrValidFix(i *net.HardwareAddr, c fuzz.Continue) {
	*i = net.HardwareAddr{0xcc, 0xaa, 0xff, 0xff, 0xee, 0xee}
}

// FuzzIPAddrValidRandom fuzzes a net.IP type with a syntactically correct address
func FuzzIPAddrValidRandom(i *net.IP, c fuzz.Continue) {
	*i = net.IP{byte(rand.Intn(256)), byte(rand.Intn(256)), byte(rand.Intn(256)), byte(rand.Intn(256))}
}

// FuzzPCFLenValid sets the length of the PCFValue field to a valid value
// by calculating the length from the PCFLen field.
func FuzzPCFLenValid(i *layers.PCFLen, c fuzz.Continue) {
	*i = layers.PCFLen(len(shimLayer.PCFValue.Value))
}

// FuzzPCFIntegrityValidRandom fuzzes the integrity value random from 0x00 to 0x03
func FuzzPCFIntegrityValidRandom(i *layers.PCFIntegrity, c fuzz.Continue) {
	*i = layers.PCFIntegrity(rand.Intn(4))
}

type varPSNValidThirdRandomNumber struct {
	fuzzPSNPacketCounter int
}

// PSNValidThirdRandomNumber holds the variables for the fuzzing function.
var PSNValidThirdRandomNumber varPSNValidThirdRandomNumber

// FuzzPSNValidThirdRandom fuzzes the PSN value so, that every third packet gets a random PSN.
func FuzzPSNValidThirdRandom(i *layers.PSN, c fuzz.Continue) {
	if PSNValidThirdRandomNumber.fuzzPSNPacketCounter%3 == 0 {
		*i = layers.PSN(rand.Int31n(4200000))
	}
	PSNValidThirdRandomNumber.fuzzPSNPacketCounter++
}

type varPSNValidThirdEarlierNumber struct {
	nextPSN              layers.PSN
	everyThirdPSN        layers.PSN
	fuzzPSNPacketCounter int
}

// PSNValidThirdEarlierNumber holds the variables for the fuzzing function.
var PSNValidThirdEarlierNumber varPSNValidThirdEarlierNumber

// FuzzPSNValidThirdEarlierNumber fuzzes the PSN value so, that every third packet gets the same value as an earlier packet.
func FuzzPSNValidThirdEarlierNumber(i *layers.PSN, c fuzz.Continue) {
	PSNValidThirdEarlierNumber.nextPSN = shimLayer.PSN.Value
	*i = PSNValidThirdEarlierNumber.nextPSN
	if PSNValidThirdEarlierNumber.fuzzPSNPacketCounter%3 == 0 {
		*i = PSNValidThirdEarlierNumber.everyThirdPSN
		PSNValidThirdEarlierNumber.everyThirdPSN = PSNValidThirdEarlierNumber.nextPSN
	}
	PSNValidThirdEarlierNumber.fuzzPSNPacketCounter++
}

type varPSNInvalidRepeatNumber struct {
	nextPSN              layers.PSN
	repeatPSN            layers.PSN
	fuzzPSNPacketCounter int
}

// PSNInvalidRepeatNumber holds the variables for the fuzzing function.
var PSNInvalidRepeatNumber varPSNInvalidRepeatNumber

// FuzzPSNInvalidRepeatNumber fuzzes the PSN value so, that every fifth packet gets the same value as the packet before.
func FuzzPSNInvalidRepeatNumber(i *layers.PSN, c fuzz.Continue) {
	if PSNInvalidRepeatNumber.fuzzPSNPacketCounter%5 != 0 {
		// Let the last value be stored every fifth packet, so we can set it a second time
		PSNInvalidRepeatNumber.repeatPSN = shimLayer.PSN.Value
	}
	PSNInvalidRepeatNumber.nextPSN = PSNInvalidRepeatNumber.repeatPSN
	*i = PSNInvalidRepeatNumber.nextPSN
	PSNInvalidRepeatNumber.fuzzPSNPacketCounter++
}

type varPSNValidUpcounting struct {
	nextPSN              layers.PSN
	fuzzPSNPacketCounter int
	randSource           rand.Source
	randGen              *rand.Rand
}

// PSNValidUpcounting holds the variables for the fuzzing function.
var PSNValidUpcounting varPSNValidUpcounting

// FuzzPSNValidUpcounting starts with a random PSN and increments it by one for every packet.
func FuzzPSNValidUpcounting(i *layers.PSN, c fuzz.Continue) {
	if PSNValidUpcounting.fuzzPSNPacketCounter == 0 {
		PSNValidUpcounting.randSource = rand.NewSource(time.Now().UnixNano())
		PSNValidUpcounting.randGen = rand.New(PSNValidUpcounting.randSource)
		PSNValidUpcounting.nextPSN = layers.PSN(PSNValidUpcounting.randGen.Int31n(420000000))
	}
	// Wrap around at the maximum uint32 value
	if PSNValidUpcounting.nextPSN < 0xFFFFFFFF {
		PSNValidUpcounting.nextPSN++
	} else {
		PSNValidUpcounting.nextPSN = 1
	}
	*i = PSNValidUpcounting.nextPSN
	PSNValidUpcounting.fuzzPSNPacketCounter++
}

type varPSNInvalidUpcounting struct {
	nextPSN              layers.PSN
	fuzzPSNPacketCounter int
	randSource           rand.Source
	randGen              *rand.Rand
}

// PSNInvalidUpcounting holds the variables for the fuzzing function.
var PSNInvalidUpcounting varPSNInvalidUpcounting

// FuzzPSNInvalidUpcounting starts with a random PSN and increments it by one for every packet.
// It wraps around, but sends a packet with PSN 0, which isn't allowed.
func FuzzPSNInvalidUpcounting(i *layers.PSN, c fuzz.Continue) {
	if PSNInvalidUpcounting.fuzzPSNPacketCounter == 0 {
		PSNInvalidUpcounting.randSource = rand.NewSource(time.Now().UnixNano())
		PSNInvalidUpcounting.randGen = rand.New(PSNInvalidUpcounting.randSource)
		PSNInvalidUpcounting.nextPSN = layers.PSN(PSNInvalidUpcounting.randGen.Int31n(420000000))
	}
	// Wrap around at the maximum value
	if PSNInvalidUpcounting.nextPSN < 0xFFFFFFFF {
		PSNInvalidUpcounting.nextPSN++
	} else {
		// By specification a PSN with value 0 isn't allowed.
		PSNInvalidUpcounting.nextPSN = 0
	}
	*i = PSNInvalidUpcounting.nextPSN
	PSNInvalidUpcounting.fuzzPSNPacketCounter++
}

type varPSNInvalidZero struct {
	nextPSN              layers.PSN
	fuzzPSNPacketCounter int
	randSource           rand.Source
	randGen              *rand.Rand
}

// PSNInvalidZero holds the variables for the fuzzing function.
var PSNInvalidZero varPSNInvalidZero

// FuzzPSNInvalidZero starts with a random PSN and increments it by one for every packet.
// It inserts a zero value for PSN every tenth packet.
func FuzzPSNInvalidZero(i *layers.PSN, c fuzz.Continue) {
	if PSNInvalidZero.fuzzPSNPacketCounter == 0 {
		PSNInvalidZero.randSource = rand.NewSource(time.Now().UnixNano())
		PSNInvalidZero.randGen = rand.New(PSNInvalidZero.randSource)
		PSNInvalidZero.nextPSN = layers.PSN(PSNInvalidZero.randGen.Int31n(420000000))
	}
	// Wrap around at the maximum value
	if PSNInvalidZero.nextPSN < 0xFFFFFFFF {
		PSNInvalidZero.nextPSN++
	} else {
		// By specification a PSN with value 0 isn't allowed.
		PSNInvalidZero.nextPSN = 1
	}

	if PSNInvalidZero.fuzzPSNPacketCounter%10 == 0 && PSNInvalidZero.fuzzPSNPacketCounter != 0 {
		*i = 0
	} else {
		*i = PSNInvalidZero.nextPSN
	}
	PSNInvalidZero.fuzzPSNPacketCounter++
}

type varPSNInvalidDowncounting struct {
	nextPSN              layers.PSN
	fuzzPSNPacketCounter int
	randSource           rand.Source
	randGen              *rand.Rand
}

// PSNInvalidDowncounting holds the variables for the fuzzing function.
var PSNInvalidDowncounting varPSNInvalidDowncounting

// FuzzPSNInvalidDowncounting starts with a random PSN and decrements it by one for every packet.
// It wraps around.
func FuzzPSNInvalidDowncounting(i *layers.PSN, c fuzz.Continue) {
	if PSNInvalidDowncounting.fuzzPSNPacketCounter == 0 {
		PSNInvalidDowncounting.randSource = rand.NewSource(time.Now().UnixNano())
		PSNInvalidDowncounting.randGen = rand.New(PSNInvalidDowncounting.randSource)
		PSNInvalidDowncounting.nextPSN = layers.PSN(PSNInvalidDowncounting.randGen.Int31n(420000000))
	}
	// Wrap around at the minimum value
	if PSNInvalidDowncounting.nextPSN > 0 {
		PSNInvalidDowncounting.nextPSN--
	} else {
		PSNInvalidDowncounting.nextPSN = 0xFFFFFFFF
	}
	*i = PSNInvalidDowncounting.nextPSN
	PSNInvalidDowncounting.fuzzPSNPacketCounter++
}

type varPSEValidUpcounting struct {
	nextPSE              layers.PSE
	fuzzPSEPacketCounter int
	randSource           rand.Source
	randGen              *rand.Rand
}

// PSEValidUpcounting holds the variables for the fuzzing function.
var PSEValidUpcounting varPSEValidUpcounting

// FuzzPSEValidUpcounting starts with a random PSN and increments it by one for every packet.
func FuzzPSEValidUpcounting(i *layers.PSE, c fuzz.Continue) {
	switch {
	case PSEValidUpcounting.fuzzPSEPacketCounter == 0:
		PSEValidUpcounting.randSource = rand.NewSource(time.Now().UnixNano())
		PSEValidUpcounting.randGen = rand.New(PSEValidUpcounting.randSource)
		PSEValidUpcounting.nextPSE = 0
	case PSEValidUpcounting.fuzzPSEPacketCounter == 1:
		PSEValidUpcounting.nextPSE = layers.PSE(PSEValidUpcounting.randGen.Int31n(420000000))
	default:
		// Wrap around at the maximum uint32 value
		if PSEValidUpcounting.nextPSE < 0xFFFFFFFF {
			PSEValidUpcounting.nextPSE++
		} else {
			PSEValidUpcounting.nextPSE = 1
		}

	}

	*i = PSEValidUpcounting.nextPSE
	PSEValidUpcounting.fuzzPSEPacketCounter++
}

type varPSEInvalidZero struct {
	nextPSE              layers.PSE
	fuzzPSEPacketCounter int
	randSource           rand.Source
	randGen              *rand.Rand
}

// PSEInvalidZero holds the variables for the fuzzing function.
var PSEInvalidZero varPSEInvalidZero

// FuzzPSEInvalidZero starts with a PSE of 0 and increments it by one for every packet.
// It wraps around. It sets the PSE to 0 every tenth packet.
func FuzzPSEInvalidZero(i *layers.PSE, c fuzz.Continue) {
	if PSEInvalidZero.fuzzPSEPacketCounter == 0 {
		PSEInvalidZero.randSource = rand.NewSource(time.Now().UnixNano())
		PSEInvalidZero.randGen = rand.New(PSEInvalidZero.randSource)
		PSEInvalidZero.nextPSE = layers.PSE(PSEInvalidZero.randGen.Int31n(420000000))
	}
	// Wrap around at the maximum value
	if PSEInvalidZero.nextPSE < 0xFFFFFFFF {
		PSEInvalidZero.nextPSE++
	} else {
		PSEInvalidZero.nextPSE = 0xFFFFFFFF
	}
	if PSEInvalidZero.fuzzPSEPacketCounter%10 == 0 && PSEInvalidZero.fuzzPSEPacketCounter != 0 {
		*i = 0
	} else {
		*i = PSEInvalidZero.nextPSE
	}
	PSEInvalidZero.fuzzPSEPacketCounter++
}

type varPCFValueInvalid struct {
	nextPCFValue              layers.PSE
	fuzzPCFValuePacketCounter int
	randSource                rand.Source
	randGen                   *rand.Rand
}

// PCFValueInvalid holds the variables for the fuzzing function.
var PCFValueInvalid varPCFValueInvalid

// FuzzPCFValueInvalid sets a random PCFValue and inserts an empty PCFValue every tenth packet.
func FuzzPCFValueInvalid(i *layers.PCFValue, c fuzz.Continue) {
	randByte := make([]byte, c.Int31n(64))
	c.Read(randByte)
	*i = randByte
	if PCFValueInvalid.fuzzPCFValuePacketCounter%10 == 0 {
		shimLayer.XFlag.Value = true
		*i = []byte{}
	}
	PCFValueInvalid.fuzzPCFValuePacketCounter++
}

type varPayloadRandomManual struct {
	nextPayload              layers.Payload
	fuzzPayloadPacketCounter int
}

// PayloadRandomManual holds the variables for the fuzzing function.
var PayloadRandomManual varPayloadRandomManual

// FuzzPayloadRandomManual sets a random Payload between -max-payload-len and -min-payload-len.
// Every 25th packet is set with another fix value, which you can add in this function.
func FuzzPayloadRandomManual(i *layers.Payload, c fuzz.Continue) {
	randByte := make([]byte, c.Intn(*maxPayloadLen-*minPayloadLen)+*minPayloadLen)
	c.Read(randByte)
	*i = randByte
	if PayloadRandomManual.fuzzPayloadPacketCounter != 0 && PayloadRandomManual.fuzzPayloadPacketCounter%25 == 0 {
		switch c.Intn(3) {
		case 0:
			shimLayer.XFlag.Value = false
			*i = []byte{0xcc, 0xa2, 0x85, 0x46, 0xbd, 0x3a, 0x89}
		case 1:
			shimLayer.XFlag.Value = false
			*i = []byte{0xbd, 0x3a, 0x89}
		case 2:
			shimLayer.XFlag.Value = false
			*i = []byte{}
		}
	}
	PayloadRandomManual.fuzzPayloadPacketCounter++
}

type varPayloadRandomSpecificFirstByte struct {
	nextPayload              layers.Payload
	fuzzPayloadPacketCounter int
}

// PayloadRandomSpecificFirstByte holds the variables for the fuzzing function.
var PayloadRandomSpecificFirstByte varPayloadRandomSpecificFirstByte

// FuzzPayloadRandomSpecificFirstByte sets a random Payload between -max-payload-len and -min-payload-len.
// Every 5th packet is set randomly with one of the interesting start bytes from the overlaying protocol.
func FuzzPayloadRandomSpecificFirstByte(i *layers.Payload, c fuzz.Continue) {
	randByte := make([]byte, c.Intn(*maxPayloadLen-*minPayloadLen)+*minPayloadLen)
	c.Read(randByte)
	*i = randByte
	if PayloadRandomSpecificFirstByte.fuzzPayloadPacketCounter != 0 && PayloadRandomSpecificFirstByte.fuzzPayloadPacketCounter%5 == 0 {
		if len(*i) != 0 {
			switch c.Intn(7) {
			case 0:
				(*i)[0] = 0xCC
			case 1:
				(*i)[0] = 0xAA
			case 2:
				(*i)[0] = 0xBB
			case 3:
				(*i)[0] = 0xFF
			case 4:
				(*i)[0] = 0x88
			case 5:
				(*i)[0] = 0x77
			case 6:
				(*i)[0] = 0x00
			}
		}
	}
	PayloadRandomSpecificFirstByte.fuzzPayloadPacketCounter++
}

type varPayloadRandomSpecificEncrypted struct {
	nextPayload              layers.Payload
	fuzzPayloadPacketCounter int
	cryptoKey                []byte
	cryptoSecret             []byte
}

// PayloadRandomSpecificEncrypted holds the variables for the fuzzing function.
var PayloadRandomSpecificEncrypted = varPayloadRandomSpecificEncrypted{
	cryptoKey:    []byte{0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF},
	cryptoSecret: []byte{0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF},
}

// FuzzvarPayloadRandomSpecificEncrypted sets a random Payload between -max-payload-len and -min-payload-len.
// Afterwards the payload gets encrypted and protected
func FuzzvarPayloadRandomSpecificEncrypted(i *layers.Payload, c fuzz.Continue) {
	// Generate random bytes
	randByte := make([]byte, c.Intn(*maxPayloadLen-*minPayloadLen)+*minPayloadLen)
	c.Read(randByte)
	*i = randByte
	// Set the first byte to a "It's a Packet" byte for the plus-debug protocol
	(*i)[0] = 0x00
	if *verbose {
		Info.Printf("Rand bytes before encryption: %x\n", *i)
	}
	// Get the Shim Header
	shimlayerHeader := SerializePLUSHeader()
	if *verbose {
		Info.Printf("ShimLayer header from Serialize function: %x\n", shimlayerHeader)
	}

	// Took the implementation for encryption and protection from plus-debug from Roman Muentener, ZHAW
	buf := make([]byte, (17 + len(shimlayerHeader) + len(*i))) // reserve 16 bytes for checksum + 1 byte for header len
	if *verbose {
		Info.Printf("buf: %x\n", buf)
	}

	bufStart := buf[17:]
	if *verbose {
		Info.Printf("bufStart: %x\n", bufStart)
	}

	buf[16] = byte(len(shimlayerHeader)) // 0-15 is for checksum/secret afterwards, 16 for header len
	_ = copy(bufStart, shimlayerHeader)
	if *verbose {
		Info.Printf("bufStart after Header Copy: %x\n", bufStart)
	}

	_ = copy(bufStart[len(shimlayerHeader):], *i)
	if *verbose {
		Info.Printf("bufStart after data copy: %x\n", bufStart)
	}

	_ = copy(buf, PayloadRandomSpecificEncrypted.cryptoSecret)
	if *verbose {
		Info.Printf("buf after secret copy: %x\n", buf)
	}

	// Encrypt the data with the function from Roman Muentener of the plus-debug protocol
	data := buf[16:]
	if *verbose {
		Info.Printf("data before encryption: %x\n", data)
	}
	keyLen := len(PayloadRandomSpecificEncrypted.cryptoKey)
	dataLen := len(data)
	for j := 0; j < dataLen; j++ {
		data[j] ^= PayloadRandomSpecificEncrypted.cryptoKey[j%keyLen]
	}
	// End of encryption

	if *verbose {
		Info.Printf("data after encryption: %x\n", data)
		Info.Printf("buf after encryption: %x\n", buf)
	}

	hash := md5.Sum(buf)
	if *verbose {
		Info.Printf("hash of buf: %x\n", hash)
	}

	if len(hash) != 16 {
		panic("Hash has bogus length! BUG. REPORT THIS!")
	}

	_ = copy(buf, hash[0:])

	// initialize i with new length
	*i = make([]byte, len(buf))
	_ = copy(*i, buf)

	if *verbose {
		Info.Printf("Payload to send (buf): %x\n", buf)
		Info.Printf("Payload to send (i): %x\n", *i)
	}

	// To check implementation of encryption and protection, the following code is the opposite from above.
	if *verbose {

		// Save the hash for comparison
		packetHash := make([]byte, 16)
		_ = copy(packetHash, buf[0:16])

		// Set the secret
		_ = copy(buf, PayloadRandomSpecificEncrypted.cryptoSecret)

		// Compute the hash
		checkHash := md5.Sum(buf)
		calculatedHash := checkHash[0:]
		Info.Printf("hash of check: %x\n", calculatedHash)

		// If hashes are not equal something is fishy
		if !bytes.Equal(packetHash, calculatedHash) {
			Info.Println("Hash not correct.")
		}

		// Decrypt the packet
		data = buf[16:]
		dataLen = len(data)
		for j := 0; j < dataLen; j++ {
			data[j] ^= PayloadRandomSpecificEncrypted.cryptoKey[j%keyLen]
		}

		headerLen := buf[16]

		// Extract the header
		header := buf[17 : 17+headerLen]
		Info.Printf("ShimLayer header from Serialize funtion: %x\n", shimlayerHeader)
		Info.Printf("Decrypted header from packet: %x\n", header)

		// Compare it with the header we got
		if !bytes.Equal(shimlayerHeader, header) {
			Info.Println("Headers doesn't match.")
		}

		buf = buf[17+headerLen:]
	}

	PayloadRandomSpecificEncrypted.fuzzPayloadPacketCounter++
}

// SerializePLUSHeader serializes the PLUS header into a byte stream from the header values.
// It is the same function as in the layers package for the ShimLayerType
func SerializePLUSHeader() []byte {
	var bytes []byte
	var lengthAndIntegrity int8

	l := shimLayer

	if l.XFlag.Value {
		//Extended Header
		bytes = make([]byte, 22+len(l.PCFValue.Value))
		// Generate length and integrity field, because they are 1 byte together.
		lengthAndIntegrity = int8(l.PCFLen.Value)<<2 | int8(l.PCFIntegrity.Value)
	} else {
		// Basic Header
		bytes = make([]byte, 20)
	}

	// Generate magic and flags in one uint32 value, because magic and flags share 4 bytes. We get the magic and shift it 4 bits to add the flags by shifting them
	// in the correct order.
	magicAndFlags := ((((uint32(l.Magic.Value) << 4) | (boolToInt(bool(l.LFlag.Value)) << 3)) | (boolToInt(bool(l.RFlag.Value)) << 2)) | (boolToInt(bool(l.SFlag.Value)) << 1)) | boolToInt(bool(l.XFlag.Value))
	// fmt.Println("Magic: ", p.Magic<<4)
	// fmt.Println("LFlag: ", boolToInt(p.LFlag)<<3)
	// fmt.Println("RFlag: ", boolToInt(p.RFlag)<<2)
	// fmt.Println("SFlag: ", boolToInt(p.SFlag)<<1)
	// fmt.Println("XFlag: ", boolToInt(p.XFlag))
	// fmt.Println(magicAndFlags)
	binary.BigEndian.PutUint32(bytes, uint32(magicAndFlags))
	binary.BigEndian.PutUint64(bytes[4:], uint64(l.CAT.Value))
	binary.BigEndian.PutUint32(bytes[12:], uint32(l.PSN.Value))
	binary.BigEndian.PutUint32(bytes[16:], uint32(l.PSE.Value))

	// Write fields of extended Header only if XFlag is set.
	if l.XFlag.Value {
		bytes[20] = uint8(l.PCFType.Value)
		bytes[21] = uint8(lengthAndIntegrity)
		copy(bytes[22:], l.PCFValue.Value)
	}
	return bytes
}

// boolToInt is a utility function for converting bool -> 0/1
// during serialization/decoding
func boolToInt(b bool) uint32 {
	if b {
		return 1
	}
	return 0
}

// fuzzFuncs defines slice for fuzzing functions and add them to slice, which is used from the fuzzer.
// You have to add your custom fuzzing functions here manually to fuzzFuncs.
var fuzzFuncs = []interface{}{FuzzPCFLenValid, FuzzPCFIntegrityValidRandom, FuzzPSNInvalidZero, FuzzPSEValidUpcounting}
