package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
	"github.com/jackpal/gateway"

	ping "github.com/sparrc/go-ping"
	"golang.org/x/crypto/ssh"
)

// localMACAddress gets the local MAC address of the specified device
func localMACAddress(dev string) net.HardwareAddr {
	iface, err := net.InterfaceByName(dev)
	if err != nil {
		panic(err.Error())
	}
	return iface.HardwareAddr
}

// localIPAddress gets the local IP address, the subnet mask and the subnet address of the specified interface
func localIPAddress(dev string) (net.IP, net.IPMask, *net.IPNet) {
	iface, err := net.InterfaceByName(dev)
	if err != nil {
		panic(err.Error())
	}

	addrs, err := iface.Addrs()
	if err != nil {
		panic(err.Error())
	}

	var ip net.IP
	var mask net.IPMask
	var network *net.IPNet
	for _, addr := range addrs {
		switch ipAddr := addr.(type) {
		case *net.IPNet:
			mask = ipAddr.Mask
			ip, network, err = net.ParseCIDR(ipAddr.String())
			if err != nil {
				Error.Fatal(err)
			}
			Info.Println("Local IPAddr: ", ipAddr)
			Info.Println("Local Subnet: ", network)
			Log.Println("Local IPAddr: ", ipAddr)
			Log.Println("Local Subnet: ", network)
			// Info.Println("Local IP: ", ip)
			// Info.Println("Local Subnet mask: ", mask)
			return ip, mask, network
		}
	}
	return nil, nil, nil
}

// remoteMACAddress gets the MAC address of the specified IP address.
// The function checks, if the target IP address is in the local subnet or not.
// If the target IP address is in a remote subnet, the MAC address of the default gateway is used.
// The function searches the arp table and if no entry for the IP address is ready
// it sends an icmp echo request (ping) to the given IP address, which creates an arp entry.
// If no arp reply is received after three retries, the function returns an error.
func remoteMACAddress(targetIP net.IP, localNetwork *net.IPNet) (string, error) {

	// targetIPAddr is the string representation of target IP address to get MAC address for
	var targetIPAddr string

	// Check if the target IP address is on the local subnet.
	// Otherwise get the default gateway and use that IP address to get the MAC address for.
	if localNetwork.Contains(targetIP) {
		targetIPAddr = targetIP.String()
		Info.Println("Target IP " + targetIPAddr + " is in local network")
		Log.Println("Target IP " + targetIPAddr + " is in local network")
	} else {
		gatewayIP, err := gateway.DiscoverGateway()
		if err != nil {
			Error.Fatal(err)
		}
		targetIPAddr = gatewayIP.String()
		Info.Println("Target IP " + targetIP.String() + " isn't in local network. Use MAC address of Gateway " + targetIPAddr + " as target.")
		Log.Println("Target IP " + targetIP.String() + " isn't in local network. Use MAC address of Gateway " + targetIPAddr + " as target.")
	}

	// retry is the number of pings and arp search before stop
	retry := 3

	// search the arp table
	macAddress, ok := searchARP(targetIPAddr)
	Info.Println("Using MAC address: ", macAddress)
	Log.Println("Using MAC address: ", macAddress)

	if !ok {
		// No entry in arp cache found, send a ping to start an arp request
		for 0 < retry {
			pinger, err := ping.NewPinger(targetIPAddr)
			if err != nil {
				Error.Fatal(err)
			}
			pinger.Count = 1
			pinger.Interval = 500 * time.Millisecond
			pinger.Timeout = 2 * time.Second
			pinger.SetPrivileged(true)
			pinger.Run() // blocks until finished
			retry--

			// search again the arp cache after pinging
			macAddress, ok = searchARP(targetIPAddr)

			// return mac address if found
			if ok {
				Info.Println("Using MAC address: ", macAddress)
				return macAddress, nil
			}

			// still no entry found, retry
			fmt.Println("MAC address not found. Next try...")
		}
	} else {
		return macAddress, nil
	}

	return "Error with arp cache.", errors.New("MAC address not found in arp cache. Give up")
}

// searchARP is looking for the mac address of the given ip address in the arp cache.
// If it isn't found, the function returns false.
func searchARP(ip string) (string, bool) {
	file, err := os.Open("/proc/net/arp")
	if err != nil {
		panic(err.Error())
	}
	defer file.Close()

	s := bufio.NewScanner(file)
	s.Scan() // skip the field descriptions on first line

	// ARPTable helds a mapping between the ip address and the mac address
	ARPTable := make(map[string]string)

	// Get all the lines from the arp cache
	for s.Scan() {
		line := s.Text()
		fields := strings.Fields(line) // field contains columns: <IP address> <HW type> <Flags> <HW address> <Mask> <Device>
		if fields[2] == "0x2" {        // column2==flags; flag 0x0 == incomplete; flag 0x2==complete; Only add entries if arp entry is complete
			ARPTable[fields[0]] = fields[3] // column0 == ip address, column3 == MAC address
		}
	}

	// Searching the ARP table for the mac address of the given ip address
	if len(ARPTable) > 0 {
		if macAddress, ok := ARPTable[ip]; ok {
			// Entry found
			return macAddress, true
		}
	}

	// Nothing found
	return "", false
}

// getAddressFromReflect is a helper function to get
// a pointer to the type of the reflect.
// Actual the only known possibility to get address to the type.
// For a specific other type, you have to add your custom type here.
func getAddressFromReflect(val reflect.Value) interface{} {

	typ := reflect.TypeOf(val.Interface())

	switch typ {
	// byte/string
	case reflect.TypeOf(([]byte)(nil)):
		return val.Addr().Interface().(*[]byte)
	case reflect.TypeOf((string)("")):
		return val.Addr().Interface().(*string)

	// Bool case
	case reflect.TypeOf((bool)(false)):
		return val.Addr().Interface().(*bool)

	// Number cases
	case reflect.TypeOf((int)(0)):
		return val.Addr().Interface().(*int)
	case reflect.TypeOf((int8)(0)):
		return val.Addr().Interface().(*int8)
	case reflect.TypeOf((int16)(0)):
		return val.Addr().Interface().(*int16)
	case reflect.TypeOf((int32)(0)):
		return val.Addr().Interface().(*int32)
	case reflect.TypeOf((int64)(0)):
		return val.Addr().Interface().(*int64)
	case reflect.TypeOf((uint)(0)):
		return val.Addr().Interface().(*uint)
	case reflect.TypeOf((uint8)(0)):
		return val.Addr().Interface().(*uint8)
	case reflect.TypeOf((uint16)(0)):
		return val.Addr().Interface().(*uint16)
	case reflect.TypeOf((uint32)(0)):
		return val.Addr().Interface().(*uint32)
	case reflect.TypeOf((uint64)(0)):
		return val.Addr().Interface().(*uint64)
	case reflect.TypeOf((float32)(0.0)):
		return val.Addr().Interface().(*float32)
	case reflect.TypeOf((float64)(0.0)):
		return val.Addr().Interface().(*float64)

	// Special types for PLUS layer
	case reflect.TypeOf((net.IP)(nil)):
		return val.Addr().Interface().(*net.IP)
	case reflect.TypeOf((net.HardwareAddr)(nil)):
		return val.Addr().Interface().(*net.HardwareAddr)
	case reflect.TypeOf((layers.PCFLen)(0)):
		return val.Addr().Interface().(*layers.PCFLen)
	case reflect.TypeOf((layers.PCFIntegrity)(0)):
		return val.Addr().Interface().(*layers.PCFIntegrity)
	case reflect.TypeOf((layers.PCFType)(0)):
		return val.Addr().Interface().(*layers.PCFType)
	case reflect.TypeOf((layers.PCFValue)(nil)):
		return val.Addr().Interface().(*layers.PCFValue)
	case reflect.TypeOf((layers.PSN)(0)):
		return val.Addr().Interface().(*layers.PSN)
	case reflect.TypeOf((layers.PSE)(0)):
		return val.Addr().Interface().(*layers.PSE)
	case reflect.TypeOf((layers.SFLAG)(false)):
		return val.Addr().Interface().(*layers.SFLAG)
	case reflect.TypeOf((layers.LFLAG)(false)):
		return val.Addr().Interface().(*layers.LFLAG)
	case reflect.TypeOf((layers.RFLAG)(false)):
		return val.Addr().Interface().(*layers.RFLAG)
	case reflect.TypeOf((layers.XFLAG)(false)):
		return val.Addr().Interface().(*layers.XFLAG)
	case reflect.TypeOf((layers.Magic)(0)):
		return val.Addr().Interface().(*layers.Magic)
	case reflect.TypeOf((layers.CAT)(0)):
		return val.Addr().Interface().(*layers.CAT)

	default:
		return nil
	}
}

// sendSSHCommand executes a specified command on a target machine via SSH.
func sendSSHCommand(targetAddr string, command string, sshUsername string, sshPassword string) {
	// var hostKey ssh.PublicKey
	// An SSH client is represented with a ClientConn.
	//
	// To authenticate with the remote server you must pass at least one
	// implementation of AuthMethod via the Auth field in ClientConfig,
	// and provide a HostKeyCallback.
	config := &ssh.ClientConfig{
		User: sshUsername,
		Auth: []ssh.AuthMethod{
			ssh.Password(sshPassword),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}
	client, err := ssh.Dial("tcp", targetAddr, config)
	if err != nil {
		Error.Fatal("Failed to dial: ", err)
	}
	defer client.Close()

	// Each ClientConn can support multiple interactive sessions,
	// represented by a Session.
	session, err := client.NewSession()
	if err != nil {
		Error.Fatal("Failed to create session: ", err)
	}
	defer session.Close()

	// Once a Session is created, you can execute a single command on
	// the remote side using the Run method.
	var b bytes.Buffer
	session.Stdout = &b
	if err := session.Run(command); err != nil {
		Error.Fatal("Failed to run: " + err.Error())
	}
	// Info.Println(b.String())

	// Check, if process is running and show the pid
	time.Sleep(1 * time.Second)
	session, err = client.NewSession()
	if err != nil {
		Error.Fatal("Failed to create session: ", err)
	}
	session.Stdout = &b
	if *sshCheckProcess != "" {
		if err := session.Run("pgrep " + *sshCheckProcess); err != nil {
			Error.Fatal("Failed to run: " + err.Error())
		}
		// Check feedback of pid and write it out.
		if b.String() == "" {
			Error.Println("Process", *sshCheckProcess, "isn't running.")
		} else {
			Info.Println("PID of process [", *sshCheckProcess, "] is: ", b.String())
		}
	} else {
		Error.Println("Process name isn't set. Can't check if it is running. Set it with command line argument -ssh-process-name.")
	}
}

// RotatePCAPFile rotates the PCAP File to limit the files to a certain file size.
// It takes a global file count variable to set the filename with an increasing number by adding it to the filePath variable.
// The function returns the handle to the file and the writer, which are used for writing the packets to.
func RotatePCAPFile(fileCount *int, filePath string, snapshotLen int32, keepNPCAPFiles int, maxStorageCapacity int) (*pcapgo.Writer, *os.File) {

	// Create filepath with an increasing number.
	fileDir, fileBaseName := filepath.Split(filePath)
	fileExt := filepath.Ext(filePath)
	fileNameWithoutExt := strings.TrimSuffix(fileBaseName, fileExt)
	pcapFilePath := filepath.Join(fileDir, fileNameWithoutExt+"-"+strconv.Itoa(*fileCount)+fileExt)

	// pcapFileSend defines the file handle to save the sent packets into a pcap file.
	pcapFileSend, err := os.Create(pcapFilePath)
	if err != nil {
		Error.Fatal(err)
	}
	pcapWriterSend := pcapgo.NewWriter(pcapFileSend)

	// Write the file header once per pcap file.
	pcapWriterSend.WriteFileHeader(uint32(snapshotLen), layers.LinkTypeEthernet)

	// Delete old files to hold the max storage capacity
	if (*fileCount >= keepNPCAPFiles) && maxStorageCapacity != 0 {
		// Start with deleting if fileCount >= keepNFiles
		// Delete the file with filename-<fileCount-keepNFiles) to get the max storage
		fileToDelete := filepath.Join(fileDir, fileNameWithoutExt+"-"+strconv.Itoa(*fileCount-keepNPCAPFiles)+fileExt)
		deletePCAPFile(fileToDelete)
	}

	*fileCount++
	return pcapWriterSend, pcapFileSend
}

// deletePCAPFile deletes the old files to hold the storage capacity.
func deletePCAPFile(filePath string) {
	err := os.Remove(filePath)
	if err != nil {
		Error.Println(err)
	}
}

// CheckCrash receives the packets of the network interface in a seperate goroutine and
// checks for "Destination unreachable" (Type 3) "Port unreachable" (Code 3) packets.
// If the SUT crashes, the port isn't responding anymore and the OS sends back an ICMP unreachable.
func CheckCrash(recvHandle *pcap.Handle, packetCountSend *int, pcapFileSend *os.File, quitCheckCrash chan bool) {
	// Get the name of the executable
	executable, err := os.Executable()
	if err != nil {
		Error.Fatal("Can't get the name of the executable.")
	}

	// Use the handle as a packet source to process all packets
	recvPacketSource := gopacket.NewPacketSource(recvHandle, recvHandle.LinkType())
	for {
		select {
		case <-quitCheckCrash:
			Info.Println("Quit for CheckCrash received.")
			return
		case recvPacket := <-recvPacketSource.Packets():

			Info.Println("ICMP PACKET RECEIVED!")
			if *verbose {
				Info.Printf("\n%v\n\n", recvPacket)
			}
			if pcapFileSend != nil {
				// It is a real fuzzing process and therefore we have a filename, where the sent packets are saved.
				Log.Printf("SUT crashed after ~%d packets sent. Replay the packets with a longer interval (800ms) to get closer to the problem packet and start the SUT in the debugger.\n"+
					"Use the following command to replay the packets:\n"+
					"sudo %s -dev=%q -packet-send-interval=800 -target-ip=%q -target-port=%d -ssh-command=%q -ssh-process-name=%q -ssh-user=%q -ssh-password=%q -pcap-path-replay=%q -replay-following",
					*packetCountSend-1, executable, *device, *destIP, *targetPort, *sshCommand, *sshCheckProcess, *sshUsername, *sshPassword, pcapFileSend.Name()) // minus one because the icmp port unreachable is sent
				Error.Fatalf("SUT crashed after ~%d packets sent. Replay the packets with a longer interval (800ms) to get closer to the problem packet. "+
					"You find the command to replay in the log file %s.", *packetCountSend-1, *logfilePath) // after the packet, which crashed the SUT
			} else {
				// It is a replay and therefore, no command has to be set.
				Log.Printf("SUT crashed after ~%d packets sent. Replay the packets with a longer interval (800ms) to get closer to the problem packet and start the SUT in the debugger.\n",
					*packetCountSend-1) // minus one because the icmp port unreachable is sent
				Error.Fatalf("SUT crashed after ~%d packets sent. Replay the packets with a longer interval (800ms) to get closer to the problem packet and start the SUT in the debugger.", *packetCountSend-1) // after the packet, which crashed the SUT
			}
		}
	}
}

// WriteFuzzLogHeader writes header about fuzzing to log file.
func WriteFuzzLogHeader() {

	// Get the name of the executable
	executable, err := os.Executable()
	if err != nil {
		Error.Fatal("Can't get the name of the executable.")
	}

	Log.Println("---------------------------------------------------------------------------------------------------------------------------------------")
	Log.Println("Start of fuzzing process:", time.Now())
	Log.Println("Operating system:", runtime.GOOS, "/", runtime.GOARCH)
	Log.Println("Interface:", *device)
	Log.Println("Fuzzing target IP:", *destIP)
	Log.Println("Fuzzing target port:", *targetPort)
	Log.Println("Seed for fuzzers:", *fuzzerSeed)
	Log.Println("Fuzzing payload:", *fuzzPayload)
	if *fuzzPayload {
		Log.Println("Payload minimum length:", *minPayloadLen, "bytes")
		Log.Println("Payload maximum length:", *maxPayloadLen, "bytes")
	}
	Log.Println("Fuzzing fields:", *fuzzFields)
	Log.Println("Number of packets to send to fuzzing target:", *numPacketsToFuzz)
	Log.Println("Sending interval between two packets:", *packetSendInterval, "milliseconds")
	Log.Println("Save fuzzed packets to pcap file:", *savePackets)
	if *savePackets {
		Log.Println("Path to pcap output file:", *pcapPathSend)
		Log.Println("Maximum pcap file size:", *pcapFileSize, "kilo bytes")
		Log.Println("Maximum storage capacity for pcap files:", *maxStorageCapacity, "kilo bytes")
	}
	Log.Println("SSH command:", *sshCommand)
	Log.Println("SSH process to check:", *sshCheckProcess)
	Log.Println("SSH username:", *sshUsername)
	Log.Println("SSH password:", *sshPassword)
	Log.Printf("Full command to repeat this fuzzing process with new log file and new path to pcap file for saving sent packets:\n"+
		"sudo %s -dev=%q -target-ip=%q -target-port=%d -local-port=%d -fuzzer-seed=%d -packet-send-interval=%d -num-packets=%d "+
		"-ssh-command=%q -ssh-process-name=%q -ssh-user=%q -ssh-password=%q "+
		"-save-sent-packets=%t -pcap-file-size=%d -max-storage=%d -fuzz-payload=%t -min-payload-len=%d -max-payload-len=%d -fuzz-fields=%t -verbose=%t",
		executable, *device, *destIP, *targetPort, *localPort, *fuzzerSeed, *packetSendInterval, *numPacketsToFuzz,
		*sshCommand, *sshCheckProcess, *sshUsername, *sshPassword,
		*savePackets, *pcapFileSize, *maxStorageCapacity, *fuzzPayload, *minPayloadLen, *maxPayloadLen, *fuzzFields, *verbose)
	Log.Println("---------------------------------------------------------------------------------------------------------------------------------------")
}

// WriteReplayLogHeader writes log header for replay packets from pcap.
func WriteReplayLogHeader() {

	// Get the name of the executable
	executable, err := os.Executable()
	if err != nil {
		Error.Fatal("Can't get the name of the executable.")
	}

	Log.Println("---------------------------------------------------------------------------------------------------------------------------------------")
	Log.Println("Start of replay packets process:", time.Now())
	Log.Println("Operating system:", runtime.GOOS, "/", runtime.GOARCH)
	Log.Println("Interface:", *device)
	Log.Println("Fuzzing target IP:", *destIP)
	Log.Println("Fuzzing target port:", *targetPort)
	Log.Println("Sending interval between two packets:", *packetSendInterval, "milliseconds")
	Log.Println("SSH command:", *sshCommand)
	Log.Println("SSH process to check:", *sshCheckProcess)
	Log.Println("SSH username:", *sshUsername)
	Log.Println("SSH password:", *sshPassword)
	Log.Println("Start file of packet replay:", *pcapPathReplay)
	Log.Println("Replay all the following files as well:", *replayFollowing)
	Log.Printf("Full command to repeat this replay process with new log file:\n"+
		"sudo %s -dev=%q -target-ip=%q -target-port=%d -packet-send-interval=%d "+
		"-ssh-command=%q -ssh-process-name=%q -ssh-user=%q -ssh-password=%q -pcap-path-replay=%q -replay-following=%t -verbose=%t",
		executable, *device, *destIP, *targetPort, *packetSendInterval,
		*sshCommand, *sshCheckProcess, *sshUsername, *sshPassword, *pcapPathReplay, *replayFollowing, *verbose)
	Log.Println("---------------------------------------------------------------------------------------------------------------------------------------")
}

// WriteFuzzReplayLogHeader writes log header for replay packets from pcap.
func WriteFuzzReplayLogHeader() {

	// Get the name of the executable
	executable, err := os.Executable()
	if err != nil {
		Error.Fatal("Can't get the name of the executable.")
	}

	Log.Println("---------------------------------------------------------------------------------------------------------------------------------------")
	Log.Println("Start of fuzzing replayed packets process:", time.Now())
	Log.Println("Operating system:", runtime.GOOS, "/", runtime.GOARCH)
	Log.Println("Interface:", *device)
	Log.Println("Fuzzing target IP:", *destIP)
	Log.Println("Fuzzing target port:", *targetPort)
	Log.Println("Seed for fuzzers:", *fuzzerSeed)
	Log.Println("Fuzzing payload:", *fuzzPayload)
	if *fuzzPayload {
		Log.Println("Payload minimum length:", *minPayloadLen, "bytes")
		Log.Println("Payload maximum length:", *maxPayloadLen, "bytes")
	}
	Log.Println("Fuzzing fields:", *fuzzFields)
	Log.Println("Sending interval between two packets:", *packetSendInterval, "milliseconds")
	Log.Println("SSH command:", *sshCommand)
	Log.Println("SSH process to check:", *sshCheckProcess)
	Log.Println("SSH username:", *sshUsername)
	Log.Println("SSH password:", *sshPassword)
	Log.Println("File of packet replay:", *pcapPathFuzz)
	Log.Printf("Full command to repeat this fuzzing process with new log file and new path to pcap file for saving sent packets:\n"+
		"sudo %s -dev=%q -target-ip=%q -target-port=%d -fuzzer-seed=%d -packet-send-interval=%d "+
		"-ssh-command=%q -ssh-process-name=%q -ssh-user=%q -ssh-password=%q "+
		"-fuzz-payload=%t -min-payload-len=%d -max-payload-len=%d -fuzz-fields=%t -pcap-path-fuzz=%q -verbose=%t",
		executable, *device, *destIP, *targetPort, *fuzzerSeed, *packetSendInterval,
		*sshCommand, *sshCheckProcess, *sshUsername, *sshPassword,
		*fuzzPayload, *minPayloadLen, *maxPayloadLen, *fuzzFields, *pcapPathFuzz, *verbose)
	Log.Println("---------------------------------------------------------------------------------------------------------------------------------------")
}

// ReplayFilenames returns a slice of the filenames to replay.
// The function checks for existence of the next files
// by counting up the number at the end of the filename.
func ReplayFilenames(filePath string) ([]string, error) {

	// replayFiles holds all the pcap files
	var replayFiles []string
	replayFiles = append(replayFiles, filePath)

	// Check for the following files only, if they should be played as well
	if *replayFollowing {
		// Split the given filename
		fileDir, fileBaseName := filepath.Split(filePath)
		fileExt := filepath.Ext(filePath)
		fileNameWithoutExt := strings.TrimSuffix(fileBaseName, fileExt)
		fileNameSplited := strings.Split(fileNameWithoutExt, "-")

		// Convert the last part to a number for counting
		fileCountStart, err := strconv.Atoi(fileNameSplited[len(fileNameSplited)-1])
		if err != nil {
			return replayFiles, errors.New("Problem with searching for further files. Probably given filename doesn't end with -<nr>")
			// Error.Fatal("Problem with searching for further files. Probably given filename doesn't end with -<nr>.")
		}
		fileNameWithoutNr := strings.TrimSuffix(fileNameWithoutExt, "-"+fileNameSplited[len(fileNameSplited)-1])

		fileCount := fileCountStart + 1

		// nextFilePath is the next filepath to check for existence
		var nextFilePath string

		// Counting up the filename and add it to the slice if it exist in filesystem.
		// Stop as soon as the nextFilePath doesn't exist in filesystem.
		for {
			nextFilePath = filepath.Join(fileDir, fileNameWithoutNr+"-"+strconv.Itoa(fileCount)+fileExt)
			if _, err := os.Stat(nextFilePath); err == nil {
				replayFiles = append(replayFiles, nextFilePath)
				fileCount++
			} else {
				break
			}
		}
	}
	return replayFiles, nil
}

// PrettyPrintProtocolStructure prints the protocol structure with the fields in a pretty form.
// The json encoding is to pretty print the struct.
func PrettyPrintProtocolStructure(shimLayer *layers.ShimLayer) {
	printProtocolStructure, err := json.MarshalIndent(shimLayer, "", "  ")
	if err != nil {
		Error.Println(err)
	}
	Log.Printf("\nProtocol structure:\n%v\n\n", string(printProtocolStructure))
}

// CountPackets counts the interesting packets in the pcap file and returns the number.
func CountPackets(filename string) (int, error) {
	// fileCountHandle is the handle to the pcap file with the saved packets.
	fileCountHandle, err := pcap.OpenOffline(filename)
	if err != nil {
		return 0, err
	}
	// Only read the packets of the specific protocol and direction from the file.
	fileCountHandle.SetBPFFilter("dst host " + *destIP + " and dst port " + strconv.Itoa(int(*targetPort)))
	defer fileCountHandle.Close()

	// packetCount is the number of packets in the opened file.
	var packetCount int
	countersource := gopacket.NewPacketSource(fileCountHandle, fileCountHandle.LinkType())
	// Do nothing with the packets, but loop through all them.
	for _ = range countersource.Packets() {
		packetCount++
	}

	return packetCount, nil
}
