// Package main is a package for fuzzing a network protocol over the wire.
// It generates random data and sends this fuzzed information over the wire
// to a target system (SUT). You can write your own functions for fuzzing.
// The main purpose of the program is to fuzz Shim Layer protocols,
// especially the PLUS protocol (Path Layer UDP Substrate).
//
// Author: Marcel Sueess, sueesmar@students.zhaw.ch
// Date: 4th April, 2018
package main

import (
	"flag"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"time"
)

var (
	// Error serves as logger for error messages.
	Error *log.Logger
	// Info serves as logger for info messages.
	Info *log.Logger
	// Log serves as logger for fuzzing campaign to save infos to the file.
	Log *log.Logger

	// device (network interface) for sending the packets.
	device = flag.String("dev", "", "Network interface, for sending and receiving packets.")
	// targetIP sets the destination of the fuzzed packets.
	destIP = flag.String("target-ip", "", "IP address of the target of the fuzzing process.")
	// fuzzerSeed sets the seed for deterministic fuzzing.
	fuzzerSeed = flag.Int64("fuzzer-seed", 0, "Seed for random generator of fuzzer. Used by gofuzz to make fuzzing deterministic.")
	// localPort sets the local source port of the packets.
	localPort = flag.Uint("local-port", 10000, "Local port of the transport layer for the local system, eg. UDP or TCP Port.")
	// targetPort sets the local source port of the packets.
	targetPort = flag.Uint("target-port", 9999, "Target port of the transport layer for the remote system (SUT), eg. UDP or TCP Port.")
	// fuzzPayload defines if the payload sould be fuzzed or if it should be fixed value.
	fuzzPayload = flag.Bool("fuzz-payload", false, "Boolean which determines, if payload should be fuzzed.")
	// fuzzPacketStructure defines if the fields of packet structure sould be fuzzed or if it should be fixed value.
	// This can be used to generally disable fuzzing, even the fields are set to true.
	fuzzFields = flag.Bool("fuzz-fields", true, "Boolean which determines, if packet fields should be fuzzed. Can be used to globally enable or disable fuzzing.")
	// minPayloadLen defines the minimal length in bytes for the payload.
	minPayloadLen = flag.Int("min-payload-len", 6, "Minimum length in bytes for payload.")
	// maxPayloadLen defines the maximal length in bytes for the payload.
	maxPayloadLen = flag.Int("max-payload-len", 1000, "Maximum length in bytes for payload.")
	// numPacketsToFuzz defines the amount of packets to send to the target.
	numPacketsToFuzz = flag.Int64("num-packets", 4294967296, "Number of packets to send to target during fuzzing.")
	// packetSendInterval defines the interval between to packets in milliseconds.
	packetSendInterval = flag.Int("packet-send-interval", 200, "Sending interval of packets in milliseconds.")
	// pcapPathSend defines the path to a pcap file to capture the sent packet. If no path is specified, the file name is built with the actual date and time.
	pcapPathSend = flag.String("pcap-path-send", "/var/tmp/fuzz-send-"+time.Now().Format("20060102150405")+".pcap", "Path to output pcap file, so save the sent packets.")
	// pcapFileSize defines the maximum size for a pcap file in kilo bytes. After this size, create a new file.
	pcapFileSize = flag.Int("pcap-file-size", 100, "Create new pcap file after ... kilo bytes.")
	// savePackets defines, if sent fuzzed packets should be saved to pcap file.
	savePackets = flag.Bool("save-sent-packets", false, "Boolean which determines if fuzzed packets should be saved to pcap file.")
	// maxStorageCapacity defines the maximum size of storage for saved pcap files
	maxStorageCapacity = flag.Int("max-storage", 0, "Maximum storage for pcap files in kilo bytes. 0 means unlimited.")
	// logfilePath defines the path to save the logfile to.
	logfilePath = flag.String("logfile-path", "/var/tmp/fuzz-log-"+time.Now().Format("20060102150405")+".txt", "Path to save the log file of fuzzing.")
	// sshCommand defines the command which is executed on the target machine.
	sshCommand = flag.String("ssh-command", "",
		`Command to start the SUT on the target. 
		To let the process run in background, even the ssh session is closed, 
		use tmux to create a named terminal multiplexer session in background.
		Install tmux with 'sudo apt-get install tmux'. 
		You can execute multiple commands separated by ';'. 
		Use '' to enclose commands containing whitespaces. 
		The following command is an example to kill an existing process and start a new one:
		pkill server; tmux new -d -s FuzzSession '~/go/src/github.com/FMNSSun/plus-debug/server/server 192.168.181.133:9999'`)
	// sshCheckProcess defines the name of the process to check for the PID.
	sshCheckProcess = flag.String("ssh-process-name", "", "Name of the process to check the status for with pgrep <ssh-process-name>.")
	// sshUsername defines the username for accessing the target machine.
	sshUsername = flag.String("ssh-user", "", "Username to acess the target machine by ssh.")
	// sshPassword defines the password for accessing the target machine.
	sshPassword = flag.String("ssh-password", "", "Password to access the target machine by ssh.")
	// pcapPathReplay defines the path to a packet capture for replay.
	pcapPathReplay = flag.String("pcap-path-replay", "", "Path to packet capture for replay.")
	// replayFollowing defines if the following pcap files should be played as well.
	replayFollowing = flag.Bool("replay-following", false,
		`Boolean which defines, if the following pcap files should be replayed as well.
		For this, the filenames of the pcap files have to end with <-nr> (e.g. -0)
		and count up with an incrementing number.`)
	// pcapPathFuzz defines the path to an existing pcap packet capture. It takes it and fuzz it.
	pcapPathFuzz = flag.String("pcap-path-fuzz", "", "Path to existing packet capture for fuzzing it.")
	// verbose sets the log level to maximum and prints more informatin to the StdOut.
	verbose = flag.Bool("verbose", false, "Writes more information to the StdOut if set to true.")
)

func main() {

	// Parse an check flags
	flag.Parse()

	// Initialize the Logger
	logfile, err := os.OpenFile(*logfilePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err != nil {
		panic("Failed to open log file: " + err.Error())
	}
	InitLog(os.Stderr, os.Stdout, logfile)

	// Input validation
	if *device == "" {
		Error.Fatal("No device for sending and receiving packets specified. Please provide the name of the interface with the option -dev.")
	}

	if *localPort <= 0 || *localPort > 65535 {
		Error.Fatal("No valid local port provided. Please provide a local port between 1 and 65535 with the option -local-port.")
	}

	if *targetPort <= 0 || *targetPort > 65535 {
		Error.Fatal("No valid target port provided. Please provide a target port between 1 and 65535 with the option -target-port.")
	}

	if *pcapPathReplay != "" && *pcapPathFuzz != "" {
		Error.Fatal("You can't set both paths for replay existing file and fuzz existing packet capture at the same time.")
	}

	if *savePackets {
		if *pcapPathSend == "" {
			Error.Fatal("The path to save the sent packets is invalid. Please provide a valid path with the option -pcap-path-send.")
		}
		if *pcapFileSize < 10 {
			Error.Fatal("The size of the pcap file is too small. Please provide a size bigger than 10 with the option -pcap-file-size.")
		}
	}

	if *logfilePath == "" {
		Error.Fatal("You haven't provided a path to save the log file. Please provide a valid path with the option -logfile-path.")
	}

	if (*sshUsername == "" || *sshPassword == "") && (*sshCommand != "") {
		Error.Fatal("You haven't provided a SSH username or password. Please use the options -ssh-user and -ssh-password.")
	}

	if *sshCommand == "" {
		Error.Print("You haven't provided a SSH command to start the SUT on the target system. Please provide it with the option -ssh-command or start it manually.")
	}

	if *packetSendInterval < 10 {
		Error.Fatal("Packet send interval too small. Please provide an interval bigger than 10 ms with the option -packet-send-interval")
	}

	if *fuzzPayload {
		if *minPayloadLen > *maxPayloadLen {
			Error.Fatal("The -min-payload-len can't be bigger than the -max-payload-len option. Please correct it.")
		}

		if *minPayloadLen < 0 || *minPayloadLen > 1350 {
			Error.Fatal("Value for -min-payload-len invalid. Please provide a value between 0 and 1350.")
		}

		if *maxPayloadLen < 0 || *maxPayloadLen > 1350 {
			Error.Fatal("Value for -max-payload-len invalid. Please provide a value between 0 and 1350.")
		}
	}

	if *maxStorageCapacity < 0 {
		Error.Fatal("Value for -max-storage-capacity invalid. Please provide a value bigger or equal to 0. 0 means unlimited and is default.")
	}

	if checkIP := net.ParseIP(*destIP); checkIP == nil {
		Error.Fatal("Invalid IP address provided. Please provide a valid IP address with the option -target-ip.")
	}

	// Listen for ctrl+c to write entry to log file.
	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, os.Interrupt)
	go func() {
		for _ = range signalChan {
			Info.Println("Process aborted by user at", time.Now().Format("02.01.2006 15:04:05"))
			Log.Println("Process aborted by user at", time.Now().Format("02.01.2006 15:04:05"))
			os.Exit(1)
		}
	}()

	// fuzzingRoundDone is a channel to wait for ending of fuzzing process.
	fuzzingRoundDone := make(chan bool)

	// Execute the code for fuzzing new packets or replay a given pcap file.
	switch {
	case *pcapPathReplay == "" && *pcapPathFuzz == "":
		// Replay path not set, so start new packet fuzzing
		go SendPackets(fuzzingRoundDone)
	case *pcapPathReplay != "":
		// Replay path set, so replay it
		go ReplayPackets(fuzzingRoundDone)
	case *pcapPathFuzz != "":
		// Path to pcap for fuzzing set, so replay AND fuzz it.
		go FuzzCapturedPackets(fuzzingRoundDone)
	}
	<-fuzzingRoundDone
}

// InitLog initializes the loggers.
// To extend it for logging to file, see https://www.ardanlabs.com/blog/2013/11/using-log-package-in-go.html
func InitLog(errorHandle io.Writer, infoHandle io.Writer, logHandle io.Writer) {
	Error = log.New(errorHandle, "ERROR: ", log.Ldate|log.Ltime|log.Lshortfile)
	Info = log.New(errorHandle, "INFO: ", log.Ldate|log.Ltime|log.Lshortfile)
	Log = log.New(logHandle, "LOG:", log.Ldate|log.Ltime)
}
