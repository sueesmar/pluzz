# pluzz - plus fuzz

pluzz is a network protocol fuzzer for shim layer protocols like [PLUS (Path Layer UDP Substrate)](https://datatracker.ietf.org/doc/draft-trammell-plus-spec/). It is expandable to other future shim layer protocols as well.

The next few sections describe the installation and usage of pluzz.

## Installation of pluzz

The fuzzer is developed and tested with Ubuntu Desktop 16.04 LTS. The following manuals are valid for that version, but should work with newer versions too.


1. Update the components of the operating system to a recent version with `sudo apt-get update`, followed by `sudo apt-get upgrade`.
2. Install Git with the command `sudo apt-get install git`.
3. Configure Git with the command `git config --global user.name "Your Name"` and `git config --global user.email "youremail@domain.com"`.
4. Download Go with command `wget https://dl.google.com/go/go1.10.1.linux-amd64.tar.gz.` (Actual version at time of writing).
5. Extract downloaded archive with `sudo tar -xvf go1.10.1.linux-amd64.tar.gz`.
6. Move extracted data to desired path by `sudo mv go /usr/local`.
7. Open file `~/.profile` with e.g. nano.
8. Add the following entries as environment variables at the end of the file:
```bash
   # set PATH so it includes user's private bin directories
   export GOROOT=/usr/local/go
   export GOPATH=$HOME/go-projects
   export PATH="$HOME/bin:$HOME/.local/bin:$GOPATH/bin:$GOROOT/bin:$PATH"
```
9. Log off from Ubuntu and log in again. Open a command line.
10. Check Go installation with command `go version`.
11. Create the Go projects folder at $HOME/go-projects.
12. Download Visual Studio Code from [Microsoft](https://code.visualstudio.com/Download) as `.deb` file. (Or your favourite IDE)
13. Install Visual Studio Code by double clicking the downloaded package and follow the instructions.
14. Install the Go extension for Visual Studio Code by clicking the `extensions` menu on the left side and search for `Go`.
15. Install the pcap development headers with command `sudo apt-get install libpcap-dev`.
16. Get the source code of `pluzz` with the command: `go get github.com/sueesmar/pluzz`.
17. Add the work folder $HOME/go-projects/src to Visual Studio Code.
18. Copy the file `plusLayer.go` to `~/go-projects/src/github.com/google/gopacket/layers` and uncomment the whole file.
19. Change the package statement in `plusLayer.go` to `package layers`.
20. Add the following code to `udp.go` in layers subpackage in function `NextLayerType()`. Set the code in front of the existing function body:
```go
   // Check for magic of ShimLayer at fixed position
   // and set the next layer according to that.
   if len(u.Payload) >= 4 {
	   magic := binary.BigEndian.Uint32(u.Payload[0:4]) >> 4
	   expected := uint32(0xd8007ff)
	   if magic == expected {
		   return ShimLayerType
	   }
   }
   // Rest of the existing code unchanged...
```
21. Compile the fuzzer with the command `go build` within the folder `~/go-projects/src/github.com/sueesmar/pluzz`.
22. Installation/preparation completed.

## Command line options for pluzz

You get a description for the command line options by executing command  `~/go-projects/src/github.com/sueesmar/pluzz/pluzz -help`.



Option | Type | Description
--- | --- | ---
-dev | string | Network interface, for sending and receiving packets.
-fuzz-fields | boolean | Boolean which determines, if packet fields should be fuzzed. Can be used to globally enable or disable fuzzing. (default true)
-fuzz-payload | boolean | Boolean which determines, if payload should be fuzzed. (default false)
-fuzzer-seed | int | Seed for random generator of fuzzer. Used by gofuzz to make fuzzing deterministic. (default 0)
-local-port | uint | Local port of the transport layer for the local system, eg. UDP or TCP Port. (default 10000)
-logfile-path | string | Path to save the log file of fuzzing. (default "/var/tmp/fuzz-log-<datetime>.txt")
-max-payload-len | int | Maximum length in bytes for payload. (default 1000)
-max-storage | int | Maximum storage for pcap files in kilo bytes. 0 means unlimited. (default 0)
-min-payload-len | int | Minimum length in bytes for payload. (default 6)
-num-packets | int | Number of packets to send to target during fuzzing. (default 4294967296)
-packet-send-interval | int | Sending interval of packets in milliseconds. (default 200)
-pcap-file-size | int | Create new pcap file after ... kilo bytes. (default 100)
-pcap-path-fuzz | string | Path to existing packet capture for fuzzing it.
-pcap-path-replay | string | Path to packet capture for replay.
-pcap-path-send | string | Path to output pcap file, so save the sent packets. (default "/var/tmp/fuzz-send-<datetime>.pcap")
-replay-following | boolean | Boolean which defines, if the following pcap files should be replayed as well. For this, the filenames of the pcap files have to end with <-nr> (e.g. -0) and count up with an incrementing number. (default false)
-save-sent-packets | boolean | Boolean which determines if fuzzed packets should be saved to pcap file. (default false)
-source-ip | string | IP address of the original source of the fuzzing process to poison its ARP table. Activates man-in-the-middle mode.
-ssh-command | string | Command to start the SUT on the target. To let the process run in background, even the SSH session is closed, use tmux to create a named terminal multiplexer session in background. Install tmux with 'sudo apt-get install tmux'. You can execute multiple commands, separated by ';'. Use '' to enclose commands containing white spaces. The following command is an example to kill an existing process and start a new one: pkill server; tmux new -d -s FuzzSession '~/go/src/github.com/FMNSSun/plus-debug/server/server 192.168.181.133:9999'
-ssh-password | string | Password to access the target machine by SSH.
-ssh-process-name | string | Name of the process to check the status for with pgrep <ssh-process-name>.
-ssh-user | string | Username to access the target machine by SSH.
-target-ip | string | IP address of the target of the fuzzing process.
-target-port | uint | Target port of the transport layer for the remote system (SUT), e.g. UDP or TCP Port. (default 9999)
-verbose | boolean | Writes more information to the StdOut, if set to true. (default false)

## Preparation of SUT

To start the SUT from the test system, you have to install an SSH server and a terminal multiplexer on the target system.

1. Install the openssh-server with command `sudo apt-get install openssh-server`.
2. Install the terminal multiplexer tmux with command `sudo apt-get install tmux`.

See the usage in [section](#command-line-options-for-pluzz) above for the command line option `ssh-command`.

## Fuzz PLUS

1. Prepare the fuzzer according to [section](#preparation-of-sut) above.
2. Define the protocol fields meta data in file `packetStructure.go`. Set the `FuzzIt` to `true` for the fields to be fuzzed or define a constant value for meta field `Value`.
3.  Enable/Disable custom fuzzing functions at the end of the file `fuzzFunctions.go`. Therefore, add the function name to the slice variable `fuzzFuncs`.
4.  Compile the fuzzer with the command `go build` within the folder ~/go-projects/src/github.com/sueesmar/pluzz.
5.  Start the fuzzing with command `sudo ~/go-projects/src/github.com/sueesmar/pluzz/pluzz` and the necessary command line options from [section](#command-line-options-for-pluzz) above.

## Develop custom fuzzing

The fuzzer allows you to fuzz each field with random values or set them with your custom logic. Therefore, you are able to define your own fuzzing functions and implement the logic yourself. Each fuzzing function consists of two parameters. The first is the protocol field to fuzz and the second a `fuzz.Continue` object. To fuzz the field, set the value of the pointer variable within the function body with the desired value. Following Listing shows an example implementation, to fuzz a field from type `net.IP` with a syntactically correct IP address. To enable your fuzzing function, add the function name to the variable `fuzzFuncs` at the end of `fuzzFunctions.go`.
```go
// FuzzIPAddrValidRandom fuzzes a net.IP type with a
// syntactically correct address
func FuzzIPAddrValidRandom(i *net.IP, c fuzz.Continue) {
	*i = net.IP{byte(rand.Intn(256)), byte(rand.Intn(256)),
		byte(rand.Intn(256)), byte(rand.Intn(256))}
}

// fuzzFuncs defines slice for fuzzing functions and add
// them to slice, which is used from the fuzzer.
// You have to add your custom fuzzing functions here
// manually to fuzzFuncs, comma separated.
var fuzzFuncs = []interface{}{FuzzIPAddrValidRandom}
```

## Develop custom Shim Layer

To simplify the development of a custom shim layer, you can use the template `shimLayerTemplate.go`.

1. Copy this file to the `gopacket.layers` subpackage.
2. Uncomment the whole file.
3. Define all the protocol field types at the beginning of the file, within the marked section for changes.
4. Define the return value, to get the address of each field by adding each field type to the function `getAddressFromReflect()` in file `fuzzHelper.go` according to the examples.
5. Define the structure of the shim layer in the `ShimLayer` struct.
6. Each field gets four meta data fields `MinLen, MaxLen, Value, FuzzIt`.
7. Implement the two functions `DecodeFromBytes()` and `SerializeTo()`.
8. Define the layers of your packet on top within `packetStructure.go`.
9. Define the order of the layers in the function `getLayerStack()` in `packetStructure.go`.
10. Set the values for the new shim layer meta fields in `InitShimLayer()` of the file `packetStructure.go`.
11. Implement the function `DecodePacket()` within `packetStructure.go`, if you want to fuzz an original packet capture with the command line option `-pcap-path-fuzz`.

## Examples for fuzzing

Goal | Command
--- | ---
Fuzzing with manual start of SUT on target system without packet capture. Sending interval is 100 milliseconds and 2000 packets should be sent. Fuzz the target system with IP address 192.168.181.133 on port 5999 | sudo  \~/go-projects/src/github.com/sueesmar/pluzz/pluzz -dev="ens33" -target-ip="192.168.181.137" -target-port=5999 -local-port=10000 -packet-send-interval=100 -num-packets=2000
Fuzzing with automatic start of SUT by SSH. Capture packets to file and split them into files of maximum 50 kB and store maximum 200 kB. | sudo \~/go-projects/src/github.com/sueesmar/pluzz/pluzz -dev="ens33" -target-ip="192.168.181.133" -target-port=5999 -local-port=10000 -packet-send-interval=100 -num-packets=2000 -ssh-command="pkill server; tmux new -d -s FuzzSession '\~/go/src/github.com/FMNSSun/plus-debug/server/server 192.168.181.133:5999'" -ssh-user="administrator" -ssh-password="admin1234." -ssh-process-name="server" -save-sent-packets -pcap-path-send="/var/tmp/fuzz-packet-capture.pcap" -logfile-path="/var/tmp/fuzz-log.txt" -pcap-file-size=50 -max-storage=200
Replay packets from file /var/tmp/fuzz-packet-capture-0.pcap | sudo \~/go-projects/src/github.com/sueesmar/pluzz/pluzz -dev="ens33" -target-ip="192.168.181.133" -target-port=5999 -local-port=10000 -packet-send-interval=100 -ssh-command="pkill server; tmux new -d -s FuzzSession '\~/go/src/github.com/FMNSSun/plus-debug/server/server 192.168.181.133:5999'" -ssh-user="administrator" -ssh-password="admin1234." -ssh-process-name="server" -pcap-path-replay="/var/tmp/fuzz-packet-capture-0.pcap" -logfile-path="/var/tmp/fuzz-replay-log.txt"
Replay packets from file /var/tmp/fuzz-packet-capture-0.pcap and the following files of the same fuzzing process. | sudo \~/go-projects/src/github.com/sueesmar/pluzz/pluzz -dev="ens33" -target-ip="192.168.181.133" -target-port=5999 -local-port=10000 -packet-send-interval=100 -ssh-command="pkill server; tmux new -d -s FuzzSession '\~/go/src/github.com/FMNSSun/plus-debug/server/server 192.168.181.133:5999'" -ssh-user="administrator" -ssh-password="admin1234." -ssh-process-name="server" -pcap-path-replay="/var/tmp/fuzz-packet-capture-0.pcap" -logfile-path="/var/tmp/fuzz-replay-log.txt" -replay-following
Replay an original packet capture from a pcap file and fuzz the values. | sudo \~/go-projects/src/github.com/sueesmar/pluzz/pluzz -dev="ens33" -target-ip="192.168.181.133" -target-port=5999 -local-port=10000 -packet-send-interval=100 -ssh-command="pkill server; tmux new -d -s FuzzSession '\~/go/src/github.com/FMNSSun/plus-debug/server/server 192.168.181.133:5999'" -ssh-user="administrator" -ssh-password="admin1234." -ssh-process-name="server" -pcap-path-fuzz="/var/tmp/fuzz-packet-capture-0.pcap" -logfile-path="/var/tmp/fuzz-capture-log.txt" -replay-following
