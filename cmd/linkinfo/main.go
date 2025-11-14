// Package main provides the CLI entry point for the linkinfo tool.
//
// It parses command-line flags, opens a packet capture on the selected
// network interface, and delegates LLDP/CDP discovery and output formatting
// to the core linkinfo package.
package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"github.com/javadmohebbi/linkinfo"
)

// main parses command-line flags, validates the selected interface, configures
// a packet capture with a BPF filter for LLDP and CDP traffic, and then
// dispatches packets to the linkinfo package for decoding and display. It can
// either exit after the first discovery or run continuously based on flags.
func main() {
	// Command-line flags:
	//   -i <interface>   : Select the network interface to capture on.
	//   -list            : List all available interfaces and exit.
	//   -continuous      : Keep listening and print all LLDP/CDP frames.
	//   -timeout <dur>   : Stop after the specified duration if not in continuous mode.
	iface := flag.String("i", "", "Interface name to capture on (required unless -list)")
	list := flag.Bool("list", false, "List available interfaces and exit")
	continuous := flag.Bool("continuous", false, "Keep listening and print every LLDP/CDP frame")
	timeout := flag.Duration("timeout", 30*time.Second, "Stop after this duration if no frame received (ignored with -continuous)")

	// Parse all registered command‑line flags.
	flag.Parse()

	// If -list is provided, enumerate all interfaces and exit.
	if *list {
		linkinfo.ListInterfaces()
		return
	}

	// Require an interface unless listing interfaces only.
	if *iface == "" {
		fmt.Println("You must specify -i <interface> or use -list")
		os.Exit(1)
	}

	handle, err := pcap.OpenLive(*iface, 1600, true, pcap.BlockForever)
	if err != nil {
		log.Fatalf("pcap OpenLive failed on %s: %v", *iface, err)
	}
	defer handle.Close()

	// Filter: LLDP ethertype OR CDP multicast destination
	// LLDP: ether proto 0x88cc
	// CDP: dst host 01:00:0c:cc:cc:cc
	bpf := "ether proto 0x88cc or ether dst 01:00:0c:cc:cc:cc"
	if err := handle.SetBPFFilter(bpf); err != nil {
		log.Fatalf("Failed to set BPF filter: %v", err)
	}
	fmt.Printf("Listening on %s with filter: %q\n", *iface, bpf)

	packetSrc := gopacket.NewPacketSource(handle, handle.LinkType())
	// packets is a channel that yields packets as they arrive from the NIC.
	packets := packetSrc.Packets()

	var deadline time.Time
	if !*continuous {
		deadline = time.Now().Add(*timeout)
	}

	for {
		if !*continuous && !deadline.IsZero() && time.Now().After(deadline) {
			fmt.Println("Timeout reached, no LLDP/CDP frames seen.")
			return
		}

		select {
		// Handle incoming packets from the capture source.
		case pkt, ok := <-packets:
			// If the packets channel closes, the capture handle was terminated.
			if !ok {
				fmt.Println("Packet source closed.")
				return
			}
			// Forward raw packet bytes to the core decoder.
			// It determines whether the packet contains LLDP/CDP info.
			info, ok := linkinfo.DecodeDiscovery(pkt, *iface)
			if !ok {
				continue
			}
			linkinfo.PrintDiscovery(info)
			// Exit immediately after first successful discovery when not in continuous mode.
			if !*continuous {
				return
			}
		// Periodic wake‑up to allow timeout checks without blocking.
		case <-time.After(500 * time.Millisecond):
			// Just loop again, to let timeout check happen
		}
	}
}
