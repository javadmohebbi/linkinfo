package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

func main() {
	iface := flag.String("i", "", "Interface name to capture on (required unless -list)")
	list := flag.Bool("list", false, "List available interfaces and exit")
	continuous := flag.Bool("continuous", false, "Keep listening and print every LLDP/CDP frame")
	timeout := flag.Duration("timeout", 30*time.Second, "Stop after this duration if no frame received (ignored with -continuous)")

	flag.Parse()

	if *list {
		listInterfaces()
		return
	}

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
		case pkt, ok := <-packets:
			if !ok {
				fmt.Println("Packet source closed.")
				return
			}
			info, ok := decodeDiscovery(pkt, *iface)
			if !ok {
				continue
			}
			printDiscovery(info)
			if !*continuous {
				return
			}
		case <-time.After(500 * time.Millisecond):
			// Just loop again, to let timeout check happen
		}
	}
}
