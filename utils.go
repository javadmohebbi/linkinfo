// utils.go contains helper functions for listing capture interfaces, formatting
// discovery output, and performing common string/ID transformations used by
// the linkinfo discovery engine.
package linkinfo

import (
	"encoding/hex"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/google/gopacket/pcap"
)

// ListInterfaces enumerates all network interfaces visible to the underlying
// pcap implementation and prints their names and IP addresses. This is used
// by the CLI to help the user select which interface to run LLDP/CDP discovery
// against. It relies on pcap.FindAllDevs, which is provided by libpcap (or
// Npcap on Windows).
func ListInterfaces() {
	devs, err := pcap.FindAllDevs()
	if err != nil {
		log.Fatalf("FindAllDevs failed: %v", err)
	}
	fmt.Println("Available interfaces:")
	for _, d := range devs {
		addrs := []string{}
		for _, a := range d.Addresses {
			addrs = append(addrs, a.IP.String())
		}
		fmt.Printf("- %s  (%s)\n", d.Name, strings.Join(addrs, ", "))
	}
}

// PrintDiscovery renders a human-readable, single-neighbor summary to stdout
// based on the contents of a DiscoveryInfo. It prints protocol, interface,
// timestamps, system identity, port details, VLAN information, and any raw TLV
// details that were not fully decoded.
func PrintDiscovery(i DiscoveryInfo) {
	// Use a simple ASCII banner to visually group each discovery result,
	// making it easier to read when running in continuous mode.
	fmt.Println("======================================")
	fmt.Printf("Protocol     : %s\n", i.Proto)
	fmt.Printf("Interface    : %s\n", i.Interface)
	fmt.Printf("Discovered   : %s\n", i.DiscoveredAt.Format(time.RFC3339))
	fmt.Printf("Source MAC   : %s\n", i.SourceMAC)
	if i.SystemName != "" {
		fmt.Printf("System Name  : %s\n", i.SystemName)
	}
	if i.Platform != "" {
		fmt.Printf("Platform     : %s\n", i.Platform)
	}
	if i.SystemDesc != "" {
		fmt.Printf("System Desc  : %s\n", i.SystemDesc)
	}
	if i.ChassisID != "" {
		fmt.Printf("Chassis ID   : %s\n", i.ChassisID)
	}
	if i.PortID != "" {
		fmt.Printf("Port ID      : %s\n", i.PortID)
	}
	if i.PortDesc != "" {
		fmt.Printf("Port Desc    : %s\n", i.PortDesc)
	}
	if i.VLAN != "" {
		fmt.Printf("VLAN         : %s\n", i.VLAN)
	}
	if i.VoiceVLAN != "" {
		fmt.Printf("Voice VLAN   : %s\n", i.VoiceVLAN)
	}
	if len(i.TaggedVLANs) > 0 {
		fmt.Printf("Tagged VLANs : %s\n", strings.Join(i.TaggedVLANs, ", "))
	}
	if len(i.VLANNames) > 0 {
		fmt.Println("VLAN Names   :")
		for _, n := range i.VLANNames {
			fmt.Printf("  - %s\n", n)
		}
	}
	if len(i.RawDetails) > 0 {
		fmt.Println("Extra TLVs   :")
		for _, line := range i.RawDetails {
			fmt.Printf("  - %s\n", line)
		}
	}
	fmt.Println("======================================")
}

// appendUnique appends values to a slice of strings, skipping duplicates while
// preserving the original order. It is used to accumulate VLAN IDs and other
// collections where repeated entries are not useful.
func appendUnique(dst []string, vals ...string) []string {
	// For each candidate value, perform a linear scan of the destination slice
	// to check if it is already present before appending.
	for _, v := range vals {
		found := false
		for _, existing := range dst {
			if existing == v {
				found = true
				break
			}
		}
		if !found {
			dst = append(dst, v)
		}
	}
	return dst
}

// formatID converts an LLDP ChassisID/PortID value into a human-readable
// string. The first byte is an LLDP subtype (see IEEE 802.1AB), which
// determines how the remaining bytes should be interpreted (e.g., MAC address,
// network address, or interface name).
func formatID(sub byte, id []byte) string {
	switch sub {
	case 4:
		// Subtype 4 indicates that the identifier is a MAC address.
		return formatMAC(id)
	default:
		// For most other subtypes, the identifier is encoded as a string (for
		// example, an ifName such as "Ethernet3/21"). If the bytes do not
		// decode to a printable string, fall back to a hex representation.
		s := strings.TrimSpace(string(id))
		if s == "" {
			return hex.EncodeToString(id)
		}
		return s
	}
}

// formatMAC converts a raw MAC address byte slice into the conventional
// colon-separated hexadecimal notation (e.g., "00:11:22:33:44:55").
func formatMAC(b []byte) string {
	// Format each byte as a two-digit hexadecimal number and join them with
	// colons to produce a standard MAC address string.
	parts := make([]string, len(b))
	for i, v := range b {
		parts[i] = fmt.Sprintf("%02x", v)
	}
	return strings.Join(parts, ":")
}
