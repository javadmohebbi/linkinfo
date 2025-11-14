package linkinfo

import (
	"encoding/hex"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/google/gopacket/pcap"
)

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

func PrintDiscovery(i DiscoveryInfo) {
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

func appendUnique(dst []string, vals ...string) []string {
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

func formatID(sub byte, id []byte) string {
	switch sub {
	case 4: // MAC address
		return formatMAC(id)
	default:
		// Often it's an ASCII string (interface name, etc.)
		s := strings.TrimSpace(string(id))
		if s == "" {
			return hex.EncodeToString(id)
		}
		return s
	}
}

func formatMAC(b []byte) string {
	parts := make([]string, len(b))
	for i, v := range b {
		parts[i] = fmt.Sprintf("%02x", v)
	}
	return strings.Join(parts, ":")
}
