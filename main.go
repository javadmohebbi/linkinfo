package main

import (
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

const (
	lldpEthertype = 0x88cc
	cdpMulticast  = "01:00:0c:cc:cc:cc"
)

type DiscoveryInfo struct {
	Proto        string
	ChassisID    string
	PortID       string
	PortDesc     string
	SystemName   string
	SystemDesc   string
	VLAN         string   // Primary / native / PVID VLAN
	VoiceVLAN    string   // Voice VLAN (LLDP-MED / CDP)
	TaggedVLANs  []string // Additional tagged VLANs (LLDP org TLVs)
	VLANNames    []string // VLAN ID + Name pairs, human-friendly
	Platform     string
	RawDetails   []string
	SourceMAC    string
	Interface    string
	DiscoveredAt time.Time
}

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

func listInterfaces() {
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

// decodeDiscovery figures out if a packet is LLDP or CDP, parses it, and returns DiscoveryInfo.
func decodeDiscovery(pkt gopacket.Packet, iface string) (DiscoveryInfo, bool) {
	ethLayer := pkt.Layer(layers.LayerTypeEthernet)
	if ethLayer == nil {
		return DiscoveryInfo{}, false
	}
	eth := ethLayer.(*layers.Ethernet)

	info := DiscoveryInfo{
		SourceMAC:    eth.SrcMAC.String(),
		Interface:    iface,
		DiscoveredAt: time.Now(),
	}

	switch eth.EthernetType {
	case lldpEthertype:
		payload := eth.Payload
		ok := parseLLDP(payload, &info)
		if !ok {
			return DiscoveryInfo{}, false
		}
		return info, true
	default:
		// Maybe CDP (destination multicast)
		if strings.EqualFold(eth.DstMAC.String(), cdpMulticast) {
			ok := parseCDP(eth.Payload, &info)
			if !ok {
				return DiscoveryInfo{}, false
			}
			return info, true
		}
	}

	return DiscoveryInfo{}, false
}

func printDiscovery(i DiscoveryInfo) {
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

// ---------------- LLDP PARSER ----------------

// LLDP TLV: 2-byte header (7 bits type, 9 bits length), then value.
func parseLLDP(b []byte, info *DiscoveryInfo) bool {
	if len(b) < 4 {
		return false
	}
	info.Proto = "LLDP"

	for len(b) >= 2 {
		h := binary.BigEndian.Uint16(b[:2])
		t := uint8(h >> 9)
		l := int(h & 0x1ff)
		if t == 0 { // End of LLDPDU
			break
		}
		if len(b) < 2+l {
			break
		}
		val := b[2 : 2+l]

		switch t {
		case 1: // Chassis ID
			if len(val) > 1 {
				sub := val[0]
				id := val[1:]
				info.ChassisID = formatID(sub, id)
			}
		case 2: // Port ID
			if len(val) > 1 {
				sub := val[0]
				id := val[1:]
				info.PortID = formatID(sub, id)
			}
		case 3: // TTL
			if len(val) == 2 {
				ttl := binary.BigEndian.Uint16(val)
				info.RawDetails = append(info.RawDetails, fmt.Sprintf("TTL=%d", ttl))
			}
		case 4: // Port Description
			info.PortDesc = string(val)
		case 5: // System Name
			info.SystemName = string(val)
		case 6: // System Description
			info.SystemDesc = string(val)
		case 7: // System Capabilities
			if len(val) >= 4 {
				supported := binary.BigEndian.Uint16(val[0:2])
				enabled := binary.BigEndian.Uint16(val[2:4])
				info.RawDetails = append(info.RawDetails,
					fmt.Sprintf("SysCaps supported=0x%04x enabled=0x%04x", supported, enabled))
			}
		case 8: // Management Address
			// We could fully decode; for now we just keep hex + try simple IPv4/IPv6 if present.
			info.RawDetails = append(info.RawDetails,
				fmt.Sprintf("MgmtAddr=%s", hex.EncodeToString(val)))
		case 127: // Organizationally Specific TLV (VLANs, LLDP-MED, etc.)
			parseLLDPOrgTLV(val, info)
		default:
			// Store unknown TLVs as basic info for debugging
			info.RawDetails = append(info.RawDetails,
				fmt.Sprintf("TLV type %d len %d", t, l))
		}

		b = b[2+l:]
	}
	return info.PortID != "" || info.SystemName != "" || info.ChassisID != ""
}

// Handle LLDP organizational TLVs (type 127)
func parseLLDPOrgTLV(val []byte, info *DiscoveryInfo) {
	if len(val) < 4 {
		return
	}
	oui := fmt.Sprintf("%02x:%02x:%02x", val[0], val[1], val[2])
	subtype := val[3]
	data := val[4:]

	switch oui {

	// IEEE 802.1 (VLAN-related TLVs)
	case "00:80:c2":
		switch subtype {
		case 1: // Port VLAN ID (PVID)
			if len(data) >= 2 {
				vlan := binary.BigEndian.Uint16(data[:2])
				info.VLAN = fmt.Sprintf("%d", vlan)
				info.RawDetails = append(info.RawDetails,
					fmt.Sprintf("PVID VLAN=%d", vlan))
			}
		case 2: // Port and Protocol VLAN ID (may contain multiple VLAN IDs)
			if len(data) >= 2 {
				var tagged []string
				for len(data) >= 2 {
					v := binary.BigEndian.Uint16(data[:2])
					if v != 0 {
						tagged = append(tagged, fmt.Sprintf("%d", v))
					}
					if len(data) > 2 {
						data = data[2:]
					} else {
						break
					}
				}
				if len(tagged) > 0 {
					info.TaggedVLANs = appendUnique(info.TaggedVLANs, tagged...)
					info.RawDetails = append(info.RawDetails,
						fmt.Sprintf("Tagged VLANs=%s", strings.Join(tagged, ",")))
				}
			}
		case 3: // VLAN Name(s)
			// Format (commonly used):
			// [2 bytes VLAN ID][1 byte name length][N bytes name] repeated
			tmp := data
			for len(tmp) >= 3 {
				vlanID := binary.BigEndian.Uint16(tmp[0:2])
				nameLen := int(tmp[2])
				if len(tmp) < 3+nameLen {
					break
				}
				name := string(tmp[3 : 3+nameLen])
				entry := fmt.Sprintf("VLAN %d = %s", vlanID, name)
				info.VLANNames = append(info.VLANNames, entry)
				info.RawDetails = append(info.RawDetails,
					fmt.Sprintf("VLANName %d=%q", vlanID, name))
				tmp = tmp[3+nameLen:]
			}
		default:
			info.RawDetails = append(info.RawDetails,
				fmt.Sprintf("OrgTLV IEEE802.1 OUI=%s subtype=%d len=%d", oui, subtype, len(data)))
		}

	// LLDP-MED (Voice VLAN and network policies)
	case "00:12:bb":
		// LLDP-MED Network Policy is subtype 2
		// Exact bit layout depends on vendor; we’ll use a common pattern:
		// data[0] = flags / application type etc.
		// data[1:3] = VLAN ID (most significant 12 bits typically used)
		// This may be vendor-dependent, but gives a useful VLAN for phones.
		if subtype == 2 && len(data) >= 3 {
			// Take 2 bytes from data[1:3] as VLAN ID (approximation)
			vlan := binary.BigEndian.Uint16(data[1:3])
			if vlan != 0 {
				info.VoiceVLAN = fmt.Sprintf("%d", vlan)
				info.RawDetails = append(info.RawDetails,
					fmt.Sprintf("LLDP-MED VoiceVLAN=%d", vlan))
			} else {
				info.RawDetails = append(info.RawDetails,
					fmt.Sprintf("LLDP-MED NetworkPolicy raw=%s", hex.EncodeToString(data)))
			}
		} else {
			info.RawDetails = append(info.RawDetails,
				fmt.Sprintf("LLDP-MED OUI=%s subtype=%d len=%d", oui, subtype, len(data)))
		}

	default:
		// Unknown org TLV, but we log it for debugging
		info.RawDetails = append(info.RawDetails,
			fmt.Sprintf("OrgTLV OUI=%s subtype=%d len=%d", oui, subtype, len(data)))
	}
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

// ---------------- CDP PARSER ----------------

// CDP: 802.3 + LLC + SNAP, then CDP header:
// [version(1) ttl(1) checksum(2)] [TLVs...]
// TLV: type(2) length(2) value(length-4)
func parseCDP(payload []byte, info *DiscoveryInfo) bool {
	info.Proto = "CDP"

	// Skip LLC+SNAP (typical) – 8 bytes: 3 LLC + 5 SNAP
	if len(payload) < 12 {
		return false
	}

	// In practice CDP header is usually right after LLC/SNAP, at offset 8.
	offset := 8
	if len(payload) < offset+4 {
		return false
	}
	cdp := payload[offset:]
	if len(cdp) < 4 {
		return false
	}

	// version := cdp[0]
	// ttl := cdp[1]
	// checksum := binary.BigEndian.Uint16(cdp[2:4])
	_ = cdp[0]
	_ = cdp[1]

	tlvs := cdp[4:]
	for len(tlvs) >= 4 {
		t := binary.BigEndian.Uint16(tlvs[0:2])
		l := int(binary.BigEndian.Uint16(tlvs[2:4]))
		if l < 4 || len(tlvs) < l {
			break
		}
		v := tlvs[4:l]

		switch t {
		case 0x0001: // Device ID
			info.SystemName = string(v)
		case 0x0003: // Port ID
			info.PortID = string(v)
		case 0x0006: // Platform
			info.Platform = string(v)
		case 0x000a: // Native VLAN
			if len(v) >= 2 {
				vlan := binary.BigEndian.Uint16(v)
				info.VLAN = fmt.Sprintf("%d", vlan)
			}
		default:
			info.RawDetails = append(info.RawDetails,
				fmt.Sprintf("TLV type 0x%04x len %d", t, l))
		}

		tlvs = tlvs[l:]
	}

	// If we got at least something meaningful, treat as valid
	return info.PortID != "" || info.SystemName != "" || info.Platform != "" || info.VLAN != "" || info.VoiceVLAN != ""
}
