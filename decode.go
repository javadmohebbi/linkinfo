// decode.go provides the top-level packet classification logic for linkinfo.
//
// It receives raw Ethernet frames from gopacket, determines whether they carry
// LLDP (IEEE 802.1AB) or Cisco Discovery Protocol (CDP) data, and then delegates
// parsing to the appropriate protocol-specific helper. For LLDP, the protocol
// is defined in IEEE 802.1AB:
// https://standards.ieee.org/ieee/802.1AB/6812/
// https://learningnetwork.cisco.com/s/article/link-layer-discovery-protocol-lldp-x
package linkinfo

import (
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// DecodeDiscovery inspects a captured gopacket.Packet and attempts to interpret
// it as either an LLDP (IEEE 802.1AB) or CDP discovery frame. It extracts the
// Ethernet header, populates a DiscoveryInfo skeleton with metadata such as the
// source MAC address, interface name, and discovery timestamp, and then
// dispatches to the LLDP or CDP parser depending on the EtherType and
// destination MAC:
//
//   - LLDP frames are identified by EtherType 0x88cc.
//   - CDP frames are heuristically identified by the Cisco multicast
//     destination MAC 01:00:0c:cc:cc:cc.
//
// On success, it returns a populated DiscoveryInfo and true. If the packet does
// not look like LLDP or CDP, or if parsing fails, it returns a zero-valued
// DiscoveryInfo and false.
func DecodeDiscovery(pkt gopacket.Packet, iface string) (DiscoveryInfo, bool) {
	// Attempt to pull out the Ethernet layer; discovery protocols run directly
	// on top of Ethernet, so packets without an Ethernet header are ignored.
	ethLayer := pkt.Layer(layers.LayerTypeEthernet)

	// If there is no Ethernet layer, this is not a frame we can decode.
	if ethLayer == nil {
		return DiscoveryInfo{}, false
	}

	// Safe type assertion: gopacket guarantees LayerTypeEthernet yields
	// *layers.Ethernet when present.
	eth := ethLayer.(*layers.Ethernet)

	// Seed a DiscoveryInfo with generic metadata before protocol-specific
	// parsing. LLDP/CDP parsers will enrich this struct with neighbor details.
	info := DiscoveryInfo{
		SourceMAC:    eth.SrcMAC.String(),
		Interface:    iface,
		DiscoveredAt: time.Now(),
	}

	// Inspect the EtherType to decide whether this is LLDP traffic. CDP does
	// not use a dedicated EtherType; it is detected by its multicast MAC.
	switch eth.EthernetType {
	case lldpEthertype:
		// LLDP uses EtherType 0x88cc and places its TLVs directly in the payload.
		payload := eth.Payload

		// Delegate parsing of the LLDP payload to the protocol-specific helper.
		ok := parseLLDP(payload, &info)
		if !ok {
			return DiscoveryInfo{}, false
		}
		return info, true
	default:
		// CDP frames are identified by their destination MAC address rather
		// than a unique EtherType. If the destination matches the Cisco CDP
		// multicast, try to decode the payload as CDP.
		if strings.EqualFold(eth.DstMAC.String(), cdpMulticast) {
			ok := parseCDP(eth.Payload, &info)
			if !ok {
				return DiscoveryInfo{}, false
			}
			return info, true
		}
	}

	// If neither LLDP nor CDP heuristics match, signal that this packet does
	// not contain recognizable discovery information.
	return DiscoveryInfo{}, false
}
