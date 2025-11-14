// lldp_parser.go contains helpers for decoding Link Layer Discovery Protocol
// (LLDP) frames into the DiscoveryInfo structure used by the linkinfo tool.
//
// LLDP is a vendor-neutral Layer 2 discovery protocol defined in IEEE 802.1AB.
// It uses a sequence of Type-Length-Value (TLV) elements to advertise
// information such as chassis ID, port ID, system name, capabilities, and
// optional organizational extensions (for example, VLAN information and
// LLDP-MED). The base specification is:
// https://standards.ieee.org/ieee/802.1AB/6812/
// https://learningnetwork.cisco.com/s/article/link-layer-discovery-protocol-lldp-x

package linkinfo

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
)

// parseLLDP decodes an LLDPDU (Link Layer Discovery Protocol Data Unit) from
// the provided byte slice and populates the supplied DiscoveryInfo. The input
// is expected to start at the beginning of the LLDPDU payload (i.e., directly
// after the Ethernet header and 0x88cc EtherType) and consists of a sequence of
// TLVs:
//
//   - Each TLV begins with a 2-byte header:
//   - 7-bit Type   (bits 15..9)
//   - 9-bit Length (bits 8..0)
//   - The header is followed by `Length` bytes of value.
//
// Mandatory TLVs include Chassis ID, Port ID, and TTL. Optional TLVs carry
// system name/description, capabilities, management address, and
// organizationally specific data (type 127), which this parser delegates to
// parseLLDPOrgTLV.
func parseLLDP(b []byte, info *DiscoveryInfo) bool {
	if len(b) < 4 {
		return false
	}

	// Mark this discovery entry as originating from LLDP rather than CDP.
	info.Proto = "LLDP"

	for len(b) >= 2 {
		// Read the 2-byte TLV header: 7-bit type and 9-bit length.

		// The upper 7 bits encode the TLV type; the lower 9 bits encode the
		// length of the value field in bytes.
		h := binary.BigEndian.Uint16(b[:2])
		t := uint8(h >> 9)
		l := int(h & 0x1ff)

		// Type 0 is the "End of LLDPDU" marker and indicates that no further
		// TLVs are present for this frame.
		if t == 0 { // End of LLDPDU
			break
		}

		// Sanity check: ensure the buffer still contains the full TLV before
		// attempting to slice out the value.
		if len(b) < 2+l {
			break
		}

		// Slice out the TLV value portion, excluding the 2-byte header.
		val := b[2 : 2+l]

		switch t {
		case 1: // Chassis ID (unique identifier for the device, e.g., MAC)
			if len(val) > 1 {
				sub := val[0]
				id := val[1:]
				info.ChassisID = formatID(sub, id)
			}
		case 2: // Port ID (identifier for the port sending the LLDPDU)
			if len(val) > 1 {
				sub := val[0]
				id := val[1:]
				info.PortID = formatID(sub, id)
			}
		case 3: // TTL (time-to-live in seconds for the advertised information)
			if len(val) == 2 {
				ttl := binary.BigEndian.Uint16(val)
				info.RawDetails = append(info.RawDetails, fmt.Sprintf("TTL=%d", ttl))
			}
		case 4: // Port Description (human-readable description of the port)
			info.PortDesc = string(val)
		case 5: // System Name (typically the switch/host name)
			info.SystemName = string(val)
		case 6: // System Description (OS, firmware, platform details)
			info.SystemDesc = string(val)
		case 7: // System Capabilities (bitmask of what the device can do and what is enabled)
			if len(val) >= 4 {
				supported := binary.BigEndian.Uint16(val[0:2])
				enabled := binary.BigEndian.Uint16(val[2:4])
				info.RawDetails = append(info.RawDetails,
					fmt.Sprintf("SysCaps supported=0x%04x enabled=0x%04x", supported, enabled))
			}
		case 8: // Management Address (IP or other address used to manage the device)
			// We could fully decode; for now we just keep hex + try simple IPv4/IPv6 if present.
			info.RawDetails = append(info.RawDetails,
				fmt.Sprintf("MgmtAddr=%s", hex.EncodeToString(val)))
		case 127: // Organizationally Specific TLV (VLANs, LLDP-MED, etc.)
			parseLLDPOrgTLV(val, info)
		default:
			// Store unknown TLVs as basic info for debugging and for extending
			// the parser later with additional LLDP features.
			info.RawDetails = append(info.RawDetails,
				fmt.Sprintf("TLV type %d len %d", t, l))
		}

		b = b[2+l:]
	}

	// Consider the decode successful if at least one of the core identity
	// fields (port, system name, chassis) has been populated.
	return info.PortID != "" || info.SystemName != "" || info.ChassisID != ""
}

// parseLLDPOrgTLV handles organizationally specific LLDP TLVs (type 127).
// These TLVs are identified by a 3-byte Organizationally Unique Identifier
// (OUI) followed by a 1-byte subtype and a variable-length payload. Common
// OUIs include:
//   - 00:80:c2 – IEEE 802.1 (often used for VLAN-related information)
//   - 00:12:bb – LLDP-MED (Media Endpoint Discovery), used by IP phones to
//     learn voice VLANs and network policies.
//
// This helper interprets VLAN-related TLVs (PVID, tagged VLANs, VLAN names) and
// LLDP-MED network policy TLVs to populate VLAN, VoiceVLAN, TaggedVLANs, and
// VLANNames in DiscoveryInfo. Unknown OUIs and subtypes are logged to
// RawDetails for troubleshooting and future extension.
func parseLLDPOrgTLV(val []byte, info *DiscoveryInfo) {
	// Require at least 4 bytes to hold the OUI (3 bytes) and subtype (1 byte).
	if len(val) < 4 {
		return
	}

	// Decode the OUI and subtype, then treat the remaining bytes as the
	// organization-specific payload.
	oui := fmt.Sprintf("%02x:%02x:%02x", val[0], val[1], val[2])
	subtype := val[3]
	data := val[4:]

	// IEEE 802.1 OUI: commonly used for VLAN-related TLVs (PVID, VLAN names,
	// and lists of tagged VLANs).
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

	// LLDP-MED OUI: used by endpoints such as IP phones to learn voice VLANs
	// and QoS/network policy parameters.
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
		// Unknown organizational TLV; record the OUI and subtype so that
		// behavior can be analyzed from captures and support can be added
		// later if needed.
		info.RawDetails = append(info.RawDetails,
			fmt.Sprintf("OrgTLV OUI=%s subtype=%d len=%d", oui, subtype, len(data)))
	}
}
