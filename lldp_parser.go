package linkinfo

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
)

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
