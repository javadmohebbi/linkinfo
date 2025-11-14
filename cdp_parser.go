package linkinfo

import (
	"encoding/binary"
	"fmt"
)

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
