// cdp_parser.go contains helpers for decoding Cisco Discovery Protocol (CDP)
// frames into the DiscoveryInfo structure used by the linkinfo tool.
//
// CDP is a Cisco-proprietary Layer 2 discovery protocol that runs directly on
// top of 802.3 with an LLC/SNAP header. The encoding is described in Cisco's
// "Cisco Discovery Protocol" documentation, for example:
// https://learningnetwork.cisco.com/s/article/cisco-discovery-protocol-cdp-x
package linkinfo

import (
	"encoding/binary"
	"fmt"
)

// parseCDP attempts to decode a Cisco Discovery Protocol (CDP) payload into the
// provided DiscoveryInfo. It expects the input slice to start at the 802.3
// payload and handles the following structure:
//   - 802.3 header (handled by gopacket)
//   - LLC + SNAP header (8 bytes: 3-byte LLC, 5-byte SNAP with OUI 0x00000c
//     and protocol ID 0x2000)
//   - CDP header:
//   - version:   1 byte
//   - TTL:       1 byte
//   - checksum:  2 bytes (big-endian)
//   - TLV list:
//   - type:      2 bytes
//   - length:    2 bytes (total TLV length, including type/length)
//   - value:     (length - 4) bytes
//
// Only a subset of TLVs is interpreted (Device ID, Port ID, Platform, Native
// VLAN). Unknown TLVs are recorded in RawDetails for debugging.
func parseCDP(payload []byte, info *DiscoveryInfo) bool {
	// Mark this discovery entry as originating from CDP rather than LLDP.
	info.Proto = "CDP"

	// Require at least enough bytes to contain LLC+SNAP and the beginning of
	// the CDP header; otherwise this cannot be a valid CDP frame.
	if len(payload) < 12 {
		return false
	}

	// CDP packets are carried over 802.3 with an 8-byte LLC+SNAP shim.
	// We skip those 8 bytes to land on the CDP header (version/TTL/checksum).
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

	// Skip the fixed 4-byte CDP header and iterate over the TLV list.
	tlvs := cdp[4:]
	for len(tlvs) >= 4 {
		// Each TLV starts with a 2-byte type and 2-byte length (including the
		// type/length fields themselves), followed by the value.
		t := binary.BigEndian.Uint16(tlvs[0:2])
		l := int(binary.BigEndian.Uint16(tlvs[2:4]))

		// Sanity check: a TLV must be at least 4 bytes (type+length) and the
		// declared length must not run past the remaining buffer.
		if l < 4 || len(tlvs) < l {
			break
		}
		v := tlvs[4:l]

		switch t {
		case 0x0001: // Device ID (typically the switch hostname)
			info.SystemName = string(v)
		case 0x0003: // Port ID (e.g., "GigabitEthernet1/0/24")
			info.PortID = string(v)
		case 0x0006: // Platform (hardware/software identifier, e.g., switch model)
			info.Platform = string(v)
		case 0x000a: // Native VLAN (untagged VLAN for this port)
			if len(v) >= 2 {
				vlan := binary.BigEndian.Uint16(v)
				info.VLAN = fmt.Sprintf("%d", vlan)
			}
		default:
			// Preserve unknown TLVs for inspection; this is useful when
			// extending support for additional CDP fields in the future.
			info.RawDetails = append(info.RawDetails,
				fmt.Sprintf("TLV type 0x%04x len %d", t, l))
		}

		tlvs = tlvs[l:]
	}

	// Consider the decode successful if we populated at least one key field.
	// This avoids treating random frames as valid CDP just because the filter
	// allowed them through.
	return info.PortID != "" || info.SystemName != "" || info.Platform != "" || info.VLAN != "" || info.VoiceVLAN != ""
}
