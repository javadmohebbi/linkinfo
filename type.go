// type.go defines core data structures used by the linkinfo discovery engine.
//
// DiscoveryInfo is the central model representing information extracted from
// LLDP (IEEE 802.1AB) and CDP (Cisco Discovery Protocol) packets, including
// system identity, port identifiers, VLAN assignments, and organizational TLVs.
package linkinfo

import "time"

const (
	lldpEthertype = 0x88cc
	cdpMulticast  = "01:00:0c:cc:cc:cc"
)

// DiscoveryInfo holds all parsed neighbor-discovery details extracted from
// LLDP and CDP frames. Each field corresponds to a specific TLV or metadata
// element commonly present in discovery protocols.
type DiscoveryInfo struct {
	// Proto identifies the discovery protocol used by the neighbor, either
	// "LLDP" (IEEE 802.1AB) or "CDP" (Cisco Discovery Protocol).
	Proto string

	// ChassisID is the unique device identifier advertised via TLV type 1.
	// This is often a MAC address but may also be a string or other format
	// depending on the subtype.
	ChassisID string

	// PortID identifies the physical or logical port on the neighbor device
	// that transmitted the LLDP/CDP frame (e.g., "Gi1/0/24").
	PortID string

	// PortDesc provides a human-readable description of the port, usually
	// TLV type 4 (LLDP) or a similar CDP TLV.
	PortDesc string

	// SystemName is the hostname of the advertising device (TLV type 5).
	SystemName string

	// SystemDesc carries software, hardware, or platform information about
	// the neighbor (TLV type 6).
	SystemDesc string

	// VLAN is the primary VLAN associated with the port. For LLDP, this is
	// often the PVID from IEEE 802.1 organizational TLVs; for CDP, it is the
	// Native VLAN (TLV type 0x000a).
	VLAN string

	// VoiceVLAN indicates the voice or media VLAN when provided by LLDP-MED
	// (OUI 00:12:bb, subtype 2) or CDP.
	VoiceVLAN string

	// TaggedVLANs lists additional 802.1Q VLAN IDs that are permitted/tagged
	// on the port, extracted from IEEE 802.1 organizational TLVs.
	TaggedVLANs []string

	// VLANNames contains optional mappings of VLAN IDs to descriptive names,
	// when advertised by the switch (e.g., TLV subtype 3 under OUI 00:80:c2).
	VLANNames []string

	// Platform identifies the hardware/software platform of a CDP device,
	// commonly indicating switch model or OS version.
	Platform string

	// RawDetails includes textual representations of TLVs that were not fully
	// interpreted, useful for debugging and extending protocol support.
	RawDetails []string

	// SourceMAC is the MAC address of the neighbor that sent the LLDP/CDP
	// frame, taken from the Ethernet header.
	SourceMAC string

	// Interface is the local interface on which this LLDP/CDP frame was
	// received.
	Interface string

	// DiscoveredAt is a timestamp marking when this discovery information was
	// observed by linkinfo.
	DiscoveredAt time.Time
}
