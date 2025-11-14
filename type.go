package linkinfo

import "time"

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
