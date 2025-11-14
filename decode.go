package linkinfo

import (
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// DecodeDiscovery figures out if a packet is LLDP or CDP, parses it, and returns DiscoveryInfo.
func DecodeDiscovery(pkt gopacket.Packet, iface string) (DiscoveryInfo, bool) {
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
