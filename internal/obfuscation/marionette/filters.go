package marionette

import (
	"net"
)

// isLocalDiscovery checks if the packet is destined for local discovery (multicast/broadcast)
func isLocalDiscovery(data []byte) bool {
	if len(data) < 20 {
		return false
	}

	// Assume IPv4 first (Version is first 4 bits)
	version := data[0] >> 4

	if version == 4 {
		// IPv4 Destination IP is at offset 16
		dstIP := net.IP(data[16:20])

		// Check for link-local multicast (224.0.0.0/24)
		// mDNS is 224.0.0.251
		// SSDP is 239.255.255.250 (Organization-Local Scope, but used for UPnP)
		if dstIP.IsMulticast() {
			return true
		}
		if dstIP.IsLinkLocalMulticast() {
			return true
		}
		// SSDP specific check just in case
		if dstIP.Equal(net.ParseIP("239.255.255.250")) {
			return true
		}
		// Limited Broadcast
		if dstIP.Equal(net.IPv4bcast) {
			return true
		}
	} else if version == 6 {
		// IPv6 Destination IP is at offset 24
		if len(data) < 40 {
			return false
		}
		dstIP := net.IP(data[24:40])
		if dstIP.IsMulticast() {
			return true
		}
	}

	return false
}
