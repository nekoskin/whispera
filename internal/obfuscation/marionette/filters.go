package marionette

import (
	"encoding/binary"
	"net"
)

func isLocalDiscovery(data []byte) bool {
	if len(data) < 20 {
		return false
	}

	version := data[0] >> 4
	var protocol byte
	var dstIP net.IP
	var headerLen int

	switch version {
	case 4:
		headerLen = int(data[0]&0x0F) * 4
		if len(data) < headerLen {
			return false
		}
		protocol = data[9]
		dstIP = net.IP(data[16:20])
	case 6:
		if len(data) < 40 {
			return false
		}
		headerLen = 40
		protocol = data[6]
		dstIP = net.IP(data[24:40])
	default:
		return false
	}

	if dstIP.IsMulticast() || dstIP.IsLinkLocalMulticast() || dstIP.Equal(net.IPv4bcast) {
		return true
	}
	if dstIP.Equal(net.ParseIP("239.255.255.250")) {
		return true
	}

	if protocol == 17 {
		if len(data) < headerLen+4 {
			return false
		}
		udpBase := headerLen
		dstPort := binary.BigEndian.Uint16(data[udpBase+2 : udpBase+4])

		if dstPort == 1900 || dstPort == 5353 {
			return true
		}
	}

	return false
}
