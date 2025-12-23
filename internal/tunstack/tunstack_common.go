package tunstack

import (
	"encoding/binary"
	"fmt"
	"net"
)

// HandlerFunc is called when a new connection/stream is established.
type HandlerFunc func(conn net.Conn, target string, protocol string)

// Stack is defined in platform-specific files (with_gvisor or stub)

// FlowKey represents a 5-tuple flow identifier for stream multiplexing
type FlowKey struct {
	SrcIP     [16]byte
	DstIP     [16]byte
	SrcPort   uint16
	DstPort   uint16
	Proto     uint8
	IPVersion uint8
}

// BuildFlowKey строит 5‑tuple для UDP V2 STREAM‑mux на сервере по сырому IP‑пакету
// из TUN (base в cmd/server/main.go). Если парсинг не удался, возвращает (nil, false).
func BuildFlowKey(pkt []byte) (*FlowKey, bool) {
	if len(pkt) < 1 {
		return nil, false
	}

	var fk FlowKey
	ipVersion := (pkt[0] >> 4) & 0x0F
	fk.IPVersion = uint8(ipVersion)

	switch ipVersion {
	case 4:
		// IPv4: минимальный заголовок 20 байт.
		if len(pkt) < 20 {
			return nil, false
		}
		ihl := int(pkt[0]&0x0F) * 4
		if ihl < 20 || len(pkt) < ihl {
			return nil, false
		}
		proto := pkt[9]
		fk.Proto = proto

		// Src/Dst IP в первых 4 байтах каждого массива (остальное нули).
		copy(fk.SrcIP[0:4], pkt[12:16])
		copy(fk.DstIP[0:4], pkt[16:20])

		// Порты только для TCP/UDP.
		if (proto == 6 || proto == 17) && len(pkt) >= ihl+4 {
			trans := pkt[ihl:]
			fk.SrcPort = binary.BigEndian.Uint16(trans[0:2])
			fk.DstPort = binary.BigEndian.Uint16(trans[2:4])
		}

	case 6:
		// IPv6: базовый заголовок 40 байт.
		if len(pkt) < 40 {
			return nil, false
		}
		nextHeader := pkt[6]
		fk.Proto = nextHeader

		copy(fk.SrcIP[:], pkt[8:24])
		copy(fk.DstIP[:], pkt[24:40])

		if (nextHeader == 6 || nextHeader == 17) && len(pkt) >= 40+4 {
			trans := pkt[40:]
			fk.SrcPort = binary.BigEndian.Uint16(trans[0:2])
			fk.DstPort = binary.BigEndian.Uint16(trans[2:4])
		}

	default:
		// Неизвестная версия IP.
		return nil, false
	}

	return &fk, true
}

// String is used only for debug logging in server; keep a compact
// representation to avoid changing any routing logic.
func (f FlowKey) String() string {
	return fmt.Sprintf("%x:%d->%x:%d proto=%d v=%d",
		f.SrcIP, f.SrcPort, f.DstIP, f.DstPort, f.Proto, f.IPVersion)
}

