package main

import (
	"net"
	"strconv"

	routingpkg "whispera/internal/routing"
)

// extractPacketInfo извлекает информацию о пакете для routing engine
func extractPacketInfo(ipPacket []byte, srcIP, dstIP net.IP) *routingpkg.PacketInfo {
	if len(ipPacket) < 20 {
		return nil
	}

	version := (ipPacket[0] >> 4) & 0x0F
	var protocol string
	var srcPort, dstPort uint16

	switch version {
	case 4:
		if len(ipPacket) < 20 {
			return nil
		}
		ipProtocol := ipPacket[9]
		switch ipProtocol {
		case 6:
			protocol = "tcp"
			if len(ipPacket) >= 20 {
				srcPort = uint16(ipPacket[20])<<8 | uint16(ipPacket[21])
				dstPort = uint16(ipPacket[22])<<8 | uint16(ipPacket[23])
			}
		case 17:
			protocol = "udp"
			if len(ipPacket) >= 20 {
				srcPort = uint16(ipPacket[20])<<8 | uint16(ipPacket[21])
				dstPort = uint16(ipPacket[22])<<8 | uint16(ipPacket[23])
			}
		case 1:
			protocol = "icmp"
		default:
			protocol = "unknown"
		}
	case 6:
		if len(ipPacket) < 40 {
			return nil
		}
		nextHeader := ipPacket[6]
		switch nextHeader {
		case 6:
			protocol = "tcp"
			if len(ipPacket) >= 40 {
				srcPort = uint16(ipPacket[40])<<8 | uint16(ipPacket[41])
				dstPort = uint16(ipPacket[42])<<8 | uint16(ipPacket[43])
			}
		case 17:
			protocol = "udp"
			if len(ipPacket) >= 40 {
				srcPort = uint16(ipPacket[40])<<8 | uint16(ipPacket[41])
				dstPort = uint16(ipPacket[42])<<8 | uint16(ipPacket[43])
			}
		case 58:
			protocol = "icmpv6"
		default:
			protocol = "unknown"
		}
	default:
		return nil
	}

	// Пытаемся получить домен из кэша routing engine
	var domain string
	if routingEngine != nil {
		// Проверяем кэш доменов (обратный lookup по IP)
		domain = routingEngine.GetDomainFromCache(dstIP)
		
		// Если домен не найден в кэше, проверяем, является ли IP Fake-IP
		// и пытаемся получить домен из FakeIPPool (если он есть на сервере)
		if domain == "" {
			domain = routingEngine.LookupFakeIP(dstIP)
		}
	}

	return &routingpkg.PacketInfo{
		SrcIP:    srcIP,
		DstIP:    dstIP,
		SrcPort:  srcPort,
		DstPort:  dstPort,
		Protocol: protocol,
		Domain:   domain,
	}
}

// applyRoutingRules применяет routing rules к пакету и возвращает outbound tag
// ОПТИМИЗИРОВАНО: Соответствует подходу Clash Verge Rev и Prizrak-Box (Mihomo/Clash Meta)
// - всегда маршрутизируем, если нет явного блокирования
// - всегда есть default outbound (как в Clash/Mihomo)
func applyRoutingRules(info *routingpkg.PacketInfo) (outboundTag string, balancerTag string, shouldRoute bool) {
	if routingEngine == nil || info == nil {
		return "", "", true // По умолчанию маршрутизируем (как в Clash/Mihomo/Prizrak-Box)
	}

	outboundTag, balancerTag, matched := routingEngine.Route(info)
	if matched {
		// Правило найдено - используем указанный outbound
		// Если outboundTag пустой, это означает "default" - используем первую активную сессию
		// (как в Prizrak-Box/Mihomo - всегда есть default outbound)
		return outboundTag, balancerTag, true
	}

	// Правило не найдено - используем дефолтный маршрут (как в Clash Verge Rev и Prizrak-Box)
	// В Clash/Mihomo всегда есть default outbound, который используется если правила не сработали
	// Это соответствует поведению Prizrak-Box (Mihomo ядро)
	return "", "", true
}

// getProtocolName возвращает имя протокола по номеру
func getProtocolName(protocol uint8) string {
	switch protocol {
	case 6:
		return "tcp"
	case 17:
		return "udp"
	case 1:
		return "icmp"
	case 58:
		return "icmpv6"
	default:
		return "unknown"
	}
}

// parsePortRange парсит диапазон портов (например, "1000-2000")
func parsePortRange(portRange string) (min, max uint16, ok bool) {
	if portRange == "" {
		return 0, 0, false
	}

	parts := splitPortRange(portRange)
	if len(parts) != 2 {
		return 0, 0, false
	}

	minVal, err1 := strconv.ParseUint(parts[0], 10, 16)
	maxVal, err2 := strconv.ParseUint(parts[1], 10, 16)

	if err1 != nil || err2 != nil {
		return 0, 0, false
	}

	return uint16(minVal), uint16(maxVal), true
}

// splitPortRange разделяет строку диапазона портов
func splitPortRange(portRange string) []string {
	// Поддержка форматов: "1000-2000", "1000,2000", "1000:2000"
	if idx := indexOf(portRange, '-'); idx >= 0 {
		return []string{portRange[:idx], portRange[idx+1:]}
	}
	if idx := indexOf(portRange, ':'); idx >= 0 {
		return []string{portRange[:idx], portRange[idx+1:]}
	}
	return []string{portRange}
}

// indexOf возвращает индекс первого вхождения символа
func indexOf(s string, c byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == c {
			return i
		}
	}
	return -1
}

