package routing

import (
	"net"
)

// IPv6FakeIPRange - диапазон IPv6 Fake-IP (используется fc00::/7 для уникальных локальных адресов)
// В реальности можно использовать любой приватный диапазон IPv6
var (
	// IPv6FakeIPRangeStart - начало диапазона IPv6 Fake-IP
	// Используем fc00::/7 (Unique Local Addresses) для Fake-IP
	IPv6FakeIPRangeStart = net.ParseIP("fc00::1")
	// IPv6FakeIPRangeEnd - конец диапазона IPv6 Fake-IP
	IPv6FakeIPRangeEnd = net.ParseIP("fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff")
	// IPv6FakeIPNetwork - сеть для IPv6 Fake-IP
	IPv6FakeIPNetwork = &net.IPNet{
		IP:   net.ParseIP("fc00::"),
		Mask: net.CIDRMask(7, 128),
	}
)

// IsIPv6FakeIP проверяет, является ли IPv6 адрес Fake-IP
func IsIPv6FakeIP(ip net.IP) bool {
	if ip == nil {
		return false
	}
	
	ip6 := ip.To16()
	if ip6 == nil {
		return false
	}
	
	// Проверяем, что это не IPv4-mapped IPv6
	if ip.To4() != nil {
		return false
	}
	
	// Проверяем, находится ли IP в диапазоне fc00::/7
	return IPv6FakeIPNetwork.Contains(ip6)
}

// IsIPv4FakeIP проверяет, является ли IPv4 адрес Fake-IP (198.18.0.0/15)
func IsIPv4FakeIP(ip net.IP) bool {
	if ip == nil {
		return false
	}
	
	ip4 := ip.To4()
	if ip4 == nil {
		return false
	}
	
	// Проверяем диапазон 198.18.0.0/15 (RFC 2544)
	return ip4[0] == 198 && (ip4[1] == 18 || ip4[1] == 19)
}

// IsFakeIP проверяет, является ли IP (IPv4 или IPv6) Fake-IP
func IsFakeIP(ip net.IP) bool {
	if ip == nil {
		return false
	}
	
	// Сначала проверяем IPv4
	if IsIPv4FakeIP(ip) {
		return true
	}
	
	// Затем проверяем IPv6
	return IsIPv6FakeIP(ip)
}

// NormalizeIP нормализует IP адрес (конвертирует IPv4-mapped IPv6 в IPv4)
func NormalizeIP(ip net.IP) net.IP {
	if ip == nil {
		return nil
	}
	
	// Если это IPv4-mapped IPv6 (::ffff:x.x.x.x), возвращаем IPv4
	if ip4 := ip.To4(); ip4 != nil && len(ip) == 16 {
		// Проверяем, является ли это IPv4-mapped IPv6
		if ip[0] == 0 && ip[1] == 0 && ip[2] == 0 && ip[3] == 0 &&
			ip[4] == 0 && ip[5] == 0 && ip[6] == 0 && ip[7] == 0 &&
			ip[8] == 0 && ip[9] == 0 && ip[10] == 0xFF && ip[11] == 0xFF {
			return ip4
		}
		return ip4
	}
	
	// Возвращаем как есть (IPv6 или обычный IPv4)
	return ip
}

// CompareIP сравнивает два IP адреса (IPv4 или IPv6)
// Возвращает: -1 если a < b, 0 если a == b, 1 если a > b
func CompareIP(a, b net.IP) int {
	if a == nil || b == nil {
		return 0
	}
	
	// Нормализуем IP адреса
	a = NormalizeIP(a)
	b = NormalizeIP(b)
	
	// Если один IPv4, а другой IPv6, IPv4 считается меньше
	aIsIPv4 := a.To4() != nil && len(a) == 4
	bIsIPv4 := b.To4() != nil && len(b) == 4
	
	if aIsIPv4 && !bIsIPv4 {
		return -1
	}
	if !aIsIPv4 && bIsIPv4 {
		return 1
	}
	
	// Оба одного типа - сравниваем побайтово
	lenA := len(a)
	lenB := len(b)
	minLen := lenA
	if lenB < minLen {
		minLen = lenB
	}
	
	for i := 0; i < minLen; i++ {
		if a[i] < b[i] {
			return -1
		}
		if a[i] > b[i] {
			return 1
		}
	}
	
	// Если длины разные, более короткий считается меньше
	if lenA < lenB {
		return -1
	}
	if lenA > lenB {
		return 1
	}
	
	return 0
}

// IPContains проверяет, содержит ли сеть IP адрес (поддержка IPv4 и IPv6)
func IPContains(network *net.IPNet, ip net.IP) bool {
	if network == nil || ip == nil {
		return false
	}
	
	// Нормализуем IP
	ip = NormalizeIP(ip)
	
	// Проверяем, что IP и сеть одного типа
	networkIP := NormalizeIP(network.IP)
	ipIsIPv4 := ip.To4() != nil && len(ip) == 4
	networkIsIPv4 := networkIP.To4() != nil && len(networkIP) == 4
	
	if ipIsIPv4 != networkIsIPv4 {
		return false
	}
	
	return network.Contains(ip)
}

// ParseIPRule парсит правило IP (может быть IP адрес, CIDR, или диапазон)
// Возвращает сеть и признак успешного парсинга
func ParseIPRule(rule string) (*net.IPNet, bool) {
	// Пробуем парсить как CIDR
	if _, network, err := net.ParseCIDR(rule); err == nil {
		return network, true
	}
	
	// Пробуем парсить как IP адрес
	if ip := net.ParseIP(rule); ip != nil {
		// Создаем сеть с маской /32 для IPv4 или /128 для IPv6
		if ip4 := ip.To4(); ip4 != nil && len(ip) == 4 {
			return &net.IPNet{
				IP:   ip4,
				Mask: net.CIDRMask(32, 32),
			}, true
		}
		// IPv6
		if ip6 := ip.To16(); ip6 != nil {
			return &net.IPNet{
				IP:   ip6,
				Mask: net.CIDRMask(128, 128),
			}, true
		}
	}
	
	return nil, false
}

