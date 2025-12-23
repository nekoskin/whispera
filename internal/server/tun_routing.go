package server

import (
	"net"
	"strings"
	"sync"
)

// ParseIPv4Header парсит IPv4 заголовок из TUN пакета
func ParseIPv4Header(packet []byte) (srcIP, dstIP net.IP, protocol byte, valid bool) {
	if len(packet) < 20 {
		return nil, nil, 0, false // Минимальный размер IPv4 заголовка
	}
	
	// Проверяем версию IP (первые 4 бита)
	version := (packet[0] >> 4) & 0x0F
	if version != 4 {
		return nil, nil, 0, false
	}
	
	// Извлекаем IP адреса
	srcIP = net.IP(packet[12:16])
	dstIP = net.IP(packet[16:20])
	protocol = packet[9] // Protocol field
	
	return srcIP, dstIP, protocol, true
}

// RouteTable - таблица маршрутизации для TUN трафика
type RouteTable struct {
	routes map[string]uint32 // IP/CIDR string -> sessionID
	mu     sync.RWMutex
}

// NewRouteTable создает новую таблицу маршрутизации
func NewRouteTable() *RouteTable {
	return &RouteTable{
		routes: make(map[string]uint32),
	}
}

// AddRoute добавляет маршрут
func (rt *RouteTable) AddRoute(destIP string, sessionID uint32) {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	rt.routes[destIP] = sessionID
}

// RemoveRoute удаляет маршрут
func (rt *RouteTable) RemoveRoute(destIP string) {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	delete(rt.routes, destIP)
}

// FindRoute ищет маршрут для destination IP
func (rt *RouteTable) FindRoute(destIP net.IP) (uint32, bool) {
	if destIP == nil {
		return 0, false
	}
	
	rt.mu.RLock()
	defer rt.mu.RUnlock()
	
	// Прямое совпадение IP
	ipStr := destIP.String()
	if sessionID, ok := rt.routes[ipStr]; ok {
		return sessionID, true
	}
	
	// Проверка CIDR (только если routeStr содержит "/")
	for routeStr, sessionID := range rt.routes {
		if len(routeStr) == 0 {
			continue
		}
		// Если это CIDR (содержит "/"), парсим как CIDR
		if strings.Contains(routeStr, "/") {
			_, network, err := net.ParseCIDR(routeStr)
			if err == nil && network != nil && network.Contains(destIP) {
				return sessionID, true
			}
		}
	}
	
	return 0, false
}

