package main

import (
	"log"
	"net"
	"sync"

	dnspkg "whispera/internal/dns"
)

var (
	clientDNSServer  *dnspkg.Server
	clientFakeIPPool *dnspkg.FakeIPPool
	dnsServerMu      sync.RWMutex
)

// startClientDNSServer запускает Fake-IP DNS сервер на клиенте
func startClientDNSServer(tunGateway string) error {
	dnsServerMu.Lock()
	defer dnsServerMu.Unlock()

	if clientFakeIPPool == nil {
		clientFakeIPPool = dnspkg.NewFakeIPPool()
		log.Printf("[DNS] Created Fake-IP pool for client")
	}

	// DNS сервер слушает на 0.0.0.0:53 (на всех интерфейсах)
	// Это необходимо, потому что tunGateway (198.18.0.2) - это gateway, а не IP интерфейса
	// Windows будет отправлять DNS запросы на 198.18.0.2:53, и они будут перехватываться через TUN интерфейс
	dnsAddr := "0.0.0.0:53"
	clientDNSServer = dnspkg.NewServer(dnsAddr, clientFakeIPPool)
	
	// Опционально: можно добавить DoH клиент для fallback
	// dohClient := dnspkg.NewDoHClient()
	// dohClient.AddEndpoint("https://cloudflare-dns.com/dns-query")
	// clientDNSServer.SetDoHClient(dohClient)
	
	if err := clientDNSServer.Start(); err != nil {
		return err
	}
	
	log.Printf("[DNS] ✅ Fake-IP DNS server started on %s", dnsAddr)
	return nil
}

// stopClientDNSServer останавливает DNS сервер
func stopClientDNSServer() {
	dnsServerMu.Lock()
	defer dnsServerMu.Unlock()

	if clientDNSServer != nil {
		clientDNSServer.Stop()
		clientDNSServer = nil
	}
	if clientFakeIPPool != nil {
		clientFakeIPPool.Stop()
		clientFakeIPPool = nil
	}
}

// GetClientFakeIPPool возвращает FakeIPPool клиента (для синхронизации с сервером)
func GetClientFakeIPPool() *dnspkg.FakeIPPool {
	dnsServerMu.RLock()
	defer dnsServerMu.RUnlock()
	return clientFakeIPPool
}

// GetDomainFromFakeIP возвращает домен для Fake-IP адреса (для передачи в пакетах)
func GetDomainFromFakeIP(ip net.IP) string {
	pool := GetClientFakeIPPool()
	if pool == nil {
		return ""
	}
	return pool.Lookup(ip)
}

// IsFakeIP проверяет, является ли IP адрес Fake-IP
func IsFakeIP(ip net.IP) bool {
	pool := GetClientFakeIPPool()
	if pool == nil {
		return false
	}
	return pool.IsFakeIP(ip)
}

