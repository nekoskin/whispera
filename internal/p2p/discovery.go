package p2p

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"whispera/internal/util"
)

// DiscoveryService отвечает за обнаружение узлов в P2P сети
type DiscoveryService struct {
	mu           sync.RWMutex
	peers        map[string]*Node
	bootstrap    []string
	udpConn      *net.UDPConn
	running      bool
	listenAddr   string
	nodeID       string
	announcePort int
	hsPort       int
	// identity for signing
	signPriv ed25519.PrivateKey
	signPub  ed25519.PublicKey
	ecdhPub  []byte
	// anti-abuse and replay protection
	ipLimits map[string]*ipLimiter
	lastTS   map[string]int64 // last accepted timestamp per nodeID
}

type ipLimiter struct {
	tokens     float64
	rate       float64
	burst      float64
	lastRefill time.Time
}

func (d *DiscoveryService) allowIP(ip string) bool {
	if d.ipLimits == nil {
		d.ipLimits = make(map[string]*ipLimiter)
	}
	lim, ok := d.ipLimits[ip]
	if !ok {
		lim = &ipLimiter{tokens: 10, rate: 10, burst: 20, lastRefill: time.Now()}
		d.ipLimits[ip] = lim
	}
	now := time.Now()
	dt := now.Sub(lim.lastRefill).Seconds()
	if dt > 0 {
		lim.tokens += dt * lim.rate
		if lim.tokens > lim.burst {
			lim.tokens = lim.burst
		}
		lim.lastRefill = now
	}
	if lim.tokens >= 1 {
		lim.tokens--
		return true
	}
	return false
}

// DiscoveryMessage представляет сообщение обнаружения
type DiscoveryMessage struct {
	Type          string `json:"type"`
	NodeID        string `json:"node_id"`
	IP            string `json:"ip"`
	Port          int    `json:"port"`
	HandshakePort int    `json:"handshake_port,omitempty"`
	PublicKey     []byte `json:"public_key"`
	Timestamp     int64  `json:"timestamp"`
	SignPub       []byte `json:"sign_pub,omitempty"`
	ECDHPub       []byte `json:"ecdh_pub,omitempty"`
	Sig           []byte `json:"sig,omitempty"`
	Expire        int64  `json:"exp,omitempty"`
}

// Start запускает сервис обнаружения
func (d *DiscoveryService) Start(ctx context.Context) {
	// Starting P2P Discovery service

	d.mu.Lock()
	d.running = true
	d.mu.Unlock()

	// Создаём UDP соединение для discovery
	la := d.listenAddr
	if la == "" {
		la = ":51821" // default port
	}
	addr, err := net.ResolveUDPAddr("udp", la)
	if err != nil {
		// UDP address creation error
		return
	}

	d.udpConn, err = net.ListenUDP("udp", addr)
	if err != nil {
		// UDP connection creation error
		return
	}
	// Discovery service listening
	defer util.SafeClose("udpConn", d.udpConn.Close)

	// Запускаем обработку сообщений
	go d.handleMessages()

	// Периодически объявляем себя
	go d.announceSelf(ctx)

	// Периодически ищем новые узлы
	go d.discoverNodes(ctx)

	// Ждём завершения контекста
	<-ctx.Done()

	d.mu.Lock()
	d.running = false
	d.mu.Unlock()

	// P2P Discovery service stopped
}

// handleMessages обрабатывает входящие сообщения
func (d *DiscoveryService) handleMessages() {
	buffer := make([]byte, 1024)

	for {
		d.mu.RLock()
		running := d.running
		d.mu.RUnlock()

		if !running {
			break
		}

		// Устанавливаем таймаут для чтения
		if err := d.udpConn.SetReadDeadline(time.Now().Add(1 * time.Second)); err != nil {
			log.Printf("error setting read deadline: %v", err)
		}

		n, addr, err := d.udpConn.ReadFromUDP(buffer)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			// UDP read error
			continue
		}

		// Per-IP rate limiting
		if !d.allowIP(addr.IP.String()) {
			continue
		}

		// Обрабатываем сообщение
		go d.processMessage(buffer[:n], addr)
	}
}

// processMessage обрабатывает одно сообщение
func (d *DiscoveryService) processMessage(data []byte, addr *net.UDPAddr) {
	var msg DiscoveryMessage
	if err := json.Unmarshal(data, &msg); err != nil {
		// Message parsing error
		return
	}

	switch msg.Type {
	case "announce":
		d.handleAnnounce(&msg, addr)
	case "ping":
		d.handlePing(&msg, addr)
	case "pong":
		d.handlePong(&msg, addr)
	default:
		// Unknown message type
	}
}

// handleAnnounce обрабатывает объявление узла
func (d *DiscoveryService) handleAnnounce(msg *DiscoveryMessage, addr *net.UDPAddr) {
	// Node announcement received

	// Verify signature (required)
	//nolint:nestif // Complex signature validation
	if len(msg.SignPub) > 0 && len(msg.Sig) > 0 {
		payload := struct {
			Type      string
			NodeID    string
			IP        string
			Port      int
			Timestamp int64
			ECDHPub   []byte
		}{
			Type:      msg.Type,
			NodeID:    msg.NodeID,
			IP:        addr.IP.String(),
			Port:      msg.Port,
			Timestamp: msg.Timestamp,
			ECDHPub:   msg.ECDHPub,
		}
		raw, _ := json.Marshal(payload)
		sum := sha256.Sum256(raw)
		if !ed25519.Verify(ed25519.PublicKey(msg.SignPub), sum[:], msg.Sig) {
			// Invalid signature in announcement
			return
		}
		// Basic freshness check
		if time.Since(time.Unix(msg.Timestamp, 0)) > 5*time.Minute {
			// Stale announcement ignored
			return
		}
		// Anti-replay per nodeID
		if d.lastTS == nil {
			d.lastTS = make(map[string]int64)
		}
		d.mu.Lock()
		if last, ok := d.lastTS[msg.NodeID]; ok && msg.Timestamp <= last {
			d.mu.Unlock()
			return
		}
		d.lastTS[msg.NodeID] = msg.Timestamp
		d.mu.Unlock()
	} else {
		// reject unsigned
		return
	}

	// Создаём узел
	node := &Node{
		ID:            msg.NodeID,
		IP:            addr.IP.String(),
		Port:          msg.Port,
		HandshakePort: msg.HandshakePort,
		PublicKey:     firstNonNil(msg.ECDHPub, msg.PublicKey),
		LastSeen:      time.Now(),
	}

	// Добавляем в список пиров
	d.mu.Lock()
	d.peers[msg.NodeID] = node
	d.mu.Unlock()

	// Отправляем подтверждение
	d.sendPong(addr)
}

// handlePing обрабатывает ping
func (d *DiscoveryService) handlePing(msg *DiscoveryMessage, addr *net.UDPAddr) {
	// Ping received from node

	// Verify signature and freshness
	if len(msg.SignPub) == 0 || len(msg.Sig) == 0 {
		return
	}
	payload := struct {
		Type      string
		NodeID    string
		IP        string
		Port      int
		Timestamp int64
		ECDHPub   []byte
	}{Type: msg.Type, NodeID: msg.NodeID, IP: "", Port: 0, Timestamp: msg.Timestamp, ECDHPub: msg.ECDHPub}
	raw, _ := json.Marshal(payload)
	sum := sha256.Sum256(raw)
	if !ed25519.Verify(ed25519.PublicKey(msg.SignPub), sum[:], msg.Sig) {
		return
	}
	if time.Since(time.Unix(msg.Timestamp, 0)) > 5*time.Minute {
		return
	}
	if d.lastTS == nil {
		d.lastTS = make(map[string]int64)
	}
	d.mu.Lock()
	if last, ok := d.lastTS[msg.NodeID]; ok && msg.Timestamp <= last {
		d.mu.Unlock()
		return
	}
	d.lastTS[msg.NodeID] = msg.Timestamp
	d.mu.Unlock()

	// Обновляем только существующего пира (автодобавление выполняется по announce/pong)
	d.mu.Lock()
	//nolint:nestif // Complex peer update logic
	if peer, exists := d.peers[msg.NodeID]; exists {
		peer.LastSeen = time.Now()
		peer.IP = addr.IP.String()
	}
	d.mu.Unlock()

	// Отправляем pong
	d.sendPong(addr)
}

// handlePong обрабатывает pong
func (d *DiscoveryService) handlePong(msg *DiscoveryMessage, addr *net.UDPAddr) {
	// Pong received from node

	// Verify signature and freshness
	if len(msg.SignPub) == 0 || len(msg.Sig) == 0 {
		return
	}
	payload := struct {
		Type      string
		NodeID    string
		IP        string
		Port      int
		Timestamp int64
		ECDHPub   []byte
	}{Type: msg.Type, NodeID: msg.NodeID, IP: "", Port: 0, Timestamp: msg.Timestamp, ECDHPub: msg.ECDHPub}
	raw, _ := json.Marshal(payload)
	sum := sha256.Sum256(raw)
	if !ed25519.Verify(ed25519.PublicKey(msg.SignPub), sum[:], msg.Sig) {
		return
	}
	if time.Since(time.Unix(msg.Timestamp, 0)) > 5*time.Minute {
		return
	}
	if d.lastTS == nil {
		d.lastTS = make(map[string]int64)
	}
	d.mu.Lock()
	if last, ok := d.lastTS[msg.NodeID]; ok && msg.Timestamp <= last {
		d.mu.Unlock()
		return
	}
	d.lastTS[msg.NodeID] = msg.Timestamp
	d.mu.Unlock()

	// Обновляем время последнего контакта
	d.mu.Lock()
	//nolint:nestif // Complex peer management
	if peer, exists := d.peers[msg.NodeID]; exists {
		peer.LastSeen = time.Now()
	} else {
		// If unknown, only add when signature is valid and keys provided
		valid := false
		if len(msg.SignPub) > 0 && len(msg.Sig) > 0 && len(msg.ECDHPub) == 32 {
			payload := struct {
				Type      string
				NodeID    string
				IP        string
				Port      int
				Timestamp int64
				ECDHPub   []byte
			}{
				Type:      msg.Type,
				NodeID:    msg.NodeID,
				IP:        addr.IP.String(),
				Port:      msg.Port,
				Timestamp: msg.Timestamp,
				ECDHPub:   msg.ECDHPub,
			}
			raw, _ := json.Marshal(payload)
			sum := sha256.Sum256(raw)
			if ed25519.Verify(ed25519.PublicKey(msg.SignPub), sum[:], msg.Sig) {
				valid = true
			}
		}
		if valid {
			d.peers[msg.NodeID] = &Node{
				ID:        msg.NodeID,
				IP:        addr.IP.String(),
				Port:      51821,
				PublicKey: msg.ECDHPub,
				LastSeen:  time.Now(),
			}
		}
	}
	d.mu.Unlock()
}

// announceSelf периодически объявляет себя
func (d *DiscoveryService) announceSelf(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			d.broadcastAnnounce()
		}
	}
}

// broadcastAnnounce транслирует объявление о себе
func (d *DiscoveryService) broadcastAnnounce() {
	// Порт, который анонсируем пирами. Если установлен явный P2P порт,
	// используем его, иначе fallback на порт discovery.
	port := d.announcePort
	//nolint:nestif // Complex port discovery logic
	if port == 0 {
		port = 51821
		if d.udpConn != nil {
			if la, ok := d.udpConn.LocalAddr().(*net.UDPAddr); ok {
				if la.Port != 0 {
					port = la.Port
				}
			}
		} else if d.listenAddr != "" {
			if a, err := net.ResolveUDPAddr("udp", d.listenAddr); err == nil && a.Port != 0 {
				port = a.Port
			}
		}
	}
	msg := DiscoveryMessage{
		Type:          "announce",
		NodeID:        d.nodeID,
		IP:            d.getMyIP(),
		Port:          port,
		HandshakePort: d.hsPort,
		Timestamp:     time.Now().Unix(),
		SignPub:       d.signPub,
		ECDHPub:       d.ecdhPub,
	}
	// Sign the payload
	payload := struct {
		Type      string
		NodeID    string
		IP        string
		Port      int
		Timestamp int64
		ECDHPub   []byte
	}{Type: msg.Type, NodeID: msg.NodeID, IP: msg.IP, Port: msg.Port, Timestamp: msg.Timestamp, ECDHPub: msg.ECDHPub}
	raw, _ := json.Marshal(payload)
	sum := sha256.Sum256(raw)
	if d.signPriv != nil {
		msg.Sig = ed25519.Sign(d.signPriv, sum[:])
	}

	data, err := json.Marshal(msg)
	if err != nil {
		// Announcement serialization error
		return
	}

	// Отправляем на все известные адреса
	d.mu.RLock()
	for _, peer := range d.peers {
		addr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", peer.IP, peer.Port))
		if err != nil {
			continue
		}

		if _, err := d.udpConn.WriteToUDP(data, addr); err != nil {
			log.Printf("error writing to UDP: %v", err)
		}
	}
	d.mu.RUnlock()

	// Announcement sent
}

// discoverNodes периодически ищет новые узлы
func (d *DiscoveryService) discoverNodes(ctx context.Context) {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			d.pingBootstrapNodes()
		}
	}
}

// pingBootstrapNodes пингует bootstrap узлы
func (d *DiscoveryService) pingBootstrapNodes() {
	msg := DiscoveryMessage{
		Type:      "ping",
		NodeID:    d.nodeID,
		Timestamp: time.Now().Unix(),
		SignPub:   d.signPub,
		ECDHPub:   d.ecdhPub,
	}
	// sign
	payload := struct {
		Type      string
		NodeID    string
		IP        string
		Port      int
		Timestamp int64
		ECDHPub   []byte
	}{Type: msg.Type, NodeID: msg.NodeID, IP: "", Port: 0, Timestamp: msg.Timestamp, ECDHPub: msg.ECDHPub}
	raw, _ := json.Marshal(payload)
	sum := sha256.Sum256(raw)
	if d.signPriv != nil {
		msg.Sig = ed25519.Sign(d.signPriv, sum[:])
	}

	data, err := json.Marshal(msg)
	if err != nil {
		return
	}

	for _, bootstrap := range d.bootstrap {
		addr, err := net.ResolveUDPAddr("udp", bootstrap)
		if err != nil {
			continue
		}

		if _, err := d.udpConn.WriteToUDP(data, addr); err != nil {
			log.Printf("error writing to UDP: %v", err)
		}
		// Ping sent to bootstrap
	}
}

// sendPong отправляет pong
func (d *DiscoveryService) sendPong(addr *net.UDPAddr) {
	if d.udpConn == nil {
		return // В тестах UDP соединение может быть не инициализировано
	}

	msg := DiscoveryMessage{
		Type:      "pong",
		NodeID:    d.nodeID,
		Timestamp: time.Now().Unix(),
		SignPub:   d.signPub,
		ECDHPub:   d.ecdhPub,
	}
	payload := struct {
		Type      string
		NodeID    string
		IP        string
		Port      int
		Timestamp int64
		ECDHPub   []byte
	}{
		Type:      msg.Type,
		NodeID:    msg.NodeID,
		IP:        addr.IP.String(),
		Port:      addr.Port,
		Timestamp: msg.Timestamp,
		ECDHPub:   msg.ECDHPub,
	}
	raw, _ := json.Marshal(payload)
	sum := sha256.Sum256(raw)
	if d.signPriv != nil {
		msg.Sig = ed25519.Sign(d.signPriv, sum[:])
	}

	data, err := json.Marshal(msg)
	if err != nil {
		return
	}

	if _, err := d.udpConn.WriteToUDP(data, addr); err != nil {
		log.Printf("[P2P Discovery] Error writing UDP: %v", err)
	}
}

func firstNonNil(a, b []byte) []byte {
	if len(a) > 0 {
		return a
	}
	return b
}

// getMyIP получает свой IP адрес
func (d *DiscoveryService) getMyIP() string {
	dialer := &net.Dialer{Timeout: 2 * time.Second}
	ctx := context.Background()
	conn, err := dialer.DialContext(ctx, "udp", "8.8.8.8:80")
	if err != nil {
		return "127.0.0.1"
	}
	defer util.SafeClose("conn", conn.Close)

	return conn.LocalAddr().(*net.UDPAddr).IP.String()
}

// GetPeers возвращает список пиров
func (d *DiscoveryService) GetPeers() []*Node {
	d.mu.RLock()
	defer d.mu.RUnlock()

	peers := make([]*Node, 0, len(d.peers))
	for _, peer := range d.peers {
		if time.Since(peer.LastSeen) < 5*time.Minute {
			peers = append(peers, peer)
		}
	}

	return peers
}

// GetPeerCount возвращает количество пиров
func (d *DiscoveryService) GetPeerCount() int {
	d.mu.RLock()
	defer d.mu.RUnlock()

	return len(d.peers)
}
