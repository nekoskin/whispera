package p2p

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net"
	"sync"
	"time"

	"whispera/internal/handshake"
	"whispera/internal/logger"
	"whispera/internal/util"

	"golang.org/x/crypto/curve25519"
)

// log is the module logger
var log = logger.Module("p2p")

// P2PNetwork представляет децентрализованную сеть Whispera
type P2PNetwork struct { //nolint:revive // Name is part of public API
	mu         sync.RWMutex
	nodes      map[string]*Node
	bootstrap  []string
	myNode     *Node
	discovery  *DiscoveryService
	routing    *RoutingEngine
	consensus  *ConsensusEngine
	encryption *P2PEncryption
	// session cache: nodeID -> sessionID
	sessions map[string]string
	// discovery listen address (udp), empty = default
	DiscoveryListen string
	// lightweight UDP transport
	udpConn *net.UDPConn
	p2pTx   int64
	p2pRx   int64
	// crypto identity
	signPriv ed25519.PrivateKey
	signPub  ed25519.PublicKey
	ecdhPriv []byte
	ecdhPub  []byte
}

// Node представляет узел в P2P сети
type Node struct {
	ID            string        `json:"id"`
	IP            string        `json:"ip"`
	Port          int           `json:"port"`
	HandshakePort int           `json:"handshake_port"`
	PublicKey     []byte        `json:"public_key"`
	LastSeen      time.Time     `json:"last_seen"`
	Latency       time.Duration `json:"latency"`
	Reliability   float64       `json:"reliability"`
	Capabilities  []string      `json:"capabilities"`
}

// NewP2PNetwork создаёт новую P2P сеть
func NewP2PNetwork(bootstrap []string) *P2PNetwork {
	return &P2PNetwork{
		nodes:     make(map[string]*Node),
		bootstrap: bootstrap,
		discovery: &DiscoveryService{
			peers:     make(map[string]*Node),
			bootstrap: bootstrap,
		},
		routing:    NewRoutingEngine("my-node-id"),
		consensus:  NewConsensusEngine(),
		encryption: NewP2PEncryption(),
		sessions:   make(map[string]string),
	}
}

// Start запускает P2P сеть
func (p *P2PNetwork) Start(ctx context.Context) error {
	// Starting decentralized P2P network

	// Создаём свой узел
	p.myNode = p.createMyNode()
	_ = p.myNode // Node created for P2P network

	// Прописываем адрес прослушивания discovery при необходимости
	if p.DiscoveryListen != "" {
		p.discovery.listenAddr = p.DiscoveryListen
	}
	// Запускаем компоненты
	// Передаём свой nodeID в discovery для корректных сообщений
	if p.myNode != nil {
		p.discovery.nodeID = p.myNode.ID
		// provide keys to discovery for signing
		p.discovery.signPriv = p.signPriv
		p.discovery.signPub = p.signPub
		p.discovery.ecdhPub = p.ecdhPub
	}
	go p.discovery.Start(ctx)
	go p.routing.Start(ctx)
	go p.consensus.Start(ctx)
	go p.encryption.Start(ctx)

	// Запускаем синхронизацию пиров из discovery в ядро сети
	go p.syncPeersLoop(ctx)

	// Запускаем лёгкий UDP транспорт (:0)
	go p.startUDPTransport(ctx)

	// Запускаем Noise UDP handshake listener (:0) и анонсируем порт
	go p.startHandshakeListener(ctx)

	// Подключаемся к bootstrap узлам
	for _, bootstrap := range p.bootstrap {
		go p.connectToBootstrap(bootstrap)
	}

	return nil
}

// createMyNode создаёт свой узел
func (p *P2PNetwork) createMyNode() *Node {
	// Генерируем уникальный ID
	id := make([]byte, 16)
	if _, err := rand.Read(id); err != nil {
		log.Error("Error generating node ID: %v", err)
		return nil
	}

	// Generate identity keys once
	if p.signPriv == nil || p.signPub == nil {
		spub, spriv, _ := ed25519.GenerateKey(rand.Reader)
		p.signPriv = spriv
		p.signPub = spub
	}
	if p.ecdhPriv == nil || p.ecdhPub == nil {
		priv := make([]byte, 32)
		if _, err := rand.Read(priv); err != nil {
			log.Error("Error generating ECDH key: %v", err)
			return nil
		}
		pub, _ := curve25519.X25519(priv, curve25519.Basepoint)
		p.ecdhPriv = priv
		p.ecdhPub = pub
	}

	return &Node{
		ID:            fmt.Sprintf("%x", id),
		IP:            p.getMyIP(),
		Port:          51820,
		HandshakePort: 0,
		LastSeen:      time.Now(),
		Reliability:   1.0,
		Capabilities:  []string{"vpn", "obfuscation", "speedtest"},
		PublicKey:     p.ecdhPub,
	}
}

// getMyIP получает свой IP адрес
func (p *P2PNetwork) getMyIP() string {
	d := &net.Dialer{Timeout: 2 * time.Second}
	ctx := context.Background()
	conn, err := d.DialContext(ctx, "udp", "8.8.8.8:80")
	if err != nil {
		return "127.0.0.1"
	}
	defer util.SafeClose("conn", conn.Close)

	return conn.LocalAddr().(*net.UDPAddr).IP.String()
}

// connectToBootstrap подключается к bootstrap узлу
func (p *P2PNetwork) connectToBootstrap(bootstrap string) {
	// Connecting to bootstrap node

	// Здесь должна быть логика подключения
	// Пока что просто логируем
	// Реальная обработка P2P
	// Bootstrap connection established
}

// FindBestRoute находит лучший маршрут к узлу
func (p *P2PNetwork) FindBestRoute(destination string) (*Route, error) {
	return p.routing.FindBestRoute(destination)
}

// BroadcastMessage транслирует сообщение по сети
func (p *P2PNetwork) BroadcastMessage(message []byte) error {
	// Broadcasting message via P2P network

	// Здесь должна быть логика трансляции
	// Пока что просто логируем
	return nil
}

// GetAvailableNodes возвращает доступные узлы
func (p *P2PNetwork) GetAvailableNodes() []*Node {
	p.mu.RLock()
	defer p.mu.RUnlock()

	nodes := make([]*Node, 0, len(p.nodes))
	for _, node := range p.nodes {
		if time.Since(node.LastSeen) < 5*time.Minute {
			nodes = append(nodes, node)
		}
	}

	return nodes
}

// AddNode добавляет узел в сеть
func (p *P2PNetwork) AddNode(node *Node) {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.nodes[node.ID] = node
	// Node added to network

	// Прокидываем в маршрутизацию
	if p.routing != nil {
		p.routing.AddNode(node)
	}
	// Регистрируем участника в консенсусе
	if p.consensus != nil {
		participant := &Participant{
			ID:         node.ID,
			Weight:     1.0,
			LastSeen:   time.Now(),
			Reputation: 1.0,
			Stake:      0,
			Active:     true,
		}
		p.consensus.AddParticipant(participant)
	}
}

// RemoveNode удаляет узел из сети
func (p *P2PNetwork) RemoveNode(nodeID string) {
	p.mu.Lock()
	defer p.mu.Unlock()

	delete(p.nodes, nodeID)
	// Node removed from network

	if p.routing != nil {
		p.routing.RemoveNode(nodeID)
	}
	if p.consensus != nil {
		p.consensus.RemoveParticipant(nodeID)
	}
	if p.sessions != nil {
		delete(p.sessions, nodeID)
	}
}

// GetNetworkStats возвращает статистику сети
func (p *P2PNetwork) GetNetworkStats() map[string]interface{} {
	p.mu.RLock()
	defer p.mu.RUnlock()

	stats := map[string]interface{}{
		"total_nodes":     len(p.nodes),
		"active_nodes":    len(p.GetAvailableNodes()),
		"bootstrap_nodes": len(p.bootstrap),
	}

	if p.myNode != nil {
		stats["my_node_id"] = p.myNode.ID
		stats["my_ip"] = p.myNode.IP
	} else {
		stats["my_node_id"] = ""
		stats["my_ip"] = ""
	}

	// Агрегированные метрики подсистем
	if p.routing != nil {
		stats["routing"] = p.routing.GetRoutingStats()
	}
	if p.consensus != nil {
		stats["consensus"] = p.consensus.GetConsensusStats()
	}
	if p.encryption != nil {
		stats["encryption"] = p.encryption.GetEncryptionStats()
	}
	stats["p2p_tx"] = p.p2pTx
	stats["p2p_rx"] = p.p2pRx

	return stats
}

// syncPeersLoop периодически синхронизирует пиров из discovery
func (p *P2PNetwork) syncPeersLoop(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			peers := p.discovery.GetPeers()
			for _, peer := range peers {
				// Добавляем только новые или обновляем метки времени
				p.mu.RLock()
				_, exists := p.nodes[peer.ID]
				p.mu.RUnlock()
				if !exists {
					p.AddNode(peer)
					// Репликация базовых метрик пиров в маршрутизатор
					if p.routing != nil {
						p.routing.AddNode(&Node{
							ID:          peer.ID,
							IP:          peer.IP,
							Port:        peer.Port,
							Latency:     peer.Latency,
							Reliability: peer.Reliability,
							LastSeen:    peer.LastSeen,
						})
					}
				} else {
					p.mu.Lock()
					if n, ok := p.nodes[peer.ID]; ok {
						n.LastSeen = time.Now()
						n.IP = peer.IP
						n.Port = peer.Port
						n.Latency = peer.Latency
						n.Reliability = peer.Reliability
					}
					p.mu.Unlock()
				}
			}
		}
	}
}

// ensureSession возвращает действительный sessionID для узла, создаёт при необходимости
func (p *P2PNetwork) ensureSession(nodeID string) (string, error) {
	p.mu.RLock()
	if sid, ok := p.sessions[nodeID]; ok && p.encryption.ValidateSession(sid) {
		p.mu.RUnlock()
		return sid, nil
	}
	p.mu.RUnlock()

	// Создаём сессию через Noise NK: получаем seed, выводим направленные ключи
	myID := ""
	if p.myNode != nil {
		myID = p.myNode.ID
	}
	// Получаем публичный ключ пира из discovery
	p.discovery.mu.RLock()
	peer := p.discovery.peers[nodeID]
	p.discovery.mu.RUnlock()
	if peer == nil || len(peer.PublicKey) != 32 {
		return "", fmt.Errorf("peer pubkey missing")
	}
	// Perform UDP Noise client handshake to peer.IP:peer.HandshakePort (fallback to Port)
	hsPort := peer.HandshakePort
	if hsPort == 0 {
		hsPort = peer.Port
	}
	raddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", peer.IP, hsPort))
	if err != nil {
		return "", err
	}
	conn, err := net.ListenUDP("udp", nil)
	if err != nil {
		return "", err
	}
	defer util.SafeClose("conn", conn.Close)
	seed, _, err := handshake.ClientIK(conn, raddr, peer.PublicKey, "")
	if err != nil {
		return "", err
	}
	// Derive directional keys from seed for P2P AES-GCM via HKDF wrapper
	session, err := p.encryption.CreateECDHSessionForPeers(myID, nodeID, seed)
	if err != nil {
		return "", err
	}
	p.mu.Lock()
	p.sessions[nodeID] = session.ID
	p.mu.Unlock()
	return session.ID, nil
}

// SendSecureMessage шифрует и отправляет сообщение (заглушка транспорта)
func (p *P2PNetwork) SendSecureMessage(nodeID string, data []byte) (*EncryptedMessage, error) {
	sid, err := p.ensureSession(nodeID)
	if err != nil {
		return nil, err
	}
	enc, err := p.encryption.EncryptMessage(sid, data)
	if err != nil {
		return nil, err
	}
	// Пытаемся отправить по UDP на адрес из discovery
	//nolint:nestif // Complex UDP connection handling
	if p.udpConn != nil {
		// ищем пира по nodeID среди discovery.peers
		p.discovery.mu.RLock()
		peer := p.discovery.peers[nodeID]
		p.discovery.mu.RUnlock()
		if peer != nil {
			ip := peer.IP
			port := peer.Port
			if port == 0 {
				port = 51821
			}
			addr, rerr := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", ip, port))
			if rerr == nil {
				// Кодируем как JSON EncryptedMessage
				// Добавляем идентификатор отправителя для приёма
				if p.myNode != nil {
					enc.FromNode = p.myNode.ID
				}
				payload, mErr := json.Marshal(enc)
				if mErr == nil {
					_, _ = p.udpConn.WriteToUDP(payload, addr)
					p.p2pTx++
					// P2P message sent
				}
			}
		}
		// P2P peer not found - continue without sending
	}
	return enc, nil
}

// ReceiveSecureMessage принимает и расшифровывает входящее сообщение
func (p *P2PNetwork) ReceiveSecureMessage(msg *EncryptedMessage) ([]byte, error) {
	plaintext, err := p.encryption.DecryptMessage(msg)
	if err != nil {
		return nil, err
	}
	// P2P message received and decrypted
	if len(plaintext) > 0 {
		// Печатаем полезную нагрузку как строку (для CLI-теста)
		// P2P payload processed
		_ = plaintext // Suppress unused warning - payload handled
	}
	return plaintext, nil
}

// startUDPTransport поднимает локальный UDP сокет и принимает входящие P2P сообщения
//
//nolint:gocyclo // Complex UDP transport initialization
func (p *P2PNetwork) startUDPTransport(ctx context.Context) {
	// Транспорт всегда слушает на :0, чтобы не конфликтовать с discovery
	laddr, err := net.ResolveUDPAddr("udp", ":0")
	if err != nil {
		// P2P UDP resolve error
		return
	}
	conn, err := net.ListenUDP("udp", laddr)
	if err != nil {
		// P2P UDP listen error
		return
	}
	p.udpConn = conn
	// P2P transport listening
	// Сообщаем discovery, какой порт анонсировать пирами
	if la, ok := conn.LocalAddr().(*net.UDPAddr); ok {
		if p.discovery != nil {
			p.discovery.announcePort = la.Port
			// Немедленно транслируем announce с правильным портом,
			// чтобы пиры обновили кэш и слали P2P на нужный порт
			go p.discovery.broadcastAnnounce()
		}
	}
	buf := make([]byte, 65535)
	for {
		_ = conn.SetReadDeadline(time.Now().Add(1 * time.Second))
		n, _, err := conn.ReadFromUDP(buf)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				select {
				case <-ctx.Done():
					_ = conn.Close()
					return
				default:
				}
				continue
			}
			continue
		}
		var em EncryptedMessage
		if uerr := json.Unmarshal(buf[:n], &em); uerr != nil {
			continue
		}
		// Обеспечиваем наличие общей сессии для пары (мой узел ↔ отправитель)
		if p.myNode != nil && em.FromNode != "" {
			if _, ok := p.sessions[em.FromNode]; !ok {
				if s, err := p.encryption.CreateSharedSessionForPeers(p.myNode.ID, em.FromNode); err == nil {
					p.sessions[em.FromNode] = s.ID
				}
			}
		}
		if _, derr := p.ReceiveSecureMessage(&em); derr == nil {
			p.p2pRx++
		}
	}
}

// startHandshakeListener запускает UDP слушатель для Noise рукопожатия и анонсирует порт в discovery
//
//nolint:gocyclo // Complex handshake listener logic
func (p *P2PNetwork) startHandshakeListener(ctx context.Context) {
	addr, err := net.ResolveUDPAddr("udp", ":0")
	if err != nil {
		// P2P handshake resolve error
		return
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		// P2P handshake listen error
		return
	}
	defer func() { _ = conn.Close() }()
	if la, ok := conn.LocalAddr().(*net.UDPAddr); ok {
		p.mu.Lock()
		if p.myNode != nil {
			p.myNode.HandshakePort = la.Port
		}
		if p.discovery != nil {
			p.discovery.hsPort = la.Port
		}
		p.mu.Unlock()
	}
	// P2P handshake listening

	buf := make([]byte, 2048)
	for {
		_ = conn.SetReadDeadline(time.Now().Add(1 * time.Second))
		n, raddr, err := conn.ReadFromUDP(buf)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				select {
				case <-ctx.Done():
					return
				default:
				}
				continue
			}
			continue
		}
		// Выполняем ответчик NK, используя первый полученный пакет
		seed, _, _, err := handshake.ServerIKFromFirst(conn, p.ecdhPriv, buf[:n], raddr, nil)
		if err != nil {
			continue
		}
		// Привязываем сессию к nodeID по IP из discovery
		var peerNodeID string
		p.discovery.mu.RLock()
		for id, nd := range p.discovery.peers {
			if nd != nil && nd.IP == raddr.IP.String() {
				peerNodeID = id
				break
			}
		}
		p.discovery.mu.RUnlock()
		if peerNodeID != "" && p.myNode != nil {
			if s, err := p.encryption.CreateECDHSessionForPeers(p.myNode.ID, peerNodeID, seed); err == nil {
				p.mu.Lock()
				p.sessions[peerNodeID] = s.ID
				p.mu.Unlock()
				// P2P session established
			}
		}
	}
}
