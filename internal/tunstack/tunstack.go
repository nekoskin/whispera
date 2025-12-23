//go:build with_gvisor

package tunstack

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"

	"whispera/internal/util"
)

// packetBufferPool - пул буферов для переиспользования памяти (оптимизация по примеру Xray-core)
var packetBufferPool = sync.Pool{
	New: func() interface{} {
		return make([]byte, 0, 1500) // Предварительно выделяем память для типичного MTU
	},
}

// getPacketBuffer получает буфер из пула
func getPacketBuffer(size int) []byte {
	buf := packetBufferPool.Get().([]byte)
	if cap(buf) < size {
		buf = make([]byte, size)
	} else {
		buf = buf[:size]
	}
	return buf
}

// putPacketBuffer возвращает буфер в пул
func putPacketBuffer(buf []byte) {
	if cap(buf) > 0 && cap(buf) <= 65535 { // Переиспользуем только разумные размеры
		buf = buf[:0] // Очищаем длину, сохраняя capacity
		packetBufferPool.Put(buf)
	}
}

// Stack acts as a user-space network stack using gVisor.
type Stack struct {
	ipStack      *stack.Stack
	linkEndpoint *channel.Endpoint
	tunDevice    io.ReadWriter
	
	tcpHandler HandlerFunc
	udpHandler HandlerFunc
	
	// Виртуальные соединения для обработки пакетов напрямую
	virtualConns map[string]*virtualConn
	virtualMutex sync.RWMutex
	
	// Отслеживание недавних SYN пакетов для предотвращения дублирования
	recentSYNs map[string]time.Time
	synMutex   sync.RWMutex
	
	// Отслеживание активных соединений по адресу назначения
	// для предотвращения множественных попыток к одному адресу
	activeDestinations map[string]time.Time
	destMutex          sync.RWMutex
	
	// Счетчики для логирования (для производительности)
	droppedPacketCount uint64
	missingConnCount   uint64
}

// virtualConn реализует net.Conn для обработки пакетов напрямую из TUN
type virtualConn struct {
	localAddr     net.Addr
	remoteAddr    net.Addr
	packetChan    chan []byte
	writeChan     chan []byte
	closed        bool
	closeOnce     sync.Once
	closeChan     chan struct{}
	tunDevice     io.ReadWriter
	connKey       string
	lastActivity  time.Time // Время последней активности (получения/отправки пакетов)
	handlerFinished bool    // Флаг, что handler завершился, но соединение еще активно
	activityMutex sync.RWMutex
}

func (c *virtualConn) Read(b []byte) (int, error) {
	select {
	case <-c.closeChan:
		return 0, io.EOF
	case packet := <-c.packetChan:
		if packet == nil {
			return 0, io.EOF
		}
		n := copy(b, packet)
		return n, nil
	}
}

func (c *virtualConn) Write(b []byte) (int, error) {
	select {
	case <-c.closeChan:
		return 0, io.ErrClosedPipe
	case c.writeChan <- b:
		return len(b), nil
	}
}

func (c *virtualConn) Close() error {
	var err error
	c.closeOnce.Do(func() {
		c.closed = true
		close(c.closeChan)
		close(c.packetChan)
		close(c.writeChan)
	})
	return err
}

// updateActivity обновляет время последней активности соединения
func (c *virtualConn) updateActivity() {
	c.activityMutex.Lock()
	// ОПТИМИЗАЦИЯ: Используем кэшированное время для уменьшения системных вызовов
	c.lastActivity = util.GetGlobalTimeCache().Now()
	c.activityMutex.Unlock()
}

// removeVirtualConn удаляет виртуальное соединение из map с задержкой
// для обработки повторных SYN пакетов и поздних ACK/DATA пакетов
func (s *Stack) removeVirtualConn(connKey string) {
	// Извлекаем целевой адрес из connKey для очистки activeDestinations
	var destKey string
	if strings.HasPrefix(connKey, "tcp:") || strings.HasPrefix(connKey, "udp:") {
		// Формат: "tcp:srcIP:srcPort->dstIP:dstPort" или "udp:srcIP:srcPort->dstIP:dstPort"
		parts := strings.Split(connKey, "->")
		if len(parts) == 2 {
			destKey = parts[1] // "dstIP:dstPort"
		}
	}
	
	// Планируем периодическую проверку активности соединения
	// Соединение будет удалено только после периода неактивности (30 секунд)
	log.Printf("[TUNSTACK] ⏰ Scheduling removal check for virtual connection: %s (will check inactivity periodically)", connKey)
	go func() {
		// Проверяем активность соединения каждые 5 секунд
		// Удаляем только если соединение неактивно более 30 секунд
		inactivityTimeout := 30 * time.Second
		checkInterval := 5 * time.Second
		
		// ОПТИМИЗАЦИЯ: Используем ticker вместо sleep для более точного контроля
		ticker := time.NewTicker(checkInterval)
		defer ticker.Stop()
		
		for {
			<-ticker.C
			
			s.virtualMutex.RLock()
			vconn, exists := s.virtualConns[connKey]
			if !exists || vconn == nil {
				s.virtualMutex.RUnlock()
				log.Printf("[TUNSTACK] ⚠️ Virtual connection %s was already removed", connKey)
				return
			}
			
			// Проверяем время последней активности
			vconn.activityMutex.RLock()
			lastActivity := vconn.lastActivity
			handlerFinished := vconn.handlerFinished
			vconn.activityMutex.RUnlock()
			s.virtualMutex.RUnlock()
			
			inactiveDuration := time.Since(lastActivity)
			
			// Если handler завершился И соединение неактивно более 30 секунд - удаляем
			if handlerFinished && inactiveDuration > inactivityTimeout {
				s.virtualMutex.Lock()
				// Проверяем еще раз после получения блокировки
				if _, stillExists := s.virtualConns[connKey]; stillExists {
					// Закрываем соединение перед удалением
					if vconnToClose := s.virtualConns[connKey]; vconnToClose != nil {
						vconnToClose.Close()
					}
					delete(s.virtualConns, connKey)
					log.Printf("[TUNSTACK] 🗑️ Removed virtual connection: %s (inactive for %v, handler finished)", connKey, inactiveDuration)
				} else {
					log.Printf("[TUNSTACK] ⚠️ Virtual connection %s was already removed", connKey)
				}
				s.virtualMutex.Unlock()
				
				// Очищаем из activeDestinations
				if destKey != "" {
					s.destMutex.Lock()
					delete(s.activeDestinations, destKey)
					s.destMutex.Unlock()
				}
				
				return
			}
			
			// Если handler еще не завершился, продолжаем проверку
			// Логируем только каждые 30 секунд, чтобы не засорять логи
			if inactiveDuration > 30*time.Second && !handlerFinished {
				log.Printf("[TUNSTACK] ⏳ Connection %s still active (handler running, last activity: %v ago)", connKey, inactiveDuration)
			}
		}
	}()
}

func (c *virtualConn) LocalAddr() net.Addr {
	return c.localAddr
}

func (c *virtualConn) RemoteAddr() net.Addr {
	return c.remoteAddr
}

func (c *virtualConn) SetDeadline(t time.Time) error {
	return nil // Not implemented
}

func (c *virtualConn) SetReadDeadline(t time.Time) error {
	return nil // Not implemented
}

func (c *virtualConn) SetWriteDeadline(t time.Time) error {
	return nil // Not implemented
}

// IsActive returns true if this is a real gVisor stack (not a stub).
func (s *Stack) IsActive() bool {
	return s.ipStack != nil
}

// NewStack creates a new gVisor-based stack.
func NewStack(tunDevice io.ReadWriter, mtu uint32, tcpHandler, udpHandler HandlerFunc) (*Stack, error) {
	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol},
	})

	// Create a channel endpoint (virtual NIC)
	linkID := tcpip.NICID(1)
	channelEndpoint := channel.New(256, mtu, "")
	
	if err := s.CreateNIC(linkID, channelEndpoint); err != nil {
		return nil, fmt.Errorf("failed to create NIC: %v", err)
	}

	s.SetPromiscuousMode(linkID, true)

	// Add IP address to NIC (198.18.0.1/30) - это необходимо для обработки пакетов
	// Без IP адреса gVisor не может обрабатывать пакеты, направленные на этот интерфейс
	ipAddr := tcpip.AddrFrom4Slice([]byte{198, 18, 0, 1})
	subnet := tcpip.AddressWithPrefix{
		Address:   ipAddr,
		PrefixLen: 30, // /30 subnet
	}
	protocolAddr := tcpip.ProtocolAddress{
		Protocol:          ipv4.ProtocolNumber,
		AddressWithPrefix: subnet,
	}
	if err := s.AddProtocolAddress(linkID, protocolAddr, stack.AddressProperties{}); err != nil {
		return nil, fmt.Errorf("failed to add IP address to NIC: %v", err)
	}
	log.Printf("[TUNSTACK] ✅ Added IP address 198.18.0.1/30 to gVisor NIC")

	// Add default route
	s.AddRoute(tcpip.Route{
		Destination: header.IPv4EmptySubnet,
		NIC:         linkID,
	})
	log.Printf("[TUNSTACK] ✅ Added default route to gVisor stack")

	ts := &Stack{
		ipStack:           s,
		linkEndpoint:      channelEndpoint,
		tunDevice:         tunDevice,
		tcpHandler:        tcpHandler,
		udpHandler:        udpHandler,
		virtualConns:      make(map[string]*virtualConn),
		recentSYNs:        make(map[string]time.Time),
		activeDestinations: make(map[string]time.Time),
	}

	ts.initForwarders()

	return ts, nil
}

// Start begins the packet processing loop.
func (s *Stack) Start(ctx context.Context) {
	go s.packetPumpIn(ctx)
	go s.packetPumpOut(ctx)
}

// Run is a compatibility wrapper for Start.
func (s *Stack) Run() error {
	s.Start(context.Background())
	return nil
}

func (s *Stack) initForwarders() {
	// TCP Forwarder - перехватывает все порты (0 означает все порты)
	// Forwarder перехватывает входящие соединения, но мы инжектируем пакеты как входящие
	// чтобы Forwarder их обработал
	tcpForwarder := tcp.NewForwarder(s.ipStack, 0, 65535, func(r *tcp.ForwarderRequest) {
		var wq waiter.Queue
		ep, err := r.CreateEndpoint(&wq)
		if err != nil {
			r.Complete(true)
			return
		}
		r.Complete(false)

		conn := gonet.NewTCPConn(&wq, ep)
		dest := fmt.Sprintf("%s:%d", r.ID().LocalAddress, r.ID().LocalPort)
		
		if s.tcpHandler != nil {
			go s.tcpHandler(conn, dest, "tcp")
		} else {
			conn.Close()
		}
	})
	
	// Обертка для логирования TCP пакетов (только для диагностики, минимум логирования)
	originalTCPHandler := tcpForwarder.HandlePacket
	tcpHandlerWrapper := func(id stack.TransportEndpointID, pkt *stack.PacketBuffer) bool {
		handled := originalTCPHandler(id, pkt)
		// Логируем только SYN пакеты для диагностики
		if handled {
			log.Printf("[TUNSTACK] ✅ TCP SYN packet handled by forwarder: %s:%d -> %s:%d", 
				id.RemoteAddress, id.RemotePort, id.LocalAddress, id.LocalPort)
		}
		return handled
	}
	s.ipStack.SetTransportProtocolHandler(tcp.ProtocolNumber, tcpHandlerWrapper)

	// UDP Forwarder
	udpForwarder := udp.NewForwarder(s.ipStack, func(r *udp.ForwarderRequest) bool {
		var wq waiter.Queue
		ep, err := r.CreateEndpoint(&wq)
		if err != nil {
			return false
		}

		conn := gonet.NewUDPConn(&wq, ep)
		dest := fmt.Sprintf("%s:%d", r.ID().LocalAddress, r.ID().LocalPort)

		if s.udpHandler != nil {
			go s.udpHandler(conn, dest, "udp")
			return true
		} else {
			conn.Close()
			return false
		}
	})
	
	// Обертка для логирования UDP пакетов (минимум логирования для производительности)
	originalUDPHandler := udpForwarder.HandlePacket
	udpHandlerWrapper := func(id stack.TransportEndpointID, pkt *stack.PacketBuffer) bool {
		handled := originalUDPHandler(id, pkt)
		// Логируем только первые пакеты для диагностики
		return handled
	}
	s.ipStack.SetTransportProtocolHandler(udp.ProtocolNumber, udpHandlerWrapper)
	
	log.Printf("[TUNSTACK] ✅ Forwarders initialized (TCP and UDP handlers registered)")
}

func (s *Stack) packetPumpIn(ctx context.Context) {
	buf := make([]byte, 65535)
	for {
		select {
		case <-ctx.Done():
			return
		default:
			n, err := s.tunDevice.Read(buf)
			if err != nil {
				// "No more data is available" - это нормальная ситуация для wintun, нужно продолжать читать
				errStr := err.Error()
				if err == io.EOF || strings.Contains(errStr, "No more data") || strings.Contains(errStr, "no more data") {
					// Это не ошибка, просто нет данных - продолжаем читать
					continue
				}
				// Только реальные ошибки логируем и выходим
				log.Printf("[TUNSTACK] Read error: %v", err)
				continue // Продолжаем работу, не выходим
			}
			if n == 0 {
				continue
			}

			// Парсим IP пакет для определения протокола и извлечения информации о соединении
			if n < 20 { // Минимальный размер IP заголовка
				continue
			}

			ipv4Header := header.IPv4(buf[:n])
			if !ipv4Header.IsValid(n) {
				continue
			}

			protocolNum := ipv4Header.Protocol()
			protocol := tcpip.TransportProtocolNumber(protocolNum)
			srcIP := ipv4Header.SourceAddress()
			dstIP := ipv4Header.DestinationAddress()

			// Проверяем, является ли это входящим ответом (источник не 198.18.0.1)
			// Входящие ответы из VPN туннеля уже записаны в TUN через tun.Write() и должны быть
			// маршрутизированы Windows к приложению, а не перехвачены gvisor
			tunIP := tcpip.AddrFrom4Slice([]byte{198, 18, 0, 1})
			isIncomingResponse := !srcIP.Equal(tunIP)
			
			// Минимум логирования для производительности - только первые пакеты

			// Для TCP и UDP пакетов: создаем виртуальные соединения и вызываем handler напрямую
			if protocol == header.TCPProtocolNumber {
				// Извлекаем TCP заголовок
				ipHeaderLen := int(ipv4Header.HeaderLength())
				if n < ipHeaderLen+20 { // Минимальный размер TCP заголовка
					continue
				}

				tcpHeader := header.TCP(ipv4Header.Payload())
				tcpHeaderLen := int(tcpHeader.DataOffset())
				if tcpHeaderLen < 20 || n < ipHeaderLen+tcpHeaderLen {
					continue
				}

				srcPort := tcpHeader.SourcePort()
				dstPort := tcpHeader.DestinationPort()
				tcpFlags := tcpHeader.Flags()

				// Проверяем, это SYN пакет (без ACK)
				isSYN := (tcpFlags & header.TCPFlagSyn) != 0 && (tcpFlags & header.TCPFlagAck) == 0

				// Логируем только SYN пакеты для диагностики
				if isSYN {
					log.Printf("[TUNSTACK] 🔵 TCP SYN packet: %s:%d -> %s:%d", srcIP, srcPort, dstIP, dstPort)
				}

				// Для входящих ответов ищем виртуальное соединение с обратным порядком IP/портов
				// Исходящий SYN создает соединение: tcp:198.18.0.1:port->remote:443
				// Входящий SYN-ACK имеет: srcIP=remote, srcPort=443, dstIP=198.18.0.1, dstPort=port
				// Нужно искать: tcp:198.18.0.1:port->remote:443 (обратный порядок)
				var connKey string
				var target string
				if isIncomingResponse {
					// Для входящего ответа ищем соединение с обратным порядком
					connKey = fmt.Sprintf("tcp:%s:%d->%s:%d", dstIP, dstPort, srcIP, srcPort)
					target = fmt.Sprintf("%s:%d", srcIP, srcPort)
				} else {
					// Для исходящего пакета используем прямой порядок
					connKey = fmt.Sprintf("tcp:%s:%d->%s:%d", srcIP, srcPort, dstIP, dstPort)
					target = fmt.Sprintf("%s:%d", dstIP, dstPort)
				}
				
				// Проверяем, существует ли уже виртуальное соединение
				s.virtualMutex.RLock()
				vconn, exists := s.virtualConns[connKey]
				synPacketSent := false // Флаг для отслеживания, был ли SYN пакет уже отправлен при создании соединения
				s.virtualMutex.RUnlock()
				
				// Для входящих ответов: если виртуальное соединение найдено, записываем в writeChan
				// Если не найдено, записываем обратно в TUN напрямую
				if isIncomingResponse {
					// Логируем для отладки (ВСЕ входящие ответы)
					log.Printf("[TUNSTACK] 🔍 Looking for virtual connection for incoming TCP response: connKey=%s, exists=%v, srcPort=%d, dstPort=%d", connKey, exists, srcPort, dstPort)
					if exists && vconn != nil {
						// Создаем копию полного IP пакета для отправки в writeChan
						// ОПТИМИЗАЦИЯ: Используем пул буферов
						fullPacketCopy := getPacketBuffer(n)
						copy(fullPacketCopy, buf[:n])
						select {
						case vconn.writeChan <- fullPacketCopy:
							vconn.updateActivity()
							log.Printf("[TUNSTACK] ✅ Routed incoming TCP response to TUN via virtual connection: %s:%d -> %s:%d (%d bytes)", srcIP, srcPort, dstIP, dstPort, n)
						default:
							// Канал переполнен - возвращаем буфер в пул
							putPacketBuffer(fullPacketCopy)
							log.Printf("[TUNSTACK] ⚠️ Virtual connection write channel full, dropping incoming TCP response")
						}
					} else {
						// Соединение не найдено - записываем обратно в TUN напрямую
						// ОПТИМИЗАЦИЯ: Используем пул буферов
						packetCopy := getPacketBuffer(n)
						copy(packetCopy, buf[:n])
						if _, err := s.tunDevice.Write(packetCopy); err != nil {
							log.Printf("[TUNSTACK] ⚠️ Failed to re-inject incoming response to TUN: %v", err)
						} else {
							log.Printf("[TUNSTACK] ✅ Re-injected incoming TCP response to TUN (no virtual conn, connKey=%s): %s:%d -> %s:%d (%d bytes)", connKey, srcIP, srcPort, dstIP, dstPort, n)
						}
						// ОПТИМИЗАЦИЯ: Возвращаем буфер в пул после использования
						putPacketBuffer(packetCopy)
					}
					continue
				}
				
				if !exists && isSYN {
					// ОПТИМИЗАЦИЯ: Используем кэшированное время для уменьшения системных вызовов
					timeCache := util.GetGlobalTimeCache()
					now := timeCache.Now()
					
					// Проверяем, не обрабатывали ли мы недавно этот SYN пакет (по connKey)
					s.synMutex.Lock()
					lastSYN, seen := s.recentSYNs[connKey]
					// Если видели этот SYN в последние 2 секунды, пропускаем его
					if seen && now.Sub(lastSYN) < 2*time.Second {
						s.synMutex.Unlock()
						log.Printf("[TUNSTACK] ⏭️ Skipping duplicate SYN packet (recently processed): %s (last seen %v ago)", connKey, now.Sub(lastSYN))
						// ВАЖНО: Если SYN был пропущен, но соединение уже существует, не создаем новое
						// Проверяем, может быть соединение уже создано другим потоком
						s.virtualMutex.RLock()
						existingVconn, existsNow := s.virtualConns[connKey]
						s.virtualMutex.RUnlock()
						if existsNow && existingVconn != nil {
							log.Printf("[TUNSTACK] ✅ Found existing virtual connection for skipped SYN: %s", connKey)
							// КРИТИЧЕСКАЯ ОПТИМИЗАЦИЯ: Для SYN пакетов всегда используем блокирующую отправку
							// Это предотвращает потерю SYN пакетов и TCP retransmissions
							synPacketCopy := getPacketBuffer(n)
							copy(synPacketCopy, buf[:n])
							// Блокирующая отправка для SYN - не отбрасываем!
							existingVconn.packetChan <- synPacketCopy
							existingVconn.updateActivity()
							log.Printf("[TUNSTACK] ✅ Sent SYN packet to existing connection: %s", connKey)
						}
						continue
					}
					// Отмечаем этот SYN как обработанный
					s.recentSYNs[connKey] = now
					s.synMutex.Unlock()
					
					// Проверяем, не создаем ли мы слишком много соединений к одному адресу (IP:Port)
					// Это более разумная проверка, чем блокировка по IP, так как позволяет
					// множественные соединения к одному IP с разными портами
					// ОПТИМИЗАЦИЯ: Используем strings.Builder для более эффективного создания строки
					var destKeyBuilder strings.Builder
					destKeyBuilder.Grow(len(dstIP.String()) + 16) // Предварительно выделяем память
					destKeyBuilder.WriteString(dstIP.String())
					destKeyBuilder.WriteByte(':')
					destKeyBuilder.WriteString(strconv.Itoa(int(dstPort)))
					destKey := destKeyBuilder.String()
					s.destMutex.Lock()
					lastDestAttempt, destSeen := s.activeDestinations[destKey]
					// Если к этому адресу уже пытались подключиться в последние 3 секунды, пропускаем
					if destSeen && now.Sub(lastDestAttempt) < 3*time.Second {
						s.destMutex.Unlock()
						log.Printf("[TUNSTACK] ⏭️ Skipping SYN to recently attempted destination: %s (last attempt %v ago)", destKey, now.Sub(lastDestAttempt))
						// Проверяем, может быть соединение уже создано для этого конкретного connKey
						s.virtualMutex.RLock()
						existingVconn, existsNow := s.virtualConns[connKey]
						s.virtualMutex.RUnlock()
						if existsNow && existingVconn != nil {
							log.Printf("[TUNSTACK] ✅ Found existing virtual connection for skipped SYN: %s", connKey)
							// Отправляем SYN пакет в существующее соединение
							// ОПТИМИЗАЦИЯ: Используем пул буферов
							synPacketCopy := getPacketBuffer(n)
							copy(synPacketCopy, buf[:n])
							select {
							case existingVconn.packetChan <- synPacketCopy:
								existingVconn.updateActivity()
								log.Printf("[TUNSTACK] ✅ Sent SYN packet to existing connection: %s", connKey)
							default:
								log.Printf("[TUNSTACK] ⚠️ packetChan full for existing connection, dropping SYN")
							}
						}
						continue
					}
					// Отмечаем попытку подключения к этому адресу
					s.activeDestinations[destKey] = now
					log.Printf("[TUNSTACK] 📝 Marked destination %s as active for connection: %s", destKey, connKey)
					s.destMutex.Unlock()
					
					// Очищаем старые записи (старше 10 секунд)
					go func() {
						s.synMutex.Lock()
						defer s.synMutex.Unlock()
						for key, timestamp := range s.recentSYNs {
							if now.Sub(timestamp) > 10*time.Second {
								delete(s.recentSYNs, key)
							}
						}
					}()
					
					// Очищаем старые записи по адресам назначения
					go func() {
						s.destMutex.Lock()
						defer s.destMutex.Unlock()
						for key, timestamp := range s.activeDestinations {
							if now.Sub(timestamp) > 10*time.Second {
								delete(s.activeDestinations, key)
							}
						}
					}()
					
					// Создаем новое виртуальное соединение для SYN пакета
					s.virtualMutex.Lock()
					// Проверяем еще раз после получения блокировки
					if _, stillExists := s.virtualConns[connKey]; !stillExists {
						log.Printf("[TUNSTACK] 🔨 Creating new virtual TCP connection: connKey=%s, srcIP=%s, srcPort=%d, dstIP=%s, dstPort=%d", 
							connKey, srcIP, srcPort, dstIP, dstPort)
						localAddr := &net.TCPAddr{
							IP:   net.IP(srcIP.AsSlice()),
							Port: int(srcPort),
						}
						remoteAddr := &net.TCPAddr{
							IP:   net.IP(dstIP.AsSlice()),
							Port: int(dstPort),
						}
						
						vconn = &virtualConn{
							localAddr:  localAddr,
							remoteAddr: remoteAddr,
							packetChan:  make(chan []byte, 8192), // КРИТИЧЕСКАЯ ОПТИМИЗАЦИЯ: Увеличено до 8192 для предотвращения потери DATA пакетов
							writeChan:   make(chan []byte, 8192), // КРИТИЧЕСКАЯ ОПТИМИЗАЦИЯ: Увеличено до 8192 для предотвращения потери DATA пакетов
							closeChan:   make(chan struct{}),
							tunDevice:   s.tunDevice,
							connKey:     connKey,
						}
						s.virtualConns[connKey] = vconn
						log.Printf("[TUNSTACK] ✅ Virtual TCP connection created and registered: connKey=%s (total connections: %d)", 
							connKey, len(s.virtualConns))
						
						// Запускаем goroutine для записи ответов обратно в TUN
						go func() {
							for {
								select {
								case <-vconn.closeChan:
									return
								case data := <-vconn.writeChan:
									if data == nil {
										return
									}
									// Данные уже являются полным IP пакетом, записываем напрямую в TUN
									if _, err := s.tunDevice.Write(data); err != nil {
										log.Printf("[TUNSTACK] ⚠️ Failed to write to TUN: %v", err)
									}
									// ОПТИМИЗАЦИЯ Xray-core: Освобождаем буфер после использования
									putPacketBuffer(data)
								}
							}
						}()
						
					// ВАЖНО: Отправляем SYN пакет в packetChan ДО вызова handler
					// Это гарантирует, что handler получит первый пакет при чтении
					// ОПТИМИЗАЦИЯ Xray-core: Используем пул буферов для переиспользования памяти
					// КРИТИЧЕСКАЯ ОПТИМИЗАЦИЯ: Для SYN пакетов всегда используем блокирующую отправку
					// Это предотвращает потерю SYN пакетов и TCP retransmissions
					synPacketCopy := getPacketBuffer(n)
					copy(synPacketCopy, buf[:n])
					// Блокирующая отправка для SYN - не отбрасываем!
					vconn.packetChan <- synPacketCopy
					synPacketSent = true // Отмечаем, что SYN пакет уже отправлен
					vconn.updateActivity()
					log.Printf("[TUNSTACK] ✅ Sent SYN packet to packetChan for connection: %s", connKey)
						
						// Вызываем handler в отдельной goroutine
						if s.tcpHandler != nil {
							log.Printf("[TUNSTACK] 🔵 Creating virtual TCP connection: %s -> %s (connKey=%s)", localAddr, remoteAddr, connKey)
							go func() {
								defer func() {
									// Помечаем, что handler завершился, но соединение остается активным
									// для обработки поздних ACK/DATA пакетов от ОС TCP стека
									s.virtualMutex.RLock()
									if vconn, exists := s.virtualConns[connKey]; exists && vconn != nil {
										vconn.activityMutex.Lock()
										vconn.handlerFinished = true
										// ОПТИМИЗАЦИЯ: Используем кэшированное время для уменьшения системных вызовов
										vconn.lastActivity = util.GetGlobalTimeCache().Now() // Обновляем активность при завершении handler
										vconn.activityMutex.Unlock()
									}
									s.virtualMutex.RUnlock()
									
									log.Printf("[TUNSTACK] 🔄 Handler finished for connection: %s, connection will remain active for late packets", connKey)
									
									// Планируем удаление соединения после периода неактивности
									// Это позволяет обработать поздние ACK/DATA пакеты от ОС
									s.removeVirtualConn(connKey)
									
									// Также удаляем из recentSYNs после небольшой задержки
									// чтобы разрешить повторные попытки через некоторое время
									go func() {
										time.Sleep(6 * time.Second)
										s.synMutex.Lock()
										delete(s.recentSYNs, connKey)
										s.synMutex.Unlock()
									}()
								}()
								s.tcpHandler(vconn, target, "tcp")
							}()
						} else {
							log.Printf("[TUNSTACK] ⚠️ No TCP handler set, but virtual connection created: %s", connKey)
						}
					} else {
						vconn = s.virtualConns[connKey]
					}
					s.virtualMutex.Unlock()
				}
				
				// Отправляем полный IP пакет в виртуальное соединение (если оно существует)
				// Это позволяет handler отправить полный пакет через VPN туннель без реконструкции заголовков
				// ВАЖНО: Не отправляем SYN пакет, если он уже был отправлен при создании соединения
				// ВАЖНО: Повторно проверяем существование соединения перед использованием, чтобы избежать race condition
				s.virtualMutex.RLock()
				currentVconn, stillExists := s.virtualConns[connKey]
				s.virtualMutex.RUnlock()
				
				if currentVconn != nil && stillExists && !(isSYN && synPacketSent) {
					// ОПТИМИЗАЦИЯ Xray-core: Используем пул буферов для переиспользования памяти
					fullPacketCopy := getPacketBuffer(n)
					copy(fullPacketCopy, buf[:n])
					
					// КРИТИЧЕСКАЯ ОПТИМИЗАЦИЯ: Для критичных пакетов (ACK, SYN-ACK) не отбрасываем, а ждем
					// Это предотвращает TCP retransmissions
					isACK := (tcpFlags & header.TCPFlagAck) != 0
					isSYNACK := isSYN && isACK
					isCritical := isACK || isSYNACK
					
					if isCritical {
						// Для критичных пакетов ждем места в канале - не отбрасываем!
						currentVconn.packetChan <- fullPacketCopy
						currentVconn.updateActivity()
					} else {
					// КРИТИЧЕСКАЯ ОПТИМИЗАЦИЯ: Для DATA пакетов используем неблокирующую отправку
					// Если канал полон, пакет будет отброшен, но это лучше чем блокировать на 100ms
					// Буфер канала увеличен до 8192, что должно быть достаточно для большинства случаев
					select {
					case currentVconn.packetChan <- fullPacketCopy:
						currentVconn.updateActivity()
					default:
						// Канал полон - отбрасываем пакет (буфер достаточно большой, это редкий случай)
						if droppedCount := atomic.AddUint64(&s.droppedPacketCount, 1); droppedCount%1000 == 0 {
							log.Printf("[TUNSTACK] ⚠️ packetChan full, dropped DATA packet #%d (last: %s:%d -> %s:%d, %d bytes)", 
								droppedCount, srcIP, srcPort, dstIP, dstPort, n)
						}
						putPacketBuffer(fullPacketCopy)
					}
					}
				} else if currentVconn == nil || !stillExists {
					// Виртуальное соединение не найдено - это может быть проблемой для ACK/DATA пакетов
					// КРИТИЧЕСКАЯ ОПТИМИЗАЦИЯ: Логируем только каждые 1000 раз для производительности
					if !isSYN {
						missingCount := atomic.AddUint64(&s.missingConnCount, 1)
						if missingCount%1000 == 0 {
							isACK := (tcpFlags & header.TCPFlagAck) != 0
							isData := n > ipHeaderLen+tcpHeaderLen
							packetType := "unknown"
							if isACK && !isData {
								packetType = "ACK"
							} else if isData {
								packetType = "DATA"
							}
							log.Printf("[TUNSTACK] ⚠️ WARNING: No virtual connection found for %s packet (count=%d): %s:%d -> %s:%d", 
								packetType, missingCount, srcIP, srcPort, dstIP, dstPort)
						} else {
							log.Printf("[TUNSTACK] 🔍 No TCP connections available (all removed?)")
						}
					} else {
						// Если соединение еще не создано, но это SYN пакет, создаем его немедленно
						// Это может произойти, если пакет пришел до того, как мы успели создать соединение
						continue
					}
				} else if isSYN && synPacketSent {
					// SYN пакет уже был отправлен - это нормально, просто пропускаем
					log.Printf("[TUNSTACK] ⏭️ Skipping duplicate SYN packet (already sent to packetChan): %s", connKey)
				}

			} else if protocol == header.UDPProtocolNumber {
				// Извлекаем UDP заголовок
				ipHeaderLen := int(ipv4Header.HeaderLength())
				if n < ipHeaderLen+8 { // Минимальный размер UDP заголовка
					continue
				}

				udpHeader := header.UDP(ipv4Header.Payload())
				srcPort := udpHeader.SourcePort()
				dstPort := udpHeader.DestinationPort()

				// Логируем информацию о UDP пакете
				if n < 200 {
					log.Printf("[TUNSTACK] 🟢 UDP packet: %s:%d -> %s:%d (incoming=%v)", 
						srcIP, srcPort, dstIP, dstPort, isIncomingResponse)
				}

				// Для входящих ответов ищем виртуальное соединение с обратным порядком IP/портов
				var connKey string
				var target string
				if isIncomingResponse {
					// Для входящего ответа ищем соединение с обратным порядком
					connKey = fmt.Sprintf("udp:%s:%d->%s:%d", dstIP, dstPort, srcIP, srcPort)
					target = fmt.Sprintf("%s:%d", srcIP, srcPort)
				} else {
					// Для исходящего пакета используем прямой порядок
					connKey = fmt.Sprintf("udp:%s:%d->%s:%d", srcIP, srcPort, dstIP, dstPort)
					target = fmt.Sprintf("%s:%d", dstIP, dstPort)
				}
				
				// Проверяем, существует ли уже виртуальное соединение
				s.virtualMutex.RLock()
				vconn, exists := s.virtualConns[connKey]
				udpPacketSent := false // Флаг для отслеживания, был ли первый UDP пакет уже отправлен при создании соединения
				s.virtualMutex.RUnlock()
				
				// Для входящих ответов: если виртуальное соединение найдено, записываем в writeChan
				// Если не найдено, записываем обратно в TUN напрямую
				if isIncomingResponse {
					// Логируем для отладки (ВСЕ входящие ответы)
					log.Printf("[TUNSTACK] 🔍 Looking for virtual connection for incoming UDP response: connKey=%s, exists=%v, srcPort=%d, dstPort=%d", connKey, exists, srcPort, dstPort)
					if exists && vconn != nil {
						// Создаем копию полного IP пакета для отправки в writeChan
						// ОПТИМИЗАЦИЯ: Используем пул буферов
						fullPacketCopy := getPacketBuffer(n)
						copy(fullPacketCopy, buf[:n])
						select {
						case vconn.writeChan <- fullPacketCopy:
							vconn.updateActivity()
							log.Printf("[TUNSTACK] ✅ Routed incoming UDP response to TUN via virtual connection: %s:%d -> %s:%d (%d bytes)", srcIP, srcPort, dstIP, dstPort, n)
						default:
							// Канал переполнен - возвращаем буфер в пул
							putPacketBuffer(fullPacketCopy)
							log.Printf("[TUNSTACK] ⚠️ Virtual connection write channel full, dropping incoming UDP response")
						}
					} else {
						// Соединение не найдено - записываем обратно в TUN напрямую
						// ОПТИМИЗАЦИЯ: Используем пул буферов
						packetCopy := getPacketBuffer(n)
						copy(packetCopy, buf[:n])
						if _, err := s.tunDevice.Write(packetCopy); err != nil {
							log.Printf("[TUNSTACK] ⚠️ Failed to re-inject incoming response to TUN: %v", err)
						} else {
							log.Printf("[TUNSTACK] ✅ Re-injected incoming UDP response to TUN (no virtual conn, connKey=%s): %s:%d -> %s:%d (%d bytes)", connKey, srcIP, srcPort, dstIP, dstPort, n)
						}
						// ОПТИМИЗАЦИЯ: Возвращаем буфер в пул после использования
						putPacketBuffer(packetCopy)
					}
					continue
				}
				
				if !exists {
					// ОПТИМИЗАЦИЯ: Используем кэшированное время для уменьшения системных вызовов
					timeCache := util.GetGlobalTimeCache()
					now := timeCache.Now()
					
					// Проверяем, есть ли уже активное соединение к целевому адресу (IP:Port)
					destKey := fmt.Sprintf("%s:%d", dstIP, dstPort)
					s.destMutex.RLock()
					lastDestAttempt, destSeen := s.activeDestinations[destKey]
					s.destMutex.RUnlock()
					
					// Если к этому адресу уже пытались подключиться в последние 3 секунды, пропускаем
					// (увеличено с 1 секунды для лучшей защиты от дублирования)
					if destSeen && now.Sub(lastDestAttempt) < 3*time.Second {
						log.Printf("[TUNSTACK] ⏭️ Skipping UDP packet to recently attempted destination: %s (last attempt %v ago)", destKey, now.Sub(lastDestAttempt))
						continue
					}
					
					// Создаем новое виртуальное соединение для UDP пакета
					s.virtualMutex.Lock()
					// Проверяем еще раз после получения блокировки
					if _, stillExists := s.virtualConns[connKey]; !stillExists {
						localAddr := &net.UDPAddr{
							IP:   net.IP(srcIP.AsSlice()),
							Port: int(srcPort),
						}
						remoteAddr := &net.UDPAddr{
							IP:   net.IP(dstIP.AsSlice()),
							Port: int(dstPort),
						}
						
						vconn = &virtualConn{
							localAddr:  localAddr,
							remoteAddr: remoteAddr,
							packetChan:  make(chan []byte, 8192), // КРИТИЧЕСКАЯ ОПТИМИЗАЦИЯ: Увеличено до 8192 для предотвращения потери DATA пакетов
							writeChan:   make(chan []byte, 8192), // КРИТИЧЕСКАЯ ОПТИМИЗАЦИЯ: Увеличено до 8192 для предотвращения потери DATA пакетов
							closeChan:   make(chan struct{}),
							tunDevice:   s.tunDevice,
							connKey:     connKey,
						}
						s.virtualConns[connKey] = vconn
						
						// Отмечаем попытку подключения к этому адресу
						s.destMutex.Lock()
						s.activeDestinations[destKey] = now
						s.destMutex.Unlock()
						
						// Запускаем goroutine для записи ответов обратно в TUN
						go func() {
							for {
								select {
								case <-vconn.closeChan:
									return
								case data := <-vconn.writeChan:
									if data == nil {
										return
									}
									// Данные уже являются полным IP пакетом, записываем напрямую в TUN
									if _, err := s.tunDevice.Write(data); err != nil {
										log.Printf("[TUNSTACK] ⚠️ Failed to write to TUN: %v", err)
									}
									// ОПТИМИЗАЦИЯ Xray-core: Освобождаем буфер после использования
									putPacketBuffer(data)
								}
							}
						}()
						
					// ВАЖНО: Отправляем первый UDP пакет в packetChan ДО вызова handler
					// Это гарантирует, что handler получит первый пакет при чтении
					// ОПТИМИЗАЦИЯ Xray-core: Используем пул буферов для переиспользования памяти
					udpPacketCopy := getPacketBuffer(n)
					copy(udpPacketCopy, buf[:n])
					select {
					case vconn.packetChan <- udpPacketCopy:
							udpPacketSent = true // Отмечаем, что первый UDP пакет уже отправлен
							vconn.updateActivity()
							log.Printf("[TUNSTACK] ✅ Sent first UDP packet to packetChan for connection: %s", connKey)
						default:
							log.Printf("[TUNSTACK] ⚠️ packetChan full when sending first UDP packet, dropping")
						}
						
						// Вызываем handler в отдельной goroutine
						if s.udpHandler != nil {
							log.Printf("[TUNSTACK] 🟢 Creating virtual UDP connection: %s -> %s", localAddr, remoteAddr)
							go func() {
								defer func() {
									// Помечаем, что handler завершился, но соединение остается активным
									s.virtualMutex.RLock()
									if vconn, exists := s.virtualConns[connKey]; exists && vconn != nil {
										vconn.activityMutex.Lock()
										vconn.handlerFinished = true
										// ОПТИМИЗАЦИЯ: Используем кэшированное время для уменьшения системных вызовов
										vconn.lastActivity = util.GetGlobalTimeCache().Now()
										vconn.activityMutex.Unlock()
									}
									s.virtualMutex.RUnlock()
									
									log.Printf("[TUNSTACK] 🔄 UDP handler finished for connection: %s, connection will remain active for late packets", connKey)
									
									// Планируем удаление соединения после периода неактивности
									s.removeVirtualConn(connKey)
								}()
								s.udpHandler(vconn, target, "udp")
							}()
						}
					} else {
						vconn = s.virtualConns[connKey]
					}
					s.virtualMutex.Unlock()
				}
				
				// Отправляем полный IP пакет в виртуальное соединение
				// Это позволяет handler отправить полный пакет через VPN туннель без реконструкции заголовков
				// ВАЖНО: Не отправляем первый UDP пакет, если он уже был отправлен при создании соединения
				if vconn != nil && !udpPacketSent {
					// Создаем копию полного IP пакета для отправки в канал
					// ОПТИМИЗАЦИЯ: Используем пул буферов
					fullPacketCopy := getPacketBuffer(n)
					copy(fullPacketCopy, buf[:n])
					select {
					case vconn.packetChan <- fullPacketCopy:
						vconn.updateActivity()
					default:
						// Канал переполнен, пропускаем пакет
					}
				}

			} else {
				// Для других протоколов (ICMP и т.д.) просто инжектируем в gVisor
				view := buffer.NewView(n)
				copy(view.AsSlice(), buf[:n])
				pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
					Payload: buffer.MakeWithData(view.AsSlice()),
				})
				s.linkEndpoint.InjectInbound(header.IPv4ProtocolNumber, pkt)
				pkt.DecRef()
			}
		}
	}
}

func (s *Stack) packetPumpOut(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
			pkt := s.linkEndpoint.Read() 
			if pkt == nil {
				continue
			}

			views := pkt.ToView()
			if views.Size() > 0 {
				data := views.AsSlice()
				_, err := s.tunDevice.Write(data)
				if err != nil {
					log.Printf("[TUNSTACK] Write error: %v", err)
				}
			}
			pkt.DecRef()
		}
	}
}

// SetPacketHandler is a legacy stub
func (s *Stack) SetPacketHandler(_ interface{}) {}

// HandleIncomingPacket обрабатывает входящий пакет от [STREAM] напрямую
// Это альтернатива записи в TUN и чтения через packetPumpIn
func (s *Stack) HandleIncomingPacket(packet []byte) error {
	log.Printf("[TUNSTACK] 🔄 HandleIncomingPacket called with %d bytes", len(packet))
	
	if len(packet) < 20 {
		log.Printf("[TUNSTACK] ⚠️ HandleIncomingPacket: packet too small (%d bytes)", len(packet))
		return fmt.Errorf("packet too small")
	}
	
	// Пытаемся найти IP заголовок, проверяя смещения от 0 до MTU (1500 байт) для больших пакетов
	// Это необходимо, так как некоторые пакеты могут иметь префикс перед IP заголовком
	// (например, padding/обфускация в VLESS/Xray может добавлять дополнительные байты)
	var ipv4Header header.IPv4
	foundIP := false
	// Используем динамический поиск: проверяем до MTU (1500 байт) или до конца пакета
	// Это покрывает случаи с большими префиксами в обфусцированных протоколах
	const maxMTU = 1500 // Стандартный MTU для Ethernet
	maxOffset := maxMTU - 20 // Максимальное смещение для поиска IP заголовка
	if len(packet) < maxOffset+20 {
		maxOffset = len(packet) - 20
	}
	if maxOffset < 0 {
		maxOffset = 0
	}
	
	for offset := 0; offset <= maxOffset && offset+20 <= len(packet); offset++ {
		ipVer := (packet[offset] >> 4) & 0x0F
		if ipVer == 4 && offset+20 <= len(packet) {
			// Проверяем, что это действительно IPv4 заголовок
			// Проверяем IHL (Internet Header Length) - должен быть >= 5 (20 байт)
			ihl := int(packet[offset] & 0x0F)
			if ihl >= 5 && ihl <= 15 && offset+ihl*4 <= len(packet) {
				// Проверяем, что протокол валидный (TCP=6, UDP=17, ICMP=1, и т.д.)
				protocolNum := packet[offset+9]
				if protocolNum == 6 || protocolNum == 17 || protocolNum == 1 {
					// Дополнительная проверка: проверяем, что IP адреса выглядят валидными
					// (не все нули и не все 255)
					srcIPBytes := packet[offset+12 : offset+16]
					dstIPBytes := packet[offset+16 : offset+20]
					allZerosSrc := srcIPBytes[0] == 0 && srcIPBytes[1] == 0 && srcIPBytes[2] == 0 && srcIPBytes[3] == 0
					allZerosDst := dstIPBytes[0] == 0 && dstIPBytes[1] == 0 && dstIPBytes[2] == 0 && dstIPBytes[3] == 0
					allOnesSrc := srcIPBytes[0] == 255 && srcIPBytes[1] == 255 && srcIPBytes[2] == 255 && srcIPBytes[3] == 255
					allOnesDst := dstIPBytes[0] == 255 && dstIPBytes[1] == 255 && dstIPBytes[2] == 255 && dstIPBytes[3] == 255
					
					// Если IP адреса выглядят валидными (не все нули и не все 255), это похоже на настоящий IP пакет
					if !(allZerosSrc && allZerosDst) && !(allOnesSrc && allOnesDst) {
						// Пытаемся создать IPv4 заголовок
						potentialHeader := header.IPv4(packet[offset:])
						if potentialHeader.IsValid(len(packet) - offset) {
							ipv4Header = potentialHeader
							foundIP = true
							if offset > 0 {
								log.Printf("[TUNSTACK] 🔍 Found IPv4 header at offset %d in packet (len=%d, ihl=%d, protocol=%d), trimming prefix", offset, len(packet), ihl, protocolNum)
								// Обрезаем префикс для дальнейшей обработки
								packet = packet[offset:]
							}
							break
						}
					}
				}
			}
		} else if ipVer == 6 && offset+40 <= len(packet) {
			// IPv6 пакет - обрабатываем как валидный IP пакет
			if offset > 0 {
				log.Printf("[TUNSTACK] 🔍 Found IPv6 header at offset %d in packet (len=%d), trimming prefix", offset, len(packet))
				packet = packet[offset:]
			}
			log.Printf("[TUNSTACK] 🔵 IPv6 packet received: %d bytes", len(packet))
			// Для IPv6 просто записываем в TUN напрямую
			_, err := s.tunDevice.Write(packet)
			return err
		}
	}
	
	if !foundIP {
		// IP заголовок не найден - логируем первые байты для диагностики
		hexDumpLen := 32
		if len(packet) < hexDumpLen {
			hexDumpLen = len(packet)
		}
		hexDump := ""
		for i := 0; i < hexDumpLen; i++ {
			hexDump += fmt.Sprintf("%02x ", packet[i])
		}
		log.Printf("[TUNSTACK] ⚠️ HandleIncomingPacket: not IPv4/IPv6 packet (len=%d). First %d bytes: %s", len(packet), hexDumpLen, hexDump)
		return fmt.Errorf("not IPv4/IPv6 packet")
	}
	
	srcIP := ipv4Header.SourceAddress()
	dstIP := ipv4Header.DestinationAddress()
	protocolNum := ipv4Header.Protocol()
	protocol := tcpip.TransportProtocolNumber(protocolNum)
	
	// Проверяем, является ли это входящим ответом (источник не 198.18.0.1)
	tunIP := tcpip.AddrFrom4Slice([]byte{198, 18, 0, 1})
	isIncomingResponse := !srcIP.Equal(tunIP)
	
	log.Printf("[TUNSTACK] 🔄 HandleIncomingPacket: %s -> %s (%d bytes, protocol=%d, isIncoming=%v, tunIP=%s)", srcIP, dstIP, len(packet), protocol, isIncomingResponse, tunIP)
	
	if !isIncomingResponse {
		// Это не входящий ответ, пропускаем
		log.Printf("[TUNSTACK] ⚠️ HandleIncomingPacket: skipping non-incoming response (srcIP=%s == tunIP=%s)", srcIP, tunIP)
		return nil
	}
	
	// Обрабатываем TCP и UDP пакеты
	if protocol == tcpip.TransportProtocolNumber(header.TCPProtocolNumber) {
		log.Printf("[TUNSTACK] 🔵 Routing to handleIncomingTCP: %s -> %s (%d bytes)", srcIP, dstIP, len(packet))
		return s.handleIncomingTCP(packet, srcIP, dstIP)
	} else if protocol == tcpip.TransportProtocolNumber(header.UDPProtocolNumber) {
		log.Printf("[TUNSTACK] 🟢 Routing to handleIncomingUDP: %s -> %s (%d bytes)", srcIP, dstIP, len(packet))
		return s.handleIncomingUDP(packet, srcIP, dstIP)
	}
	
	// Для других протоколов просто записываем в TUN
	log.Printf("[TUNSTACK] ⚠️ Unknown protocol %d, writing directly to TUN: %s -> %s (%d bytes)", protocolNum, srcIP, dstIP, len(packet))
	_, err := s.tunDevice.Write(packet)
	return err
}

func (s *Stack) handleIncomingTCP(packet []byte, srcIP, dstIP tcpip.Address) error {
	ipv4Header := header.IPv4(packet)
	ipHeaderLen := int(ipv4Header.HeaderLength())
	if len(packet) < ipHeaderLen+20 {
		return fmt.Errorf("packet too small for TCP")
	}
	
	tcpHeader := header.TCP(ipv4Header.Payload())
	tcpHeaderLen := int(tcpHeader.DataOffset())
	if tcpHeaderLen < 20 || len(packet) < ipHeaderLen+tcpHeaderLen {
		return fmt.Errorf("invalid TCP header")
	}
	
	srcPort := tcpHeader.SourcePort()
	dstPort := tcpHeader.DestinationPort()
	tcpFlags := tcpHeader.Flags()
	isSYN := (tcpFlags & header.TCPFlagSyn) != 0
	isACK := (tcpFlags & header.TCPFlagAck) != 0
	isSYNACK := isSYN && isACK
	isRST := (tcpFlags & header.TCPFlagRst) != 0
	isFIN := (tcpFlags & header.TCPFlagFin) != 0
	
	// Для входящего ответа ищем соединение с обратным порядком IP/портов
	connKey := fmt.Sprintf("tcp:%s:%d->%s:%d", dstIP, dstPort, srcIP, srcPort)
	
	s.virtualMutex.RLock()
	vconn, exists := s.virtualConns[connKey]
	s.virtualMutex.RUnlock()
	
	log.Printf("[TUNSTACK] 🔍 HandleIncomingTCP: %s:%d -> %s:%d (flags: SYN=%v, ACK=%v, SYN-ACK=%v, RST=%v, FIN=%v, connKey=%s, exists=%v, %d bytes)", 
		srcIP, srcPort, dstIP, dstPort, isSYN, isACK, isSYNACK, isRST, isFIN, connKey, exists, len(packet))
	
	if !exists {
		// Логируем все доступные TCP соединения для отладки
		s.virtualMutex.RLock()
		tcpConnCount := 0
		for key, vc := range s.virtualConns {
			if vc != nil && len(key) >= 4 && key[:4] == "tcp:" {
				tcpConnCount++
				if tcpConnCount <= 5 { // Логируем первые 5 TCP соединений
					log.Printf("[TUNSTACK] 🔍 Available TCP conn: %s", key)
				}
			}
		}
		s.virtualMutex.RUnlock()
		if tcpConnCount > 5 {
			log.Printf("[TUNSTACK] 🔍 ... and %d more TCP connections (total: %d)", tcpConnCount-5, tcpConnCount)
		}
		log.Printf("[TUNSTACK] ⚠️ No matching TCP connection found for connKey=%s (looking for response to %s:%d -> %s:%d)", 
			connKey, dstIP, dstPort, srcIP, srcPort)
	}
	
	if exists && vconn != nil {
		// ОПТИМИЗАЦИЯ Xray-core: Используем пул буферов
		fullPacketCopy := getPacketBuffer(len(packet))
		copy(fullPacketCopy, packet)
		
		// КРИТИЧЕСКАЯ ОПТИМИЗАЦИЯ: Для входящих ответов (SYN-ACK, ACK) не отбрасываем, а ждем
		// Это критично для предотвращения TCP retransmissions
		// Определяем тип пакета для принятия решения
		if len(packet) >= 20 {
			ipHeaderLen := int((packet[0] & 0x0F) * 4)
			if len(packet) > ipHeaderLen+13 {
				tcpFlags := packet[ipHeaderLen+13]
				isACK := (tcpFlags & 0x10) != 0
				isSYN := (tcpFlags & 0x02) != 0
				isSYNACK := isSYN && isACK
				isCritical := isACK || isSYNACK
				
				if isCritical {
					// Для критичных пакетов ждем места в канале - не отбрасываем!
					// Это предотвращает TCP retransmissions
					vconn.writeChan <- fullPacketCopy
					vconn.updateActivity()
					// КРИТИЧЕСКАЯ ОПТИМИЗАЦИЯ: Убираем логирование для производительности
					return nil
				}
			}
		}
		
		// КРИТИЧЕСКАЯ ОПТИМИЗАЦИЯ: Для DATA пакетов используем неблокирующую отправку
		// Буфер канала увеличен до 8192, что должно быть достаточно
		select {
		case vconn.writeChan <- fullPacketCopy:
			vconn.updateActivity()
			return nil
		default:
			// Канал полон - освобождаем буфер (редкий случай при переполнении)
			putPacketBuffer(fullPacketCopy)
			if atomic.AddUint64(&s.droppedPacketCount, 1)%100 == 0 {
				log.Printf("[TUNSTACK] ⚠️ Virtual connection write channel timeout, dropped incoming TCP response")
			}
			return fmt.Errorf("write channel timeout")
		}
	} else {
		// Соединение не найдено - записываем обратно в TUN напрямую
		if _, err := s.tunDevice.Write(packet); err != nil {
			log.Printf("[TUNSTACK] ⚠️ Failed to write incoming TCP response to TUN: %v", err)
			return err
		} else {
			log.Printf("[TUNSTACK] ✅ Wrote incoming TCP response to TUN (no virtual conn, connKey=%s): %s:%d -> %s:%d (%d bytes)", connKey, srcIP, srcPort, dstIP, dstPort, len(packet))
			return nil
		}
	}
}

func (s *Stack) handleIncomingUDP(packet []byte, srcIP, dstIP tcpip.Address) error {
	ipv4Header := header.IPv4(packet)
	ipHeaderLen := int(ipv4Header.HeaderLength())
	if len(packet) < ipHeaderLen+8 {
		return fmt.Errorf("packet too small for UDP")
	}
	
	udpHeader := header.UDP(ipv4Header.Payload())
	srcPort := udpHeader.SourcePort()
	dstPort := udpHeader.DestinationPort()
	
	// Для входящего ответа ищем соединение с обратным порядком IP/портов
	connKey := fmt.Sprintf("udp:%s:%d->%s:%d", dstIP, dstPort, srcIP, srcPort)
	
	s.virtualMutex.RLock()
	vconn, exists := s.virtualConns[connKey]
	s.virtualMutex.RUnlock()
	
	log.Printf("[TUNSTACK] 🔍 HandleIncomingUDP: connKey=%s, exists=%v, srcPort=%d, dstPort=%d", connKey, exists, srcPort, dstPort)
	
	if exists && vconn != nil {
		// Создаем копию полного IP пакета для отправки в writeChan
		fullPacketCopy := make([]byte, len(packet))
		copy(fullPacketCopy, packet)
		select {
		case vconn.writeChan <- fullPacketCopy:
			vconn.updateActivity()
			log.Printf("[TUNSTACK] ✅ Routed incoming UDP response via virtual connection: %s:%d -> %s:%d (%d bytes)", srcIP, srcPort, dstIP, dstPort, len(packet))
			return nil
		default:
			log.Printf("[TUNSTACK] ⚠️ Virtual connection write channel full, dropping incoming UDP response")
			return fmt.Errorf("write channel full")
		}
	} else {
		// Соединение не найдено - записываем обратно в TUN напрямую
		if _, err := s.tunDevice.Write(packet); err != nil {
			log.Printf("[TUNSTACK] ⚠️ Failed to write incoming UDP response to TUN: %v", err)
			return err
		} else {
			log.Printf("[TUNSTACK] ✅ Wrote incoming UDP response to TUN (no virtual conn, connKey=%s): %s:%d -> %s:%d (%d bytes)", connKey, srcIP, srcPort, dstIP, dstPort, len(packet))
			return nil
		}
	}
}
