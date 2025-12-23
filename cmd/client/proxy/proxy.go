package main

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	aeadpkg "whispera/internal/crypto"
	metr "whispera/internal/metrics"
	"whispera/internal/proto"
	"whispera/internal/proxy"
	"whispera/internal/client/streamutil"
	"whispera/internal/util"
	"nhooyr.io/websocket"
)

// findFreePort находит свободный порт, начиная с startPort
func findFreePort(startPort int) (int, error) {
	for port := startPort; port < startPort+10; port++ {
		addr, err := net.ResolveTCPAddr("tcp", fmt.Sprintf("127.0.0.1:%d", port))
		if err != nil {
			continue
		}
		listener, err := net.ListenTCP("tcp", addr)
		if err != nil {
			continue
		}
		listener.Close()
		return port, nil
	}
	return 0, errors.New("no free port found")
}

// ProxyConnection управляет проксируемым соединением
type ProxyConnection struct {
	ID       uint32
	Client   net.Conn
	Target   net.Conn
	DataChan chan []byte
	Closed   chan struct{}
}

var (
	proxyConnections        = make(map[uint32]*ProxyConnection)
	proxyMutex              = sync.RWMutex{} // ОПТИМИЗАЦИЯ: Используем RWMutex для лучшей производительности при чтении
	proxySeqCounter  uint32 = 1000000 // Начинаем с большого числа, чтобы не конфликтовать с TUN
	
	// ОПТИМИЗАЦИЯ: Пул буферов для создания пакетов
	proxyPacketPool = sync.Pool{
		New: func() interface{} {
			return make([]byte, 0, 512) // Предварительно выделяем память для типичного пакета
		},
	}
	
	// ОПТИМИЗАЦИЯ: Пул буферов для чтения данных
	proxyReadBufferPool = sync.Pool{
		New: func() interface{} {
			return make([]byte, 65535) // Максимальный размер UDP пакета
		},
	}
)

// startSOCKS5Proxy запускает SOCKS5 прокси сервер в proxy mode
func startSOCKS5Proxy(vpnConn *net.UDPConn, raddr *net.UDPAddr, aeadState *aeadpkg.AEADState, sessionID uint32, keepaliveSec int) {
	// Захватываем raddr в локальную переменную для использования в замыкании
	proxyRaddr := raddr
	// Создаем SOCKS5 сервер на стандартном порту
	handler := func(clientConn net.Conn, targetAddr string, targetPort uint16) error {
		address := net.JoinHostPort(targetAddr, strconv.Itoa(int(targetPort)))
		log.Printf("[SOCKS5] New connection request to %s (via UDP tunnel)", address)

		// Генерируем уникальный ID для этого прокси-соединения
		proxyMutex.Lock()
		proxyID := atomic.AddUint32(&proxySeqCounter, 1)
		proxyConn := &ProxyConnection{
			ID:       proxyID,
			Client:   clientConn,
			Target:   nil, // Для UDP не создаем прямое соединение
			DataChan: make(chan []byte, 1024), // ОПТИМИЗАЦИЯ: Увеличено с 100 до 1024 для лучшей пропускной способности
			Closed:   make(chan struct{}),
		}
		proxyConnections[proxyID] = proxyConn
		proxyMutex.Unlock()

		log.Printf("[SOCKS5] Proxying connection to %s (proxyID=%d)", address, proxyID)

		// Очищаем при закрытии
		defer func() {
			proxyMutex.Lock()
			delete(proxyConnections, proxyID)
			close(proxyConn.Closed)
			proxyMutex.Unlock()
		}()

		// Отправляем CONNECT запрос на сервер через VPN
		// Формат: [proxyID:4][cmd:0][addrLen:1][addr:N][port:2]
		addrBytes := []byte(targetAddr)
		if len(addrBytes) > 255 {
			return fmt.Errorf("address too long")
		}
		// ОПТИМИЗАЦИЯ: Используем пул буферов
		connectPkt := proxyPacketPool.Get().([]byte)
		connectPkt = connectPkt[:0]
		connectPkt = append(connectPkt, make([]byte, 4)...)
		binary.BigEndian.PutUint32(connectPkt[0:4], proxyID)
		connectPkt = append(connectPkt, 0) // cmd = CONNECT
		connectPkt = append(connectPkt, byte(len(addrBytes)))
		connectPkt = append(connectPkt, addrBytes...)
		portBytes := make([]byte, 2)
		binary.BigEndian.PutUint16(portBytes, targetPort)
		connectPkt = append(connectPkt, portBytes...)

		// Отправляем CONNECT запрос через UDP VPN туннель.
		// В payload шлём только [cmd:0][addrLen][addr][port], а proxyID добавляется в sendProxyDataUDP.
		var seqSend uint32 = 1
		payload := connectPkt[4:]
		if err := sendProxyDataUDP(vpnConn, proxyRaddr, aeadState, sessionID, proxyID, payload, &seqSend); err != nil {
			proxyPacketPool.Put(connectPkt[:0])
			log.Printf("[SOCKS5] Failed to send CONNECT request: %v", err)
			return err
		}
		// ОПТИМИЗАЦИЯ: Возвращаем буфер в пул после использования
		proxyPacketPool.Put(connectPkt[:0])

		// Отправляем данные от клиента к целевому серверу через VPN
		clientToVPN := make(chan []byte, 1024) // ОПТИМИЗАЦИЯ: Увеличено с 100 до 1024 для лучшей пропускной способности
		go func() {
			// ОПТИМИЗАЦИЯ: Используем пул буферов для чтения
			buf := proxyReadBufferPool.Get().([]byte)
			defer proxyReadBufferPool.Put(buf)
			for {
				n, err := clientConn.Read(buf)
				if err != nil {
					close(clientToVPN)
					return
				}
				// ОПТИМИЗАЦИЯ: Создаем копию данных для отправки в канал
				data := make([]byte, n)
				copy(data, buf[:n])
				select {
				case clientToVPN <- data:
				case <-proxyConn.Closed:
					return
				}
			}
		}()

		// ОПТИМИЗАЦИЯ: Асинхронная отправка данных клиента через VPN с батчингом
		go func() {
			batch := make([][]byte, 0, 16)      // Батч до 16 пакетов
			ticker := time.NewTicker(5 * time.Millisecond)
			defer ticker.Stop()
			
			flushBatch := func() {
				if len(batch) == 0 {
					return
				}
				// ОПТИМИЗАЦИЯ: Отправляем все пакеты из батча параллельно
				var wg sync.WaitGroup
				for _, data := range batch {
					wg.Add(1)
					go func(pktData []byte) {
						defer wg.Done()
						dataPkt := proxyPacketPool.Get().([]byte)
						dataPkt = dataPkt[:0]
						dataPkt = append(dataPkt, 1) // cmd = DATA
						dataPkt = append(dataPkt, pktData...)
						if err := sendProxyDataUDP(vpnConn, proxyRaddr, aeadState, sessionID, proxyID, dataPkt, &seqSend); err != nil {
							log.Printf("[SOCKS5] Failed to send data to VPN: %v", err)
						}
						proxyPacketPool.Put(dataPkt[:0])
					}(data)
				}
				wg.Wait()
				batch = batch[:0]
			}
			
			for {
				select {
				case data, ok := <-clientToVPN:
					if !ok {
						flushBatch()
						return
					}
					batch = append(batch, data)
					if len(batch) >= 16 {
						flushBatch()
					}
				case <-ticker.C:
					flushBatch()
				case <-proxyConn.Closed:
					flushBatch()
					return
				}
			}
		}()

		// Получаем данные от VPN (ответы от целевого сервера) и отправляем клиенту
		go func() {
			for {
				select {
				case data := <-proxyConn.DataChan:
					if _, err := clientConn.Write(data); err != nil {
						return
					}
				case <-proxyConn.Closed:
					return
				}
			}
		}()

		// Ждем закрытия соединения
		select {
		case <-proxyConn.Closed:
		case <-time.After(24 * time.Hour): // Таймаут для безопасности
		}
		log.Printf("[SOCKS5] Connection to %s closed", address)
		return nil
	}

	// Пробуем найти свободный порт, начиная с 1080
	socksPort, err := findFreePort(1080)
	if err != nil {
		log.Printf("[ERROR] Failed to find free port for SOCKS5: %v", err)
		return
	}

	socksAddr := fmt.Sprintf("127.0.0.1:%d", socksPort)
	socksServer := proxy.NewSOCKS5Server(socksAddr, handler)
	log.Printf("[SOCKS5] ✅ Starting SOCKS5 proxy server on %s (UDP tunnel)", socksAddr)
	log.Printf("[SOCKS5] 📍 Configure your applications to use SOCKS5 proxy: %s", socksAddr)
	log.Printf("[SOCKS5] 🔧 Proxy format: socks5://127.0.0.1:%d (no authentication required)", socksPort)
	if err := socksServer.ListenAndServe(); err != nil {
		log.Printf("[ERROR] SOCKS5 server failed: %v", err)
	} else {
		log.Printf("[SOCKS5] ✅ SOCKS5 proxy server stopped")
	}
}

// sendProxyDataUDP отправляет данные через UDP VPN туннель для прокси-соединения
func sendProxyDataUDP(vpnConn *net.UDPConn, raddr *net.UDPAddr, st *aeadpkg.AEADState, sessionID uint32, proxyID uint32, data []byte, seqSend *uint32) error {
	// ОПТИМИЗАЦИЯ: Используем пул буферов для создания payload
	payload := proxyPacketPool.Get().([]byte)
	payload = payload[:0]
	payload = append(payload, make([]byte, 4)...)
	binary.BigEndian.PutUint32(payload[0:4], proxyID)
	payload = append(payload, data...)
	defer proxyPacketPool.Put(payload[:0])

	var hdr proto.PacketHeader
	hdr.Version = proto.Version
	hdr.Flags = 0
	hdr.SessionID = sessionID
	hdr.Seq = *seqSend
	payloadLen, ok := streamutil.SafeUint16(len(payload) + 16)
	if !ok {
		return errors.New("payload too large")
	}
	hdr.PayloadLen = payloadLen
	aad := hdr.MarshalBinary()
	ct, err := st.Encrypt(hdr.Seq, aad, payload)
	if err != nil {
		return err
	}
	pkt := util.Concat(aad, ct)
	var writeErr error
	if raddr != nil {
		_, writeErr = vpnConn.WriteToUDP(pkt, raddr)
	} else {
		_, writeErr = vpnConn.Write(pkt)
	}
	if writeErr != nil {
		return writeErr
	}
	metr.PacketsTx.Inc()
	metr.BytesTx.Add(float64(len(pkt)))
	*seqSend++
	return nil
	// payload будет возвращен в пул через defer
}

// sendProxyData отправляет данные через VPN туннель для прокси-соединения
func sendProxyData(vpnConn net.Conn, st *aeadpkg.AEADState, sessionID uint32, proxyID uint32, data []byte, seqSend *uint32) error {
	// ОПТИМИЗАЦИЯ: Используем пул буферов для создания payload
	payload := proxyPacketPool.Get().([]byte)
	payload = payload[:0]
	payload = append(payload, make([]byte, 4)...)
	binary.BigEndian.PutUint32(payload[0:4], proxyID)
	payload = append(payload, data...)
	defer proxyPacketPool.Put(payload[:0])

	var hdr proto.PacketHeader
	hdr.Version = proto.Version
	hdr.Flags = 0
	hdr.SessionID = sessionID
	hdr.Seq = *seqSend
	payloadLen, ok := streamutil.SafeUint16(len(payload) + 16)
	if !ok {
		return errors.New("payload too large")
	}
	hdr.PayloadLen = payloadLen
	aad := hdr.MarshalBinary()
	ct, err := st.Encrypt(hdr.Seq, aad, payload)
	if err != nil {
		return err
	}
	pkt := util.Concat(aad, ct)
	if err := streamutil.WriteFrame(vpnConn, pkt); err != nil {
		return err
	}
	metr.PacketsTx.Inc()
	metr.BytesTx.Add(float64(len(pkt)))
	*seqSend++
	return nil
}

// sendProxyDataWS отправляет данные через WebSocket VPN туннель для прокси-соединения
func sendProxyDataWS(ctx context.Context, ws *websocket.Conn, st *aeadpkg.AEADState, sessionID uint32, proxyID uint32, data []byte, seqSend *uint32) error {
	// ОПТИМИЗАЦИЯ: Используем пул буферов для создания payload
	payload := proxyPacketPool.Get().([]byte)
	payload = payload[:0]
	payload = append(payload, make([]byte, 4)...)
	binary.BigEndian.PutUint32(payload[0:4], proxyID)
	payload = append(payload, data...)
	defer proxyPacketPool.Put(payload[:0])

	var hdr proto.PacketHeader
	hdr.Version = proto.Version
	hdr.Flags = 0
	hdr.SessionID = sessionID
	hdr.Seq = *seqSend
	payloadLen, ok := streamutil.SafeUint16(len(payload) + 16)
	if !ok {
		return errors.New("payload too large")
	}
	hdr.PayloadLen = payloadLen
	aad := hdr.MarshalBinary()
	ct, err := st.Encrypt(hdr.Seq, aad, payload)
	if err != nil {
		return err
	}
	pkt := util.Concat(aad, ct)
	if err := ws.Write(ctx, websocket.MessageBinary, pkt); err != nil {
		return err
	}
	metr.PacketsTx.Inc()
	metr.BytesTx.Add(float64(len(pkt)))
	*seqSend++
	return nil
}

// startSOCKS5ProxyTCP запускает SOCKS5 прокси сервер для TCP соединения
func startSOCKS5ProxyTCP(vpnConn net.Conn, aeadState *aeadpkg.AEADState, sessionID uint32, keepaliveSec int) {
	handler := func(clientConn net.Conn, targetAddr string, targetPort uint16) error {
		address := net.JoinHostPort(targetAddr, strconv.Itoa(int(targetPort)))
		log.Printf("[SOCKS5] New connection request to %s (via TCP tunnel)", address)

		// Подключаемся к целевому серверу
		targetConn, err := net.DialTimeout("tcp", address, 10*time.Second)
		if err != nil {
			log.Printf("[SOCKS5] Failed to connect to %s: %v", address, err)
			return err
		}
		defer targetConn.Close()

		// Генерируем уникальный ID для этого прокси-соединения
		proxyMutex.Lock()
		proxyID := atomic.AddUint32(&proxySeqCounter, 1)
		proxyConn := &ProxyConnection{
			ID:       proxyID,
			Client:   clientConn,
			Target:   targetConn,
			DataChan: make(chan []byte, 1024), // ОПТИМИЗАЦИЯ: Увеличено с 100 до 1024 для лучшей пропускной способности
			Closed:   make(chan struct{}),
		}
		proxyConnections[proxyID] = proxyConn
		proxyMutex.Unlock()

		log.Printf("[SOCKS5] Proxying connection to %s (proxyID=%d)", address, proxyID)

		// Очищаем при закрытии
		defer func() {
			proxyMutex.Lock()
			delete(proxyConnections, proxyID)
			close(proxyConn.Closed)
			proxyMutex.Unlock()
		}()

		// Проксируем данные в обе стороны
		// Клиент -> VPN -> Сервер -> Целевой сервер
		// Целевой сервер -> Сервер -> VPN -> Клиент

		// Отправляем данные от клиента к целевому серверу через VPN
		var seqSend uint32 = 1
		clientToVPN := make(chan []byte, 1024) // ОПТИМИЗАЦИЯ: Увеличено с 100 до 1024 для лучшей пропускной способности
		go func() {
			// ОПТИМИЗАЦИЯ: Используем пул буферов для чтения
			buf := proxyReadBufferPool.Get().([]byte)
			defer proxyReadBufferPool.Put(buf)
			for {
				n, err := clientConn.Read(buf)
				if err != nil {
					close(clientToVPN)
					return
				}
				// ОПТИМИЗАЦИЯ: Создаем копию данных для отправки в канал
				data := make([]byte, n)
				copy(data, buf[:n])
				select {
				case clientToVPN <- data:
				case <-proxyConn.Closed:
					return
				}
			}
		}()

		// Отправляем данные клиента через VPN
		go func() {
			for {
				select {
				case data, ok := <-clientToVPN:
					if !ok {
						return
					}
					if err := sendProxyData(vpnConn, aeadState, sessionID, proxyID, data, &seqSend); err != nil {
						log.Printf("[SOCKS5] Failed to send data to VPN: %v", err)
						return
					}
				case <-proxyConn.Closed:
					return
				}
			}
		}()

		// Получаем данные от VPN (ответы от целевого сервера) и отправляем клиенту
		go func() {
			for {
				select {
				case data := <-proxyConn.DataChan:
					if _, err := clientConn.Write(data); err != nil {
						return
					}
				case <-proxyConn.Closed:
					return
				}
			}
		}()

		// Читаем ответы от целевого сервера и отправляем напрямую клиенту
		// (не через VPN, так как целевой сервер подключен на стороне клиента)
		go func() {
			// ОПТИМИЗАЦИЯ: Используем пул буферов для чтения
			buf := proxyReadBufferPool.Get().([]byte)
			defer proxyReadBufferPool.Put(buf)
			for {
				n, err := targetConn.Read(buf)
				if err != nil {
					return
				}
				// Отправляем ответ напрямую клиенту
				if _, err := clientConn.Write(buf[:n]); err != nil {
					return
				}
			}
		}()

		// Ждем закрытия соединения (клиент или целевой сервер закрыл)
		select {
		case <-proxyConn.Closed:
		case <-time.After(24 * time.Hour): // Просто таймаут для безопасности
		}
		log.Printf("[SOCKS5] Connection to %s closed", address)
		return nil
	}

	// Пробуем найти свободный порт, начиная с 1080
	socksPort, err := findFreePort(1080)
	if err != nil {
		log.Printf("[ERROR] Failed to find free port for SOCKS5: %v", err)
		return
	}

	socksAddr := fmt.Sprintf("127.0.0.1:%d", socksPort)
	socksServer := proxy.NewSOCKS5Server(socksAddr, handler)
	log.Printf("[SOCKS5] ✅ Starting SOCKS5 proxy server on %s (TCP tunnel)", socksAddr)
	log.Printf("[SOCKS5] 📍 Configure your applications to use SOCKS5 proxy: %s", socksAddr)
	log.Printf("[SOCKS5] 🔧 Proxy format: socks5://127.0.0.1:%d (no authentication required)", socksPort)
	if err := socksServer.ListenAndServe(); err != nil {
		log.Printf("[ERROR] SOCKS5 server failed: %v", err)
	} else {
		log.Printf("[SOCKS5] ✅ SOCKS5 proxy server stopped")
	}
}

// startSOCKS5ProxyWS запускает SOCKS5 прокси сервер для WebSocket соединения
func startSOCKS5ProxyWS(ctx context.Context, ws *websocket.Conn, aeadState *aeadpkg.AEADState, sessionID uint32, keepaliveSec int) {
	handler := func(clientConn net.Conn, targetAddr string, targetPort uint16) error {
		address := net.JoinHostPort(targetAddr, strconv.Itoa(int(targetPort)))
		log.Printf("[SOCKS5] New connection request to %s (via WebSocket tunnel)", address)

		// Генерируем уникальный ID для этого прокси-соединения
		proxyMutex.Lock()
		proxyID := atomic.AddUint32(&proxySeqCounter, 1)
		proxyConn := &ProxyConnection{
			ID:       proxyID,
			Client:   clientConn,
			Target:   nil, // Не подключаемся напрямую - сервер сделает это
			DataChan: make(chan []byte, 1024), // ОПТИМИЗАЦИЯ: Увеличено с 100 до 1024 для лучшей пропускной способности
			Closed:   make(chan struct{}),
		}
		proxyConnections[proxyID] = proxyConn
		proxyMutex.Unlock()

		log.Printf("[SOCKS5] Requesting proxy connection to %s (proxyID=%d)", address, proxyID)

		// Очищаем при закрытии
		defer func() {
			proxyMutex.Lock()
			delete(proxyConnections, proxyID)
			close(proxyConn.Closed)
			proxyMutex.Unlock()
		}()

		// Отправляем запрос на подключение через VPN
		// Формат: [proxyID:4][cmd:1][addrLen:1][addr:N][port:2]
		// cmd: 0 = CONNECT, 1 = DATA
		var seqSend uint32 = 1
		// ОПТИМИЗАЦИЯ: Используем пул буферов
		connectReq := proxyPacketPool.Get().([]byte)
		connectReq = connectReq[:0]
		connectReq = append(connectReq, make([]byte, 4)...)
		binary.BigEndian.PutUint32(connectReq[0:4], proxyID)
		connectReq = append(connectReq, 0) // cmd = CONNECT
		connectReq = append(connectReq, byte(len(targetAddr)))
		connectReq = append(connectReq, []byte(targetAddr)...)
		portBytes := make([]byte, 2)
		binary.BigEndian.PutUint16(portBytes, targetPort)
		connectReq = append(connectReq, portBytes...)

		payload := connectReq[4:]
		if err := sendProxyDataWS(ctx, ws, aeadState, sessionID, proxyID, payload, &seqSend); err != nil {
			proxyPacketPool.Put(connectReq[:0])
			log.Printf("[SOCKS5] Failed to send CONNECT request: %v", err)
			return err
		}
		// ОПТИМИЗАЦИЯ: Возвращаем буфер в пул после использования
		proxyPacketPool.Put(connectReq[:0])

		// Отправляем данные от клиента к целевому серверу через VPN
		clientToVPN := make(chan []byte, 1024) // ОПТИМИЗАЦИЯ: Увеличено с 100 до 1024 для лучшей пропускной способности
		go func() {
			// ОПТИМИЗАЦИЯ: Используем пул буферов для чтения
			buf := proxyReadBufferPool.Get().([]byte)
			defer proxyReadBufferPool.Put(buf)
			for {
				n, err := clientConn.Read(buf)
				if err != nil {
					close(clientToVPN)
					return
				}
				// ОПТИМИЗАЦИЯ: Создаем копию данных для отправки в канал
				data := make([]byte, n)
				copy(data, buf[:n])
				select {
				case clientToVPN <- data:
				case <-proxyConn.Closed:
					return
				}
			}
		}()

		// Отправляем данные клиента через VPN (cmd=1 для данных)
		go func() {
			for {
				select {
				case data, ok := <-clientToVPN:
					if !ok {
						return
					}
					// ОПТИМИЗАЦИЯ: Используем пул буферов для создания пакета
					dataPkt := proxyPacketPool.Get().([]byte)
					dataPkt = dataPkt[:0]
					dataPkt = append(dataPkt, 1) // cmd = DATA
					dataPkt = append(dataPkt, data...)
					if err := sendProxyDataWS(ctx, ws, aeadState, sessionID, proxyID, dataPkt, &seqSend); err != nil {
						proxyPacketPool.Put(dataPkt[:0])
						log.Printf("[SOCKS5] Failed to send data to VPN: %v", err)
						return
					}
					proxyPacketPool.Put(dataPkt[:0])
				case <-proxyConn.Closed:
					return
				}
			}
		}()

		// Получаем данные от VPN (ответы от целевого сервера) и отправляем клиенту
		go func() {
			for {
				select {
				case data := <-proxyConn.DataChan:
					if _, err := clientConn.Write(data); err != nil {
						return
					}
				case <-proxyConn.Closed:
					return
				}
			}
		}()

		// Ждем закрытия соединения
		select {
		case <-proxyConn.Closed:
		case <-time.After(24 * time.Hour):
		}
		log.Printf("[SOCKS5] Connection to %s closed", address)
		return nil
	}

	// Пробуем найти свободный порт, начиная с 1080
	socksPort, err := findFreePort(1080)
	if err != nil {
		log.Printf("[ERROR] Failed to find free port for SOCKS5: %v", err)
		return
	}

	socksAddr := fmt.Sprintf("127.0.0.1:%d", socksPort)
	socksServer := proxy.NewSOCKS5Server(socksAddr, handler)
	log.Printf("[SOCKS5] ✅ Starting SOCKS5 proxy server on %s (WebSocket tunnel)", socksAddr)
	log.Printf("[SOCKS5] 📍 Configure your applications to use SOCKS5 proxy: %s", socksAddr)
	log.Printf("[SOCKS5] 🔧 Proxy format: socks5://127.0.0.1:%d (no authentication required)", socksPort)
	if err := socksServer.ListenAndServe(); err != nil {
		log.Printf("[ERROR] SOCKS5 server failed: %v", err)
	} else {
		log.Printf("[SOCKS5] ✅ SOCKS5 proxy server stopped")
	}
}

// startSOCKS5ProxyWS2 запускает SOCKS5 прокси сервер для HTTP/2 WebSocket соединения
func startSOCKS5ProxyWS2(ctx context.Context, ws *websocket.Conn, aeadState *aeadpkg.AEADState, sessionID uint32, keepaliveSec int) {
	handler := func(clientConn net.Conn, targetAddr string, targetPort uint16) error {
		address := net.JoinHostPort(targetAddr, strconv.Itoa(int(targetPort)))
		log.Printf("[SOCKS5] New connection request to %s (via HTTP/2 WebSocket tunnel)", address)

		// Генерируем уникальный ID для этого прокси-соединения
		proxyMutex.Lock()
		proxyID := atomic.AddUint32(&proxySeqCounter, 1)
		proxyConn := &ProxyConnection{
			ID:       proxyID,
			Client:   clientConn,
			Target:   nil, // Не подключаемся напрямую - сервер сделает это
			DataChan: make(chan []byte, 1024), // ОПТИМИЗАЦИЯ: Увеличено с 100 до 1024 для лучшей пропускной способности
			Closed:   make(chan struct{}),
		}
		proxyConnections[proxyID] = proxyConn
		proxyMutex.Unlock()

		log.Printf("[SOCKS5] Requesting proxy connection to %s (proxyID=%d)", address, proxyID)

		// Очищаем при закрытии
		defer func() {
			proxyMutex.Lock()
			delete(proxyConnections, proxyID)
			close(proxyConn.Closed)
			proxyMutex.Unlock()
		}()

		// Отправляем запрос на подключение через VPN
		var seqSend uint32 = 1
		connectReq := make([]byte, 0, 8+len(targetAddr))
		connectReq = append(connectReq, make([]byte, 4)...)
		binary.BigEndian.PutUint32(connectReq[0:4], proxyID)
		connectReq = append(connectReq, 0) // cmd = CONNECT
		connectReq = append(connectReq, byte(len(targetAddr)))
		connectReq = append(connectReq, []byte(targetAddr)...)
		portBytes := make([]byte, 2)
		binary.BigEndian.PutUint16(portBytes, targetPort)
		connectReq = append(connectReq, portBytes...)

		if err := sendProxyDataWS(ctx, ws, aeadState, sessionID, proxyID, connectReq[4:], &seqSend); err != nil {
			log.Printf("[SOCKS5] Failed to send CONNECT request: %v", err)
			return err
		}

		// Отправляем данные от клиента к целевому серверу через VPN
		clientToVPN := make(chan []byte, 1024) // ОПТИМИЗАЦИЯ: Увеличено с 100 до 1024 для лучшей пропускной способности
		go func() {
			// ОПТИМИЗАЦИЯ: Используем пул буферов для чтения
			buf := proxyReadBufferPool.Get().([]byte)
			defer proxyReadBufferPool.Put(buf)
			for {
				n, err := clientConn.Read(buf)
				if err != nil {
					close(clientToVPN)
					return
				}
				// ОПТИМИЗАЦИЯ: Создаем копию данных для отправки в канал
				data := make([]byte, n)
				copy(data, buf[:n])
				select {
				case clientToVPN <- data:
				case <-proxyConn.Closed:
					return
				}
			}
		}()

		// Отправляем данные клиента через VPN (cmd=1 для данных)
		go func() {
			for {
				select {
				case data, ok := <-clientToVPN:
					if !ok {
						return
					}
					// ОПТИМИЗАЦИЯ: Используем пул буферов для создания пакета
					dataPkt := proxyPacketPool.Get().([]byte)
					dataPkt = dataPkt[:0]
					dataPkt = append(dataPkt, 1) // cmd = DATA
					dataPkt = append(dataPkt, data...)
					if err := sendProxyDataWS(ctx, ws, aeadState, sessionID, proxyID, dataPkt, &seqSend); err != nil {
						proxyPacketPool.Put(dataPkt[:0])
						log.Printf("[SOCKS5] Failed to send data to VPN: %v", err)
						return
					}
					proxyPacketPool.Put(dataPkt[:0])
				case <-proxyConn.Closed:
					return
				}
			}
		}()

		// Получаем данные от VPN (ответы от целевого сервера) и отправляем клиенту
		go func() {
			for {
				select {
				case data := <-proxyConn.DataChan:
					if _, err := clientConn.Write(data); err != nil {
						return
					}
				case <-proxyConn.Closed:
					return
				}
			}
		}()

		// Ждем закрытия соединения
		select {
		case <-proxyConn.Closed:
		case <-time.After(24 * time.Hour):
		}
		log.Printf("[SOCKS5] Connection to %s closed", address)
		return nil
	}

	// Пробуем найти свободный порт, начиная с 1080
	socksPort, err := findFreePort(1080)
	if err != nil {
		log.Printf("[ERROR] Failed to find free port for SOCKS5: %v", err)
		return
	}

	socksAddr := fmt.Sprintf("127.0.0.1:%d", socksPort)
	socksServer := proxy.NewSOCKS5Server(socksAddr, handler)
	log.Printf("[SOCKS5] ✅ Starting SOCKS5 proxy server on %s (HTTP/2 WebSocket tunnel)", socksAddr)
	log.Printf("[SOCKS5] 📍 Configure your applications to use SOCKS5 proxy: %s", socksAddr)
	log.Printf("[SOCKS5] 🔧 Proxy format: socks5://127.0.0.1:%d (no authentication required)", socksPort)
	if err := socksServer.ListenAndServe(); err != nil {
		log.Printf("[ERROR] SOCKS5 server failed: %v", err)
	} else {
		log.Printf("[SOCKS5] ✅ SOCKS5 proxy server stopped")
	}
}

