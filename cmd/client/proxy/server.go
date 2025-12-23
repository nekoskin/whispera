package main

import (
	"context"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"strconv"
	"time"

	aeadpkg "whispera/internal/crypto"
	proxypkg "whispera/internal/proxy"
	"nhooyr.io/websocket"
)

// findFreePort is defined in proxy.go

// StartSOCKS5Proxy запускает SOCKS5 прокси сервер для UDP туннеля
func StartSOCKS5Proxy(
	vpnConn *net.UDPConn,
	raddr *net.UDPAddr,
	aeadState *aeadpkg.AEADState,
	sessionID uint32,
	keepaliveSec int,
	manager *Manager,
) {
	proxyRaddr := raddr
	handler := func(clientConn net.Conn, targetAddr string, targetPort uint16) error {
		address := net.JoinHostPort(targetAddr, strconv.Itoa(int(targetPort)))
		log.Printf("[SOCKS5] New connection request to %s (via UDP tunnel)", address)

		// Создаем новое прокси-соединение через менеджер
		proxyConn := &Connection{
			Client:   clientConn,
			Target:   nil, // Для UDP не создаем прямое соединение
			DataChan: make(chan []byte, 1024), // ОПТИМИЗАЦИЯ: Увеличено с 100 до 1024 для лучшей пропускной способности
			Closed:   make(chan struct{}),
		}
		proxyID := manager.AddConnection(proxyConn)

		log.Printf("[SOCKS5] Proxying connection to %s (proxyID=%d)", address, proxyID)

		// Очищаем при закрытии
		defer manager.RemoveConnection(proxyID)

		// Отправляем CONNECT запрос на сервер через VPN
		addrBytes := []byte(targetAddr)
		if len(addrBytes) > 255 {
			return fmt.Errorf("address too long")
		}
		connectPkt := make([]byte, 0, 1+1+len(addrBytes)+2)
		connectPkt = append(connectPkt, 0) // cmd = CONNECT
		connectPkt = append(connectPkt, byte(len(addrBytes)))
		connectPkt = append(connectPkt, addrBytes...)
		portBytes := make([]byte, 2)
		binary.BigEndian.PutUint16(portBytes, targetPort)
		connectPkt = append(connectPkt, portBytes...)

		var seqSend uint32 = 1
		if err := sendProxyDataUDP(vpnConn, proxyRaddr, aeadState, sessionID, proxyID, connectPkt, &seqSend); err != nil {
			log.Printf("[SOCKS5] Failed to send CONNECT request: %v", err)
			return err
		}

		clientToVPN := make(chan []byte, 1024) // ОПТИМИЗАЦИЯ: Увеличено с 100 до 1024 для лучшей пропускной способности
		go func() {
			buf := make([]byte, 65535)
			for {
				n, err := clientConn.Read(buf)
				if err != nil {
					close(clientToVPN)
					return
				}
				select {
				case clientToVPN <- buf[:n]:
				case <-proxyConn.Closed:
					return
				}
			}
		}()

		go func() {
			for {
				select {
				case data, ok := <-clientToVPN:
					if !ok {
						return
					}
					dataPkt := make([]byte, 0, 1+len(data))
					dataPkt = append(dataPkt, 1) // cmd = DATA
					dataPkt = append(dataPkt, data...)
					if err := sendProxyDataUDP(vpnConn, proxyRaddr, aeadState, sessionID, proxyID, dataPkt, &seqSend); err != nil {
						log.Printf("[SOCKS5] Failed to send data to VPN: %v", err)
						return
					}
				case <-proxyConn.Closed:
					return
				}
			}
		}()

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

		select {
		case <-proxyConn.Closed:
		case <-time.After(24 * time.Hour):
		}
		log.Printf("[SOCKS5] Connection to %s closed", address)
		return nil
	}

	socksPort, err := findFreePort(1080)
	if err != nil {
		log.Printf("[ERROR] Failed to find free port for SOCKS5: %v", err)
		return
	}

	socksAddr := fmt.Sprintf("127.0.0.1:%d", socksPort)
	socksServer := proxypkg.NewSOCKS5Server(socksAddr, handler)
	log.Printf("[SOCKS5] ✅ Starting SOCKS5 proxy server on %s (UDP tunnel)", socksAddr)
	log.Printf("[SOCKS5] 📍 Configure your applications to use SOCKS5 proxy: %s", socksAddr)
	log.Printf("[SOCKS5] 🔧 Proxy format: socks5://127.0.0.1:%d (no authentication required)", socksPort)
	if err := socksServer.ListenAndServe(); err != nil {
		log.Printf("[ERROR] SOCKS5 server failed: %v", err)
	} else {
		log.Printf("[SOCKS5] ✅ SOCKS5 proxy server stopped")
	}
}

// StartSOCKS5ProxyTCP запускает SOCKS5 прокси сервер для TCP туннеля
func StartSOCKS5ProxyTCP(
	vpnConn net.Conn,
	aeadState *aeadpkg.AEADState,
	sessionID uint32,
	keepaliveSec int,
	manager *Manager,
) {
	handler := func(clientConn net.Conn, targetAddr string, targetPort uint16) error {
		address := net.JoinHostPort(targetAddr, strconv.Itoa(int(targetPort)))
		log.Printf("[SOCKS5] New connection request to %s (via TCP tunnel)", address)

		targetConn, err := net.DialTimeout("tcp", address, 10*time.Second)
		if err != nil {
			log.Printf("[SOCKS5] Failed to connect to %s: %v", address, err)
			return err
		}
		defer targetConn.Close()

		// Создаем новое прокси-соединение через менеджер
		proxyConn := &Connection{
			Client:   clientConn,
			Target:   targetConn,
			DataChan: make(chan []byte, 1024), // ОПТИМИЗАЦИЯ: Увеличено с 100 до 1024 для лучшей пропускной способности
			Closed:   make(chan struct{}),
		}
		proxyID := manager.AddConnection(proxyConn)

		log.Printf("[SOCKS5] Proxying connection to %s (proxyID=%d)", address, proxyID)

		// Очищаем при закрытии
		defer manager.RemoveConnection(proxyID)

		var seqSend uint32 = 1
		clientToVPN := make(chan []byte, 1024) // ОПТИМИЗАЦИЯ: Увеличено с 100 до 1024 для лучшей пропускной способности
		go func() {
			buf := make([]byte, 65535)
			for {
				n, err := clientConn.Read(buf)
				if err != nil {
					close(clientToVPN)
					return
				}
				select {
				case clientToVPN <- buf[:n]:
				case <-proxyConn.Closed:
					return
				}
			}
		}()

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

		go func() {
			buf := make([]byte, 65535)
			for {
				n, err := targetConn.Read(buf)
				if err != nil {
					return
				}
				if _, err := clientConn.Write(buf[:n]); err != nil {
					return
				}
			}
		}()

		select {
		case <-proxyConn.Closed:
		case <-time.After(24 * time.Hour): // Таймаут для безопасности
		}
		log.Printf("[SOCKS5] Connection to %s closed", address)
		return nil
	}

	socksPort, err := findFreePort(1080)
	if err != nil {
		log.Printf("[ERROR] Failed to find free port for SOCKS5: %v", err)
		return
	}

	socksAddr := fmt.Sprintf("127.0.0.1:%d", socksPort)
	socksServer := proxypkg.NewSOCKS5Server(socksAddr, handler)
	log.Printf("[SOCKS5] ✅ Starting SOCKS5 proxy server on %s (TCP tunnel)", socksAddr)
	log.Printf("[SOCKS5] 📍 Configure your applications to use SOCKS5 proxy: %s", socksAddr)
	log.Printf("[SOCKS5] 🔧 Proxy format: socks5://127.0.0.1:%d (no authentication required)", socksPort)
	if err := socksServer.ListenAndServe(); err != nil {
		log.Printf("[ERROR] SOCKS5 server failed: %v", err)
	} else {
		log.Printf("[SOCKS5] ✅ SOCKS5 proxy server stopped")
	}
}

// StartSOCKS5ProxyWS запускает SOCKS5 прокси сервер для WebSocket туннеля
func StartSOCKS5ProxyWS(
	ctx context.Context,
	ws *websocket.Conn,
	aeadState *aeadpkg.AEADState,
	sessionID uint32,
	keepaliveSec int,
	manager *Manager,
) {
	handler := func(clientConn net.Conn, targetAddr string, targetPort uint16) error {
		address := net.JoinHostPort(targetAddr, strconv.Itoa(int(targetPort)))
		log.Printf("[SOCKS5] New connection request to %s (via WebSocket tunnel)", address)

		// Создаем новое прокси-соединение через менеджер
		proxyConn := &Connection{
			Client:   clientConn,
			Target:   nil,
			DataChan: make(chan []byte, 1024), // ОПТИМИЗАЦИЯ: Увеличено с 100 до 1024 для лучшей пропускной способности
			Closed:   make(chan struct{}),
		}
		proxyID := manager.AddConnection(proxyConn)

		log.Printf("[SOCKS5] Requesting proxy connection to %s (proxyID=%d)", address, proxyID)

		// Очищаем при закрытии
		defer manager.RemoveConnection(proxyID)

		var seqSend uint32 = 1
		connectReq := make([]byte, 0, 4+len(targetAddr))
		connectReq = append(connectReq, 0) // cmd = CONNECT
		connectReq = append(connectReq, byte(len(targetAddr)))
		connectReq = append(connectReq, []byte(targetAddr)...)
		portBytes := make([]byte, 2)
		binary.BigEndian.PutUint16(portBytes, targetPort)
		connectReq = append(connectReq, portBytes...)

		if err := sendProxyDataWS(ctx, ws, aeadState, sessionID, proxyID, connectReq, &seqSend); err != nil {
			log.Printf("[SOCKS5] Failed to send CONNECT request: %v", err)
			return err
		}

		clientToVPN := make(chan []byte, 1024) // ОПТИМИЗАЦИЯ: Увеличено с 100 до 1024 для лучшей пропускной способности
		go func() {
			buf := make([]byte, 65535)
			for {
				n, err := clientConn.Read(buf)
				if err != nil {
					close(clientToVPN)
					return
				}
				select {
				case clientToVPN <- buf[:n]:
				case <-proxyConn.Closed:
					return
				}
			}
		}()

		go func() {
			for {
				select {
				case data, ok := <-clientToVPN:
					if !ok {
						return
					}
					dataPkt := append([]byte{1}, data...)
					if err := sendProxyDataWS(ctx, ws, aeadState, sessionID, proxyID, dataPkt, &seqSend); err != nil {
						log.Printf("[SOCKS5] Failed to send data to VPN: %v", err)
						return
					}
				case <-proxyConn.Closed:
					return
				}
			}
		}()

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

		select {
		case <-proxyConn.Closed:
		case <-time.After(24 * time.Hour):
		}
		log.Printf("[SOCKS5] Connection to %s closed", address)
		return nil
	}

	socksPort, err := findFreePort(1080)
	if err != nil {
		log.Printf("[ERROR] Failed to find free port for SOCKS5: %v", err)
		return
	}

	socksAddr := fmt.Sprintf("127.0.0.1:%d", socksPort)
	socksServer := proxypkg.NewSOCKS5Server(socksAddr, handler)
	log.Printf("[SOCKS5] ✅ Starting SOCKS5 proxy server on %s (WebSocket tunnel)", socksAddr)
	log.Printf("[SOCKS5] 📍 Configure your applications to use SOCKS5 proxy: %s", socksAddr)
	log.Printf("[SOCKS5] 🔧 Proxy format: socks5://127.0.0.1:%d (no authentication required)", socksPort)
	if err := socksServer.ListenAndServe(); err != nil {
		log.Printf("[ERROR] SOCKS5 server failed: %v", err)
	} else {
		log.Printf("[SOCKS5] ✅ SOCKS5 proxy server stopped")
	}
}

// StartSOCKS5ProxyWS2 запускает SOCKS5 прокси сервер для HTTP/2 WebSocket туннеля
func StartSOCKS5ProxyWS2(
	ctx context.Context,
	ws *websocket.Conn,
	aeadState *aeadpkg.AEADState,
	sessionID uint32,
	keepaliveSec int,
	manager *Manager,
) {
	handler := func(clientConn net.Conn, targetAddr string, targetPort uint16) error {
		address := net.JoinHostPort(targetAddr, strconv.Itoa(int(targetPort)))
		log.Printf("[SOCKS5] New connection request to %s (via HTTP/2 WebSocket tunnel)", address)

		// Создаем новое прокси-соединение через менеджер
		proxyConn := &Connection{
			Client:   clientConn,
			Target:   nil,
			DataChan: make(chan []byte, 1024), // ОПТИМИЗАЦИЯ: Увеличено с 100 до 1024 для лучшей пропускной способности
			Closed:   make(chan struct{}),
		}
		proxyID := manager.AddConnection(proxyConn)

		log.Printf("[SOCKS5] Requesting proxy connection to %s (proxyID=%d)", address, proxyID)

		// Очищаем при закрытии
		defer manager.RemoveConnection(proxyID)

		var seqSend uint32 = 1
		connectReq := make([]byte, 0, 4+len(targetAddr))
		connectReq = append(connectReq, 0) // cmd = CONNECT
		connectReq = append(connectReq, byte(len(targetAddr)))
		connectReq = append(connectReq, []byte(targetAddr)...)
		portBytes := make([]byte, 2)
		binary.BigEndian.PutUint16(portBytes, targetPort)
		connectReq = append(connectReq, portBytes...)

		if err := sendProxyDataWS(ctx, ws, aeadState, sessionID, proxyID, connectReq, &seqSend); err != nil {
			log.Printf("[SOCKS5] Failed to send CONNECT request: %v", err)
			return err
		}

		clientToVPN := make(chan []byte, 1024) // ОПТИМИЗАЦИЯ: Увеличено с 100 до 1024 для лучшей пропускной способности
		go func() {
			buf := make([]byte, 65535)
			for {
				n, err := clientConn.Read(buf)
				if err != nil {
					close(clientToVPN)
					return
				}
				select {
				case clientToVPN <- buf[:n]:
				case <-proxyConn.Closed:
					return
				}
			}
		}()

		go func() {
			for {
				select {
				case data, ok := <-clientToVPN:
					if !ok {
						return
					}
					dataPkt := append([]byte{1}, data...)
					if err := sendProxyDataWS(ctx, ws, aeadState, sessionID, proxyID, dataPkt, &seqSend); err != nil {
						log.Printf("[SOCKS5] Failed to send data to VPN: %v", err)
						return
					}
				case <-proxyConn.Closed:
					return
				}
			}
		}()

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

		select {
		case <-proxyConn.Closed:
		case <-time.After(24 * time.Hour):
		}
		log.Printf("[SOCKS5] Connection to %s closed", address)
		return nil
	}

	socksPort, err := findFreePort(1080)
	if err != nil {
		log.Printf("[ERROR] Failed to find free port for SOCKS5: %v", err)
		return
	}

	socksAddr := fmt.Sprintf("127.0.0.1:%d", socksPort)
	socksServer := proxypkg.NewSOCKS5Server(socksAddr, handler)
	log.Printf("[SOCKS5] ✅ Starting SOCKS5 proxy server on %s (HTTP/2 WebSocket tunnel)", socksAddr)
	log.Printf("[SOCKS5] 📍 Configure your applications to use SOCKS5 proxy: %s", socksAddr)
	log.Printf("[SOCKS5] 🔧 Proxy format: socks5://127.0.0.1:%d (no authentication required)", socksPort)
	if err := socksServer.ListenAndServe(); err != nil {
		log.Printf("[ERROR] SOCKS5 server failed: %v", err)
	} else {
		log.Printf("[SOCKS5] ✅ SOCKS5 proxy server stopped")
	}
}
