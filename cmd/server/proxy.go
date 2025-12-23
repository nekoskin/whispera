package main

import (
	"context"
	"encoding/binary"
	"log"
	"net"
	"strconv"
	"time"

	"nhooyr.io/websocket"

	aeadpkg "whispera/internal/crypto"
	"whispera/internal/proto"
	srvpkg "whispera/internal/server"
	"whispera/internal/util"
)

func handleWSProxyPacket(payload []byte, wsConn *websocket.Conn, st *aeadpkg.AEADState, sessionID uint32) bool {
	if len(payload) < 5 {
		return false
	}

	proxyID := binary.BigEndian.Uint32(payload[0:4])
	cmd := payload[4]

	serverProxyMutex.Lock()
	proxyConn, exists := serverProxyConnections[proxyID]
	if !exists && cmd == 0 {
		seqSend := uint32(1)
		proxyConn = &ServerProxyConnection{
			ID:        proxyID,
			Target:    nil,
			WSConn:    wsConn,
			AEADState: st,
			SessionID: sessionID,
			SeqSend:   &seqSend,
			Closed:    make(chan struct{}),
		}
		serverProxyConnections[proxyID] = proxyConn
		exists = true
	}
	serverProxyMutex.Unlock()

	if !exists {
		return false
	}

	switch cmd {
	case 0:
		if len(payload) < 8 {
			return true
		}
		addrLen := int(payload[5])
		if len(payload) < 6+addrLen+2 {
			return true
		}

		targetAddr := string(payload[6 : 6+addrLen])
		targetPort := binary.BigEndian.Uint16(payload[6+addrLen : 6+addrLen+2])
		address := net.JoinHostPort(targetAddr, strconv.Itoa(int(targetPort)))

		log.Printf("[SERVER-PROXY] Connecting to %s (proxyID=%d)", address, proxyID)
		targetConn, err := net.DialTimeout("tcp", address, 10*time.Second)
		if err != nil {
			log.Printf("[SERVER-PROXY] Failed to connect to %s: %v", address, err)
			finalizeProxyConnection(proxyID, proxyConn)
			return true
		}

		proxyConn.Target = targetConn
		forwardProxyTargetResponses(proxyID, proxyConn, targetConn)
	case 1:
		if proxyConn.Target == nil || len(payload) <= 5 {
			return true
		}
		if _, err := proxyConn.Target.Write(payload[5:]); err != nil {
			finalizeProxyConnection(proxyID, proxyConn)
		}
	default:
		return true
	}

	return true
}

func handleUDPProxyPacket(payload []byte, session *srvpkg.SessionState, sessionID uint32, conn *net.UDPConn, clientAddr *net.UDPAddr) bool {
	if len(payload) < 5 {
		return false
	}

	proxyID := binary.BigEndian.Uint32(payload[0:4])
	cmd := payload[4]

	serverProxyMutex.Lock()
	proxyConn, exists := serverProxyConnections[proxyID]
	if !exists && cmd == 0 {
		session.Mu.RLock()
		aeadState := session.AEADState
		session.Mu.RUnlock()
		if aeadState == nil {
			serverProxyMutex.Unlock()
			return true
		}

		seqSend := uint32(1)
		proxyConn = &ServerProxyConnection{
			ID:         proxyID,
			Target:     nil,
			UDPConn:    conn,
			ClientAddr: clientAddr,
			AEADState:  aeadState,
			SessionID:  sessionID,
			SeqSend:    &seqSend,
			Closed:     make(chan struct{}),
		}
		serverProxyConnections[proxyID] = proxyConn
		exists = true
	}
	serverProxyMutex.Unlock()

	if !exists {
		return false
	}

	switch cmd {
	case 0:
		if len(payload) < 8 {
			return true
		}
		addrLen := int(payload[5])
		if len(payload) < 6+addrLen+2 {
			return true
		}

		targetAddr := string(payload[6 : 6+addrLen])
		targetPort := binary.BigEndian.Uint16(payload[6+addrLen : 6+addrLen+2])
		address := net.JoinHostPort(targetAddr, strconv.Itoa(int(targetPort)))

		log.Printf("[SERVER-PROXY] Connecting to %s (proxyID=%d)", address, proxyID)
		targetConn, err := net.DialTimeout("tcp", address, 10*time.Second)
		if err != nil {
			log.Printf("[SERVER-PROXY] Failed to connect to %s: %v", address, err)
			finalizeProxyConnection(proxyID, proxyConn)
			return true
		}

		proxyConn.Target = targetConn
		forwardProxyTargetResponses(proxyID, proxyConn, targetConn)
	case 1:
		if proxyConn.Target == nil || len(payload) <= 5 {
			return true
		}
		if _, err := proxyConn.Target.Write(payload[5:]); err != nil {
			finalizeProxyConnection(proxyID, proxyConn)
		}
	default:
		return true
	}

	return true
}

func forwardProxyTargetResponses(proxyID uint32, proxyConn *ServerProxyConnection, targetConn net.Conn) {
	go func() {
		buf := make([]byte, maxUDPPacket)
		for {
			n, err := targetConn.Read(buf)
			if err != nil {
				finalizeProxyConnection(proxyID, proxyConn)
				return
			}
			if n <= 0 {
				continue
			}

			dataPkt := make([]byte, 0, 5+n)
			dataPkt = append(dataPkt, make([]byte, 4)...)
			binary.BigEndian.PutUint32(dataPkt[0:4], proxyID)
			dataPkt = append(dataPkt, 1)
			dataPkt = append(dataPkt, buf[:n]...)

			var hdr proto.PacketHeader
			hdr.Version = proto.Version
			hdr.Flags = 0
			hdr.SessionID = proxyConn.SessionID

			proxyConn.SeqMutex.Lock()
			hdr.Seq = *proxyConn.SeqSend
			*proxyConn.SeqSend++
			proxyConn.SeqMutex.Unlock()

			payloadLen, ok := safeUint16(len(dataPkt) + 16)
			if !ok {
				continue
			}
			hdr.PayloadLen = payloadLen

			aad := hdr.MarshalBinary()
			ct, err := proxyConn.AEADState.Encrypt(hdr.Seq, aad, dataPkt)
			if err != nil {
				continue
			}
			pkt := util.Concat(aad, ct)
			sendProxyPayload(proxyConn, pkt)
		}
	}()
}

func sendProxyPayload(proxyConn *ServerProxyConnection, pkt []byte) {
	if proxyConn == nil {
		return
	}

	if proxyConn.UDPConn != nil && proxyConn.ClientAddr != nil {
		_, _ = proxyConn.UDPConn.WriteToUDP(pkt, proxyConn.ClientAddr)
		return
	}

	if proxyConn.WSConn != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = proxyConn.WSConn.Write(ctx, websocket.MessageBinary, pkt)
	}
}

func finalizeProxyConnection(proxyID uint32, proxyConn *ServerProxyConnection) {
	serverProxyMutex.Lock()
	current, ok := serverProxyConnections[proxyID]
	if ok && current == proxyConn {
		delete(serverProxyConnections, proxyID)
	}
	serverProxyMutex.Unlock()

	if proxyConn == nil {
		return
	}

	if proxyConn.Target != nil {
		_ = proxyConn.Target.Close()
	}

	if proxyConn.Closed != nil {
		select {
		case <-proxyConn.Closed:
		default:
			close(proxyConn.Closed)
		}
	}
}
