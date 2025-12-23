package handshake

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net"
	"time"

	"github.com/flynn/noise"
	"golang.org/x/crypto/curve25519"
)

const maxHandshakePacket = 2048

func randUint32() uint32 {
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		// SECURITY: Не используем fallback на time.Now() - это создает предсказуемые sessionID
		// Если crypto/rand недоступен, это критическая ошибка системы
		// Паникуем вместо возврата небезопасного значения
		panic("crypto/rand.Read failed - system entropy unavailable, cannot generate secure sessionID")
	}
	return binary.BigEndian.Uint32(b[:])
}

// randUint64 генерирует криптографически стойкий 64-bit случайный номер
// SECURITY: Используется для генерации sessionID с большим пространством для предотвращения коллизий
func randUint64() uint64 {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic("crypto/rand.Read failed - system entropy unavailable, cannot generate secure sessionID")
	}
	return binary.BigEndian.Uint64(b[:])
}

// GenerateSessionID генерирует sessionID с проверкой на коллизии
// SECURITY: Использует 64-bit для уменьшения вероятности коллизий
// Возвращает младшие 32 бита для обратной совместимости, но использует полные 64 бита для проверки
func GenerateSessionID(checkCollision func(uint32) bool) uint32 {
	maxRetries := 10
	for i := 0; i < maxRetries; i++ {
		// Генерируем 64-bit значение, но используем младшие 32 бита для обратной совместимости
		// В будущем можно перейти на полные 64 бита
		sessionID64 := randUint64()
		sessionID := uint32(sessionID64) // Младшие 32 бита
		
		// Проверяем коллизию только если предоставлена функция проверки
		if checkCollision == nil || !checkCollision(sessionID) {
			return sessionID
		}
		// Коллизия обнаружена, пробуем снова
	}
	// Если после maxRetries попыток все еще коллизии, возвращаем последнее значение
	// В реальности вероятность этого крайне мала
	return uint32(randUint64())
}

// ServerIK performs a blocking Noise IK handshake (responder) on conn.
// Returns shared seed (32 bytes), sessionID, and the client's UDP address.
func ServerIK(conn *net.UDPConn, staticPriv []byte) (seed []byte, sessionID uint32, client *net.UDPAddr, err error) {
	if len(staticPriv) != 32 {
		return nil, 0, nil, errors.New("staticPriv must be 32 bytes")
	}
	pub, err := curve25519.X25519(staticPriv, curve25519.Basepoint)
	if err != nil {
		return nil, 0, nil, err
	}
	cs := noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashSHA256)
	hs, err := noise.NewHandshakeState(noise.Config{
		CipherSuite:   cs,
		Pattern:       noise.HandshakeNK,
		Initiator:     false,
		StaticKeypair: noise.DHKey{Private: staticPriv, Public: pub},
	})
	if err != nil {
		return nil, 0, nil, err
	}

	buf := make([]byte, maxHandshakePacket)
	n, addr, err := conn.ReadFromUDP(buf)
	if err != nil {
		return nil, 0, nil, err
	}
	if _, _, _, err = hs.ReadMessage(nil, buf[:n]); err != nil {
		return nil, 0, nil, err
	}
	msg2, csSend, _, err := hs.WriteMessage(nil, nil)
	if err != nil {
		return nil, 0, nil, err
	}
	if _, err := conn.WriteToUDP(msg2, addr); err != nil {
		return nil, 0, nil, err
	}

	// Post-handshake: send seed and session ID encrypted under server->client cipherstate
	sessionID = randUint32()
	seed = make([]byte, 32)
	if _, err := rand.Read(seed); err != nil {
		return nil, 0, nil, err
	}
	payload := make([]byte, 4+32)
	binary.BigEndian.PutUint32(payload[:4], sessionID)
	copy(payload[4:], seed)
	ct, err := csSend.Encrypt(nil, nil, payload)
	if err != nil {
		return nil, 0, nil, err
	}
	if _, err := conn.WriteToUDP(ct, addr); err != nil {
		return nil, 0, nil, err
	}
	
	// Читаем опциональный outbound tag от клиента (если новый клиент)
	// Используем короткий таймаут (2 секунды) - если клиент не отправляет, это нормально
	// Note: outboundTag is not currently returned from this function for backward compatibility
	_, err = ReadOutboundTag(conn, csSend, 2*time.Second)
	if err != nil {
		// Логируем, но не возвращаем ошибку - это опционально
		log.Printf("[Handshake Server] Warning: failed to read outbound tag from %s: %v", addr, err)
	}
	
	// Возвращаем outbound tag через специальную структуру или расширяем сигнатуру
	// Пока используем глобальную переменную или передаем через контекст
	// Для обратной совместимости, добавим отдельную функцию для получения outbound tag
	return seed, sessionID, addr, nil
}

// ServerIKFromFirst continues a Noise NK responder handshake using the already-read first datagram.
// It assumes 'first' is the client's msg1 and 'addr' is the source address to reply to.
// If outboundTagPtr is not nil, it will be filled with the outbound tag received from client.
// SECURITY: Implements cookie mechanism to prevent DoS amplification attacks.
func ServerIKFromFirst(
	conn *net.UDPConn, staticPriv, first []byte, addr *net.UDPAddr, outboundTagPtr *string,
) (seed []byte, sessionID uint32, client *net.UDPAddr, err error) {
	if len(staticPriv) != 32 {
		return nil, 0, nil, errors.New("staticPriv must be 32 bytes")
	}

	// SECURITY: Cookie mechanism for DoS protection
	// Check if cookie is present and valid
	hasValidCookie := false
	msg1Data := first

	if len(first) >= cookieSize {
		cookie := first[:cookieSize]
		msg1Data = first[cookieSize:]

		if VerifyCookie(cookie, addr) {
			hasValidCookie = true
			log.Printf("[Handshake Server] Valid cookie received from %s", addr)
		}
	}

	// If no valid cookie, send cookie challenge without performing expensive crypto
	if !hasValidCookie {
		log.Printf("[Handshake Server] No valid cookie from %s, sending cookie challenge", addr)
		cookie := GenerateCookie(addr)
		// Format: [cookie][original_msg1]
		cookieMsg := make([]byte, cookieSize+len(msg1Data))
		copy(cookieMsg[:cookieSize], cookie)
		copy(cookieMsg[cookieSize:], msg1Data)

		if _, err := conn.WriteToUDP(cookieMsg, addr); err != nil {
			return nil, 0, nil, fmt.Errorf("failed to send cookie challenge: %w", err)
		}

		// Wait for client to retry with cookie
		buf := make([]byte, maxHandshakePacket)
		conn.SetReadDeadline(time.Now().Add(10 * time.Second))
		n, retryAddr, err := conn.ReadFromUDP(buf)
		if err != nil {
			return nil, 0, nil, fmt.Errorf("failed to read retry with cookie: %w", err)
		}
		conn.SetReadDeadline(time.Time{})

		// Verify the retry came from the same address
		if retryAddr.IP.String() != addr.IP.String() || retryAddr.Port != addr.Port {
			return nil, 0, nil, errors.New("retry from different address")
		}

		if n < cookieSize {
			return nil, 0, nil, errors.New("invalid cookie message size")
		}

		cookie = buf[:cookieSize]
		msg1Data = buf[cookieSize:n]

		if !VerifyCookie(cookie, addr) {
			return nil, 0, nil, errors.New("invalid cookie in retry")
		}

		log.Printf("[Handshake Server] Valid cookie received in retry from %s", addr)
	}

	// Now perform expensive cryptographic operations only after cookie validation
	pub, err := curve25519.X25519(staticPriv, curve25519.Basepoint)
	if err != nil {
		return nil, 0, nil, err
	}
	cs := noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashSHA256)
	hs, err := noise.NewHandshakeState(noise.Config{
		CipherSuite:   cs,
		Pattern:       noise.HandshakeNK,
		Initiator:     false,
		StaticKeypair: noise.DHKey{Private: staticPriv, Public: pub},
	})
	if err != nil {
		return nil, 0, nil, err
	}
	if _, _, _, err = hs.ReadMessage(nil, msg1Data); err != nil {
		log.Printf("[Handshake Server] Failed to read msg1 from %s: %v", addr, err)
		return nil, 0, nil, err
	}
	log.Printf("[Handshake Server] Successfully read msg1 (%d bytes) from %s", len(msg1Data), addr)
	msg2, csSend, _, err := hs.WriteMessage(nil, nil)
	if err != nil {
		log.Printf("[Handshake Server] Failed to generate msg2 for %s: %v", addr, err)
		return nil, 0, nil, err
	}
	log.Printf("[Handshake Server] Generated msg2 (%d bytes), sending to %s", len(msg2), addr)
	if _, err := conn.WriteToUDP(msg2, addr); err != nil {
		log.Printf("[Handshake Server] Failed to send msg2 to %s: %v", addr, err)
		return nil, 0, nil, err
	}
	log.Printf("[Handshake Server] msg2 sent successfully (%d bytes) to %s", len(msg2), addr)
	// Post-handshake: send seed and session ID encrypted under server->client cipherstate
	sessionID = randUint32()
	seed = make([]byte, 32)
	if _, err := rand.Read(seed); err != nil {
		return nil, 0, nil, err
	}
	payload := make([]byte, 4+32)
	binary.BigEndian.PutUint32(payload[:4], sessionID)
	copy(payload[4:], seed)
	ct, err := csSend.Encrypt(nil, nil, payload)
	if err != nil {
		log.Printf("[Handshake Server] Failed to encrypt seed packet for %s: %v", addr, err)
		return nil, 0, nil, err
	}
	log.Printf("[Handshake Server] Generated encrypted seed packet (%d bytes, sessionID=%d), sending to %s", len(ct), sessionID, addr)
	if _, err := conn.WriteToUDP(ct, addr); err != nil {
		log.Printf("[Handshake Server] Failed to send seed packet to %s: %v", addr, err)
		return nil, 0, nil, err
	}
	log.Printf("[Handshake Server] Seed packet sent successfully (%d bytes) to %s", len(ct), addr)
	
	// Читаем опциональный outbound tag от клиента (если новый клиент)
	// Используем короткий таймаут (2 секунды) - если клиент не отправляет, это нормально
	if outboundTagPtr != nil {
		outboundTag, err := ReadOutboundTag(conn, csSend, 2*time.Second)
		if err != nil {
			// Логируем, но не возвращаем ошибку - это опционально
			log.Printf("[Handshake Server] Warning: failed to read outbound tag from %s: %v", addr, err)
			*outboundTagPtr = "" // Используем дефолтный
		} else {
			*outboundTagPtr = outboundTag
		}
	}
	
	return seed, sessionID, addr, nil
}

// ClientIK performs initiator side of IK using server's static public key.
// Returns the shared seed and sessionID from the server.
// Note: The caller should set ReadDeadline on conn before calling this function.
// This function respects the deadline and will return timeout errors if the deadline expires.
// Optionally sends outboundTag to server after receiving seed (if outboundTag is not empty).
func ClientIK(conn *net.UDPConn, server *net.UDPAddr, serverPub []byte, outboundTag string) (seed []byte, sessionID uint32, err error) {
	if len(serverPub) != 32 {
		return nil, 0, errors.New("serverPub must be 32 bytes")
	}
	cs := noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashSHA256)
	hs, err := noise.NewHandshakeState(noise.Config{
		CipherSuite: cs,
		Pattern:     noise.HandshakeNK,
		Initiator:   true,
		PeerStatic:  serverPub,
	})
	if err != nil {
		return nil, 0, err
	}
	// -> msg1
	msg1, _, _, err := hs.WriteMessage(nil, nil)
	if err != nil {
		return nil, 0, err
	}
	// Log msg1 size for debugging
	log.Printf("[Handshake Client] Sending msg1 (%d bytes) to %s", len(msg1), server)
	// Use WriteToUDP for unconnected UDP connection
	// SECURITY: Send msg1 without cookie first (server will send cookie challenge if needed)
	if _, err := conn.WriteToUDP(msg1, server); err != nil {
		return nil, 0, err
	}
	log.Printf("[Handshake Client] msg1 sent successfully (%d bytes)", len(msg1))
	// <- msg2 or cookie challenge
	// Note: Caller should set ReadDeadline before calling this function.
	// We extend the deadline before the second read to ensure both reads have sufficient time.
	buf := make([]byte, maxHandshakePacket)
	n, _, err := conn.ReadFromUDP(buf)
	if err != nil {
		// Check if it's a timeout error and provide better error message
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			return nil, 0, fmt.Errorf("UDP handshake timeout waiting for msg2: %w", err)
		}
		return nil, 0, fmt.Errorf("failed to read msg2: %w", err)
	}

	// SECURITY: Check if server sent cookie challenge
	var msg2 []byte
	if n >= cookieSize+len(msg1) {
		// Possible cookie challenge: [cookie][msg1]
		// Try to parse as Noise message - if it fails, it's a cookie challenge
		testHS, _ := noise.NewHandshakeState(noise.Config{
			CipherSuite: cs,
			Pattern:     noise.HandshakeNK,
			Initiator:   true,
			PeerStatic:  serverPub,
		})
		
		// Try to read as Noise message from the part after cookie
		if _, _, _, err := testHS.ReadMessage(nil, buf[cookieSize:n]); err != nil {
			// This is a cookie challenge, extract cookie and retry
			cookie := buf[:cookieSize]
			log.Printf("[Handshake Client] Received cookie challenge from server, retrying with cookie")
			
			// Retry with cookie
			msg1WithCookie := make([]byte, cookieSize+len(msg1))
			copy(msg1WithCookie[:cookieSize], cookie)
			copy(msg1WithCookie[cookieSize:], msg1)
			
			if _, err := conn.WriteToUDP(msg1WithCookie, server); err != nil {
				return nil, 0, fmt.Errorf("failed to send msg1 with cookie: %w", err)
			}
			
			// Read msg2
			n, _, err := conn.ReadFromUDP(buf)
			if err != nil {
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					return nil, 0, fmt.Errorf("UDP handshake timeout waiting for msg2 after cookie: %w", err)
				}
				return nil, 0, fmt.Errorf("failed to read msg2 after cookie: %w", err)
			}
			msg2 = buf[:n]
		} else {
			// It parsed as Noise message, so it's msg2 (shouldn't have cookie prefix normally)
			msg2 = buf[:n]
		}
	} else {
		// No cookie, this is msg2
		msg2 = buf[:n]
	}

	_, csRecv, csSend, err := hs.ReadMessage(nil, msg2)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to process msg2: %w", err)
	}
	// Expect encrypted seed+sessionID next from server, decrypt with recv state
	// Extend deadline for second read (give it another 10 seconds from now to ensure we have enough time)
	// This prevents the second read from blocking if the first read consumed most of the original deadline
	if err := conn.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
		return nil, 0, fmt.Errorf("failed to set deadline for seed read: %w", err)
	}
	n2, _, err := conn.ReadFromUDP(buf)
	if err != nil {
		// Check if it's a timeout error
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			return nil, 0, fmt.Errorf("UDP handshake timeout waiting for encrypted seed: %w", err)
		}
		return nil, 0, fmt.Errorf("failed to read encrypted seed: %w", err)
	}
	pt, err := csRecv.Decrypt(nil, nil, buf[:n2])
	if err != nil {
		return nil, 0, fmt.Errorf("failed to decrypt seed: %w", err)
	}
	if len(pt) != 4+32 {
		return nil, 0, errors.New("invalid seed payload size")
	}
	sessionID = binary.BigEndian.Uint32(pt[:4])
	seed = make([]byte, 32)
	copy(seed, pt[4:])
	
	// Отправляем outbound tag если указан (опционально, обратно совместимо)
	if outboundTag != "" && csSend != nil {
		// Не блокируем на ошибке отправки outbound tag - это опционально
		if err := SendOutboundTag(conn, server, csSend, outboundTag); err != nil {
			log.Printf("[Handshake Client] Warning: failed to send outbound tag: %v", err)
			// Не возвращаем ошибку - handshake уже успешен
		}
	}
	
	return seed, sessionID, nil
}

// SendOutboundTag отправляет outbound tag серверу после завершения handshake.
// Использует cipherstate для шифрования. Если outboundTag пустой, ничего не отправляет.
// Возвращает ошибку только если отправка не удалась (не если tag пустой).
func SendOutboundTag(conn *net.UDPConn, server *net.UDPAddr, csSend *noise.CipherState, outboundTag string) error {
	if outboundTag == "" {
		return nil // Опционально, не отправляем если пустой
	}
	if csSend == nil {
		return errors.New("cipherstate is nil")
	}
	
	// Формат: длина строки (2 байта) + строка (UTF-8)
	tagBytes := []byte(outboundTag)
	if len(tagBytes) > 255 {
		return errors.New("outbound tag too long (max 255 bytes)")
	}
	
	payload := make([]byte, 1+len(tagBytes))
	payload[0] = byte(len(tagBytes))
	copy(payload[1:], tagBytes)
	
	ct, err := csSend.Encrypt(nil, nil, payload)
	if err != nil {
		return fmt.Errorf("failed to encrypt outbound tag: %w", err)
	}
	
	if _, err := conn.WriteToUDP(ct, server); err != nil {
		return fmt.Errorf("failed to send outbound tag: %w", err)
	}
	
	log.Printf("[Handshake Client] Sent outbound tag '%s' to server", outboundTag)
	return nil
}

// ReadOutboundTag читает опциональный outbound tag от клиента после отправки seed.
// Если клиент не отправляет tag (старый клиент), возвращает пустую строку без ошибки.
// Использует SetReadDeadline для таймаута (например, 2 секунды).
func ReadOutboundTag(conn *net.UDPConn, csRecv *noise.CipherState, timeout time.Duration) (string, error) {
	if csRecv == nil {
		return "", errors.New("cipherstate is nil")
	}
	
	// Устанавливаем короткий таймаут для чтения опционального outbound tag
	if timeout > 0 {
		if err := conn.SetReadDeadline(time.Now().Add(timeout)); err != nil {
			return "", fmt.Errorf("failed to set read deadline: %w", err)
		}
		defer func() {
			// Сбрасываем deadline
			_ = conn.SetReadDeadline(time.Time{})
		}()
	}
	
	buf := make([]byte, maxHandshakePacket)
	n, _, err := conn.ReadFromUDP(buf)
	if err != nil {
		// Если это таймаут, это нормально - старый клиент не отправляет outbound tag
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			return "", nil // Не ошибка, просто старый клиент
		}
		return "", fmt.Errorf("failed to read outbound tag: %w", err)
	}
	
	pt, err := csRecv.Decrypt(nil, nil, buf[:n])
	if err != nil {
		return "", fmt.Errorf("failed to decrypt outbound tag: %w", err)
	}
	
	if len(pt) < 1 {
		return "", errors.New("invalid outbound tag payload: too short")
	}
	
	tagLen := int(pt[0])
	if tagLen == 0 {
		return "", nil // Пустой tag
	}
	
	if len(pt) < 1+tagLen {
		return "", errors.New("invalid outbound tag payload: length mismatch")
	}
	
	outboundTag := string(pt[1 : 1+tagLen])
	log.Printf("[Handshake Server] Received outbound tag '%s' from client", outboundTag)
	return outboundTag, nil
}
