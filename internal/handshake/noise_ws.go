package handshake

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"log"
	"strings"
	"time"

	"github.com/flynn/noise"
	"golang.org/x/crypto/curve25519"
	"nhooyr.io/websocket"
)

// ServerNKOverWS runs Noise NK handshake over a WebSocket connection.
// Each Noise message and the final encrypted seed payload are sent as a single binary WS message.
// If outboundTagPtr is not nil, it will be filled with the outbound tag received from client.
func ServerNKOverWS(
	ctx context.Context, conn *websocket.Conn, staticPriv []byte, outboundTagPtr *string,
) (seed []byte, sessionID uint32, err error) {
	if len(staticPriv) != 32 {
		return nil, 0, errors.New("staticPriv must be 32 bytes")
	}
	pub, err := curve25519.X25519(staticPriv, curve25519.Basepoint)
	if err != nil {
		return nil, 0, err
	}
	cs := noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashSHA256)
	hs, err := noise.NewHandshakeState(noise.Config{
		CipherSuite:   cs,
		Pattern:       noise.HandshakeNK,
		Initiator:     false,
		StaticKeypair: noise.DHKey{Private: staticPriv, Public: pub},
	})
	if err != nil {
		return nil, 0, err
	}
	// msg1 from client
	log.Printf("[Handshake] Waiting for msg1 from client...")
	// Set a read deadline to ensure we don't wait forever
	readCtx, readCancel := context.WithTimeout(ctx, 15*time.Second)
	defer readCancel()
	
	startTime := time.Now()
	msgType, msg1, err := conn.Read(readCtx)
	readDuration := time.Since(startTime)
	
	if err != nil {
		// Check if it's a context cancellation or connection closure
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			log.Printf("[Handshake] Failed to read msg1 after %v: context cancelled or timeout: %v", readDuration, err)
		} else {
			// Check if error message indicates connection closure
			errStr := err.Error()
			if strings.Contains(strings.ToLower(errStr), "eof") || strings.Contains(strings.ToLower(errStr), "closed") || strings.Contains(strings.ToLower(errStr), "close") {
				log.Printf("[Handshake] Failed to read msg1 after %v: connection closed by client before sending msg1: %v", readDuration, err)
			} else {
				log.Printf("[Handshake] Failed to read msg1 after %v: connection error: %v", readDuration, err)
			}
		}
		return nil, 0, err
	}
	if msgType != websocket.MessageBinary {
		log.Printf("[Handshake] Expected binary message, got type %d", msgType)
		return nil, 0, errors.New("expected binary message for msg1")
	}
	log.Printf("[Handshake] Received msg1 (%d bytes), processing...", len(msg1))
	if _, _, _, err = hs.ReadMessage(nil, msg1); err != nil {
		log.Printf("[Handshake] Failed to process msg1: %v", err)
		return nil, 0, err
	}
	log.Printf("[Handshake] msg1 processed successfully, sending msg2...")
	// msg2 to client
	msg2, csSend, _, err := hs.WriteMessage(nil, nil)
	if err != nil {
		log.Printf("[Handshake] Failed to create msg2: %v", err)
		return nil, 0, err
	}
	if err := conn.Write(ctx, websocket.MessageBinary, msg2); err != nil {
		log.Printf("[Handshake] Failed to send msg2: %v", err)
		return nil, 0, err
	}
	log.Printf("[Handshake] msg2 sent successfully (%d bytes), sending encrypted seed...", len(msg2))
	// Send {sid, seed} encrypted as a final WS message
	sessionID = func() uint32 { var b [4]byte; _, _ = rand.Read(b[:]); return binary.BigEndian.Uint32(b[:]) }()
	seed = make([]byte, 32)
	if _, err := rand.Read(seed); err != nil {
		return nil, 0, err
	}
	payload := make([]byte, 4+32)
	binary.BigEndian.PutUint32(payload[:4], sessionID)
	copy(payload[4:], seed)
	ct, err := csSend.Encrypt(nil, nil, payload)
	if err != nil {
		return nil, 0, err
	}
	if err := conn.Write(ctx, websocket.MessageBinary, ct); err != nil {
		log.Printf("[Handshake] Failed to send encrypted seed: %v", err)
		return nil, 0, err
	}
	log.Printf("[Handshake] Handshake completed successfully, sessionID=%d", sessionID)
	
	// Читаем опциональный outbound tag от клиента (если новый клиент)
	// Используем короткий таймаут (2 секунды) - если клиент не отправляет, это нормально
	if outboundTagPtr != nil {
		outboundTag, err := ReadOutboundTagOverWS(ctx, conn, csSend, 2*time.Second)
		if err != nil {
			// Логируем, но не возвращаем ошибку - это опционально
			log.Printf("[Handshake Server] Warning: failed to read outbound tag: %v", err)
			*outboundTagPtr = "" // Используем дефолтный
		} else {
			*outboundTagPtr = outboundTag
		}
	}
	
	return seed, sessionID, nil
}

// ClientNKOverWS runs Noise NK over a WebSocket to the server public key.
// Optionally sends outboundTag to server after receiving seed (if outboundTag is not empty).
func ClientNKOverWS(
	ctx context.Context, conn *websocket.Conn, serverPub []byte, outboundTag string,
) (seed []byte, sessionID uint32, err error) {
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
	msg1, _, _, err := hs.WriteMessage(nil, nil)
	if err != nil {
		log.Printf("[Handshake Client] Failed to create msg1: %v", err)
		return nil, 0, err
	}
	log.Printf("[Handshake Client] Sending msg1 (%d bytes)...", len(msg1))
	
	// Проверяем, не истек ли контекст перед отправкой
	select {
	case <-ctx.Done():
		log.Printf("[Handshake Client] Context cancelled before sending msg1: %v", ctx.Err())
		return nil, 0, ctx.Err()
	default:
	}
	
	// Проверяем, что соединение все еще активно перед отправкой
	
	// Отправляем msg1 с проверкой ошибок
	startTime := time.Now()
	
	// Используем отдельный контекст с таймаутом для записи
	writeCtx, writeCancel := context.WithTimeout(ctx, 10*time.Second)
	defer writeCancel()
	
	if err := conn.Write(writeCtx, websocket.MessageBinary, msg1); err != nil {
		writeDuration := time.Since(startTime)
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			log.Printf("[Handshake Client] Failed to send msg1 after %v: context cancelled or timeout: %v", writeDuration, err)
		} else {
			var closeErr websocket.CloseError
			if errors.As(err, &closeErr) {
				log.Printf("[Handshake Client] Failed to send msg1 after %v: WebSocket closed (code=%d, reason=%q): %v", 
					writeDuration, closeErr.Code, closeErr.Reason, err)
			} else {
				log.Printf("[Handshake Client] Failed to send msg1 after %v: connection error: %v", writeDuration, err)
			}
		}
		return nil, 0, err
	}
	writeDuration := time.Since(startTime)
	log.Printf("[Handshake Client] msg1 sent successfully in %v", writeDuration)
	log.Printf("[Handshake Client] msg1 sent successfully, waiting for msg2...")
	_, msg2, err := conn.Read(ctx)
	if err != nil {
		log.Printf("[Handshake Client] Failed to read msg2: %v", err)
		return nil, 0, err
	}
	log.Printf("[Handshake Client] Received msg2 (%d bytes), processing...", len(msg2))
	_, csRecv, csSend, err := hs.ReadMessage(nil, msg2)
	if err != nil {
		log.Printf("[Handshake Client] Failed to process msg2: %v", err)
		return nil, 0, err
	}
	log.Printf("[Handshake Client] msg2 processed successfully, waiting for encrypted seed...")
	_, ct, err := conn.Read(ctx)
	if err != nil {
		log.Printf("[Handshake Client] Failed to read encrypted seed: %v", err)
		return nil, 0, err
	}
	log.Printf("[Handshake Client] Received encrypted seed (%d bytes), decrypting...", len(ct))
	pt, err := csRecv.Decrypt(nil, nil, ct)
	if err != nil {
		log.Printf("[Handshake Client] Failed to decrypt seed: %v", err)
		return nil, 0, err
	}
	if len(pt) != 4+32 {
		log.Printf("[Handshake Client] Invalid seed payload size: %d", len(pt))
		return nil, 0, errors.New("invalid seed payload size")
	}
	sessionID = binary.BigEndian.Uint32(pt[:4])
	seed = make([]byte, 32)
	copy(seed, pt[4:])
	log.Printf("[Handshake Client] Handshake completed successfully, sessionID=%d", sessionID)
	
	// Отправляем outbound tag если указан (опционально, обратно совместимо)
	if outboundTag != "" && csSend != nil {
		if err := SendOutboundTagOverWS(ctx, conn, csSend, outboundTag); err != nil {
			// Не блокируем на ошибке отправки outbound tag - это опционально
			log.Printf("[Handshake Client] Warning: failed to send outbound tag: %v", err)
		}
	}
	
	return seed, sessionID, nil
}

// SendOutboundTagOverWS отправляет outbound tag серверу после завершения handshake через WebSocket.
// Использует cipherstate для шифрования. Если outboundTag пустой, ничего не отправляет.
func SendOutboundTagOverWS(ctx context.Context, conn *websocket.Conn, csSend *noise.CipherState, outboundTag string) error {
	if outboundTag == "" {
		return nil // Опционально, не отправляем если пустой
	}
	if csSend == nil {
		return errors.New("cipherstate is nil")
	}
	
	// Формат: длина строки (1 байт) + строка (UTF-8)
	tagBytes := []byte(outboundTag)
	if len(tagBytes) > 255 {
		return errors.New("outbound tag too long (max 255 bytes)")
	}
	
	payload := make([]byte, 1+len(tagBytes))
	payload[0] = byte(len(tagBytes))
	copy(payload[1:], tagBytes)
	
	ct, err := csSend.Encrypt(nil, nil, payload)
	if err != nil {
		return errors.New("failed to encrypt outbound tag: " + err.Error())
	}
	
	if err := conn.Write(ctx, websocket.MessageBinary, ct); err != nil {
		return errors.New("failed to send outbound tag: " + err.Error())
	}
	
	log.Printf("[Handshake Client] Sent outbound tag '%s' to server (WebSocket)", outboundTag)
	return nil
}

// ReadOutboundTagOverWS читает опциональный outbound tag от клиента после отправки seed через WebSocket.
// Если клиент не отправляет tag (старый клиент), возвращает пустую строку без ошибки.
// Использует контекст с таймаутом (например, 2 секунды).
func ReadOutboundTagOverWS(ctx context.Context, conn *websocket.Conn, csRecv *noise.CipherState, timeout time.Duration) (string, error) {
	if csRecv == nil {
		return "", errors.New("cipherstate is nil")
	}
	
	// Создаем контекст с таймаутом для чтения опционального outbound tag
	readCtx, readCancel := context.WithTimeout(ctx, timeout)
	defer readCancel()
	
	msgType, ct, err := conn.Read(readCtx)
	if err != nil {
		// Если это таймаут, это нормально - старый клиент не отправляет outbound tag
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
			return "", nil // Не ошибка, просто старый клиент
		}
		return "", errors.New("failed to read outbound tag: " + err.Error())
	}
	
	if msgType != websocket.MessageBinary {
		return "", errors.New("expected binary message for outbound tag")
	}
	
	pt, err := csRecv.Decrypt(nil, nil, ct)
	if err != nil {
		return "", errors.New("failed to decrypt outbound tag: " + err.Error())
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
	log.Printf("[Handshake Server] Received outbound tag '%s' from client (WebSocket)", outboundTag)
	return outboundTag, nil
}
