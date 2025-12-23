package handshake

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"log"
	"net"
	"time"

	"github.com/flynn/noise"
	"golang.org/x/crypto/curve25519"
)

func writeFrame(w io.Writer, b []byte) error {
	var hdr [2]byte
	if len(b) > 65535 {
		return errors.New("frame too large")
	}
	length := len(b)
	if length < 0 {
		length = 0
	}
	if length > 65535 {
		length = 65535
	}
	//nolint:gosec // length is clamped to 0-65535 range
	binary.BigEndian.PutUint16(hdr[:], uint16(length))
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	_, err := w.Write(b)
	return err
}

func readFrame(r io.Reader) ([]byte, error) {
	var hdr [2]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	n := int(binary.BigEndian.Uint16(hdr[:]))
	if n <= 0 || n > 65535 {
		return nil, errors.New("bad frame size")
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

// ServerNKOverConn runs Noise NK handshake over a stream (TCP net.Conn)
// and returns seed and sessionID. After handshake, an encrypted frame with
// {sessionID(4), seed(32)} is sent to the client.
// If outboundTagPtr is not nil, it will be filled with the outbound tag received from client.
func ServerNKOverConn(conn net.Conn, staticPriv []byte, outboundTagPtr *string) (seed []byte, sessionID uint32, err error) {
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

	msg1, err := readFrame(conn)
	if err != nil {
		return nil, 0, err
	}
	if _, _, _, err = hs.ReadMessage(nil, msg1); err != nil {
		return nil, 0, err
	}
	msg2, csSend, _, err := hs.WriteMessage(nil, nil)
	if err != nil {
		return nil, 0, err
	}
	if err := writeFrame(conn, msg2); err != nil {
		return nil, 0, err
	}

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
	if err := writeFrame(conn, ct); err != nil {
		return nil, 0, err
	}
	
	// Читаем опциональный outbound tag от клиента (если новый клиент)
	// Используем короткий таймаут (2 секунды) - если клиент не отправляет, это нормально
	if outboundTagPtr != nil {
		outboundTag, err := ReadOutboundTagOverStream(conn, csSend, 2*time.Second)
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

// ClientNKOverConn runs NK over a stream to the server public key.
// Optionally sends outboundTag to server after receiving seed (if outboundTag is not empty).
func ClientNKOverConn(conn net.Conn, serverPub []byte, outboundTag string) (seed []byte, sessionID uint32, err error) {
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
		return nil, 0, err
	}
	if err := writeFrame(conn, msg1); err != nil {
		return nil, 0, err
	}
	msg2, err := readFrame(conn)
	if err != nil {
		return nil, 0, err
	}
	_, csRecv, csSend, err := hs.ReadMessage(nil, msg2)
	if err != nil {
		return nil, 0, err
	}
	ct, err := readFrame(conn)
	if err != nil {
		return nil, 0, err
	}
	pt, err := csRecv.Decrypt(nil, nil, ct)
	if err != nil {
		return nil, 0, err
	}
	if len(pt) != 4+32 {
		return nil, 0, errors.New("invalid seed payload size")
	}
	sessionID = binary.BigEndian.Uint32(pt[:4])
	seed = make([]byte, 32)
	copy(seed, pt[4:])
	
	// Отправляем outbound tag если указан (опционально, обратно совместимо)
	if outboundTag != "" && csSend != nil {
		if err := SendOutboundTagOverStream(conn, csSend, outboundTag); err != nil {
			// Не блокируем на ошибке отправки outbound tag - это опционально
			// Логируем, но не возвращаем ошибку - handshake уже успешен
		}
	}
	
	return seed, sessionID, nil
}

// SendOutboundTagOverStream отправляет outbound tag серверу после завершения handshake через stream (TCP).
// Использует cipherstate для шифрования. Если outboundTag пустой, ничего не отправляет.
func SendOutboundTagOverStream(conn net.Conn, csSend *noise.CipherState, outboundTag string) error {
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
	
	if err := writeFrame(conn, ct); err != nil {
		return errors.New("failed to send outbound tag: " + err.Error())
	}
	
	log.Printf("[Handshake Client] Sent outbound tag '%s' to server (TCP)", outboundTag)
	return nil
}

// ReadOutboundTagOverStream читает опциональный outbound tag от клиента после отправки seed через stream (TCP).
// Если клиент не отправляет tag (старый клиент), возвращает пустую строку без ошибки.
// Использует SetReadDeadline для таймаута (например, 2 секунды).
func ReadOutboundTagOverStream(conn net.Conn, csRecv *noise.CipherState, timeout time.Duration) (string, error) {
	if csRecv == nil {
		return "", errors.New("cipherstate is nil")
	}
	
	// Устанавливаем короткий таймаут для чтения опционального outbound tag
	if timeout > 0 {
		if tcpConn, ok := conn.(*net.TCPConn); ok {
			if err := tcpConn.SetReadDeadline(time.Now().Add(timeout)); err != nil {
				return "", errors.New("failed to set read deadline: " + err.Error())
			}
			defer func() {
				// Сбрасываем deadline
				_ = tcpConn.SetReadDeadline(time.Time{})
			}()
		} else {
			// Для других типов соединений используем общий интерфейс
			if err := conn.SetReadDeadline(time.Now().Add(timeout)); err != nil {
				return "", errors.New("failed to set read deadline: " + err.Error())
			}
			defer func() {
				// Сбрасываем deadline
				_ = conn.SetReadDeadline(time.Time{})
			}()
		}
	}
	
	ct, err := readFrame(conn)
	if err != nil {
		// Если это таймаут, это нормально - старый клиент не отправляет outbound tag
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			return "", nil // Не ошибка, просто старый клиент
		}
		return "", errors.New("failed to read outbound tag: " + err.Error())
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
	log.Printf("[Handshake Server] Received outbound tag '%s' from client (TCP)", outboundTag)
	return outboundTag, nil
}
