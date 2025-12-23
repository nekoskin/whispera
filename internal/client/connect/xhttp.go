package connect

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"strings"

	"whispera/internal/obfuscation"
	vlesspkg "whispera/internal/vless"
	xhttppkg "whispera/internal/xhttp"
)

// RunXHTTPClient establishes XHTTP connection with Marionette obfuscation
// According to Xray-core specification, XHTTP does NOT create TCP/TLS connections
// It works as an obfuscation layer over existing connections
func RunXHTTPClient(
	addr string,
	publicKeyHex string,
	shortIDHex string,
	serverName string,
	fingerprint string,
	alpn string,
	obfuscationManager *obfuscation.IntegrationManager,
) (uint32, net.Conn, error) {
	publicKeyBytes, err := hex.DecodeString(publicKeyHex)
	if err != nil || len(publicKeyBytes) != 32 {
		return 0, nil, fmt.Errorf("invalid XHTTP public key: %w", err)
	}

	var publicKey ed25519.PublicKey = publicKeyBytes

	shortIDBytes, err := hex.DecodeString(shortIDHex)
	if err != nil || len(shortIDBytes) != 8 {
		return 0, nil, fmt.Errorf("invalid XHTTP short ID: %w", err)
	}

	// Create XHTTP client config with obfuscation manager (MANDATORY)
	// XHTTP requires Marionette obfuscation - obfuscationManager must not be nil
	if obfuscationManager == nil {
		return 0, nil, fmt.Errorf("XHTTP requires Marionette obfuscation manager")
	}
	config, err := xhttppkg.NewClientConfig(publicKey, shortIDBytes, serverName, obfuscationManager)
	if err != nil {
		return 0, nil, fmt.Errorf("XHTTP config creation failed: %w", err)
	}
	// Note: fingerprint parameter is ignored - XHTTP doesn't use it

	// XHTTP specification: First establish base TCP/TLS connection
	// Then apply XHTTP obfuscation layer on top of it
	log.Printf("[XHTTP Client] Establishing base TCP/TLS connection to %s...", addr)

	// Extract port to decide whether to use TLS (host не используется — для SNI берём serverName)
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		return 0, nil, fmt.Errorf("invalid address: %w", err)
	}

	// Determine if TLS is needed (port 443 or 4443)
	useTLS := port == "443" || port == "4443"

	var baseConn net.Conn
	if useTLS {
		// Establish TLS connection first
		tlsConfig := &tls.Config{
			ServerName:         serverName,
			InsecureSkipVerify: false,
		}
		// ALPN: приближаем поведение к Xray XHTTP (h2/http1.1 или заданное пользователем)
		if alpn != "" {
			// Поддерживаем формат "h2,http/1.1"
			protos := make([]string, 0, 4)
			for _, p := range strings.Split(alpn, ",") {
				p = strings.TrimSpace(p)
				if p != "" {
					protos = append(protos, p)
				}
			}
			if len(protos) > 0 {
				tlsConfig.NextProtos = protos
			}
		}
		baseConn, err = tls.Dial("tcp", addr, tlsConfig)
		if err != nil {
			return 0, nil, fmt.Errorf("TLS dial failed: %w", err)
		}
		log.Printf("[XHTTP Client] ✅ Base TLS connection established to %s", addr)
	} else {
		// Establish plain TCP connection
		baseConn, err = net.Dial("tcp", addr)
		if err != nil {
			return 0, nil, fmt.Errorf("TCP dial failed: %w", err)
		}
		log.Printf("[XHTTP Client] ✅ Base TCP connection established to %s", addr)
	}

	// Wrap the connection first
	log.Printf("[XHTTP Client] Applying XHTTP obfuscation layer...")
	conn, err := config.WrapConn(baseConn)
	if err != nil {
		baseConn.Close()
		return 0, nil, fmt.Errorf("XHTTP wrap failed: %w", err)
	}
	log.Printf("[XHTTP Client] ✅ XHTTP obfuscation layer applied")

	// Then write VLESS header to obfuscated connection
	sessionID := generateSessionIDFromUUID()

	vlessHdr := &vlesspkg.RequestHeader{
		Version:  vlesspkg.Version,
		UUID:     sessionIDToUUID(sessionID),
		Addons:   0,
		Command:  vlesspkg.CommandTCP,
		Port:     0,
		AddrType: vlesspkg.AddrTypeIPv4,
		Address:  []byte{0, 0, 0, 0},
	}

	if err := vlesspkg.WriteRequestHeader(conn, vlessHdr); err != nil {
		conn.Close()
		return 0, nil, fmt.Errorf("VLESS header write failed: %w", err)
	}
	log.Printf("[XHTTP Client] ✅ VLESS header sent to obfuscated connection, sessionID=%d", sessionID)

	return sessionID, conn, nil
}

func generateSessionIDFromUUID() uint32 {
	uuid := make([]byte, 16)
	if _, err := rand.Read(uuid); err != nil {
		uuid[0] = 0xFF
		uuid[1] = 0xFF
		uuid[2] = 0xFF
		uuid[3] = 0xFF
	}
	return binary.BigEndian.Uint32(uuid[:4])
}

func sessionIDToUUID(sid uint32) [16]byte {
	var uuid [16]byte
	uuid[0] = byte(sid >> 24)
	uuid[1] = byte(sid >> 16)
	uuid[2] = byte(sid >> 8)
	uuid[3] = byte(sid)
	for i := 4; i < 16; i++ {
		uuid[i] = byte(i)
	}
	return uuid
}
