package reality

import (
	"crypto/ed25519"
	"net"

	"github.com/xtls/reality"
)

type ClientConfig struct {
	PublicKey   ed25519.PublicKey
	ShortID     []byte
	ServerName  string
	Fingerprint string
	Show        bool
}

func NewClientConfig(publicKey ed25519.PublicKey, shortID []byte, serverName string) *ClientConfig {
	return &ClientConfig{
		PublicKey:   publicKey,
		ShortID:     shortID,
		ServerName:  serverName,
		Fingerprint: "chrome",
		Show:        false,
	}
}

func (c *ClientConfig) Dial(addr string) (net.Conn, error) {
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return nil, err
	}

	fingerprintType := c.Fingerprint
	if fingerprintType == "" {
		fingerprintType = "chrome"
	}

	var shortIDKey [8]byte
	copy(shortIDKey[:], c.ShortID)

	shortIDsMap := make(map[[8]byte]bool)
	shortIDsMap[shortIDKey] = true

	config := &reality.Config{
		Show:       c.Show,
		ServerName: c.ServerName,
		Type:       fingerprintType,
		ShortIds:   shortIDsMap,
	}

	realityConn := reality.Client(conn, config)
	return realityConn, nil
}

