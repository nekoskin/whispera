package reality

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"net"
	"time"

	"github.com/xtls/reality"
)

type ServerConfig struct {
	PrivateKey   ed25519.PrivateKey
	ShortIDs     [][]byte
	ServerNames  []string
	Target       string
	Show         bool
	MinClientVer string
	MaxClientVer string
	MaxTimeDiff  int64
}

func NewServerConfig(target string, serverNames []string) (*ServerConfig, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}

	shortID := make([]byte, 8)
	if _, err := rand.Read(shortID); err != nil {
		return nil, err
	}

	return &ServerConfig{
		PrivateKey:  priv,
		ShortIDs:    [][]byte{shortID},
		ServerNames: serverNames,
		Target:      target,
		Show:        false,
	}, nil
}

func NewServerConfigWithKeys(target string, serverNames []string, privateKey ed25519.PrivateKey, shortIDs [][]byte) (*ServerConfig, error) {
	return &ServerConfig{
		PrivateKey:  privateKey,
		ShortIDs:    shortIDs,
		ServerNames: serverNames,
		Target:      target,
		Show:        false,
	}, nil
}

func (s *ServerConfig) HandleConn(ctx context.Context, conn net.Conn) (net.Conn, error) {
	serverNamesMap := make(map[string]bool)
	for _, name := range s.ServerNames {
		serverNamesMap[name] = true
	}

	shortIDsMap := make(map[[8]byte]bool)
	for _, id := range s.ShortIDs {
		if len(id) == 8 {
			var key [8]byte
			copy(key[:], id)
			shortIDsMap[key] = true
		}
	}

	config := &reality.Config{
		Show:         s.Show,
		Dest:         s.Target,
		ServerNames:  serverNamesMap,
		PrivateKey:   []byte(s.PrivateKey),
		ShortIds:     shortIDsMap,
		MinClientVer: []byte(s.MinClientVer),
		MaxClientVer: []byte(s.MaxClientVer),
		MaxTimeDiff:  time.Duration(s.MaxTimeDiff) * time.Second,
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := &net.Dialer{}
			return d.DialContext(ctx, network, address)
		},
	}

	realityConn, err := reality.Server(ctx, conn, config)
	return realityConn, err
}

func (s *ServerConfig) GetPublicKey() []byte {
	return s.PrivateKey.Public().(ed25519.PublicKey)
}

func (s *ServerConfig) GetShortIDs() [][]byte {
	return s.ShortIDs
}
 
