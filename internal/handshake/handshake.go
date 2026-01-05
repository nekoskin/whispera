// Package handshake provides Whispera protocol handshake utilities
package handshake

import (
	"crypto/rand"
	"fmt"
	"net"
	"time"

	"golang.org/x/crypto/curve25519"
)

// ClientHandshake performs a client-initiated Whispera handshake using X25519
// Returns: shared secret for key derivation, response bytes, error
func ClientHandshake(conn *net.UDPConn, raddr *net.UDPAddr, peerPubKey []byte, psk string) ([]byte, []byte, error) {
	if len(peerPubKey) != 32 {
		return nil, nil, fmt.Errorf("invalid peer public key length")
	}

	// Generate ephemeral keypair
	ephPriv := make([]byte, 32)
	if _, err := rand.Read(ephPriv); err != nil {
		return nil, nil, err
	}
	ephPub, err := curve25519.X25519(ephPriv, curve25519.Basepoint)
	if err != nil {
		return nil, nil, err
	}

	// Send ephemeral public key
	if _, err := conn.WriteToUDP(ephPub, raddr); err != nil {
		return nil, nil, err
	}

	// Read response
	buf := make([]byte, 64)
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, _, err := conn.ReadFromUDP(buf)
	if err != nil {
		return nil, nil, err
	}

	// Derive shared secret
	shared, err := curve25519.X25519(ephPriv, peerPubKey)
	if err != nil {
		return nil, nil, err
	}

	return shared, buf[:n], nil
}

// ServerHandshake processes handshake packet as server
// Returns: shared secret, responder pubkey, response to send, error
func ServerHandshake(conn *net.UDPConn, privKey []byte, firstPacket []byte, raddr *net.UDPAddr, psk []byte) ([]byte, []byte, []byte, error) {
	if len(firstPacket) < 32 {
		return nil, nil, nil, fmt.Errorf("packet too short for handshake")
	}

	initiatorPub := firstPacket[:32]

	// Derive shared secret using X25519
	shared, err := curve25519.X25519(privKey, initiatorPub)
	if err != nil {
		return nil, nil, nil, err
	}

	// Generate responder ephemeral
	respPriv := make([]byte, 32)
	if _, err := rand.Read(respPriv); err != nil {
		return nil, nil, nil, err
	}
	respPub, err := curve25519.X25519(respPriv, curve25519.Basepoint)
	if err != nil {
		return nil, nil, nil, err
	}

	// Send response
	if _, err := conn.WriteToUDP(respPub, raddr); err != nil {
		return nil, nil, nil, err
	}

	return shared, respPub, respPub, nil
}

// ClientIK - deprecated, use ClientHandshake instead
// Kept for backward compatibility
func ClientIK(conn *net.UDPConn, raddr *net.UDPAddr, peerPubKey []byte, psk string) ([]byte, []byte, error) {
	return ClientHandshake(conn, raddr, peerPubKey, psk)
}

// ServerIKFromFirst - deprecated, use ServerHandshake instead
// Kept for backward compatibility
func ServerIKFromFirst(conn *net.UDPConn, privKey []byte, firstPacket []byte, raddr *net.UDPAddr, psk []byte) ([]byte, []byte, []byte, error) {
	return ServerHandshake(conn, privKey, firstPacket, raddr, psk)
}
