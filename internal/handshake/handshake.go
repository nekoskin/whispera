package handshake

import (
	"crypto/rand"
	"fmt"
	"net"
	"time"

	"golang.org/x/crypto/curve25519"
)

func ClientHandshake(conn *net.UDPConn, raddr *net.UDPAddr, peerPubKey []byte, psk string) ([]byte, []byte, error) {
	if len(peerPubKey) != 32 {
		return nil, nil, fmt.Errorf("invalid peer public key length")
	}

	ephPriv := make([]byte, 32)
	if _, err := rand.Read(ephPriv); err != nil {
		return nil, nil, err
	}
	ephPub, err := curve25519.X25519(ephPriv, curve25519.Basepoint)
	if err != nil {
		return nil, nil, err
	}

	if _, err := conn.WriteToUDP(ephPub, raddr); err != nil {
		return nil, nil, err
	}

	buf := make([]byte, 64)
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, _, err := conn.ReadFromUDP(buf)
	if err != nil {
		return nil, nil, err
	}

	shared, err := curve25519.X25519(ephPriv, peerPubKey)
	if err != nil {
		return nil, nil, err
	}

	return shared, buf[:n], nil
}

func ServerHandshake(conn *net.UDPConn, privKey []byte, firstPacket []byte, raddr *net.UDPAddr, psk []byte) ([]byte, []byte, []byte, error) {
	if len(firstPacket) < 32 {
		return nil, nil, nil, fmt.Errorf("packet too short for handshake")
	}

	initiatorPub := firstPacket[:32]

	shared, err := curve25519.X25519(privKey, initiatorPub)
	if err != nil {
		return nil, nil, nil, err
	}

	respPriv := make([]byte, 32)
	if _, err := rand.Read(respPriv); err != nil {
		return nil, nil, nil, err
	}
	respPub, err := curve25519.X25519(respPriv, curve25519.Basepoint)
	if err != nil {
		return nil, nil, nil, err
	}

	if _, err := conn.WriteToUDP(respPub, raddr); err != nil {
		return nil, nil, nil, err
	}

	return shared, respPub, respPub, nil
}

func ClientIK(conn *net.UDPConn, raddr *net.UDPAddr, peerPubKey []byte, psk string) ([]byte, []byte, error) {
	return ClientHandshake(conn, raddr, peerPubKey, psk)
}
func ServerIKFromFirst(conn *net.UDPConn, privKey []byte, firstPacket []byte, raddr *net.UDPAddr, psk []byte) ([]byte, []byte, []byte, error) {
	return ServerHandshake(conn, privKey, firstPacket, raddr, psk)
}
