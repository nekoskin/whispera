package main

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

// torrentsim runs as a sink that swallows peer connections, or as a client that
// opens N connections through a SOCKS5 proxy and speaks the BitTorrent handshake
// on each, so the stand can watch how the server counts them.
func main() {
	switch os.Getenv("MODE") {
	case "sink":
		runSink()
	default:
		runClient()
	}
}

func runSink() {
	ln, err := net.Listen("tcp", os.Getenv("SINK_LISTEN"))
	if err != nil {
		fmt.Println("sink listen:", err)
		os.Exit(1)
	}
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		go io.Copy(io.Discard, conn)
	}
}

func runClient() {
	proxy := os.Getenv("SOCKS_ADDR")
	target := os.Getenv("TARGET")
	n, _ := strconv.Atoi(os.Getenv("COUNT"))
	if n == 0 {
		n = 1
	}
	held := make([]net.Conn, 0, n)
	for i := 0; i < n; i++ {
		conn, err := dialTorrent(proxy, target)
		if err != nil {
			fmt.Printf("connection %d failed: %v\n", i, err)
			continue
		}
		held = append(held, conn)
	}
	fmt.Printf("holding %d/%d torrent connections\n", len(held), n)
	if len(held) == 0 {
		os.Exit(1)
	}
	time.Sleep(time.Duration(envInt("HOLD_SECONDS", 30)) * time.Second)
	for _, c := range held {
		c.Close()
	}
}

func dialTorrent(proxy, target string) (net.Conn, error) {
	conn, err := net.DialTimeout("tcp", proxy, 5*time.Second)
	if err != nil {
		return nil, err
	}
	if err := socksConnect(conn, target); err != nil {
		conn.Close()
		return nil, err
	}
	if _, err := conn.Write(bitTorrentHandshake()); err != nil {
		conn.Close()
		return nil, err
	}
	return conn, nil
}

func socksConnect(conn net.Conn, target string) error {
	// Offer only no-auth so the proxy admits us without credentials.
	if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		return err
	}
	reply := make([]byte, 2)
	if _, err := io.ReadFull(conn, reply); err != nil {
		return err
	}
	if reply[1] != 0x00 {
		return fmt.Errorf("proxy refused no-auth: %x", reply[1])
	}

	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		return err
	}
	port, _ := strconv.Atoi(portStr)
	req := []byte{0x05, 0x01, 0x00, 0x03, byte(len(host))}
	req = append(req, host...)
	req = binary.BigEndian.AppendUint16(req, uint16(port))
	if _, err := conn.Write(req); err != nil {
		return err
	}
	resp := make([]byte, 4)
	if _, err := io.ReadFull(conn, resp); err != nil {
		return err
	}
	if resp[1] != 0x00 {
		return fmt.Errorf("connect failed: %x", resp[1])
	}
	// Drain the bound address so the stream is left at the payload.
	switch resp[3] {
	case 0x01:
		io.ReadFull(conn, make([]byte, 4+2))
	case 0x04:
		io.ReadFull(conn, make([]byte, 16+2))
	case 0x03:
		l := make([]byte, 1)
		io.ReadFull(conn, l)
		io.ReadFull(conn, make([]byte, int(l[0])+2))
	}
	return nil
}

func bitTorrentHandshake() []byte {
	b := append([]byte{0x13}, []byte("BitTorrent protocol")...)
	b = append(b, make([]byte, 8)...)
	b = append(b, []byte(strings.Repeat("i", 20))...)
	b = append(b, []byte(strings.Repeat("p", 20))...)
	return b
}

func envInt(name string, def int) int {
	if v, err := strconv.Atoi(os.Getenv(name)); err == nil {
		return v
	}
	return def
}
