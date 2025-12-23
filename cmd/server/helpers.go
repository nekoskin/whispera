package main

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

func normalizeListenAddr(addr string) string {
	if strings.HasPrefix(addr, ":") {
		return "0.0.0.0" + addr
	}
	return addr
}

type tlsErrorLogger struct {
	original io.Writer
}

func (f *tlsErrorLogger) Write(p []byte) (n int, err error) {
	msg := string(p)
	// Suppress common bot/scanner TLS errors - these are expected noise
	if strings.Contains(msg, "client sent an HTTP request to an HTTPS server") {
		return len(p), nil
	}
	if strings.Contains(msg, "first record does not look like a TLS handshake") {
		return len(p), nil
	}
	if strings.Contains(msg, ": EOF") || (strings.Contains(msg, "EOF") && strings.Contains(msg, "TLS")) {
		return len(p), nil
	}
	// Suppress TLS handshake errors from bots/scanners with incompatible configurations
	if strings.Contains(msg, "http: TLS handshake error") {
		// Подавляем все TLS handshake ошибки с EOF - это ожидаемо от ботов/сканеров
		if strings.Contains(msg, "EOF") {
			return len(p), nil
		}
		// Подавляем другие распространенные TLS handshake ошибки
		if strings.Contains(msg, "unknown certificate") ||
			strings.Contains(msg, "bad certificate") ||
			strings.Contains(msg, "certificate verify failed") ||
			strings.Contains(msg, "remote error: tls:") ||
			strings.Contains(msg, "unsupported application protocols") ||
			strings.Contains(msg, "unsupported versions") ||
			strings.Contains(msg, "no cipher suite supported") ||
			strings.Contains(msg, "client offered only unsupported versions") ||
			strings.Contains(msg, "client requested unsupported application protocols") ||
			strings.Contains(msg, "tls:") {
			return len(p), nil
		}
	}
	// Suppress generic TLS errors that are common from scanners
	if strings.Contains(msg, "tls:") && (strings.Contains(msg, "handshake") || strings.Contains(msg, "bad certificate") || strings.Contains(msg, "record")) {
		return len(p), nil
	}
	return f.original.Write(p)
}

type tlsErrorFilter struct {
	original io.Writer
}

func (f *tlsErrorFilter) Write(p []byte) (n int, err error) {
	msg := string(p)
	// Suppress common bot/scanner TLS errors - these are expected noise
	if strings.Contains(msg, "client sent an HTTP request to an HTTPS server") {
		return len(p), nil
	}
	if strings.Contains(msg, "first record does not look like a TLS handshake") {
		return len(p), nil
	}
	if strings.Contains(msg, ": EOF") || (strings.Contains(msg, "EOF") && strings.Contains(msg, "TLS")) {
		return len(p), nil
	}
	// Suppress TLS handshake errors from bots/scanners with incompatible configurations
	if strings.Contains(msg, "http: TLS handshake error") {
		// Подавляем все TLS handshake ошибки с EOF - это ожидаемо от ботов/сканеров
		if strings.Contains(msg, "EOF") {
			return len(p), nil
		}
		// Подавляем другие распространенные TLS handshake ошибки
		if strings.Contains(msg, "unknown certificate") ||
			strings.Contains(msg, "bad certificate") ||
			strings.Contains(msg, "certificate verify failed") ||
			strings.Contains(msg, "remote error: tls:") ||
			strings.Contains(msg, "unsupported application protocols") ||
			strings.Contains(msg, "unsupported versions") ||
			strings.Contains(msg, "no cipher suite supported") ||
			strings.Contains(msg, "client offered only unsupported versions") ||
			strings.Contains(msg, "client requested unsupported application protocols") ||
			strings.Contains(msg, "tls:") {
			return len(p), nil
		}
	}
	// Suppress generic TLS errors that are common from scanners
	if strings.Contains(msg, "tls:") && (strings.Contains(msg, "handshake") || strings.Contains(msg, "bad certificate") || strings.Contains(msg, "record")) {
		return len(p), nil
	}
	return f.original.Write(p)
}

type bufferedConn struct {
	net.Conn
	*bufio.Reader
}

func (bc *bufferedConn) Read(b []byte) (int, error) {
	return bc.Reader.Read(b)
}

type singleConnListener struct {
	conn net.Conn
	done chan struct{}
	once sync.Once
}

func (l *singleConnListener) Accept() (net.Conn, error) {
	var conn net.Conn
	l.once.Do(func() {
		conn = l.conn
		close(l.done)
	})
	if conn == nil {
		<-l.done
		return nil, io.EOF
	}
	return conn, nil
}

func (l *singleConnListener) Close() error {
	return nil
}

func (l *singleConnListener) Addr() net.Addr {
	return l.conn.LocalAddr()
}

func safeUint16(val int) (uint16, bool) {
	if val < 0 || val > 65535 {
		return 0, false
	}
	return uint16(val), true
}

func isMulticastOrBroadcast(ip net.IP) bool {
	if ip == nil {
		return false
	}
	if ip.To4() != nil {
		return ip[0] >= 224 && ip[0] <= 239 ||
			ip.Equal(net.IPv4bcast) ||
			ip.Equal(net.IPv4allsys) ||
			ip.Equal(net.IPv4allrouter)
	}
	if ip.To16() != nil {
		return len(ip) >= 1 && ip[0] == 0xff
	}
	return false
}

func ipv6PayloadOffset(ipPacket []byte) (int, uint8, bool) {
	if len(ipPacket) < 40 {
		return 0, 0, false
	}
	nextHeader := ipPacket[6]
	switch nextHeader {
	case 0, 43, 44, 50, 51, 60, 135, 139, 140, 59:
		return 0, 0, false
	default:
		return 40, nextHeader, true
	}
}

func getEnvOrDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func getEnvBool(key string, defaultValue bool) bool {
	if value := os.Getenv(key); value != "" {
		switch strings.ToLower(value) {
		case "1", "true", "yes", "on":
			return true
		case "0", "false", "no", "off":
			return false
		}
	}
	return defaultValue
}

func getEnvDuration(key string, defaultValue time.Duration) time.Duration {
	if value := os.Getenv(key); value != "" {
		if d, err := time.ParseDuration(value); err == nil {
			return d
		}
	}
	return defaultValue
}

func prefixToMask(prefix int) (string, error) {
	if prefix < 0 || prefix > 32 {
		return "", fmt.Errorf("invalid prefix: %d", prefix)
	}
	mask := ^uint32(0) << (32 - uint(prefix))
	parts := []string{
		strconv.Itoa(int((mask >> 24) & 0xFF)),
		strconv.Itoa(int((mask >> 16) & 0xFF)),
		strconv.Itoa(int((mask >> 8) & 0xFF)),
		strconv.Itoa(int(mask & 0xFF)),
	}
	return strings.Join(parts, "."), nil
}
