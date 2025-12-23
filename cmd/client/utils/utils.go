package main

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"math"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

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

func configureWindowsRoutes(tunName string, serverIP string, tunIP string, tunGateway string, tunPrefix int) error {
	mask, err := prefixToMask(tunPrefix)
	if err != nil {
		return err
	}

	run := func(args ...string) error {
		cmd := exec.Command(args[0], args[1:]...)
		output, err := cmd.CombinedOutput()
		if err != nil && len(output) > 0 {
			return fmt.Errorf("%s: %w: %s", strings.Join(args, " "), err, string(output))
		}
		return err
	}

	if err := run("netsh", "interface", "ipv4", "set", "address",
		"name="+strconv.Quote(tunName),
		"source=static",
		"address="+tunIP,
		"mask="+mask,
		"gateway="+tunGateway,
		"store=active",
	); err != nil {
		return err
	}

	if err := run("netsh", "interface", "ipv4", "set", "dnsservers",
		"name="+strconv.Quote(tunName),
		"source=static",
		"address="+tunGateway,
		"register=primary",
		"validate=no",
	); err != nil {
		return err
	}

	if err := run("netsh", "interface", "ipv4", "set", "interface", tunName, "metric=5"); err != nil {
		return err
	}

	if serverIP != "" {
		if err := run("route", "add", serverIP, "mask", "255.255.255.255", tunGateway, "metric", "1"); err != nil {
			return err
		}
	}

	if err := run("route", "add", "0.0.0.0", "mask", "0.0.0.0", tunGateway, "metric", "1"); err != nil {
		if !strings.Contains(err.Error(), "The route addition failed") {
			return err
		}
	}

	return nil
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

func randUint32() uint32 {
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		log.Printf("Warning: failed to generate random uint32, using fallback: %v", err)
		nanos := time.Now().UnixNano()
		if nanos < 0 || nanos > math.MaxUint32 {
			nanos %= (math.MaxUint32 + 1)
			if nanos < 0 {
				nanos += math.MaxUint32 + 1
			}
		}
		return uint32(nanos)
	}
	return binary.BigEndian.Uint32(b[:])
}

func safeUint16(val int) (uint16, bool) {
	if val < 0 || val > math.MaxUint16 {
		return 0, false
	}
	return uint16(val), true
}

func writeFrame(w net.Conn, b []byte) error {
	var hdr [2]byte
	payloadLen, ok := safeUint16(len(b))
	if !ok {
		return errors.New("frame too large")
	}
	binary.BigEndian.PutUint16(hdr[:], payloadLen)
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	_, err := w.Write(b)
	return err
}

func readFrame(r net.Conn) ([]byte, error) {
	var hdr [2]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	n := int(binary.BigEndian.Uint16(hdr[:]))
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

func FindFreePort(startPort int) (int, error) {
	for port := startPort; port < startPort+10; port++ {
		addr, err := net.ResolveTCPAddr("tcp", fmt.Sprintf("127.0.0.1:%d", port))
		if err != nil {
			continue
		}
		listener, err := net.ListenTCP("tcp", addr)
		if err != nil {
			continue
		}
		listener.Close()
		return port, nil
	}
	return 0, errors.New("no free port found")
}
