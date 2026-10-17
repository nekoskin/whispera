package main

import (
	"net"
	"testing"
	"time"
)

func splitIntoRecords(hello []byte, parts int) [][]byte {
	payload := hello[5:]
	size := (len(payload) + parts - 1) / parts
	var out [][]byte
	for len(payload) > 0 {
		n := size
		if n > len(payload) {
			n = len(payload)
		}
		rec := []byte{0x16, 0x03, 0x03, byte(n >> 8), byte(n)}
		out = append(out, append(rec, payload[:n]...))
		payload = payload[n:]
	}
	return out
}

func serveRecords(t *testing.T, records [][]byte) net.Conn {
	t.Helper()
	client, server := net.Pipe()
	go func() {
		defer client.Close()
		for _, rec := range records {
			if _, err := client.Write(rec); err != nil {
				return
			}
		}
	}()
	return server
}

func readFirst(t *testing.T, c net.Conn) []byte {
	t.Helper()
	buf := make([]byte, 32<<10)
	n, err := c.Read(buf)
	if err != nil {
		t.Fatalf("first read: %v", err)
	}
	return buf[:n]
}

func TestReassembleRecoversFingerprintOfSplitHello(t *testing.T) {
	hello := helloWithExtOrder([]int{0x0000, 0x000a, 0x000b, 0x000d, 0x0010, 0x002b})
	want, ok := ja4(hello)
	if !ok {
		t.Fatal("ja4 failed on the whole hello")
	}

	records := splitIntoRecords(hello, 8)
	if _, ok := ja4(records[0]); ok {
		t.Fatal("the first record alone parsed, so the split proves nothing")
	}

	c := serveRecords(t, records)
	defer c.Close()
	first := readFirst(t, c)

	raw, whole, reads := reassembleHello(c, first)
	if whole == nil {
		t.Fatal("hello was not reassembled")
	}
	got, ok := ja4(whole)
	if !ok || got != want {
		t.Fatalf("reassembled ja4 %q, want %q", got, want)
	}
	if reads != len(records) {
		t.Fatalf("counted %d reads, want %d", reads, len(records))
	}
	var sent int
	for _, rec := range records {
		sent += len(rec)
	}
	if len(raw) != sent {
		t.Fatalf("forwarded %d bytes, want the %d the client sent", len(raw), sent)
	}
}

func TestReassembleLeavesWholeHelloAlone(t *testing.T) {
	hello := helloWithExtOrder([]int{0x0000, 0x000a, 0x000b, 0x000d, 0x0010, 0x002b})
	c := serveRecords(t, [][]byte{hello})
	defer c.Close()
	first := readFirst(t, c)

	raw, whole, reads := reassembleHello(c, first)
	if whole == nil || reads != 1 {
		t.Fatalf("whole hello: reads %d, reassembled %v", reads, whole != nil)
	}
	if len(raw) != len(hello) {
		t.Fatalf("forwarded %d bytes, want %d", len(raw), len(hello))
	}
}

func TestReassembleIgnoresNonHello(t *testing.T) {
	c := serveRecords(t, [][]byte{[]byte("GET / HTTP/1.1\r\n\r\n")})
	defer c.Close()
	first := readFirst(t, c)

	start := time.Now()
	_, whole, reads := reassembleHello(c, first)
	if whole != nil || reads != 1 {
		t.Fatalf("plain HTTP treated as a hello: reads %d, reassembled %v", reads, whole != nil)
	}
	if time.Since(start) > time.Second {
		t.Fatal("waited for more data on a first packet that is not a hello")
	}
}

func TestReassembleGivesUpOnTruncatedHello(t *testing.T) {
	saved := reassembleWait
	reassembleWait = 50 * time.Millisecond
	defer func() { reassembleWait = saved }()

	hello := helloWithExtOrder([]int{0x0000, 0x000a, 0x000b, 0x000d, 0x0010, 0x002b})
	records := splitIntoRecords(hello, 4)
	c := serveRecords(t, records[:2])
	defer c.Close()
	first := readFirst(t, c)

	raw, whole, _ := reassembleHello(c, first)
	if whole != nil {
		t.Fatal("a truncated hello was reported whole")
	}
	if len(raw) != len(records[0])+len(records[1]) {
		t.Fatalf("forwarded %d bytes, want the two records that arrived", len(raw))
	}
}

func TestReassembleStopsOnForeignRecord(t *testing.T) {
	hello := helloWithExtOrder([]int{0x0000, 0x000a, 0x000b, 0x000d, 0x0010, 0x002b})
	records := splitIntoRecords(hello, 4)
	foreign := []byte{0x17, 0x03, 0x03, 0x00, 0x02, 0xaa, 0xbb}
	c := serveRecords(t, [][]byte{records[0], foreign})
	defer c.Close()
	first := readFirst(t, c)

	start := time.Now()
	_, whole, _ := reassembleHello(c, first)
	if whole != nil {
		t.Fatal("a stream with an application-data record was reported as a hello")
	}
	if time.Since(start) > time.Second {
		t.Fatal("kept waiting after a record that cannot belong to a hello")
	}
}
