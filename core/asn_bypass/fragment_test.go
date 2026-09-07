package asn_bypass

import (
	"bytes"
	"encoding/binary"
	"net"
	"testing"
)

type captureConn struct {
	net.Conn
	records [][]byte
}

func (c *captureConn) Write(p []byte) (int, error) {
	c.records = append(c.records, append([]byte(nil), p...))
	return len(p), nil
}

func buildClientHello(host string, padding int) ([]byte, int, int) {
	var ext bytes.Buffer
	ext.Write([]byte{0x00, 0x00})
	binary.Write(&ext, binary.BigEndian, uint16(5+len(host)))
	binary.Write(&ext, binary.BigEndian, uint16(3+len(host)))
	ext.WriteByte(0x00)
	binary.Write(&ext, binary.BigEndian, uint16(len(host)))
	sniInExt := ext.Len()
	ext.WriteString(host)

	if padding > 0 {
		ext.Write([]byte{0x00, 0x15})
		binary.Write(&ext, binary.BigEndian, uint16(padding))
		ext.Write(make([]byte, padding))
	}

	var body bytes.Buffer
	body.Write([]byte{0x03, 0x03})
	body.Write(make([]byte, 32))
	body.WriteByte(0x00)
	binary.Write(&body, binary.BigEndian, uint16(2))
	body.Write([]byte{0x13, 0x01})
	body.WriteByte(0x01)
	body.WriteByte(0x00)
	binary.Write(&body, binary.BigEndian, uint16(ext.Len()))
	extAt := body.Len()
	body.Write(ext.Bytes())

	hs := make([]byte, 4, 4+body.Len())
	hs[0] = 0x01
	hs[1] = byte(body.Len() >> 16)
	hs[2] = byte(body.Len() >> 8)
	hs[3] = byte(body.Len())
	hs = append(hs, body.Bytes()...)

	rec := make([]byte, 5, 5+len(hs))
	rec[0] = 0x16
	rec[1] = 0x03
	rec[2] = 0x01
	binary.BigEndian.PutUint16(rec[3:], uint16(len(hs)))
	rec = append(rec, hs...)

	sniStart := 4 + extAt + sniInExt
	return rec, sniStart, sniStart + len(host)
}

func TestFragmentSplitsSNI(t *testing.T) {
	for _, padding := range []int{0, 1600} {
		record, sniStart, sniEnd := buildClientHello("www.google.com", padding)
		conn := &captureConn{}
		if err := writeFragmentedTLSRecord(conn, record, 40); err != nil {
			t.Fatalf("padding=%d: %v", padding, err)
		}

		at, split := 0, false
		for i, r := range conn.records {
			if len(r) < 5 {
				t.Fatalf("padding=%d: record %d is shorter than a header", padding, i)
			}
			at += len(r) - 5
			if at > sniStart && at < sniEnd {
				split = true
			}
		}
		if !split {
			t.Fatalf("padding=%d: no record boundary landed inside the SNI (%d..%d), records %d",
				padding, sniStart, sniEnd, len(conn.records))
		}
		if len(conn.records) > maxHelloRecords+1 {
			t.Fatalf("padding=%d: %d records, budget is %d", padding, len(conn.records), maxHelloRecords+1)
		}
	}
}
