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
		if err := writeFragmentedTLSRecord(conn, record, fragmentPlan{size: 40, maxRecords: defaultMaxHelloRecords}); err != nil {
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
		if len(conn.records) > defaultMaxHelloRecords {
			t.Fatalf("padding=%d: %d records, budget is %d", padding, len(conn.records), defaultMaxHelloRecords)
		}
	}
}

func TestFragmentRespectsRecordBudget(t *testing.T) {
	record, _, _ := buildClientHello("www.google.com", 1600)
	want := record[5:]
	for budget := 1; budget <= defaultMaxHelloRecords; budget++ {
		for attempt := 0; attempt < 200; attempt++ {
			conn := &captureConn{}
			if err := writeFragmentedTLSRecord(conn, record, fragmentPlan{size: 40, maxRecords: budget}); err != nil {
				t.Fatalf("budget=%d: %v", budget, err)
			}
			if len(conn.records) > budget {
				t.Fatalf("budget=%d: wrote %d records", budget, len(conn.records))
			}
			if budget == 1 && len(conn.records) != 1 {
				t.Fatalf("a budget of one must leave in one record, got %d", len(conn.records))
			}
			var got []byte
			for i, r := range conn.records {
				if len(r) < 5 {
					t.Fatalf("budget=%d: record %d is shorter than a header", budget, i)
				}
				if int(binary.BigEndian.Uint16(r[3:5])) != len(r)-5 {
					t.Fatalf("budget=%d: record %d header says %d, body is %d",
						budget, i, binary.BigEndian.Uint16(r[3:5]), len(r)-5)
				}
				got = append(got, r[5:]...)
			}
			if !bytes.Equal(got, want) {
				t.Fatalf("budget=%d: reassembled %d bytes, hello is %d", budget, len(got), len(want))
			}
		}
	}
}
