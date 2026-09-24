package asn_bypass

import (
	"testing"
	"time"
)

func TestFragmentPauseIsSkippedWhenZero(t *testing.T) {
	start := time.Now()
	for i := 0; i < 8; i++ {
		fragmentPause(0, 0)
	}
	if elapsed := time.Since(start); elapsed > 2*time.Millisecond {
		t.Fatalf("a zero pause still waited %v", elapsed)
	}
}

func TestFragmentedWriteWithoutPauseIsFast(t *testing.T) {
	hello, _, _ := buildClientHello("www.example.com", 512)
	conn := &captureConn{}

	start := time.Now()
	if err := writeFragmentedTLSRecord(conn, hello, fragmentPlan{size: defaultFragSize, maxRecords: defaultMaxHelloRecords}); err != nil {
		t.Fatal(err)
	}
	if elapsed := time.Since(start); elapsed > 5*time.Millisecond {
		t.Fatalf("splitting without a pause took %v", elapsed)
	}
	if len(conn.records) < 2 {
		t.Fatalf("hello was not split: %d records", len(conn.records))
	}
}

func TestFragmentCountIsHonoured(t *testing.T) {
	hello, _, _ := buildClientHello("www.example.com", 512)
	for _, limit := range []int{2, 3, 8} {
		conn := &captureConn{}
		plan := fragmentPlan{size: defaultFragSize, maxRecords: limit}
		if err := writeFragmentedTLSRecord(conn, hello, plan); err != nil {
			t.Fatal(err)
		}
		if len(conn.records) > limit+1 {
			t.Errorf("limit %d produced %d records", limit, len(conn.records))
		}
		if len(conn.records) < 2 {
			t.Errorf("limit %d did not split the hello at all", limit)
		}
	}
}
