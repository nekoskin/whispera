package main

import (
	"testing"
	"time"
)

func rec(typ byte, size int) []byte {
	out := []byte{typ, 0x03, 0x03, byte(size >> 8), byte(size)}
	return append(out, make([]byte, size)...)
}

func TestScannerSplitsRecordsAcrossReads(t *testing.T) {
	stream := append(rec(0x16, 100), rec(appData, 517)...)
	var s tlsScanner
	got := s.push(stream[:60])
	if len(got) != 0 {
		t.Fatalf("a partial record yielded %d records", len(got))
	}
	got = s.push(stream[60:])
	if len(got) != 2 || got[0].typ != 0x16 || got[1].typ != appData || got[1].size != 517 {
		t.Fatalf("records not reassembled: %+v", got)
	}
}

func TestEncapsulatedHandshakeIsFlagged(t *testing.T) {
	w := newHSWatch()
	w.feedUp(rec(appData, 53))
	w.feedDown(rec(appData, 2350))
	w.feedUp(rec(appData, 497))
	time.Sleep(2 * time.Millisecond)
	w.feedDown(rec(appData, 1203))
	w.feedDown(rec(appData, 2389))
	if !w.encapsulatedLocked() {
		t.Fatalf("a hello-sized upstream record answered by a burst must flag: %s", w.report())
	}
}

func TestPlainTransferIsNotFlagged(t *testing.T) {
	w := newHSWatch()
	for _, s := range []int{53, 118, 26, 43, 43, 19} {
		w.feedUp(rec(appData, s))
	}
	for _, s := range []int{36, 367, 97, 53, 139, 62, 30, 26} {
		w.feedDown(rec(appData, s))
	}
	if w.encapsulatedLocked() || w.splitLocked() {
		t.Fatalf("a plain single TLS opening must not flag: %s", w.report())
	}
}

func TestReshapedHelloIsStillFlagged(t *testing.T) {
	w := newHSWatch()
	w.feedUp(rec(appData, 53))
	w.feedDown(rec(appData, 2350))
	for _, s := range []int{31, 40, 53, 64, 71, 96, 110, 118, 130, 96, 71, 53} {
		w.feedUp(rec(appData, s))
	}
	time.Sleep(2 * time.Millisecond)
	w.feedDown(rec(appData, 1800))
	w.feedDown(rec(appData, 2100))
	if w.encapsulatedLocked() {
		t.Fatalf("a hello chopped into many records is not a lone hello: %s", w.report())
	}
	if !w.splitLocked() {
		t.Fatalf("chopping the hello into small records must not evade detection: %s", w.report())
	}
}

func TestChoppedHelloIsFlaggedBySplit(t *testing.T) {
	w := newHSWatch()
	w.feedUp(rec(appData, 53))
	w.feedDown(rec(appData, 2350))
	w.feedUp(rec(appData, 256))
	w.feedUp(rec(appData, 248))
	time.Sleep(2 * time.Millisecond)
	w.feedDown(rec(appData, 1500))
	if w.encapsulatedLocked() {
		t.Fatalf("the lone-hello rule should not fire on a split: %s", w.report())
	}
	if !w.splitLocked() {
		t.Fatalf("a run of medium records answered by a burst is a chopped hello: %s", w.report())
	}
}
