package main

import (
	"net"
	"testing"
	"time"
)

type addrConn struct {
	net.Conn
	addr net.Addr
}

func (c addrConn) RemoteAddr() net.Addr { return c.addr }

func from(ip string) net.Conn {
	return addrConn{addr: &net.TCPAddr{IP: net.ParseIP(ip), Port: 40000}}
}

func TestBurstFreezesTheThirdHello(t *testing.T) {
	b := newBurstJudge()
	c := from("10.0.0.2")
	now := time.Now()
	for i := 0; i < b.count-1; i++ {
		if ok, why := b.admit(c, "chrome", now.Add(time.Duration(i)*time.Millisecond)); !ok {
			t.Fatalf("hello %d frozen too early: %s", i, why)
		}
	}
	if ok, _ := b.admit(c, "chrome", now.Add(10*time.Millisecond)); ok {
		t.Fatal("the hello completing a burst should be frozen")
	}
	if ok, _ := b.admit(from("10.0.0.3"), "chrome", now.Add(11*time.Millisecond)); !ok {
		t.Fatal("another client is not part of this burst")
	}
	if ok, _ := b.admit(c, "chrome", now.Add(b.freeze+b.window+time.Second)); !ok {
		t.Fatal("the freeze should lift")
	}
}

func TestBurstEscalatesWhenTheFingerprintChanges(t *testing.T) {
	b := newBurstJudge()
	c := from("10.0.0.2")
	now := time.Now()
	for i := 0; i < b.count; i++ {
		b.admit(c, "chrome", now)
	}
	later := now.Add(time.Second)
	if ok, _ := b.admit(c, "firefox", later); ok {
		t.Fatal("a frozen client should stay frozen")
	}
	if ok, _ := b.admit(c, "firefox", now.Add(b.freeze+time.Second)); ok {
		t.Fatal("changing the fingerprint while frozen should extend the freeze")
	}
	if ok, _ := b.admit(c, "firefox", later.Add(b.escalate+time.Second)); !ok {
		t.Fatal("the extended freeze should still lift")
	}
}

func TestBurstSparesFingerprintsNotHeld(t *testing.T) {
	b := newBurstJudge()
	b.held["chrome"] = true
	c := from("10.0.0.2")
	now := time.Now()
	for i := 0; i < 2*b.count; i++ {
		if ok, _ := b.admit(c, "firefox", now); !ok {
			t.Fatal("a fingerprint that is not held should pass a burst")
		}
	}
}
