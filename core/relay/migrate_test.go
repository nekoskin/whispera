package relay

import (
	"bytes"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/nekoskin/whispera/core/protocol"
)

func TestFlowTableOpenGetDrop(t *testing.T) {
	tbl := newFlowTable()
	tok := bytes.Repeat([]byte{1}, protocol.FlowTokenLen)
	f := tbl.open("alice", tok)
	if tbl.get("alice", tok) != f {
		t.Fatal("open flow not found")
	}
	if tbl.get("mallory", tok) != nil {
		t.Fatal("a flow must not be visible under another user")
	}
	tbl.drop("alice", tok)
	if tbl.get("alice", tok) != nil {
		t.Fatal("dropped flow still present")
	}
}

func framedPipe() (*protocol.FramedConn, net.Conn) {
	srv, cli := net.Pipe()
	return protocol.NewFramedConn(srv, protocol.NewShapeBudget()), cli
}

func readSegment(t *testing.T, cli net.Conn) ([]byte, bool) {
	t.Helper()
	fc := protocol.NewFramedConn(cli, protocol.NewShapeBudget())
	var got []byte
	buf := make([]byte, 4096)
	for {
		n, err := fc.Read(buf)
		got = append(got, buf[:n]...)
		if errors.Is(err, protocol.ErrMigrate) {
			return got, true
		}
		if err == io.EOF {
			return got, false
		}
		if err != nil {
			t.Fatalf("read segment: %v", err)
		}
	}
}

func TestMigratableDownloadSpreadsOverConnections(t *testing.T) {
	s := &Server{flows: newFlowTable()}
	user := "alice"
	token := bytes.Repeat([]byte{7}, protocol.FlowTokenLen)

	payload := bytes.Repeat([]byte("abcdefgh"), 5000)
	targetSrv, targetCli := net.Pipe()
	go func() {
		_, _ = io.Copy(targetCli, bytes.NewReader(payload))
		targetCli.Close()
	}()

	first, firstCli := framedPipe()
	release := make(chan struct{})
	s.serveMigratable(first, targetSrv, user, token, release)

	var got []byte
	cli := firstCli
	segments := 0
	for {
		seg, migrating := readSegment(t, cli)
		got = append(got, seg...)
		segments++
		if !migrating {
			cli.Close()
			break
		}
		cli.Close()
		srv2, cli2 := framedPipe()
		go func() {
			if !s.resume(user, token, srv2) {
				t.Errorf("resume refused")
			}
		}()
		cli = cli2
	}
	<-release

	if !bytes.Equal(got, payload) {
		t.Fatalf("got %d bytes, want %d", len(got), len(payload))
	}
	if segments < 2 {
		t.Fatalf("a 40KB download should have spread over several connections, used %d", segments)
	}
	deadline := time.Now().Add(2 * time.Second)
	for s.flows.get(user, token) != nil {
		if time.Now().After(deadline) {
			t.Fatal("flow should be dropped once the download finished")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestResumeRefusedForUnknownToken(t *testing.T) {
	s := &Server{flows: newFlowTable()}
	srv, _ := framedPipe()
	done := make(chan bool, 1)
	go func() { done <- s.resume("alice", bytes.Repeat([]byte{9}, protocol.FlowTokenLen), srv) }()
	select {
	case ok := <-done:
		if ok {
			t.Fatal("resume of an unknown token should be refused")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("resume of an unknown token should fail fast, not block")
	}
}
