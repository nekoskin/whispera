package relay

import (
	"net"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/nekoskin/whispera/common/buf"
	logger "github.com/nekoskin/whispera/common/log"
	"github.com/nekoskin/whispera/core/protocol"
)

const migrateParkTTL = 10 * time.Second

const migrateCapDefault = 8 << 10

var migrateCap = migrateCapBytes()

func migrateCapBytes() int {
	if v := os.Getenv("WHISPERA_MIGRATE_CAP"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return n
		}
	}
	return migrateCapDefault
}

type segment struct {
	stream  *protocol.FramedConn
	release chan struct{}
}

type migFlow struct {
	resume chan segment
}

type flowTable struct {
	mu sync.Mutex
	m  map[string]*migFlow
}

func newFlowTable() *flowTable { return &flowTable{m: map[string]*migFlow{}} }

func flowKey(user string, token []byte) string { return user + "\x00" + string(token) }

func (t *flowTable) open(user string, token []byte) *migFlow {
	f := &migFlow{resume: make(chan segment)}
	t.mu.Lock()
	t.m[flowKey(user, token)] = f
	t.mu.Unlock()
	return f
}

func (t *flowTable) drop(user string, token []byte) {
	t.mu.Lock()
	delete(t.m, flowKey(user, token))
	t.mu.Unlock()
}

func (t *flowTable) get(user string, token []byte) *migFlow {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.m[flowKey(user, token)]
}

func (f *migFlow) handResume(stream *protocol.FramedConn) bool {
	seg := segment{stream: stream, release: make(chan struct{})}
	select {
	case f.resume <- seg:
		<-seg.release
		return true
	case <-time.After(migrateParkTTL):
		return false
	}
}

type migratingWriter struct {
	flow     *migFlow
	cur      segment
	released bool
	sent     int
}

func (w *migratingWriter) releaseCur() {
	if !w.released {
		close(w.cur.release)
		w.released = true
	}
}

func (w *migratingWriter) Write(b []byte) (int, error) {
	total := 0
	for len(b) > 0 {
		if w.sent >= migrateCap {
			if err := w.rotate(); err != nil {
				return total, err
			}
		}
		n := len(b)
		if room := migrateCap - w.sent; n > room {
			n = room
		}
		m, err := w.cur.stream.Write(b[:n])
		total += m
		w.sent += m
		if err != nil {
			w.releaseCur()
			return total, err
		}
		b = b[n:]
	}
	return total, nil
}

func (w *migratingWriter) rotate() error {
	err := w.cur.stream.Migrate()
	w.releaseCur()
	if err != nil {
		return err
	}
	select {
	case seg := <-w.flow.resume:
		w.cur = seg
		w.released = false
		w.sent = 0
		return nil
	case <-time.After(migrateParkTTL):
		logger.Trace().Infow("flow expired waiting for resume")
		return errFlowExpired
	}
}

func (w *migratingWriter) done() {
	_ = w.cur.stream.EndStream()
	w.releaseCur()
}

var errFlowExpired = &flowError{"migrating flow expired before the client resumed"}

type flowError struct{ msg string }

func (e *flowError) Error() string { return e.msg }

func (s *Server) serveMigratable(first *protocol.FramedConn, target net.Conn, user string, token []byte, firstRelease chan struct{}) {
	flow := s.flows.open(user, token)
	go func() {
		defer s.flows.drop(user, token)
		defer target.Close()

		w := &migratingWriter{flow: flow, cur: segment{stream: first, release: firstRelease}}

		done := make(chan struct{})
		go func() {
			_, _ = buf.Copy(buf.NewReader(first), buf.NewWriter(target))
			if tc, ok := target.(*net.TCPConn); ok {
				tc.CloseWrite()
			}
			close(done)
		}()

		if _, err := buf.Copy(buf.NewReader(target), buf.NewWriter(w)); err != nil {
			w.releaseCur()
		} else {
			w.done()
		}
		<-done
	}()
}

func (s *Server) resume(user string, token []byte, stream *protocol.FramedConn) bool {
	flow := s.flows.get(user, token)
	if flow == nil {
		return false
	}
	return flow.handResume(stream)
}
