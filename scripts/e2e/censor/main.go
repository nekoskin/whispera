package main

import (
	"encoding/binary"
	"io"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

type window struct{ lo, hi int }

var (
	mu      sync.RWMutex
	current window
	cycle   = []window{{0, 0}, {16400, 17000}, {15000, 16399}, {0, 0}, {17001, 20000}}
)

func rotate(every time.Duration) {
	i := 0
	for {
		mu.Lock()
		current = cycle[i%len(cycle)]
		w := current
		mu.Unlock()
		if w.lo == 0 && w.hi == 0 {
			log.Printf("rule: pass everything")
		} else {
			log.Printf("rule: drop flows whose first data record is %d..%d", w.lo, w.hi)
		}
		i++
		time.Sleep(every)
	}
}

func blocked(size int) bool {
	mu.RLock()
	w := current
	mu.RUnlock()
	return w.hi > 0 && size >= w.lo && size <= w.hi
}

func firstDataRecord(head []byte) (int, bool) {
	for len(head) >= 5 {
		n := int(binary.BigEndian.Uint16(head[3:5]))
		if head[0] == 0x17 {
			return n, true
		}
		if len(head) < 5+n {
			return 0, false
		}
		head = head[5+n:]
	}
	return 0, false
}

func pipe(dst, src net.Conn, wg *sync.WaitGroup) {
	defer wg.Done()
	io.Copy(dst, src)
	if c, ok := dst.(*net.TCPConn); ok {
		c.CloseWrite()
	}
}

func handle(c net.Conn, upstream string) {
	defer c.Close()
	up, err := net.DialTimeout("tcp", upstream, 5*time.Second)
	if err != nil {
		log.Printf("upstream dial failed: %v", err)
		return
	}
	defer up.Close()

	var wg sync.WaitGroup
	wg.Add(1)
	go pipe(c, up, &wg)

	buf := make([]byte, 0, 64<<10)
	tmp := make([]byte, 32<<10)
	deadline := time.Now().Add(20 * time.Second)
	c.SetReadDeadline(deadline)
	for {
		n, err := c.Read(tmp)
		if n > 0 {
			buf = append(buf, tmp[:n]...)
			if _, werr := up.Write(tmp[:n]); werr != nil {
				return
			}
			if size, ok := firstDataRecord(buf); ok {
				if blocked(size) {
					log.Printf("DROP  first data record %d bytes", size)
					if tc, ok := c.(*net.TCPConn); ok {
						tc.SetLinger(0)
					}
					return
				}
				log.Printf("PASS  first data record %d bytes", size)
				break
			}
		}
		if err != nil {
			return
		}
		if time.Now().After(deadline) {
			break
		}
	}
	c.SetReadDeadline(time.Time{})

	wg.Add(1)
	go pipe(up, c, &wg)
	wg.Wait()
}

func main() {
	listen := os.Getenv("CENSOR_LISTEN")
	if listen == "" {
		listen = ":8443"
	}
	upstream := os.Getenv("CENSOR_UPSTREAM")
	if upstream == "" {
		upstream = "server:443"
	}
	every := 20 * time.Second
	if v := os.Getenv("CENSOR_ROTATE"); v != "" {
		if secs, err := strconv.Atoi(strings.TrimSuffix(v, "s")); err == nil {
			every = time.Duration(secs) * time.Second
		}
	}

	go rotate(every)

	ln, err := net.Listen("tcp", listen)
	if err != nil {
		log.Fatalf("listen: %v", err)
	}
	log.Printf("censor on %s -> %s, rule rotates every %s", listen, upstream, every)
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		go handle(c, upstream)
	}
}
