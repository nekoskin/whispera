package main

import (
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"sync"
	"time"

	utls "github.com/refraction-networking/utls"
)

var presets = map[string]utls.ClientHelloID{
	"chrome":  utls.HelloChrome_Auto,
	"firefox": utls.HelloFirefox_Auto,
	"safari":  utls.HelloSafari_Auto,
	"ios":     utls.HelloIOS_Auto,
	"edge":    utls.HelloEdge_Auto,
}

var mix = []string{"chrome", "firefox", "safari", "edge", "ios"}

func presetByName(name string) utls.ClientHelloID {
	if id, ok := presets[name]; ok {
		return id
	}
	return utls.HelloChrome_Auto
}

func browserFor(fp string, n int) string {
	switch fp {
	case "":
		return "chrome"
	case "mix":
		return mix[n%len(mix)]
	default:
		return fp
	}
}

func claimSlot(users int) int {
	for i := 1; i <= users; i++ {
		if err := os.Mkdir(fmt.Sprintf("/cfg/legit-slot-%d", i), 0o755); err == nil {
			return i
		}
	}
	return 1
}

func envInt(name string, def int) int {
	if v := os.Getenv(name); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}

func dialOnce(addr, sni string, id utls.ClientHelloID) (bool, error) {
	raw, err := net.DialTimeout("tcp", addr, 8*time.Second)
	if err != nil {
		return false, err
	}
	defer raw.Close()
	raw.SetDeadline(time.Now().Add(8 * time.Second))

	u := utls.UClient(raw, &utls.Config{ServerName: sni, InsecureSkipVerify: true}, id)
	if err := u.Handshake(); err != nil {
		return false, err
	}
	fmt.Fprintf(u, "GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", sni)
	buf := make([]byte, 512)
	_, _ = u.Read(buf)
	io.Copy(io.Discard, u)
	return true, nil
}

func neighbor(tag, addr, sni, browser string, every time.Duration, deadline time.Time) {
	id := presetByName(browser)
	out, err := os.Create(fmt.Sprintf("/out/legit-%s.csv", tag))
	if err != nil {
		fmt.Fprintln(os.Stderr, "legit: cannot open output:", err)
		return
	}
	defer out.Close()
	fmt.Fprintln(out, "ts,ok,fp")

	for time.Now().Before(deadline) {
		ok, derr := dialOnce(addr, sni, id)
		code := "ok"
		if !ok {
			code = "fail"
			_ = derr
		}
		fmt.Fprintf(out, "%d,%s,%s\n", time.Now().Unix(), code, browser)
		out.Sync()
		time.Sleep(every)
	}
	os.WriteFile(fmt.Sprintf("/out/legit-%s.finished", tag), []byte("done\n"), 0o644)
}

func main() {
	addr := os.Getenv("LEGIT_ADDR")
	if addr == "" {
		addr = "censor:8443"
	}
	sni := os.Getenv("LEGIT_SNI")
	if sni == "" {
		sni = "www.google.com"
	}
	fp := os.Getenv("LEGIT_FP")

	base := claimSlot(envInt("LEGIT_USERS", 1))
	conc := envInt("LEGIT_CONC", 1)
	every := time.Duration(envInt("LEGIT_EVERY", 1)) * time.Second
	deadline := time.Now().Add(time.Duration(envInt("RUN_SECONDS", 120)) * time.Second)

	var wg sync.WaitGroup
	for w := 0; w < conc; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			tag := fmt.Sprintf("%d", base)
			if conc > 1 {
				tag = fmt.Sprintf("%d-%d", base, w+1)
			}
			neighbor(tag, addr, sni, browserFor(fp, base+w), every, deadline)
		}(w)
	}
	wg.Wait()
}
