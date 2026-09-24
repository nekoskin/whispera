// A legitimate browser on the stand: it opens ordinary TLS to the censor with a
// real uTLS browser fingerprint and no tunnel. It exists so the censor's JA3 of
// this client equals the JA3 of a tunnel dialing with the same preset — which
// is the whole point of replication. Banning that hash then takes this browser
// too, and a rule with that collateral is one a real operator has to withdraw.
package main

import (
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
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

func presetByName(name string) utls.ClientHelloID {
	if id, ok := presets[name]; ok {
		return id
	}
	return utls.HelloChrome_Auto
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
	// A real browser would speak HTTP now; a tiny request is enough for the
	// censor to have judged the hello, which is all this measures.
	fmt.Fprintf(u, "GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", sni)
	buf := make([]byte, 512)
	_, _ = u.Read(buf)
	io.Copy(io.Discard, u)
	return true, nil
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
	if fp == "" {
		fp = "chrome"
	}
	id := presetByName(fp)

	slot := claimSlot(envInt("LEGIT_USERS", 1))
	every := time.Duration(envInt("LEGIT_EVERY", 1)) * time.Second
	deadline := time.Now().Add(time.Duration(envInt("RUN_SECONDS", 120)) * time.Second)

	out, err := os.Create(fmt.Sprintf("/out/legit-%d.csv", slot))
	if err != nil {
		fmt.Fprintln(os.Stderr, "legit: cannot open output:", err)
		os.Exit(1)
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
		fmt.Fprintf(out, "%d,%s,%s\n", time.Now().Unix(), code, fp)
		out.Sync()
		time.Sleep(every)
	}
	os.WriteFile(fmt.Sprintf("/out/legit-%d.finished", slot), []byte("done\n"), 0o644)
}
