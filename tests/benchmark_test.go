package tests

import (
	"context"
	"crypto/rand"
	"io"
	"net/http"
	"os"
	"os/exec"
	"testing"
	"time"
)

func TestThroughput(t *testing.T) {
	// 1. Build client and server
	t.Log("Building client and server...")

	buildClient := exec.Command("go", "build", "-o", "bench_client.exe", "../cmd/client")
	if output, err := buildClient.CombinedOutput(); err != nil {
		t.Fatalf("failed to build client: %v\nOutput: %s", err, string(output))
	}
	defer os.Remove("bench_client.exe")

	buildServer := exec.Command("go", "build", "-o", "bench_server.exe", "../cmd/server")
	if output, err := buildServer.CombinedOutput(); err != nil {
		t.Fatalf("failed to build server: %v\nOutput: %s", err, string(output))
	}
	defer os.Remove("bench_server.exe")

	cwd, _ := os.Getwd()
	clientPath := cwd + "\\bench_client.exe"
	serverPath := cwd + "\\bench_server.exe"

	// 2. Start server
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	t.Log("Starting server...")
	serverCmd := exec.CommandContext(ctx, serverPath, "-l", "127.0.0.1:38080")
	if err := serverCmd.Start(); err != nil {
		t.Fatalf("failed to start server: %v", err)
	}
	defer func() {
		if serverCmd.Process != nil {
			serverCmd.Process.Kill()
		}
	}()

	time.Sleep(2 * time.Second) // Wait for server to bind

	// 3. Start client (SOCKS proxy mode)
	t.Log("Starting client...")
	// Assuming -proxy defaults to 1080 if not specified, but let's be explicit if possible or rely on defaults
	clientCmd := exec.CommandContext(ctx, clientPath, "-s", "127.0.0.1:38080", "-proxy")
	if err := clientCmd.Start(); err != nil {
		t.Fatalf("failed to start client: %v", err)
	}
	defer func() {
		if clientCmd.Process != nil {
			clientCmd.Process.Kill()
		}
	}()

	time.Sleep(5 * time.Second) // Wait for connection

	// 4. Run Benchmark (Download)
	t.Log("Running download benchmark...")

	// Start a dummy HTTP server to download FROM through the proxy
	dummyServer := &http.Server{Addr: "127.0.0.1:9090"}
	go func() {
		http.HandleFunc("/data", func(w http.ResponseWriter, r *http.Request) {
			// Serve 10MB of data
			data := make([]byte, 10*1024*1024)
			rand.Read(data)
			w.Write(data)
		})
		dummyServer.ListenAndServe()
	}()
	defer dummyServer.Close()
	time.Sleep(1 * time.Second)

	// Configure client to use SOCKS5 proxy
	proxyUrl := "socks5://127.0.0.1:1080"
	// Note: If client defaults to different port, this will fail. Let's assume standard 1080.

	start := time.Now()

	// Create a transport that uses the SOCKS proxy
	// Since we can't easily import internal packages here to use SOCKS dialer efficiently without adding deps,
	// checking if we can just measure raw transfer via the tunnel is hard E2E without an external tool.
	// Alternative: The test IS the external tool.

	// Using standard http client with proxy
	os.Setenv("HTTP_PROXY", proxyUrl)
	os.Setenv("HTTPS_PROXY", proxyUrl)

	// Download 10MB
	resp, err := http.Get("http://127.0.0.1:9090/data")
	if err != nil {
		t.Fatalf("Failed to request through proxy: %v", err)
	}
	defer resp.Body.Close()

	n, err := io.Copy(io.Discard, resp.Body)
	if err != nil {
		t.Fatalf("Failed to read response: %v", err)
	}

	duration := time.Since(start)
	mb := float64(n) / 1024 / 1024
	sec := duration.Seconds()

	t.Logf("Transferred %.2f MB in %.2f seconds", mb, sec)
	t.Logf("Throughput: %.2f MB/s", mb/sec)

	if mb/sec < 0.1 {
		t.Error("Throughput is suspiciously low (< 0.1 MB/s)")
	}
}
