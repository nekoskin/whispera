// Package main is the entry point for the Whispera modular client
package main

import (
	"flag"
	"os"
	"os/signal"
	"syscall"
	"time"

	"whispera/internal/core/lifecycle"
	"whispera/internal/logger"

	// Modules
	"whispera/internal/modules/config"
	"whispera/internal/modules/crypto"
	"whispera/internal/modules/dnsmodule"
	"whispera/internal/modules/handshake"
	"whispera/internal/modules/obfuscator"
	"whispera/internal/modules/session"
	"whispera/internal/modules/socks5"
	"whispera/internal/modules/tunnel"
)

// log is the module logger
var log = logger.Module("client")

var Version = "2.0.0"

var (
	configPath = flag.String("config", "", "Path to configuration file")
	serverAddr = flag.String("server", "", "Server address (host:port)")
	socksAddr  = flag.String("socks", "127.0.0.1:10800", "SOCKS5 listen address for hev-socks5-tunnel")
)

func main() {
	flag.Parse()

	// Load config
	var cfg *config.ClientConfig
	var err error
	if *configPath != "" {
		cfg, err = config.LoadClient(*configPath)
		if err != nil {
			log.Fatalf("Failed to load config: %v", err)
		}
	} else {
		cfg = &config.ClientConfig{
			Server: *serverAddr,
		}
	}
	if *serverAddr != "" {
		cfg.Server = *serverAddr
	}

	log.Printf("Starting Whispera Client v%s", Version)
	log.Printf("Server: %s", cfg.Server)

	// Lifecycle manager
	lc := lifecycle.NewManager(lifecycle.Config{
		ShutdownTimeout: 30 * time.Second,
		GracefulStop:    true,
	})

	ctx := lc.Context()

	// Create and register modules
	cryptoMod, _ := crypto.New(nil)
	lc.Register(cryptoMod)

	obfsMod, _ := obfuscator.New(&obfuscator.Config{
		DefaultProfile: cfg.ObfsPreset,
		ThreatLevel:    5,
	})
	lc.Register(obfsMod)

	sessMod, _ := session.New(&session.Config{MaxSessions: 10})
	lc.Register(sessMod)

	hsMod, _ := handshake.New(&handshake.Config{
		RateLimit: 100,
		RateBurst: 50,
		Timeout:   10 * time.Second,
	})
	lc.Register(hsMod)

	// SOCKS5 Server for HevTunnel (replaces internal TUN)
	socksMod, _ := socks5.New(&socks5.Config{
		ListenAddr: *socksAddr,
	})
	lc.Register(socksMod)

	dnsMod, _ := dnsmodule.New(&dnsmodule.Config{
		Upstream:     "1.1.1.1:53",
		CacheEnabled: true,
	})
	lc.Register(dnsMod)

	tunnelMod, _ := tunnel.New(&tunnel.Config{
		ServerAddr:        cfg.Server,
		KeepaliveInterval: 30 * time.Second,
	})
	lc.Register(tunnelMod)

	// Wire tunnel to SOCKS5 for encrypted relay
	socksMod.SetTunnel(tunnelMod)

	// Start
	if err := lc.Start(); err != nil {
		log.Fatalf("Failed to start: %v", err)
	}

	// Handle signals
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigChan
		log.Println("Shutting down...")
		lc.Stop()
	}()

	log.Println("Client running. Press Ctrl+C to stop.")
	<-ctx.Done()
}
