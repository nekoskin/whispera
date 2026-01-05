package tests

import (
	"context"
	"os"
	"os/exec"
	"testing"
	"time"
)

func TestClientServerConnectivity(t *testing.T) {
	// 1. Build client and server
	t.Log("Building client and server...")

	buildClient := exec.Command("go", "build", "-o", "test_client.exe", "../cmd/client")
	if output, err := buildClient.CombinedOutput(); err != nil {
		t.Fatalf("failed to build client: %v\nOutput: %s", err, string(output))
	}
	defer os.Remove("test_client.exe")

	buildServer := exec.Command("go", "build", "-o", "test_server.exe", "../cmd/server")
	if output, err := buildServer.CombinedOutput(); err != nil {
		t.Fatalf("failed to build server: %v\nOutput: %s", err, string(output))
	}
	defer os.Remove("test_server.exe")

	cwd, _ := os.Getwd()
	clientPath := cwd + "\\test_client.exe"
	serverPath := cwd + "\\test_server.exe"

	// 2. Start server
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	t.Log("Starting server...")
	serverCmd := exec.CommandContext(ctx, serverPath, "-l", "127.0.0.1:28080")
	// serverCmd.Stdout/Stderr can be captured to verify logs if needed
	if err := serverCmd.Start(); err != nil {
		t.Fatalf("failed to start server: %v", err)
	}
	defer serverCmd.Process.Kill()

	time.Sleep(2 * time.Second) // Wait for server to bind

	// 3. Start client
	t.Log("Starting client...")
	clientCmd := exec.CommandContext(ctx, clientPath, "-s", "127.0.0.1:28080", "-v")
	if err := clientCmd.Start(); err != nil {
		t.Fatalf("failed to start client: %v", err)
	}
	defer clientCmd.Process.Kill()

	time.Sleep(5 * time.Second) // Wait for potential handshake

	// 4. Verify processes are still alive (basic check)
	select {
	case <-ctx.Done():
		t.Fatalf("test timed out")
	default:
		if serverCmd.ProcessState != nil && serverCmd.ProcessState.Exited() {
			t.Errorf("server exited early: %v", serverCmd.ProcessState)
		}
		if clientCmd.ProcessState != nil && clientCmd.ProcessState.Exited() {
			t.Errorf("client exited early: %v", clientCmd.ProcessState)
		}
	}

	t.Log("E2E Basic connectivity test finishes (processes were started successfully)")
}

func TestConfigValidation(t *testing.T) {
	// Build client if not exists
	if _, err := os.Stat("test_client.exe"); os.IsNotExist(err) {
		buildClient := exec.Command("go", "build", "-o", "test_client.exe", "../cmd/client")
		if output, err := buildClient.CombinedOutput(); err != nil {
			t.Fatalf("failed to build client: %v\nOutput: %s", err, string(output))
		}
		defer os.Remove("test_client.exe")
	}

	tests := []struct {
		name        string
		configPath  string
		expectValid bool
	}{
		{"ValidYAML", "../sample_phase2.yaml", true},
		{"ValidJSON", "../sample_phase2.json", true},
		{"InvalidYAML", "../sample_invalid.yaml", false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cmd := exec.Command("./test_client.exe", "-config", tc.configPath, "-validate-config")
			output, err := cmd.CombinedOutput()
			if tc.expectValid {
				if err != nil {
					t.Errorf("expected valid config, got error: %v\nOutput: %s", err, string(output))
				}
			} else {
				if err == nil {
					t.Error("expected invalid config, but validation passed")
				}
			}
		})
	}
}
