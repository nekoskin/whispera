package client

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestTrimmingLogWipesPastTheLineLimit(t *testing.T) {
	path := filepath.Join(t.TempDir(), "client.log")
	lg, err := newTrimmingLog(path)
	if err != nil {
		t.Fatalf("newTrimmingLog: %v", err)
	}
	defer lg.f.Close()

	for i := 0; i < logMaxLines()*3; i++ {
		if _, err := lg.Write([]byte(fmt.Sprintf("line %d with a body long enough to matter\n", i))); err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	got := countLines(data)
	if got > logMaxLines() {
		t.Fatalf("file holds %d lines, limit is %d", got, logMaxLines())
	}
	t.Logf("after %d writes the file holds %d lines", logMaxLines()*3, got)
}

func TestTrimmingLogKeepsWhatFits(t *testing.T) {
	path := filepath.Join(t.TempDir(), "client.log")
	content := "first line\nsecond line\n"
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatalf("seed: %v", err)
	}

	lg, err := newTrimmingLog(path)
	if err != nil {
		t.Fatalf("newTrimmingLog: %v", err)
	}
	defer lg.f.Close()

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !strings.Contains(string(data), "first line") {
		t.Fatal("a file under the limit was wiped")
	}
}

func TestCountLines(t *testing.T) {
	cases := map[string]int{
		"":             0,
		"one\n":        1,
		"one\ntwo\n":   2,
		"no newline":   0,
		"one\npartial": 1,
	}
	for in, want := range cases {
		if got := countLines([]byte(in)); got != want {
			t.Fatalf("countLines(%q) = %d, want %d", in, got, want)
		}
	}
}
