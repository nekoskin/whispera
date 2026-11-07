package client

import (
	"fmt"
	"os"
	"path/filepath"

	"testing"
)

func TestTrimmingLogWipesPastTheLineLimit(t *testing.T) {
	path := filepath.Join(t.TempDir(), "client.log")
	lg, err := newTrimmingLog(path, mainLogLimits())
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
