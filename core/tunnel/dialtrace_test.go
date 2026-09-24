package tunnel

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeTrace(t *testing.T, rows int) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "dials.csv")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	fmt.Fprintln(f, dialTraceHeader)
	for i := 0; i < rows; i++ {
		fmt.Fprintf(f, "%d,origin|frag,%d,0,1,%s\n", 1700000000000+i, i%4, dialStageHandshake)
	}
	return path
}

func TestTrimDialTraceKeepsTailAndHeader(t *testing.T) {
	path := writeTrace(t, 5000)
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lastRow := strings.Split(strings.TrimRight(string(before), "\n"), "\n")
	want := lastRow[len(lastRow)-1]

	const keep = 16 << 10
	if err := trimDialTrace(path, keep); err != nil {
		t.Fatalf("trim: %v", err)
	}

	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Size() > keep+int64(len(dialTraceHeader))+1 {
		t.Errorf("file is %d bytes, allowance is %d", fi.Size(), keep)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
	if lines[0] != dialTraceHeader {
		t.Errorf("first line is %q, want the header back", lines[0])
	}
	if lines[len(lines)-1] != want {
		t.Errorf("last row is %q, want the newest dial %q", lines[len(lines)-1], want)
	}
	for i, l := range lines[1:] {
		if strings.Count(l, ",") != strings.Count(dialTraceHeader, ",") {
			t.Fatalf("row %d survived the cut broken: %q", i, l)
		}
	}
}

func TestTrimDialTraceLeavesSmallFileAlone(t *testing.T) {
	path := writeTrace(t, 10)
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := trimDialTrace(path, 1<<20); err != nil {
		t.Fatalf("trim: %v", err)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Error("a file inside its allowance was rewritten")
	}
}

func TestDialTraceKeepBytesDefault(t *testing.T) {
	t.Setenv("WHISPERA_DIAL_TRACE_MB", "")
	if got := dialTraceKeepBytes(); got != dialTraceDefaultMB<<20 {
		t.Errorf("default allowance is %d, want %d", got, dialTraceDefaultMB<<20)
	}
	t.Setenv("WHISPERA_DIAL_TRACE_MB", "9")
	if got := dialTraceKeepBytes(); got != 9<<20 {
		t.Errorf("allowance is %d, want %d", got, 9<<20)
	}
	t.Setenv("WHISPERA_DIAL_TRACE_MB", "nonsense")
	if got := dialTraceKeepBytes(); got != dialTraceDefaultMB<<20 {
		t.Errorf("bad value gave %d, want the default %d", got, dialTraceDefaultMB<<20)
	}
}
