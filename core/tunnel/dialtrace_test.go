package tunnel

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nekoskin/whispera/core/protocol"
)

func TestCurateDropsJunkAndKeepsNewest(t *testing.T) {
	path := filepath.Join(t.TempDir(), "dials.csv")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Fprintln(f, dialTraceHeader)
	const firstMs int64 = 1700000000000
	for i := int64(0); i < 4000; i++ {
		fmt.Fprintf(f, "%d,origin|net|joint,%d,0,1,%s,0,%s,0\n", firstMs+i, i%4, dialStageHandshake, protocol.SymptomOK)
		fmt.Fprintf(f, "%d,origin|net|joint,0,%d,0,%s,0,%s,0\n", firstMs+i, dialTraceLocalResult, dialStageHandshake, protocol.SymptomOK)
		fmt.Fprintf(f, "%d,origin|net|joint,1,1,0,%s,0,%s,0\n", firstMs+i, dialStageConnect, protocol.SymptomTCPReset)
	}
	f.Close()
	want := fmt.Sprintf("%d,origin|net|joint,%d,0,1,%s,0,%s,0", firstMs+3999, 3999%4, dialStageHandshake, protocol.SymptomOK)

	const keep = 16 << 10
	if err := curateDialTrace(path, keep); err != nil {
		t.Fatalf("curate: %v", err)
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
		t.Errorf("first line is %q, want the header", lines[0])
	}
	for _, l := range lines[1:] {
		if !dialTraceTrains(strings.Split(l, ",")) {
			t.Fatalf("a non-trainable row survived: %q", l)
		}
	}
	if lines[len(lines)-1] != want {
		t.Errorf("last row is %q, want the newest trainable dial %q", lines[len(lines)-1], want)
	}
}

func TestLiveDeathsAreTrainable(t *testing.T) {
	for _, stage := range []string{dialStageLiveReset, dialStageLiveEnd} {
		row := strings.Split(fmt.Sprintf("1700000000000,origin|net|joint,1,1,0,%s,0,%s,0", stage, protocol.SymptomLiveReset), ",")
		if !dialTraceTrains(row) {
			t.Fatalf("a %s row was dropped, but policyfit reads it as a death after the handshake", stage)
		}
	}
}
