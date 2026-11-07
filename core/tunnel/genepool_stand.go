//go:build stand

package tunnel

import (
	"context"
	stdlog "log"
	"net"
	"os"
	"sync"
	"time"

	"github.com/nekoskin/whispera/core/protocol"
	"github.com/nekoskin/whispera/core/protocol/fingerprint"
)

var (
	genePoolOnce sync.Once
	genePoolInst *protocol.GenePool

	forcedGeneOnce sync.Once
	forcedGeneVal  protocol.Gene
	forcedGeneSet  bool
)

func genePool() *protocol.GenePool {
	genePoolOnce.Do(func() { genePoolInst = protocol.NewGenePool(fingerprint.PresetCount()) })
	return genePoolInst
}

func forcedGene() (protocol.Gene, bool) {
	forcedGeneOnce.Do(func() {
		if g, ok := protocol.ParseGene(os.Getenv("WHISPERA_GENE")); ok {
			forcedGeneVal, forcedGeneSet = g, true
		}
	})
	return forcedGeneVal, forcedGeneSet
}

func applyIdent(c *protocol.ClientConfig, ident int) {
	c.HelloID = fingerprint.PresetAt(ident)
	c.HelloRaw = nil
}

func applyGene(c *protocol.ClientConfig, d tcpBypassDialer) (protocol.Gene, bool) {
	_, forced := forcedGene()
	if d == nil || (!protocol.GenePoolEnabled() && !forced) {
		return protocol.Gene{}, false
	}
	g, ok := forcedGene()
	if !ok {
		g = genePool().Select()
	}
	applyIdent(c, g.Ident)
	c.TCPDialer = func(ctx context.Context, network, addr string) (net.Conn, error) {
		writeGene(g)
		return d.DialTCPWithShape(ctx, network, addr, g.Records, g.PauseMs)
	}
	return g, true
}

// writeGene publishes the gene chosen for the dial about to open, so the stand
// evader can apply its wire parts (scramble/phantom) to that same flow. Atomic
// rename keeps the evader from reading a half-written file.
func writeGene(g protocol.Gene) {
	path := os.Getenv("WHISPERA_GENE_FILE")
	if path == "" {
		return
	}
	tmp := path + ".tmp"
	if os.WriteFile(tmp, []byte(g.String()), 0o644) == nil {
		_ = os.Rename(tmp, path)
	}
}

func observeGene(g protocol.Gene, alive bool) {
	if _, forced := forcedGene(); forced {
		return
	}
	live := 0
	if alive {
		live = 1
	}
	stdlog.Printf("[INFO] gene_trace %d,%s,%d", time.Now().UnixMilli(), g, live)
	genePool().Observe(g, alive)
}
