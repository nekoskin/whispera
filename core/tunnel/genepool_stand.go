//go:build stand

package tunnel

import (
	"context"
	stdlog "log"
	"net"
	"os"
	"strconv"
	"strings"
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
		spec := os.Getenv("WHISPERA_GENE")
		if spec == "" {
			return
		}
		g := protocol.Gene{}
		for _, part := range strings.Split(spec, "/") {
			if part == "" {
				continue
			}
			n, err := strconv.Atoi(part[1:])
			if err != nil {
				return
			}
			switch part[0] {
			case 'i':
				g.Ident = n
			case 'r':
				g.Records = n
			case 'p':
				g.PauseMs = n
			}
		}
		forcedGeneVal, forcedGeneSet = g, true
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
		return d.DialTCPWithShape(ctx, network, addr, g.Records, g.PauseMs)
	}
	return g, true
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
