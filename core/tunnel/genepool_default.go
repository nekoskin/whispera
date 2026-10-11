//go:build !stand

package tunnel

import "github.com/nekoskin/whispera/core/protocol"

func applyGene(*protocol.ClientConfig, tcpBypassDialer) (protocol.Gene, bool) {
	return protocol.Gene{}, false
}

func observeGene(protocol.Gene, bool) {}
