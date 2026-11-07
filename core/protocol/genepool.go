package protocol

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

func GenePoolEnabled() bool { return os.Getenv("WHISPERA_GENEPOOL") == "1" }

type Gene struct {
	Ident   int
	Records int
	PauseMs int
	// Scramble reorders the hello records on the wire, applied by the stand
	// evader (the kernel socket always sends in sequence order). 0 keeps order.
	Scramble int
	// PhantomTTL stamps a decoy record over the server name with this IP TTL, so
	// it reaches a reassembling inspector but expires before the server. 0 = off.
	PhantomTTL int
}

func (g Gene) String() string {
	return fmt.Sprintf("i%d/r%d/p%dms/s%d/t%d", g.Ident, g.Records, g.PauseMs, g.Scramble, g.PhantomTTL)
}

// ParseGene reads a gene back from its String form, tolerating missing fields
// and the "ms" suffix on the pause. It is the single reader for both the client
// (forced gene) and the stand evader.
func ParseGene(spec string) (Gene, bool) {
	g, any := Gene{}, false
	for _, part := range strings.Split(spec, "/") {
		if len(part) < 2 {
			continue
		}
		digits := part[1:]
		for len(digits) > 0 && (digits[len(digits)-1] < '0' || digits[len(digits)-1] > '9') {
			digits = digits[:len(digits)-1]
		}
		n, err := strconv.Atoi(digits)
		if err != nil {
			continue
		}
		switch part[0] {
		case 'i':
			g.Ident = n
		case 'r':
			g.Records = n
		case 'p':
			g.PauseMs = n
		case 's':
			g.Scramble = n
		case 't':
			g.PhantomTTL = n
		default:
			continue
		}
		any = true
	}
	return g, any
}
