package protocol

import (
	"fmt"
	"os"
)

func GenePoolEnabled() bool { return os.Getenv("WHISPERA_GENEPOOL") == "1" }

type Gene struct {
	Ident   int
	Records int
	PauseMs int
}

func (g Gene) String() string { return fmt.Sprintf("i%d/r%d/p%dms", g.Ident, g.Records, g.PauseMs) }
