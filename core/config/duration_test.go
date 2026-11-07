package config

import (
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

func TestDurationSurvivesRepeatedSaves(t *testing.T) {
	type holder struct {
		D Duration `yaml:"d"`
	}

	h := holder{D: Duration(30 * time.Second)}
	for i := 1; i <= 5; i++ {
		out, err := yaml.Marshal(h)
		if err != nil {
			t.Fatalf("round %d: marshal: %v", i, err)
		}
		var back holder
		if err := yaml.Unmarshal(out, &back); err != nil {
			t.Fatalf("round %d: unmarshal %q: %v", i, out, err)
		}
		if back.D.D() != 30*time.Second {
			t.Fatalf("round %d: %s round-tripped to %v, want 30s", i, out, back.D.D())
		}
		h = back
	}
}
