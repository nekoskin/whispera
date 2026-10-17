package protocol

import (
	"path/filepath"
	"reflect"
	"testing"
)

func steady(v float64) func() float64 { return func() float64 { return v } }

func TestMutantNeedsAPool(t *testing.T) {
	if _, ok := newOnlinePolicy().selectMutant("c", nil, mutantMaxRecords, steady(0.5)); ok {
		t.Fatal("no hellos to draw from, so no mutant")
	}
}

func TestMutantTriesEveryHelloBeforeRepeatingADeadOne(t *testing.T) {
	o := newOnlinePolicy()
	pool := []string{"a", "b", "c"}
	seen := map[string]bool{}
	for i := 0; i < len(pool); i++ {
		m, ok := o.selectMutant("c", pool, mutantMaxRecords, steady(0.5))
		if !ok {
			t.Fatal("expected a mutant")
		}
		if seen[m.Hello] {
			t.Fatalf("hello %s picked again while others were untried", m.Hello)
		}
		seen[m.Hello] = true
		o.noteMutant("c", m, false)
	}
}

func TestMutantKeepsWhatSurvived(t *testing.T) {
	o := newOnlinePolicy()
	pool := []string{"a", "b", "c"}
	o.noteMutant("c", Mutant{Hello: "a", Records: 1}, false)
	o.noteMutant("c", Mutant{Hello: "b", Records: 3}, true)
	for i := 0; i < 5; i++ {
		m, _ := o.selectMutant("c", pool, mutantMaxRecords, steady(0.99))
		if m != (Mutant{Hello: "b", Records: 3}) {
			t.Fatalf("picked %v, want the mutant that survived", m)
		}
	}
	m, _ := o.selectMutant("c", pool, mutantMaxRecords, steady(0))
	if m.Hello != "c" || m.Records != 3 {
		t.Fatalf("exploring should try the untried hello with the survivor's records, got %v", m)
	}
}

func TestMutantDropsASurvivorThatDied(t *testing.T) {
	o := newOnlinePolicy()
	pool := []string{"a", "b"}
	o.noteMutant("c", Mutant{Hello: "a", Records: 1}, true)
	o.noteMutant("c", Mutant{Hello: "a", Records: 1}, false)
	m, _ := o.selectMutant("c", pool, mutantMaxRecords, steady(0.99))
	if m.Hello != "b" {
		t.Fatalf("picked %v, want the untried hello after the survivor died", m)
	}
}

func TestMutantRecordsStayWholeWithoutFragmentation(t *testing.T) {
	o := newOnlinePolicy()
	o.noteMutant("c", Mutant{Hello: "a", Records: 6}, true)
	if m, _ := o.selectMutant("c", []string{"a"}, 1, steady(0.99)); m.Records != 1 {
		t.Fatalf("records %d, want 1 when the hello cannot be fragmented", m.Records)
	}
}

func TestMutantDialsLetDeadArmsDecay(t *testing.T) {
	o := newOnlinePolicy()
	o.Note("c", 0, false, true)
	for i := 0; i < deadArmDecay; i++ {
		o.noteMutant("c", Mutant{Hello: "a", Records: 1}, true)
	}
	if !o.alive("c", 0) {
		t.Fatal("dials on mutants should still count toward re-probing the base arms")
	}
}

func TestMutantPopulationIsCapped(t *testing.T) {
	o := newOnlinePolicy()
	for r := 0; r < mutantPopCap()+5; r++ {
		o.noteMutant("c", Mutant{Hello: mutantHelloID([]byte{byte(r)}), Records: 1}, r%2 == 0)
	}
	if n := len(o.mutants["c"]); n != mutantPopCap() {
		t.Fatalf("%d mutants kept, want %d", n, mutantPopCap())
	}
}

func TestMutantsSurviveRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policy-online.json")
	before := newOnlinePolicy()
	m := Mutant{Hello: mutantHelloID([]byte("hello")), Records: 2}
	before.noteMutant("sni|net|joint", m, true)
	before.noteMutant("sni|net|joint", Mutant{Hello: "short", Records: 1}, true)
	if err := before.save(path); err != nil {
		t.Fatal(err)
	}
	after := newOnlinePolicy()
	if err := after.load(path); err != nil {
		t.Fatal(err)
	}
	got := after.mutants["sni|net|joint"]
	if len(got) != 1 || !reflect.DeepEqual(*got[0], mutantStat{Mutant: m, Alive: 1, Total: 1}) {
		t.Fatalf("restored %v, want only the well-formed mutant", got)
	}
}

func TestMutantPoolHoldsTheSeedHellos(t *testing.T) {
	if len(mutantPool()) == 0 {
		t.Fatal("the seed fingerprints should give the evolution something to start from")
	}
}

func TestMutantPreferredOnlyWhileTheBaseArmsFail(t *testing.T) {
	o := newOnlinePolicy()
	o.noteMutant("c", Mutant{Hello: "a", Records: 1}, true)
	if o.mutantPreferred("c", steady(0.99)) {
		t.Fatal("no base dial has failed, so the base arms should be used")
	}
	o.Note("c", 4, false, true)
	if !o.mutantPreferred("c", steady(0.99)) {
		t.Fatal("the last base dial failed and a mutant survived, so the mutant should be used")
	}
	if o.mutantPreferred("c", steady(0)) {
		t.Fatal("a share of dials should still re-probe the base arms")
	}
	o.Note("c", 9, true, true)
	if o.mutantPreferred("c", steady(0.99)) {
		t.Fatal("a base arm came back, so the base arms should be used again")
	}
}

func TestMutantNotPreferredWithoutASurvivor(t *testing.T) {
	o := newOnlinePolicy()
	o.noteMutant("c", Mutant{Hello: "a", Records: 1}, false)
	o.Note("c", 4, false, true)
	if o.mutantPreferred("c", steady(0.99)) {
		t.Fatal("no mutant has survived, so there is nothing to prefer")
	}
}
