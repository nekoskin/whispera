package protocol

import (
	"bytes"
	"fmt"
	"go/format"
	"math"
	"math/rand"
	"sort"
	"strings"
	"time"
)

type PolicyDial struct {
	Ms    int64
	Arm   int
	Alive bool
}

func PolicyDocs(dials []PolicyDial, gap time.Duration) [][]int {
	sorted := append([]PolicyDial(nil), dials...)
	sort.SliceStable(sorted, func(i, j int) bool { return sorted[i].Ms < sorted[j].Ms })
	var docs [][]int
	cur := []int{polBOS}
	var last int64
	for _, d := range sorted {
		if d.Arm < 0 || d.Arm >= polArms {
			continue
		}
		if len(cur) > 1 && d.Ms-last > gap.Milliseconds() {
			docs = append(docs, cur)
			cur = []int{polBOS}
		}
		cur = append(cur, polDial(d.Arm, d.Alive))
		last = d.Ms
	}
	if len(cur) > 1 {
		docs = append(docs, cur)
	}
	return docs
}

type PolicyFitConfig struct {
	Steps     int
	EvalEvery int
	Rehearsal float64
	Seed      int64
}

type PolicyFitReport struct {
	Steps       int
	BestStep    int
	TestDials   int
	ArmRateLoss float64
	FrozenLoss  float64
	FittedLoss  float64
	CensorDials int
	FrozenLost  map[string]int
	FittedLost  map[string]int
}

func (r PolicyFitReport) Better(censorSlack float64) bool {
	if r.BestStep == 0 || r.FittedLoss >= r.FrozenLoss {
		return false
	}
	for mode, lost := range r.FrozenLost {
		if float64(r.FittedLost[mode]) > float64(lost)*(1+censorSlack) {
			return false
		}
	}
	return true
}

type FittedPolicy struct{ p *polParams }

const (
	polLossFloor      = 1e-6
	polExportDecimals = 1e6
	polMinTrainDoc    = 3
)

func FitPolicy(train, val, test [][]int, cfg PolicyFitConfig) (FittedPolicy, PolicyFitReport) {
	rng := rand.New(rand.NewSource(cfg.Seed))
	rehearsal := censorCorpus(censorRehearsal, rng)
	pool := make([][]int, 0, len(train))
	for _, d := range train {
		if len(d) >= polMinTrainDoc {
			pool = append(pool, d)
		}
	}

	p, adam := newPolParams(), newPolAdam()
	best, bestStep := p.clone(), 0
	bestLoss, _ := conditionalLoss(p, val)
	for step := 1; step <= cfg.Steps && len(pool) > 0; step++ {
		docs := pool
		if rng.Float64() < cfg.Rehearsal {
			docs = rehearsal
		}
		d := docs[rng.Intn(len(docs))]
		start := rng.Intn(len(d) - 1)
		end := start + polBlock + 1
		if end > len(d) {
			end = len(d)
		}
		polTrainStep(p, adam, d[start:end])
		if cfg.EvalEvery > 0 && step%cfg.EvalEvery == 0 {
			if loss, _ := conditionalLoss(p, val); loss < bestLoss {
				best, bestStep, bestLoss = p.clone(), step, loss
			}
		}
	}
	best.round(polExportDecimals)

	frozen := newPolParams()
	report := PolicyFitReport{
		Steps:       cfg.Steps,
		BestStep:    bestStep,
		ArmRateLoss: armRateLoss(train, test),
		CensorDials: censorTrials * censorLength,
		FrozenLost:  map[string]int{},
		FittedLost:  map[string]int{},
	}
	report.FrozenLoss, report.TestDials = conditionalLoss(frozen, test)
	report.FittedLoss, _ = conditionalLoss(best, test)
	for _, mode := range policyCensors {
		report.FrozenLost[mode] = censorLost(frozen, mode)
		report.FittedLost[mode] = censorLost(best, mode)
	}
	return FittedPolicy{p: best}, report
}

func (p *polParams) clone() *polParams {
	c := newPolGrads()
	src := p.all()
	for i, m := range c.all() {
		for r := range m {
			copy(m[r], src[i][r])
		}
	}
	return c
}

func (p *polParams) round(scale float64) {
	for _, m := range p.all() {
		for _, row := range m {
			for j, v := range row {
				row[j] = math.Round(v*scale) / scale
			}
		}
	}
}

func outcomeLoss(pAlive float64, alive bool) float64 {
	q := math.Min(math.Max(pAlive, polLossFloor), 1-polLossFloor)
	if alive {
		return -math.Log(q)
	}
	return -math.Log(1 - q)
}

func conditionalLoss(p *polParams, docs [][]int) (float64, int) {
	total, n := 0.0, 0
	for _, d := range docs {
		for i := 1; i < len(d); i++ {
			arm, alive := d[i]/2, d[i]%2 == 0
			total += outcomeLoss(p.armScores(d[:i], polArms)[arm], alive)
			n++
		}
	}
	if n == 0 {
		return 0, 0
	}
	return total / float64(n), n
}

func armRateLoss(train, test [][]int) float64 {
	var alive, seen [polArms]float64
	for _, d := range train {
		for _, tok := range d[1:] {
			seen[tok/2]++
			if tok%2 == 0 {
				alive[tok/2]++
			}
		}
	}
	total, n := 0.0, 0
	for _, d := range test {
		for _, tok := range d[1:] {
			arm := tok / 2
			total += outcomeLoss((alive[arm]+1)/(seen[arm]+2), tok%2 == 0)
			n++
		}
	}
	if n == 0 {
		return 0
	}
	return total / float64(n)
}

const (
	censorGrid      = "grid"
	censorGridHard  = "gridhard"
	censorRehearsal = censorGrid

	censorPeriod       = 8
	censorTrials       = 12
	censorLength       = 200
	censorSeedBase     = 500
	censorEpisodes     = 120
	censorEpisodeDials = 96
	censorPeriodMin    = 4
	censorPeriodMax    = 20
	censorWideBudget   = 4
	censorNarrowBudget = 2
)

var policyCensors = []string{censorGrid, censorGridHard}

func censorSurvives(mode string, rule, arm int) bool {
	preset, budget := JointArmParts(arm, polPresets())
	if mode == censorGrid {
		if rule == 0 {
			return preset <= 1 && budget <= censorWideBudget
		}
		return preset >= 1 && budget <= censorNarrowBudget
	}
	if rule == 0 {
		return preset <= 1 && budget <= censorNarrowBudget
	}
	return preset == 2 && budget >= censorWideBudget
}

func censorSchedule(length, period int, rng *rand.Rand) []int {
	rule := rng.Intn(2)
	out := make([]int, length)
	for i := range out {
		out[i] = rule
		if (i+1)%period == 0 {
			rule = 1 - rule
		}
	}
	return out
}

func censorCorpus(mode string, rng *rand.Rand) [][]int {
	docs := make([][]int, 0, censorEpisodes)
	for e := 0; e < censorEpisodes; e++ {
		period := censorPeriodMin + rng.Intn(censorPeriodMax-censorPeriodMin+1)
		sched := censorSchedule(censorEpisodeDials, period, rng)
		doc := []int{polBOS}
		for _, rule := range sched {
			arm := rng.Intn(polArms)
			doc = append(doc, polDial(arm, censorSurvives(mode, rule, arm)))
		}
		docs = append(docs, doc)
	}
	return docs
}

func censorLost(p *polParams, mode string) int {
	every := func(int) bool { return true }
	lost := 0
	for trial := 0; trial < censorTrials; trial++ {
		sched := censorSchedule(censorLength, censorPeriod, rand.New(rand.NewSource(censorSeedBase+int64(trial))))
		hist := []int{polBOS}
		for _, rule := range sched {
			arm := bestFittingArm(p.armScores(hist, polArms), every)
			alive := censorSurvives(mode, rule, arm)
			if !alive {
				lost++
			}
			hist = append(hist, polDial(arm, alive))
			if len(hist) > polBlock {
				hist = hist[len(hist)-polBlock:]
			}
		}
	}
	return lost
}

func (f FittedPolicy) GoSource() ([]byte, error) {
	var b bytes.Buffer
	fmt.Fprintf(&b, "package protocol\n\nconst (\n")
	for _, c := range []struct {
		name string
		v    int
	}{{"polEmbd", polEmbd}, {"polHead", polHead}, {"polBlock", polBlock}, {"polLayer", polLayer}, {"polArms", polArms}, {"polFeatDim", polFeatDim}} {
		fmt.Fprintf(&b, "\t%s = %d\n", c.name, c.v)
	}
	b.WriteString(")\n")
	flat := []struct {
		name string
		m    [][]float64
	}{
		{"polWin", f.p.win}, {"polOin", f.p.oin}, {"polBosIn", f.p.bosIn},
		{"polWout", f.p.wout}, {"polOout", f.p.oout}, {"polBosOut", f.p.bosOut},
		{"polWpe", f.p.wpe},
	}
	for _, m := range flat {
		fmt.Fprintf(&b, "\nvar %s = [][]float64{\n", m.name)
		writeRows(&b, m.m, "\t")
		b.WriteString("}\n")
	}
	layered := []struct {
		name string
		m    [][]float64
	}{
		{"polWq", f.p.wq}, {"polWk", f.p.wk}, {"polWv", f.p.wv},
		{"polWo", f.p.wo}, {"polFc1", f.p.fc1}, {"polFc2", f.p.fc2},
	}
	for _, m := range layered {
		fmt.Fprintf(&b, "\nvar %s = [][][]float64{\n\t{\n", m.name)
		writeRows(&b, m.m, "\t\t")
		b.WriteString("\t},\n}\n")
	}
	return format.Source(b.Bytes())
}

func writeRows(b *bytes.Buffer, m [][]float64, indent string) {
	for _, row := range m {
		cells := make([]string, len(row))
		for j, v := range row {
			cells[j] = fmt.Sprintf("%.6f", v)
		}
		fmt.Fprintf(b, "%s{%s},\n", indent, strings.Join(cells, ", "))
	}
}
