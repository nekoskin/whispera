package protocol

import (
	"math"
	"os"
	"sync"
)

func polRMSNorm(x []float64) []float64 {
	sum := 0.0
	for _, v := range x {
		sum += v * v
	}
	r := math.Sqrt(sum/float64(len(x)) + 1e-8)
	out := make([]float64, len(x))
	for i, v := range x {
		out[i] = v / r
	}
	return out
}

func polSoftmax(z []float64) []float64 {
	top := math.Inf(-1)
	for _, v := range z {
		if v > top {
			top = v
		}
	}
	out := make([]float64, len(z))
	sum := 0.0
	for i, v := range z {
		e := math.Exp(v - top)
		out[i] = e
		sum += e
	}
	for i := range out {
		out[i] /= sum
	}
	return out
}

func polApply(x []float64, w [][]float64) []float64 {
	out := make([]float64, len(w))
	for j, row := range w {
		sum := 0.0
		for k, v := range row {
			sum += x[k] * v
		}
		out[j] = sum
	}
	return out
}

const polBOS = polArms * 2

func polPresets() int { return polFeatDim - armDeliveryDims }

func polTokenEmbed(tok int) []float64 {
	row := make([]float64, polEmbd)
	if tok == polBOS {
		copy(row, polBosIn[0])
		return row
	}
	arm, out := tok/2, tok%2
	feat := JointArmFeatures(arm, polPresets())
	for j := 0; j < polEmbd; j++ {
		s := polOin[out][j]
		for f := 0; f < polFeatDim; f++ {
			s += feat[f] * polWin[j][f]
		}
		row[j] = s
	}
	return row
}

func polForward(tokens []int) [][]float64 {
	t := len(tokens)
	x := make([][]float64, t)
	for i, tok := range tokens {
		row := polTokenEmbed(tok)
		for j := 0; j < polEmbd; j++ {
			row[j] += polWpe[i][j]
		}
		x[i] = polRMSNorm(row)
	}

	headDim := polEmbd / polHead
	for layer := 0; layer < polLayer; layer++ {
		q := make([][]float64, t)
		k := make([][]float64, t)
		v := make([][]float64, t)
		for i := 0; i < t; i++ {
			h := polRMSNorm(x[i])
			q[i] = polApply(h, polWq[layer])
			k[i] = polApply(h, polWk[layer])
			v[i] = polApply(h, polWv[layer])
		}

		o := make([][]float64, t)
		for i := range o {
			o[i] = make([]float64, polEmbd)
		}
		scale := math.Sqrt(float64(headDim))
		for head := 0; head < polHead; head++ {
			base := head * headDim
			for i := 0; i < t; i++ {
				scores := make([]float64, i+1)
				for u := 0; u <= i; u++ {
					dot := 0.0
					for d := 0; d < headDim; d++ {
						dot += q[i][base+d] * k[u][base+d]
					}
					scores[u] = dot / scale
				}
				a := polSoftmax(scores)
				for u := 0; u <= i; u++ {
					for d := 0; d < headDim; d++ {
						o[i][base+d] += a[u] * v[u][base+d]
					}
				}
			}
		}

		for i := 0; i < t; i++ {
			proj := polApply(o[i], polWo[layer])
			x2 := make([]float64, polEmbd)
			for j := 0; j < polEmbd; j++ {
				x2[j] = x[i][j] + proj[j]
			}
			f := polApply(polRMSNorm(x2), polFc1[layer])
			for j, val := range f {
				if val < 0 {
					f[j] = 0
				}
			}
			back := polApply(f, polFc2[layer])
			row := make([]float64, polEmbd)
			for j := 0; j < polEmbd; j++ {
				row[j] = x2[j] + back[j]
			}
			x[i] = row
		}
	}

	return x
}

func polDial(arm int, alive bool) int {
	if alive {
		return arm * 2
	}
	return arm*2 + 1
}

func polArmSurvival(xLast []float64, arm int) float64 {
	feat := JointArmFeatures(arm, polPresets())
	sOK, sDead := 0.0, 0.0
	for j := 0; j < polEmbd; j++ {
		projOK, projDead := polOout[0][j], polOout[1][j]
		for f := 0; f < polFeatDim; f++ {
			projOK += feat[f] * polWout[j][f]
			projDead += feat[f] * polWout[polEmbd+j][f]
		}
		sOK += xLast[j] * projOK
		sDead += xLast[j] * projDead
	}
	return 1.0 / (1.0 + math.Exp(-(sOK - sDead)))
}

func policyArmScores(history []int, arms int) []float64 {
	if len(history) == 0 {
		history = []int{polBOS}
	}
	if len(history) > polBlock {
		history = history[len(history)-polBlock:]
	}
	x := polForward(history)
	xLast := x[len(x)-1]
	out := make([]float64, arms)
	for a := 0; a < arms; a++ {
		out[a] = polArmSurvival(xLast, a)
	}
	return out
}

func PolicyEnabled() bool { return os.Getenv("WHISPERA_POLICY") != "0" }

func JointArmEnabled() bool { return os.Getenv("WHISPERA_JOINT_ARM") != "0" }

func policyJointUsable(presets int) bool { return JointArmCount(presets) == polArms }

func frozenJointUsable(presets int) bool {
	return presets == polPresets() && JointArmCount(presets) >= polArms
}

func (h *HandshakeStrategy) SelectJointPolicy(ctx string, presets int, fragmented bool) (arm int, ok bool) {
	if !frozenJointUsable(presets) {
		return 0, false
	}
	return h.policyArm(ctx, jointArmFits(fragmented), JointArmCount(presets)), true
}

func (h *HandshakeStrategy) policyArm(ctx string, fits func(int) bool, arms int) int {
	policyHist.mu.Lock()
	rev := policyHist.rev[ctx]
	policyHist.mu.Unlock()

	policyArmCache.mu.Lock()
	if g, ok := policyArmCache.m[ctx]; ok && g.rev == rev && fits(g.arm) {
		policyArmCache.mu.Unlock()
		return g.arm
	}
	policyArmCache.mu.Unlock()

	policyHist.mu.Lock()
	rev = policyHist.rev[ctx]
	seq := make([]int, 0, len(policyHist.m[ctx])+1)
	seq = append(seq, polBOS)
	seq = append(seq, policyHist.m[ctx]...)
	policyHist.mu.Unlock()

	best := bestFittingArm(policyArmScores(seq, arms), fits)

	policyArmCache.mu.Lock()
	if policyArmCache.m == nil {
		policyArmCache.m = make(map[string]armGuess)
	}
	if g, ok := policyArmCache.m[ctx]; !ok || g.rev <= rev {
		policyArmCache.m[ctx] = armGuess{rev: rev, arm: best}
	}
	policyArmCache.mu.Unlock()
	return best
}

func policyUsable() bool { return len(fragmentBudgets) == polArms }

var policyHist struct {
	mu  sync.Mutex
	m   map[string][]int
	rev map[string]uint64
}

type armGuess struct {
	rev uint64
	arm int
}

var policyArmCache struct {
	mu sync.Mutex
	m  map[string]armGuess
}

func (h *HandshakeStrategy) NoteDial(ctx string, arm int, alive bool) {
	policyHist.mu.Lock()
	defer policyHist.mu.Unlock()
	if policyHist.m == nil {
		policyHist.m = make(map[string][]int)
		policyHist.rev = make(map[string]uint64)
	}
	seq := append(policyHist.m[ctx], polDial(arm, alive))
	if len(seq) > polBlock {
		seq = seq[len(seq)-polBlock:]
	}
	policyHist.m[ctx] = seq
	policyHist.rev[ctx]++
}

func (h *HandshakeStrategy) SelectFragmentsPolicy(ctx string) (budget, arm int, ok bool) {
	if !policyUsable() {
		return 0, 0, false
	}
	arm = h.policyArm(ctx, anyArm, len(fragmentBudgets))
	return fragmentBudgets[arm], arm, true
}

func bestFittingArm(scores []float64, fits func(int) bool) int {
	best := -1
	for a, s := range scores {
		if fits(a) && (best < 0 || s > scores[best]) {
			best = a
		}
	}
	return best
}
