"""The same model as neural.py, with the arithmetic done on arrays.

neural.py builds a graph of scalar objects and walks it backwards — beautiful to
read, and slow enough that one measurement took tens of minutes, which is how a
day of work turns into three experiments instead of thirty. The architecture
here is identical (one layer, four heads, RMSNorm, ReLU, Adam); only the
derivatives are written out by hand instead of being discovered at runtime.

Correctness is checked against neural.py, not asserted: same data and same seed
should give the same loss curve to within the noise of initialisation.

    python neural/fast.py <hello|flow|flow-up|timing> <glob>
    python neural/fast.py eval <kind> <real-glob> <ours-glob>
    python neural/fast.py diff <kind> <real-glob> <ours-glob>
    python neural/fast.py control <kind> <real-glob>
    python neural/fast.py shape <real-glob> <ours-glob>
    python neural/fast.py shapes <real-glob> <ours-1> <ours-2> ...
    python neural/fast.py gradcheck            (LAYER=n EMBD=n to size it)
    python neural/fast.py probe [core/relay/model_weights.go]
    EXPORT=core/relay/model_weights.go PREFIX=m python neural/fast.py flow <glob>

eval gives one number: how distinguishable we are. diff says what that number is
made of, class by class, which is the part you can act on. control measures the
judge against real traffic it has never seen standing in for ours, where the
honest answer is zero — run it first, because any gap below the floor it reports
is noise. probe prints what the weights compiled into Go say for a few fixed
histories; the Go test holds the port to those numbers, so re-run it after any
export.

STEPS overrides the training length, which otherwise scales with the corpus.
After EXPORT, run gofmt on the generated file and refresh the probe values in
core/relay/model_test.go.
"""

import io
import math
import os
import random
import sys
import glob

import numpy as np

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Reuse the parsing and bucketing from neural.py so both paths see identical
# documents — a fast trainer on a different corpus would prove nothing.
_src = open(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'neural.py'), encoding='utf-8').read()
_ns = {}
exec(_src.split('# Let there be a Tokenizer')[0].split('mode =')[0], _ns)
load_docs = _ns['load_docs']
size_bounds, gap_bounds = _ns['size_bounds'], _ns['gap_bounds']

# The runtime model has to stay small: Go runs a forward pass per record in the
# datapath, and cost grows as n_layer * n_embd^2 — at embd 64 and four layers a
# record would cost a quarter of a millisecond, which a busy connection cannot
# afford. The judge has no such limit; it reads captures offline and wants every
# bit of capacity the corpus can support. Hence the sizes are settings, not
# constants: EMBD/HEAD/BLOCK/LAYER shape whichever of the two is being trained.
#
# Capacity is bounded by data, not by ambition. A model with more parameters than
# the corpus has tokens memorises it and reports a gap of zero on everything.
n_embd = int(os.environ.get('EMBD', 16))
n_head = int(os.environ.get('HEAD', 4))
block_size = int(os.environ.get('BLOCK', 16))
n_layer = int(os.environ.get('LAYER', 1))
head_dim = n_embd // n_head
learning_rate, beta1, beta2, eps_adam = 0.01, 0.85, 0.99, 1e-8
num_steps = 1000


def rmsnorm(x):
    r = np.sqrt((x * x).mean(-1, keepdims=True) + 1e-8)
    return x / r, r


def drmsnorm(dy, x, r):
    """Gradient through x / sqrt(mean(x^2)): the scale depends on x itself, so
    the derivative has a second term pulling along x."""
    d = x.shape[-1]
    return (dy - x * (dy * x).sum(-1, keepdims=True) / (d * r * r)) / r


def softmax(z):
    z = z - z.max(-1, keepdims=True)
    e = np.exp(z)
    return e / e.sum(-1, keepdims=True)


class Model:
    def __init__(self, vocab, rng):
        def m(a, b):
            return rng.normal(0, 0.02, size=(a, b))
        self.vocab = vocab
        self.p = {
            'wte': m(vocab, n_embd), 'wpe': m(block_size, n_embd), 'lm_head': m(vocab, n_embd),
        }
        for i in range(n_layer):
            self.p[f'{i}.wq'] = m(n_embd, n_embd)
            self.p[f'{i}.wk'] = m(n_embd, n_embd)
            self.p[f'{i}.wv'] = m(n_embd, n_embd)
            self.p[f'{i}.wo'] = m(n_embd, n_embd)
            self.p[f'{i}.fc1'] = m(4 * n_embd, n_embd)
            self.p[f'{i}.fc2'] = m(n_embd, 4 * n_embd)
        self.m = {k: np.zeros_like(v) for k, v in self.p.items()}
        self.v = {k: np.zeros_like(v) for k, v in self.p.items()}

    def size(self):
        return sum(v.size for v in self.p.values())

    def forward(self, tokens):
        p, T = self.p, len(tokens)
        x0 = p['wte'][tokens] + p['wpe'][:T]
        x, r1 = rmsnorm(x0)
        mask = np.triu(np.full((T, T), -1e9), 1)

        layers = []
        for i in range(n_layer):
            x_in = x
            h, rh = rmsnorm(x)
            q, k, v = h @ p[f'{i}.wq'].T, h @ p[f'{i}.wk'].T, h @ p[f'{i}.wv'].T
            qh = q.reshape(T, n_head, head_dim).transpose(1, 0, 2)
            kh = k.reshape(T, n_head, head_dim).transpose(1, 0, 2)
            vh = v.reshape(T, n_head, head_dim).transpose(1, 0, 2)
            a = softmax(qh @ kh.transpose(0, 2, 1) / math.sqrt(head_dim) + mask)
            o = (a @ vh).transpose(1, 0, 2).reshape(T, n_embd)
            x2 = x_in + o @ p[f'{i}.wo'].T

            h2, rh2 = rmsnorm(x2)
            f = h2 @ p[f'{i}.fc1'].T
            fr = np.maximum(f, 0)
            x = x2 + fr @ p[f'{i}.fc2'].T
            layers.append((x_in, h, rh, qh, kh, vh, a, o, x2, h2, rh2, f, fr))

        logits = x @ p['lm_head'].T
        return logits, (tokens, T, x0, r1, layers, x)

    def backward(self, cache, dlogits):
        p = self.p
        tokens, T, x0, r1, layers, x_out = cache
        g = {kk: np.zeros_like(vv) for kk, vv in p.items()}

        g['lm_head'] += dlogits.T @ x_out
        dx = dlogits @ p['lm_head']

        for i in reversed(range(n_layer)):
            x_in, h, rh, qh, kh, vh, a, o, x2, h2, rh2, f, fr = layers[i]

            dfr = dx @ p[f'{i}.fc2']
            g[f'{i}.fc2'] += dx.T @ fr
            df = dfr * (f > 0)
            g[f'{i}.fc1'] += df.T @ h2
            dh2 = df @ p[f'{i}.fc1']
            dx2 = dx + drmsnorm(dh2, x2, rh2)

            do = dx2 @ p[f'{i}.wo']
            g[f'{i}.wo'] += dx2.T @ o
            doh = do.reshape(T, n_head, head_dim).transpose(1, 0, 2)
            da = doh @ vh.transpose(0, 2, 1)
            dvh = a.transpose(0, 2, 1) @ doh
            datt = a * (da - (da * a).sum(-1, keepdims=True))
            datt /= math.sqrt(head_dim)
            dqh = datt @ kh
            dkh = datt.transpose(0, 2, 1) @ qh

            def merge(z):
                return z.transpose(1, 0, 2).reshape(T, n_embd)
            dq, dk, dv = merge(dqh), merge(dkh), merge(dvh)
            g[f'{i}.wq'] += dq.T @ h
            g[f'{i}.wk'] += dk.T @ h
            g[f'{i}.wv'] += dv.T @ h
            dh = dq @ p[f'{i}.wq'] + dk @ p[f'{i}.wk'] + dv @ p[f'{i}.wv']
            dx = dx2 + drmsnorm(dh, x_in, rh)

        dx0 = drmsnorm(dx, x0, r1)
        np.add.at(g['wte'], tokens, dx0)
        g['wpe'][:T] += dx0
        return g

    def step(self, g, t, steps):
        lr = learning_rate * (1 - t / steps)
        for kk in self.p:
            self.m[kk] = beta1 * self.m[kk] + (1 - beta1) * g[kk]
            self.v[kk] = beta2 * self.v[kk] + (1 - beta2) * g[kk] ** 2
            mh = self.m[kk] / (1 - beta1 ** (t + 1))
            vh = self.v[kk] / (1 - beta2 ** (t + 1))
            self.p[kk] -= lr * mh / (np.sqrt(vh) + eps_adam)

    def loss_of(self, tokens):
        """Average surprise per token over the whole document, without touching
        the weights."""
        total, count = 0.0, 0
        for inp, tgt in windows(tokens, self.vocab):
            logits, _ = self.forward(inp)
            probs = softmax(logits)
            total += -np.log(np.maximum(probs[np.arange(len(tgt)), tgt], 1e-12)).sum()
            count += len(tgt)
        return total / count if count else None


def windows(tokens, vocab):
    """Cut one document into the windows the model actually sees.

    A connection carries hundreds of records and the attention window holds
    sixteen, so a document has to be split. Taking only its first window — which
    is what this did — threw away most of every capture: 878 records of real
    traffic became 350, and the model never saw what a connection looks like
    once it is past its opening exchange.

    The cut matches the runtime: mCache in Go clears its window when full and
    carries on from position zero, so training on consecutive windows teaches
    the model the same view it will be asked to score from. Targets run one
    token ahead and reach into the next window; the last one predicts BOS,
    the end of the stream."""
    out = []
    for i in range(0, len(tokens) - 1, block_size):
        inp = tokens[i:i + block_size]
        tgt = tokens[i + 1:i + 1 + len(inp)]
        if len(tgt) < len(inp):
            tgt = tgt + [vocab - 1]
        out.append((inp, np.array(tgt)))
    return out


def train(docs, vocab, seed=42):
    rng = np.random.default_rng(seed)
    model = Model(vocab, rng)
    batches = [w for d in docs for w in windows(d, vocab)]
    if not batches:
        raise SystemExit("no windows to train on")
    # With more windows than steps, walking them in order would train on the
    # openings of the first few connections and never reach the rest.
    rng.shuffle(batches)
    # A fixed 1000 steps was one pass over a small capture and a fifth of a pass
    # over a real one — the corpus got bigger and the model saw less of it. Scale
    # with the data so every window is visited a few times either way.
    steps = int(os.environ.get('STEPS', 0)) or max(num_steps, 4 * len(batches))
    for t in range(steps):
        inp, targets = batches[t % len(batches)]
        if len(inp) < 2:
            continue
        logits, cache = model.forward(inp)
        probs = softmax(logits)
        dlogits = probs.copy()
        dlogits[np.arange(len(targets)), targets] -= 1
        dlogits /= len(targets)
        model.step(model.backward(cache, dlogits), t, steps)
        if t % 500 == 0 or t == steps - 1:
            loss = -np.log(np.maximum(probs[np.arange(len(targets)), targets], 1e-12)).mean()
            print(f"step {t + 1:5d} / {steps} | windows {len(batches)} | loss {loss:.4f}", end='\r')
    print()
    return model


def alphabet(kind, docs):
    """The symbols a model of this feature is defined over.

    For the bucketed features this is every bucket, whether or not the corpus
    happened to contain it — not sorted(set(corpus)). Go sends mBucketOf(size)
    straight in as a token id, so the id of a bucket has to be the bucket, and
    with a set of what was seen it is only its rank among the survivors. A
    capture missing one bucket silently shifts every id above it, and weights
    exported from one that is missing several (flow-up here gives 3 buckets of
    10) index past the end of the embedding table in Go."""
    if kind == 'hello':
        return sorted(set(''.join(docs)))
    bounds = gap_bounds if kind.startswith('timing') else size_bounds
    return [chr(33 + i) for i in range(len(bounds))]


def tokenize(docs, chars):
    index = {c: i for i, c in enumerate(chars)}
    bos = len(chars)
    return [[bos] + [index[c] for c in d] for d in docs], len(chars) + 1, chars


def diff(kind, real_glob, ours_glob, seed=42):
    """Say what the gap is made of.

    A single number tells you that you are distinguishable, not what to change.
    This trains the same judge and then breaks its surprise down by class: which
    record sizes we emit that real traffic does not, and how much of the total
    each one costs. That is the difference between a score and a lead."""
    real = load_docs(kind, sorted(glob.glob(real_glob)))
    ours = load_docs(kind, sorted(glob.glob(ours_glob)))
    if not real or not ours:
        raise SystemExit("need documents on both sides")
    chars = alphabet(kind, real + ours)
    random.seed(seed)
    random.shuffle(real)
    cut = max(1, len(real) // 5)
    held, train_docs = real[:cut], real[1 * cut:]
    toks, vocab, _ = tokenize(train_docs, chars)
    model = train(toks, vocab, seed)
    index = {c: i for i, c in enumerate(chars)}

    def shape(ds):
        n = [len(d) for d in ds]
        return sum(n) / len(n) if n else 0.0

    def surprise_by_class(ds):
        """Average -log p the judge pays for each class we emit, and how often."""
        cost = [0.0] * len(chars)
        seen = [0] * len(chars)
        for d in ds:
            tokens = [vocab - 1] + [index[c] for c in d if c in index]
            for inp, tgt in windows(tokens, vocab):
                logits, _ = model.forward(inp)
                probs = softmax(logits)
                for pos, target in enumerate(tgt):
                    if target >= len(chars):
                        continue
                    cost[target] += -math.log(max(probs[pos][target], 1e-12))
                    seen[target] += 1
        return cost, seen

    print(f"feature: {kind} | real docs {len(real)} | ours {len(ours)}")
    print(f"records per connection: real {shape(real):.1f}   ours {shape(ours):.1f}")

    r_cost, r_seen = surprise_by_class(held)
    o_cost, o_seen = surprise_by_class(ours)
    r_total, o_total = sum(r_seen), sum(o_seen)
    bounds = gap_bounds if kind.startswith('timing') else size_bounds
    unit = 'us' if kind.startswith('timing') else 'B'

    print(f"\n{'class':<16}{'real %':>9}{'ours %':>9}{'nats/rec':>10}{'share of gap':>14}")
    total_excess = 0.0
    rows = []
    for i, c in enumerate(chars):
        lo = bounds[i]
        hi = bounds[i + 1] if i + 1 < len(bounds) else None
        name = f"{lo}-{hi}{unit}" if hi else f"{lo}+{unit}"
        r_share = 100 * r_seen[i] / r_total if r_total else 0.0
        o_share = 100 * o_seen[i] / o_total if o_total else 0.0
        o_mean = o_cost[i] / o_seen[i] if o_seen[i] else 0.0
        # What this class contributes to our average surprise: its cost per
        # record times how much of our traffic it is.
        excess = o_mean * (o_seen[i] / o_total) if o_total else 0.0
        total_excess += excess
        rows.append((name, r_share, o_share, o_mean, excess))
    for name, r_share, o_share, o_mean, excess in rows:
        if r_share < 0.05 and o_share < 0.05:
            continue
        pct = 100 * excess / total_excess if total_excess else 0.0
        print(f"{name:<16}{r_share:>8.1f}%{o_share:>8.1f}%{o_mean:>10.2f}{pct:>13.0f}%")
    print(f"\nour average surprise: {total_excess:.2f} nats/record")
    print("share of gap: where our surprise comes from. A class we emit often and")
    print("the judge does not expect is what to change first.")


def stats(real_glob, direction='down'):
    """Print the constants the Go shaper is calibrated with, measured.

    Every table in relay.go came from a capture read by the parser that had no
    TCP reassembly, so they describe a stream 86% of whose connections had lost
    framing — the run of tiny records they encode is mostly the wreckage of
    half-parsed ones. These are the same quantities off a reassembled capture."""
    flows = _ns['raw_flows'](sorted(glob.glob(real_glob)), direction)
    sizes = [s for f, _ in flows for s in f]
    gaps = [g for _, gs in flows for g in gs[1:]]
    if not sizes:
        raise SystemExit("no records")

    small_limit = 1000
    runs = {(False, False): 0, (False, True): 0, (True, False): 0, (True, True): 0}
    for f, _ in flows:
        for a, b in zip(f, f[1:]):
            runs[(a < small_limit, b < small_limit)] += 1
    after_small = runs[(True, True)] / max(runs[(True, True)] + runs[(True, False)], 1)
    after_full = runs[(False, True)] / max(runs[(False, True)] + runs[(False, False)], 1)

    print(f"connections {len(flows)} | records {len(sizes)} | per connection {len(sizes)/len(flows):.1f}")
    print(f"\n// smallRecordLimit = {small_limit}")
    print(f"smallAfterSmall = {after_small:.4f}")
    print(f"smallAfterFull  = {after_full:.4f}")

    counts = {}
    for s in sizes:
        if s < small_limit:
            counts[s] = counts.get(s, 0) + 1
    top = sorted(counts.items(), key=lambda kv: -kv[1])[:15]
    print(f"\nvar smallWireSizes = []struct{{ size, weight int }}{{")
    for size, weight in sorted(top):
        print(f"\t{{{size}, {weight}}},", end='')
    print("\n}")

    print(f"\nvar realGapWeights = []struct{{ upTo, weight int }}{{")
    edges = gap_bounds[1:] + [2000000]
    lo, line = 0, []
    for hi in edges:
        line.append((hi, sum(1 for g in gaps if lo <= g < hi)))
        lo = hi
    for i in range(0, len(line), 4):
        print('\t' + ' '.join(f"{{{h}, {w}}}," for h, w in line[i:i + 4]))
    print("}")

    # Filler records have to be sized like real ones or they are just a new
    # signature wearing a hat. These are the sizes real traffic actually emits,
    # over the whole range and not only the small end, so a record invented to
    # fill a silence lands on a size the origin would have sent.
    whole = {}
    for s in sizes:
        whole[s] = whole.get(s, 0) + 1
    top = sorted(whole.items(), key=lambda kv: -kv[1])[:24]
    covered = sum(w for _, w in top)
    print(f"\nvar realWireSizes = []struct{{ size, weight int }}{{")
    for i in range(0, len(top), 4):
        print('\t' + ' '.join(f"{{{s}, {w}}}," for s, w in sorted(top[i:i + 4])))
    print("}")
    print(f"// covers {100*covered/len(sizes):.0f}% of real records")

    full = sum(1 for s in sizes if s >= 16000)
    print(f"\nfull-size records (16000+): {100*full/len(sizes):.1f}% of real traffic")


def shape(real_glob, ours_glob, direction='down'):
    """Compare the two distributions directly, without a model in the way.

    The judge predicts the next value from the previous ones, which works for
    record sizes and not for gaps: a server pauses because it ran out of data,
    not because it paused before, so timing scores learned 0.02 and its verdicts
    meant nothing. But the thing we actually want to know — do our pauses look
    like real ones — is a question about distributions, and that needs no model
    at all. This is what showed the idle filler works: it moved our median gap
    from 32us to 115us against real traffic's 115us."""
    def summarise(paths):
        flows = _ns['raw_flows'](sorted(glob.glob(paths)), direction)
        sizes = sorted(s for f, _ in flows for s in f)
        gaps = sorted(g for _, gs in flows for g in gs[1:])
        return flows, sizes, gaps

    rf, rs, rg = summarise(real_glob)
    of, os_, og = summarise(ours_glob)
    if not rs or not os_:
        raise SystemExit("need records on both sides")

    def q(xs, p):
        return xs[min(int(len(xs) * p), len(xs) - 1)] if xs else 0

    def share(xs, pred):
        return 100 * sum(1 for x in xs if pred(x)) / len(xs) if xs else 0.0

    rows = [
        ("connections", len(rf), len(of), ''),
        ("records per connection", len(rs) / max(len(rf), 1), len(os_) / max(len(of), 1), ''),
        ("record size, median", q(rs, 0.5), q(os_, 0.5), 'B'),
        ("records >= 16000B", share(rs, lambda s: s >= 16000), share(os_, lambda s: s >= 16000), '%'),
        ("records < 64B", share(rs, lambda s: s < 64), share(os_, lambda s: s < 64), '%'),
        ("gap, median", q(rg, 0.5), q(og, 0.5), 'us'),
        ("gap, p90", q(rg, 0.9), q(og, 0.9), 'us'),
        ("gaps < 100us", share(rg, lambda g: g < 100), share(og, lambda g: g < 100), '%'),
    ]
    print(f"\n{'':<26}{'real':>12}{'ours':>12}{'off by':>10}")
    print('-' * 60)
    for name, r, o, unit in rows:
        off = '' if not r else f"{(o - r) / r * 100:+.0f}%"
        print(f"{name:<26}{r:>11.1f}{unit:<1}{o:>11.1f}{unit:<1}{off:>10}")
    print("\nNo model here: these are the distributions themselves. A judge is only")
    print("needed for what depends on order; how often a size or a pause occurs is")
    print("answered by counting.")


def gradcheck():
    """Check the hand-written derivatives against the definition of a derivative.

    backward() is written out by hand — that is the whole reason this file is
    fast — so nothing catches an error in it except this. A wrong gradient does
    not crash: it trains to a worse model, and every number downstream is quietly
    off. Run it after touching forward or backward, and with LAYER>1, where the
    chain through the residual stream is easy to get subtly wrong."""
    rng = np.random.default_rng(0)
    vocab = 7
    m = Model(vocab, rng)
    tokens = [vocab - 1, 0, 1, 2, 3]
    targets = np.array([0, 1, 2, 3, vocab - 1])

    def loss():
        logits, _ = m.forward(tokens)
        return -np.log(softmax(logits)[np.arange(len(targets)), targets]).mean()

    logits, cache = m.forward(tokens)
    probs = softmax(logits)
    d = probs.copy()
    d[np.arange(len(targets)), targets] -= 1
    d /= len(targets)
    g = m.backward(cache, d)

    eps, worst, checked = 1e-6, 0.0, 0
    print(f"layers {n_layer} | embd {n_embd} | heads {n_head} | params {m.size()}")
    for name in sorted(m.p):
        for i, j in ((0, 0), (m.p[name].shape[0] - 1, m.p[name].shape[1] - 1)):
            m.p[name][i, j] += eps
            hi = loss()
            m.p[name][i, j] -= 2 * eps
            lo = loss()
            m.p[name][i, j] += eps
            num = (hi - lo) / (2 * eps)
            # Relative error is meaningless on a gradient of ~1e-9, where the
            # numeric estimate is mostly rounding; judge those on absolute size.
            err = abs(num - g[name][i, j]) / max(abs(num), 1e-6)
            worst = max(worst, err)
            checked += 1
    print(f"checked {checked} entries | worst relative error {worst:.2e}")
    if worst > 1e-3:
        raise SystemExit("gradients disagree with the numeric estimate")
    print("gradients agree")


def shapes(real_glob, ours_globs, direction='down'):
    """Same comparison as shape, over several captures, with the spread.

    One capture is not a measurement. Two runs of identical code came out at 25.8
    and 8.4 records per connection because the sites answered differently — and a
    change was credited for it. Anything smaller than the spread printed here is
    not a result."""
    def summarise(paths):
        flows = _ns['raw_flows'](sorted(glob.glob(paths)), direction)
        sizes = sorted(s for f, _ in flows for s in f)
        gaps = sorted(g for _, gs in flows for g in gs[1:])
        if not sizes:
            return None
        q = lambda xs, p: xs[min(int(len(xs) * p), len(xs) - 1)] if xs else 0
        share = lambda xs, f: 100 * sum(1 for x in xs if f(x)) / len(xs) if xs else 0.0
        return {
            'records per connection': len(sizes) / max(len(flows), 1),
            'record size, median': q(sizes, 0.5),
            'records >= 16000B': share(sizes, lambda s: s >= 16000),
            'records < 64B': share(sizes, lambda s: s < 64),
            'gap, median': q(gaps, 0.5),
            'gap, p90': q(gaps, 0.9),
            'gaps < 100us': share(gaps, lambda g: g < 100),
        }

    ref = summarise(real_glob)
    if ref is None:
        raise SystemExit("no records in the reference")
    runs = [m for m in (summarise(p) for p in ours_globs) if m]
    if not runs:
        raise SystemExit("no records on our side")

    print(f"\nreference: {os.path.basename(real_glob)}   ours: {len(runs)} capture(s)\n")
    print(f"{'':<26}{'real':>10}{'ours (mean)':>14}{'spread':>9}{'off by':>9}")
    print('-' * 68)
    for key in ref:
        vals = [r[key] for r in runs]
        mean = sum(vals) / len(vals)
        spread = (max(vals) - min(vals)) / 2
        off = '' if not ref[key] else f"{(mean - ref[key]) / ref[key] * 100:+.0f}%"
        flag = ' (noise)' if ref[key] and spread > abs(mean - ref[key]) else ''
        print(f"{key:<26}{ref[key]:>10.1f}{mean:>14.1f}{spread:>8.1f}{off:>9}{flag}")
    print("\nspread is half the range across runs. Where it exceeds the distance to")
    print("real, the difference is not measurable with this many captures.")


def control(kind, real_glob, seed=42):
    """Hold the judge to a known answer before believing it on ours.

    Real traffic split in three: train, held-out, and a second held-out piece
    fed in as if it were ours. The gap between the last two is by construction
    zero — same source, same everything — so whatever the judge reports there is
    its own noise floor. A gap on our traffic smaller than this number is not a
    finding, and a control that comes out far from zero means the judge is
    overfitting and none of its verdicts count."""
    docs = load_docs(kind, sorted(glob.glob(real_glob)))
    if len(docs) < 15:
        raise SystemExit(f"need at least 15 connections to split three ways, got {len(docs)}")
    random.seed(seed)
    random.shuffle(docs)
    cut = max(1, len(docs) // 5)
    held, as_ours, train_docs = docs[:cut], docs[cut:2 * cut], docs[2 * cut:]
    chars = alphabet(kind, docs)
    toks, vocab, _ = tokenize(train_docs, chars)
    model = train(toks, vocab, seed)
    index = {c: i for i, c in enumerate(chars)}

    def mean(ds):
        vals = []
        for d in ds:
            loss = model.loss_of([vocab - 1] + [index[c] for c in d if c in index])
            if loss is not None:
                vals.append(loss)
        return sum(vals) / len(vals) if vals else float('nan')

    counts = {}
    total = 0
    for d in train_docs:
        for c in d:
            counts[c] = counts.get(c, 0) + 1
            total += 1
    freq = -sum((c / total) * math.log(c / total) for c in counts.values())

    held_loss, ours_loss = mean(held), mean(as_ours)
    print(f"control/{kind} | train {len(train_docs)} | held {len(held)} | as-ours {len(as_ours)}")
    print(f"guessing by frequency: {freq:.4f}")
    print(f"the judge, held-out:   {held_loss:.4f}  (learned {freq - held_loss:+.4f})")
    print(f"the judge, as-ours:    {ours_loss:.4f}")
    print(f"noise floor: {abs(ours_loss - held_loss):.4f} nats/record")
    print("Any gap on real traffic smaller than this means nothing.")


PROBE_HISTORIES = ([], [0], [0, 5], [5, 5, 5])


def probe(weights_go):
    """Read weights back out of the generated Go file and run them.

    The Go port reimplements the forward pass by hand, so it can drift from the
    trainer without anything failing. These numbers are what the trainer says for
    the weights actually compiled in; TestPortAgreesWithTheTrainer holds the Go
    side to them."""
    import re
    src = open(weights_go, encoding='utf-8').read()
    pre = re.search(r'const (\w+?)Vocab, ', src).group(1)
    dims = re.search(r'Vocab, \w+Embd, \w+Head, \w+Block, \w+Layer = '
                     r'(\d+), (\d+), (\d+), (\d+), (\d+)', src)
    vocab, embd, heads = int(dims.group(1)), int(dims.group(2)), int(dims.group(3))
    block, layers = int(dims.group(4)), int(dims.group(5))
    # Every dimension, not just embd and layers. Heads and block size leave the
    # weight shapes untouched, so a mismatch loads cleanly and computes a
    # different attention — and probe then overwrites the Go test's expectations
    # with numbers no port could ever produce.
    if (embd, heads, block, layers) != (n_embd, n_head, block_size, n_layer):
        raise SystemExit(
            f"weights are {layers}x{embd}, {heads} heads, block {block}; "
            f"this run is {n_layer}x{n_embd}, {n_head} heads, block {block_size}: "
            f"set LAYER={layers} EMBD={embd} HEAD={heads} BLOCK={block}")

    model = Model(vocab, np.random.default_rng(0))
    for key in ('wte', 'wpe', 'lm_head'):
        body = re.search(r'var ' + pre + '_' + key + r' = \[\]\[\]float64\{(.*?)\n\}', src, re.S).group(1)
        rows = re.findall(r'\{([^{}]*)\}', body)
        model.p[key] = np.array([[float(x) for x in r.split(',')] for r in rows])
    # Per-layer weights are slices of matrices; take them apart the same way.
    for part in ('wq', 'wk', 'wv', 'wo', 'fc1', 'fc2'):
        body = re.search(r'var ' + pre + '_' + part + r' = \[\]\[\]\[\]float64\{(.*?)\n\}', src, re.S).group(1)
        blocks = re.findall(r'\{\n(.*?)\n\t\},', body, re.S)
        for i, block in enumerate(blocks):
            rows = re.findall(r'\{([^{}]*)\}', block)
            model.p[f'{i}.{part}'] = np.array([[float(x) for x in r.split(',')] for r in rows])
    rows = []
    for hist in PROBE_HISTORIES:
        logits, _ = model.forward([vocab - 1] + hist)
        probs = softmax(logits[-1])
        rows.append(probs)
        print('probe ' + str(hist) + ': ' + ' '.join(f'{p:.6f}' for p in probs))

    # Write the numbers into the Go test as well. Copying four rows of eleven
    # floats by hand after every retrain is a step that gets skipped, and a
    # skipped update turns the one test guarding the port into a failing one
    # everybody learns to ignore.
    test_go = os.environ.get('PROBE_TEST', 'core/relay/model_test.go')
    if not os.path.exists(test_go):
        return
    src_t = open(test_go, encoding='utf-8').read()
    block = ['\twant := map[int][]float64{']
    for i, probs in enumerate(rows):
        block.append(f'\t\t{i}: {{' + ', '.join(f'{p:.6f}' for p in probs) + '},')
    block.append('\t}')
    new = chr(10).join(block)
    start = src_t.index('\twant := map[int][]float64{')
    end = src_t.index('\t}', src_t.index('\t\t3: ', start)) + len('\t}')
    open(test_go, 'w', encoding='utf-8').write(src_t[:start] + new + src_t[end:])
    print(f'updated probe values in {test_go}')


def main():
    if len(sys.argv) < 2:
        raise SystemExit(__doc__)
    mode = sys.argv[1]

    if mode == 'probe':
        probe(sys.argv[2] if len(sys.argv) > 2 else 'core/relay/model_weights.go')
        return

    if mode == 'diff':
        diff(sys.argv[2], sys.argv[3], sys.argv[4])
        return

    if mode == 'control':
        control(sys.argv[2], sys.argv[3])
        return

    if mode == 'shapes':
        shapes(sys.argv[2], sys.argv[3:])
        return

    if mode == 'gradcheck':
        gradcheck()
        return

    if mode == 'shape':
        shape(sys.argv[2], sys.argv[3], sys.argv[4] if len(sys.argv) > 4 else 'down')
        return

    if mode == 'stats':
        stats(sys.argv[2], sys.argv[3] if len(sys.argv) > 3 else 'down')
        return

    if mode == 'eval':
        kind, real_glob, ours_glob = sys.argv[2], sys.argv[3], sys.argv[4]
        real = load_docs(kind, sorted(glob.glob(real_glob)))
        ours = load_docs(kind, sorted(glob.glob(ours_glob)))
        random.seed(int(os.environ.get('SEED', '42')))
        random.shuffle(real)
        cut = max(1, len(real) // 5)
        held, train_docs = real[:cut], real[cut:]

        seed = int(os.environ.get('SEED', '42'))
        random.seed(seed)
        random.shuffle(train_docs)
        toks, vocab, chars = tokenize(train_docs, alphabet(kind, train_docs))
        model = train(toks, vocab, seed)
        index = {c: i for i, c in enumerate(chars)}

        def encode(ds):
            return [[vocab - 1] + [index[c] for c in d if c in index] for d in ds]

        def mean(ds):
            vals = [l for l in (model.loss_of(t) for t in encode(ds)) if l is not None]
            return sum(vals) / len(vals) if vals else float('nan')

        counts = {}
        total = 0
        for d in train_docs:
            for c in d:
                counts[c] = counts.get(c, 0) + 1
                total += 1
        freq = -sum((c / total) * math.log(c / total) for c in counts.values())

        held_loss, our_loss = mean(held), mean(ours)
        print(f"mode: eval/{kind} | train {len(train_docs)} | held-out {len(held)} | ours {len(ours)}")
        print(f"guessing by frequency:     {freq:.4f}")
        print(f"the model:                 {held_loss:.4f}")
        print(f"-> learned: {freq - held_loss:.4f}")
        print(f"loss on our traffic:       {our_loss:.4f}")
        print(f"gap: {our_loss - held_loss:+.4f} nats/token")
        return

    docs = load_docs(mode, sorted(glob.glob(sys.argv[2])))
    if not docs:
        raise SystemExit("no documents")
    print(f"mode: {mode} | docs {len(docs)}")
    toks, vocab, chars = tokenize(docs, alphabet(mode, docs))
    model = train(toks, vocab)

    export = os.environ.get('EXPORT')
    if export:
        pre = os.environ.get('PREFIX', 'm')
        bounds = gap_bounds if mode.startswith('timing') else size_bounds
        blist = ', '.join(str(x) for x in bounds)
        out = ['// Code generated by neural/fast.py. DO NOT EDIT.', '', 'package relay', '']
        out.append(f'// Trained on {len(docs)} documents of real traffic, mode {mode}.')
        out.append(f'// {model.size()} parameters: {n_layer} layer(s), embd {n_embd}, {n_head} heads.')
        out.append(f'const {pre}Vocab, {pre}Embd, {pre}Head, {pre}Block, {pre}Layer = '
                   f'{vocab}, {n_embd}, {n_head}, {block_size}, {n_layer}')
        out.append('')
        out.append(f'var {pre}Bounds = []int{{{blist}}}')
        out.append('')

        def matrix(name, mat):
            out.append(f'var {pre}_{name} = [][]float64{{')
            for row in mat:
                out.append(chr(9) + '{' + ', '.join(f'{v:.6f}' for v in row) + '},')
            out.append('}')
            out.append('')

        for key in ('wte', 'wpe', 'lm_head'):
            matrix(key, model.p[key])
        # Per-layer weights go out as slices of matrices so Go can loop over
        # depth instead of naming every layer.
        for part in ('wq', 'wk', 'wv', 'wo', 'fc1', 'fc2'):
            out.append(f'var {pre}_{part} = [][][]float64{{')
            for i in range(n_layer):
                out.append(chr(9) + '{')
                for row in model.p[f'{i}.{part}']:
                    out.append(chr(9) * 2 + '{' + ', '.join(f'{v:.6f}' for v in row) + '},')
                out.append(chr(9) + '},')
            out.append('}')
            out.append('')
        io.open(export, 'w', encoding='utf-8').write(chr(10).join(out))
        print(f'exported {model.size()} parameters to {export}')


if __name__ == '__main__':
    main()