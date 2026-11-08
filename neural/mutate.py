"""A policy that picks the next mutation, trained on dial outcomes.

This is not a judge. The model never scores traffic and never sees a packet. It
reads the recent history of (arm played, outcome) and answers one question: if I
play this arm next, does the handshake survive? The controller plays the arm
with the best answer, so the network acts in the traffic instead of grading it.

Why a network at all, when UCB1 already converges. UCB1 averages an arm over the
whole run, which makes it blind to time: a censor that turns its rule over every
K dials costs the bandit the same dials at every switch, forever, because the
evidence that the arm was good is still in the average. A sequence model sees
the history, so it can notice the turn-over and move before the loss. That is
the whole of "mutate faster than the censor's cycle" in one measurement.

Two censors are measured, because the answer depends on the censor:

  easy  the two rules share a safe arm (budget 2 survives both) - this is the
        Docker stand as it stands today, and anything wins on it
  hard  the safe sets are disjoint, so no fixed arm survives and the only way
        to avoid losses is to anticipate the switch

    python neural/mutate.py easy
    python neural/mutate.py hard
"""

import csv
import io
import json
import math
import os
import random
import sys


# The dial policy in PyTorch. The Go client runs the forward pass on every dial;
# this side trains it, offline from policyfit and online on this machine, over a
# JSON-lines pipe the client opens (op "torchserve"). Sources for each choice:
#   stacked self-attention blocks over the dial sequence, b=2 (SASRec, Kang &
#   McAuley ICDM 2018, arxiv 1808.09781, ablation on b), pre-norm residual
#   blocks (Xiong et al. ICML 2020, arxiv 2002.04745) with a final norm after
#   the last block (GPT-2, Radford et al. 2019), dropout on the embedding and
#   sublayer outputs (SASRec, 0.2 on dense data); numeric measurements enter
#   as a linear projection added to the token (FT-Transformer, Gorishniy et al.
#   NeurIPS 2021, arxiv 2106.11959) next to a "measured" indicator, the masking
#   input of GRU-D (Che et al. Sci Rep 2018); time of day and day of week as
#   sin/cos of their periods, the periodic part of Time2Vec (Kazemi et al.
#   2019, arxiv 1907.05321); online steps pull toward the
#   shipped weights with lambda/2 |theta - theta0|^2 (NeuralUCB, Zhou et al.
#   ICML 2020); failures of the arm and its siblings enter as a hazard, survival = sigmoid(z) * exp(-sum softplus(w_k) r_k) with
#   r_k a decayed count of recent failures: proportional hazards (Cox, JRSS-B 1972) over a self-exciting intensity
#   (Hawkes, Biometrika 1971) kept positive by softplus (Neural Hawkes, Mei & Eisner NeurIPS 2017), log(1 - e^x)
#   computed as in Maechler (Rmpfr vignette 2012); the first packets of each dial (direction, size, gap, TCP flags,
#   TTL against the server's, window, TLS record type and length) pass a 2-layer bidirectional GRU with H=8 and the
#   final states of every layer and direction become the dial's packet vector (RAPIER, Qing et al. 2023, arxiv
#   2309.04798, Table II, after FS-Net, Liu et al. INFOCOM 2019), with the gate equations and U(-1/sqrt(H), 1/sqrt(H))
#   init of torch.nn.GRU; offline the encoder also restores its own packet tokens through a mirrored GRU decoder at
#   weight 0.5 with gradients clipped to norm 5 (FS-Net reference code, github.com/WSPTTH/FS-Net), and predicts the
#   outcome of its own dial from its packets with the classes rebalanced to equal weight and task weight 1, the
#   reward-prediction auxiliary task of UNREAL (Jaderberg et al. ICLR 2017, arxiv 1611.05397); offline each dial's
#   packets, death tail and hello-chain position are each hidden with probability 0.1 and shown as missing, so the
#   net stays right where captures are absent (ModDrop, Neverova et al. TPAMI 2016, arxiv 1501.00102); a check head trained
#   as in SelectiveNet (Geifman & El-Yaniv,
#   ICML 2019) rates how far each prediction can be trusted. Everything is float64 so the Go client reproduces the scores to
#   1e-9 and rejects any reply it cannot. After a fit the packet vectors of the training dials get one Gaussian per outcome
#   with a tied covariance and the death tails one of their own (Lee et al. NeurIPS 2018, arxiv 1807.03888), the
#   covariance shrunk toward a scaled identity as in Ledoit & Wolf (J. Multivariate Anal. 2004, sklearn LedoitWolf) so a
#   field that never varied on the stand does not dominate the distance; the bar on the Mahalanobis distance is the
#   conformal threshold over the validation dials, so at most a share alpha of failed dials under blocks the net trained on
#   pass it (marginal conformal p-values, Bates, Candes, Lei, Romano & Sesia, Ann. Statist. 2023, arxiv 2104.08279), and
#   a failed dial past it is a block pattern the net never trained on.

def torch_net(torch, cfg):
    nn = torch.nn
    E, heads, H = cfg['embd'], cfg['heads'], cfg['hidden_scale'] * cfg['embd']
    shapes = {
        'arm': (cfg['arms'], E), 'win': (E, len(cfg['arm_features'][0])), 'outcome': (cfg['outcomes'], E),
        'wire': (E, cfg['wire_dims']), 'meas': (E, cfg['meas_dims']), 'gap_in': (E, 1), 'slow_in': (E, 1),
        'gap_query': (E, 1), 'chain_query': (E, cfg['chain_dims']), 'bos_in': (1, E), 'wpe': (cfg['block'], E), 'recent': (1, cfg['recent_dims']),
        'clock': (E, cfg['clock_dims']), 'clock_query': (E, cfg['clock_dims']),
        'check': (1, E), 'check_bias': (1, 1),
    }
    for l in range(cfg['layers']):
        for name, shape in (('wq', (E, E)), ('wk', (E, E)), ('wv', (E, E)), ('wo', (E, E)), ('fc1', (H, E)), ('fc2', (E, H))):
            shapes['%d.%s' % (l, name)] = shape
    PH, PL = cfg['packet_hidden'], cfg['packet_layers']
    shapes['pkt'] = (E, 2 * PL * PH)
    shapes['pkt_tail'] = (E, 2 * PL * PH)
    for l in range(PL):
        for d in ('f', 'b'):
            width = cfg['packet_dims'] if l == 0 else 2 * PH
            for name, shape in (('ih', (3 * PH, width)), ('hh', (3 * PH, PH)), ('bih', (1, 3 * PH)), ('bhh', (1, 3 * PH))):
                shapes['gru.%d.%s.%s' % (l, d, name)] = shape
    for l in range(PL):
        for d in ('f', 'b'):
            width = 2 * PL * PH if l == 0 else 2 * PH
            for name, shape in (('ih', (3 * PH, width)), ('hh', (3 * PH, PH)), ('bih', (1, 3 * PH)), ('bhh', (1, 3 * PH))):
                shapes['dec.%d.%s.%s' % (l, d, name)] = shape
    from torch.func import functional_call
    grus = {
        'gru': nn.GRU(cfg['packet_dims'], PH, PL, batch_first=True, bidirectional=True),
        'dec': nn.GRU(2 * PL * PH, PH, PL, batch_first=True, bidirectional=True),
    }
    V = 2 * cfg['rec_buckets']
    shapes.update({'rec.w1': (PH, 2 * PH), 'rec.b1': (1, PH), 'rec.w2': (V, PH), 'rec.b2': (1, V)})
    shapes.update({'aux.w': (cfg['outcomes'], 2 * PL * PH), 'aux.b': (1, cfg['outcomes'])})

    class PolicyNet(nn.Module):
        def __init__(self):
            super().__init__()
            self.names = list(shapes)
            self.index = {}
            self.w = nn.ParameterList()
            for name, shape in shapes.items():
                if name in cfg['zero_init']:
                    start = torch.zeros(shape)
                elif name.startswith(('gru.', 'dec.')):
                    bound = 1 / math.sqrt(PH)
                    start = torch.rand(shape) * 2 * bound - bound
                else:
                    start = torch.randn(shape) * cfg['init_std']
                self.index[name] = len(self.w)
                self.w.append(nn.Parameter(start))
            self.register_buffer('feat', torch.tensor(cfg['arm_features']))
            self.cfg = cfg
            self.drop = nn.Dropout(cfg['dropout'])
            self.rec_weight = 0.0
            self.rec = torch.zeros(())
            self.aux_weight = 0.0
            self.moddrop = 0.0
            self.aux = torch.zeros(())

        def P(self, name):
            return self.w[self.index[name]]

        def load(self, mats):
            with torch.no_grad():
                for name in self.names:
                    if name in mats:
                        self.P(name).copy_(torch.tensor(mats[name]))

        def mats(self):
            return {name: self.P(name).detach().tolist() for name in self.names}

        def norm(self, x):
            return x / torch.sqrt((x * x).mean(-1, keepdim=True) + cfg['norm_eps'])

        def gru_stack(self, prefix, x, lens):
            weights = {}
            for l in range(PL):
                for d, suffix in (('f', ''), ('b', '_reverse')):
                    for ours, theirs in (('ih', 'weight_ih'), ('hh', 'weight_hh')):
                        weights['%s_l%d%s' % (theirs, l, suffix)] = self.P('%s.%d.%s.%s' % (prefix, l, d, ours))
                    for ours, theirs in (('bih', 'bias_ih'), ('bhh', 'bias_hh')):
                        weights['%s_l%d%s' % (theirs, l, suffix)] = self.P('%s.%d.%s.%s' % (prefix, l, d, ours))[0]
            packed = nn.utils.rnn.pack_padded_sequence(x, lens, batch_first=True, enforce_sorted=False)
            out, h = functional_call(grus[prefix], weights, (packed,))
            out, _ = nn.utils.rnn.pad_packed_sequence(out, batch_first=True, total_length=x.shape[1])
            return h.permute(1, 0, 2).reshape(x.shape[0], -1), out

        def reconstruction(self, seqs, lens, enc):
            _, out = self.gru_stack('dec', enc.unsqueeze(1).expand(-1, seqs.shape[1], -1).contiguous(), lens)
            hidden = nn.functional.selu(out @ self.P('rec.w1').T + self.P('rec.b1')[0])
            logits = hidden @ self.P('rec.w2').T + self.P('rec.b2')[0]
            buckets = cfg['rec_buckets']
            size = (seqs[..., 1] * buckets).long().clamp(max=buckets - 1)
            token = seqs[..., 0].long() * buckets + size
            loss = nn.functional.cross_entropy(logits.reshape(-1, logits.shape[-1]), token.reshape(-1), reduction='none')
            weight = (torch.arange(seqs.shape[1]).unsqueeze(0) < lens.unsqueeze(1)).reshape(-1).to(loss.dtype)
            return (loss * weight).sum() / weight.sum().clamp(min=1)

        def own_outcome(self, pool, tok, pk):
            has = pool.pkt[tok] > 0
            if not has.any():
                return torch.zeros(())
            y = pool.outcome[tok][has]
            logits = pk[has] @ self.P('aux.w').T + self.P('aux.b')[0]
            per = nn.functional.cross_entropy(logits, y, reduction='none')
            weight = (1 / torch.bincount(y, minlength=cfg['outcomes']).to(per.dtype).clamp(min=1))[y]
            return (per * weight).sum() / weight.sum()

        def packets(self, pool, rows, restore=False):
            uniq, inverse = torch.unique(rows, return_inverse=True)
            lens = pool.table.len[uniq]
            enc = pool.table.seq.new_zeros(len(uniq), 2 * PL * PH)
            full = lens > 0
            if full.any():
                kept = lens[full]
                seqs = pool.table.seq[uniq[full], :int(kept.max().item())]
                finals, _ = self.gru_stack('gru', seqs, kept)
                enc = enc.index_put((full.nonzero(as_tuple=True)[0],), finals)
                if restore and self.training and self.rec_weight > 0:
                    self.rec = self.reconstruction(seqs, kept, finals)
            return enc[inverse]

        def drop_modalities(self, pk, tail, meas, chain):
            def kept(like):
                return torch.rand(like.shape[:2]) >= self.moddrop
            keep_pk, keep_tail, keep_chain, keep_query = kept(pk), kept(tail), kept(meas), kept(chain)
            missing = meas.new_tensor(cfg['chain_missing'])
            at = cfg['chain_at']
            meas = torch.cat([meas[..., :1] * keep_pk.unsqueeze(-1), meas[..., 1:at],
                              torch.where(keep_chain.unsqueeze(-1), meas[..., at:], missing)], -1)
            chain = torch.where(keep_query.unsqueeze(-1), chain, missing)
            return pk * keep_pk.unsqueeze(-1), tail * keep_tail.unsqueeze(-1), meas, chain

        def forward(self, pool, tok, bos, tok_gap, tgt, qgap):
            B, T = tok.shape
            self.rec = torch.zeros(())
            self.aux = torch.zeros(())
            pk = self.packets(pool, pool.pkt[tok], restore=True)
            tail = self.packets(pool, pool.tail[tok])
            if self.training and self.aux_weight > 0:
                self.aux = self.own_outcome(pool, tok, pk)
            meas, chain = pool.meas[tok], pool.chain[tgt]
            if self.training and self.moddrop > 0:
                pk, tail, meas, chain = self.drop_modalities(pk, tail, meas, chain)
            arms = self.P('arm') + self.feat @ self.P('win').T
            wire = pool.wire[tok]
            seen = nn.functional.one_hot(wire.clamp(min=0), cfg['wire_dims']).to(arms.dtype) * (wire >= 0).unsqueeze(-1)
            emb = (arms[pool.arm[tok]] + self.P('outcome')[pool.outcome[tok]] + seen @ self.P('wire').T
                   + tok_gap.unsqueeze(-1) * self.P('gap_in')[:, 0] + pool.slow[tok].unsqueeze(-1) * self.P('slow_in')[:, 0]
                   + meas @ self.P('meas').T + pk @ self.P('pkt').T + tail @ self.P('pkt_tail').T
                   + pool.clock[tok] @ self.P('clock').T)
            emb = torch.where(bos.unsqueeze(-1), self.P('bos_in')[0].expand_as(emb), emb)
            x = self.norm(self.drop(emb + self.P('wpe')[:T]))
            hd = E // heads
            causal = torch.ones(T, T, dtype=torch.bool).tril()
            for l in range(cfg['layers']):
                h = self.norm(x)
                q, k, v = ((h @ self.P('%d.%s' % (l, n)).T).view(B, T, heads, hd).transpose(1, 2) for n in ('wq', 'wk', 'wv'))
                att = ((q @ k.transpose(-1, -2)) / math.sqrt(hd)).masked_fill(~causal, float('-inf')).softmax(-1)
                o = (att @ v).transpose(1, 2).reshape(B, T, E)
                mid = x + self.drop(o @ self.P('%d.wo' % l).T)
                x = mid + self.drop(torch.relu(self.norm(mid) @ self.P('%d.fc1' % l).T) @ self.P('%d.fc2' % l).T)
            x = self.norm(x)
            query = x + qgap.unsqueeze(-1) * self.P('gap_query')[:, 0] + pool.clock[tgt] @ self.P('clock_query').T + chain @ self.P('chain_query').T
            base = (query * arms[pool.arm[tgt]]).sum(-1)
            hazard = pool.recent[tgt] @ torch.logaddexp(self.P('recent')[0], torch.zeros(()))
            return nn.functional.logsigmoid(base) - hazard, query @ self.P('check')[0] + self.P('check_bias')[0, 0]

    return PolicyNet()


class PacketTable:
    """Packet sequences of the dials, one row per distinct sequence, row 0 empty."""

    def __init__(self, torch, rows, cfg):
        rows = rows or [[]]
        width = max([len(r or []) for r in rows] + [1])
        self.seq = torch.zeros(len(rows), width, cfg['packet_dims'])
        self.len = torch.zeros(len(rows), dtype=torch.long)
        for i, r in enumerate(rows):
            if r:
                self.seq[i, :len(r)] = torch.tensor(r)
                self.len[i] = len(r)


class TorchPool:
    """Docs flattened into one table, with a padding row at the end."""

    def __init__(self, torch, docs, cfg, table):
        self.table = table
        pkt = []
        chain = []
        tail = []
        arm, outcome, wire, gap, slow, meas, recent, clock = [], [], [], [], [], [], [], []
        self.spans = []
        for d in docs:
            n = len(d['arm'])
            self.spans.append((len(arm), n))
            arm += d['arm']
            outcome += d['outcome']
            wire += d['wire']
            gap += d['gap']
            slow += d['slow']
            meas += d.get('meas') or [[0.0] * cfg['meas_dims']] * n
            pkt += d.get('packets') or [0] * n
            tail += d.get('tail') or [0] * n
            chain += d.get('chain') or [[0.0, 1.0]] * n
            recent += d['recent']
            clock += d['clock']
        self.pad = len(arm)
        self.gap = torch.tensor(gap + [0.0])
        self.arm = torch.tensor(arm + [0], dtype=torch.long)
        self.outcome = torch.tensor(outcome + [0], dtype=torch.long)
        self.wire = torch.tensor(wire + [-1], dtype=torch.long)
        self.slow = torch.tensor(slow + [0.0])
        self.meas = torch.tensor(meas + [[0.0] * cfg['meas_dims']])
        self.pkt = torch.tensor(pkt + [0], dtype=torch.long)
        self.tail = torch.tensor(tail + [0], dtype=torch.long)
        self.chain = torch.tensor(chain + [[0.0, 1.0]])
        self.recent = torch.tensor(recent + [[0.0] * cfg['recent_dims']])
        self.clock = torch.tensor(clock + [[0.0] * cfg['clock_dims']])
        self.alive = (self.outcome == 0).to(self.slow.dtype)


def torch_windows(torch, pool, windows, block):
    """windows: (first row, start, end) per window. Token 0 is BOS, token i+1 is
    dial i; target i is dial i scored from the dials before it, the way the Go
    client scores a dial from its history."""
    w = torch.tensor(windows, dtype=torch.long).view(-1, 3)
    B = w.shape[0]
    base = (w[:, 0] + w[:, 1]).unsqueeze(1)
    n = (w[:, 2] - w[:, 1]).unsqueeze(1)
    i = torch.arange(block).unsqueeze(0)
    valid = i < n
    tgt = torch.where(valid, base + i, pool.pad)
    qgap = torch.where(valid & (i > 0), pool.gap[tgt], torch.zeros(()))
    held = (i >= 1) & (i - 1 < n - 1)
    tok = torch.where(held, base + i - 1, pool.pad)
    tok_gap = torch.where(held & (i >= 2), pool.gap[tok], torch.zeros(()))
    bos = (i == 0).expand(B, block)
    return tok, bos, tok_gap, tgt, qgap, valid


def torch_log1mexp(torch, x):
    """log(1 - e^x) for x < 0 without cancellation (Maechler 2012)."""
    return torch.where(x > -math.log(2), torch.log(-torch.expm1(x)), torch.log1p(-torch.exp(x)))


def torch_window_loss(torch, net, pool, windows, block, cfg):
    """SelectiveNet (Geifman & El-Yaniv, ICML 2019): the check head g learns
    which predictions to trust; risk is counted on what g trusts, a quadratic
    penalty holds its coverage at sel_coverage, and the survival head also
    trains on every dial as the auxiliary loss."""
    tok, bos, tok_gap, tgt, qgap, valid = torch_windows(torch, pool, windows, block)
    log_alive, check = net(pool, tok, bos, tok_gap, tgt, qgap)
    mask = valid.to(log_alive.dtype)
    log_alive = log_alive.clamp(max=-torch.finfo(log_alive.dtype).eps)
    alive = pool.alive[tgt]
    per = -(alive * log_alive + (1 - alive) * torch_log1mexp(torch, log_alive)) * mask
    aux = (per.sum(1) / mask.sum(1)).mean()
    g = torch.sigmoid(check) * mask
    coverage = g.sum() / mask.sum()
    risk = (per * g).sum() / g.sum()
    selective = risk + cfg['sel_lambda'] * torch.clamp(cfg['sel_coverage'] - coverage, min=0) ** 2
    return cfg['sel_alpha'] * selective + (1 - cfg['sel_alpha']) * aux + net.rec_weight * net.rec + net.aux_weight * net.aux


def torch_conditional(torch, net, pool, block, targets=None, chunk=4096, checks=None):
    """Probability each dial lives, from the dials before it in its doc; the
    check head's trust in each of those predictions goes to `checks`."""
    if targets is None:
        targets = [(row, i) for row, n in pool.spans for i in range(n)]
    out = []
    net.eval()
    with torch.no_grad():
        for c in range(0, len(targets), chunk):
            part = targets[c:c + chunk]
            windows = [(row, max(0, i + 1 - block), i + 1) for row, i in part]
            tok, bos, tok_gap, tgt, qgap, _ = torch_windows(torch, pool, windows, block)
            log_alive, check = net(pool, tok, bos, tok_gap, tgt, qgap)
            last = torch.tensor([e - s - 1 for _, s, e in windows])
            rows = torch.arange(len(part))
            out += torch.exp(log_alive[rows, last]).tolist()
            if checks is not None:
                checks += torch.sigmoid(check[rows, last]).tolist()
    return out


def torch_outcome_loss(p, alive, floor=1e-6):
    q = min(max(p, floor), 1 - floor)
    return -math.log(q) if alive else -math.log(1 - q)


def torch_mean_loss(torch, net, pool, block):
    probs = torch_conditional(torch, net, pool, block)
    if not probs:
        return 0.0
    alive = pool.alive[:-1].tolist()
    return sum(torch_outcome_loss(p, a == 1) for p, a in zip(probs, alive)) / len(probs)


def torch_ledoit_wolf(torch, x):
    n, p = x.shape
    cov = x.T @ x / n
    mu = torch.trace(cov) / p
    x2 = x * x
    beta = ((x2.T @ x2).sum() / n - (cov ** 2).sum()) / (p * n)
    delta = ((cov - mu * torch.eye(p)) ** 2).sum() / p
    shrinkage = torch.clamp(torch.minimum(beta, delta) / delta, min=0) if delta > 0 else torch.zeros(())
    return (1 - shrinkage) * cov + shrinkage * mu * torch.eye(p)


def torch_packet_sets(torch, net, pool, cfg):
    rows = torch.arange(pool.pad)
    opening, tail = pool.pkt[rows] > 0, pool.tail[rows] > 0
    return {
        'opening': (net.packets(pool, pool.pkt[rows])[opening], pool.outcome[rows][opening], cfg['outcomes']),
        'tail': (net.packets(pool, pool.tail[rows])[tail], torch.zeros(int(tail.sum()), dtype=torch.long), 1),
    }


def torch_gaussians(torch, enc, label, classes):
    count = torch.bincount(label, minlength=classes).to(enc.dtype)
    means = torch.zeros(classes, enc.shape[1]).index_add(0, label, enc) / count.clamp(min=1).unsqueeze(1)
    precision = torch.linalg.pinv(torch_ledoit_wolf(torch, enc - means[label]), hermitian=True)
    return means, precision, count


def torch_conformal_bars(torch, distance, label, classes, alpha):
    bars = []
    for c in range(classes):
        calibration = distance[label == c].sort(descending=True).values
        rank = int(alpha * (len(calibration) + 1))
        bars.append(calibration[rank - 1].item() if rank >= 1 else 0.0)
    return bars


def torch_novelty(torch, net, fit, calibration, cfg):
    net.train(False)
    out = {}
    with torch.no_grad():
        seen, held = torch_packet_sets(torch, net, fit, cfg), torch_packet_sets(torch, net, calibration, cfg)
        for name, (enc, label, classes) in seen.items():
            if not len(enc):
                out[name] = {}
                continue
            means, precision, count = torch_gaussians(torch, enc, label, classes)
            cal, cal_label, _ = held[name]
            centred = cal - means[cal_label]
            distance = ((centred @ precision) * centred).sum(-1)
            out[name] = {'mean': means.tolist(), 'precision': precision.tolist(), 'count': count.tolist(),
                         'calibrated': torch.bincount(cal_label, minlength=classes).tolist(),
                         'bar': torch_conformal_bars(torch, distance, cal_label, classes, cfg['novelty_alpha'])}
    return out


def torch_adam(torch, net, cfg):
    return torch.optim.Adam(net.parameters(), lr=cfg['rate'], betas=(cfg['beta1'], cfg['beta2']), eps=cfg['adam_eps'])


def torch_step(torch, net, opt, pool, windows, block, anchor=None, lam=0.0, dropout=False):
    net.train(dropout)
    loss = torch_window_loss(torch, net, pool, windows, block, net.cfg)
    if anchor is not None and lam > 0:
        loss = loss + lam / 2 * sum(((p - a) ** 2).sum() for p, a in zip(net.parameters(), anchor))
    opt.zero_grad()
    loss.backward()
    opt.step()
    return loss.item()


def torch_sample(rng, pool, block):
    row, n = pool.spans[rng.randrange(len(pool.spans))]
    end = 1 + rng.randrange(n)
    return row, max(0, end - block), end


def torch_replay(torch, cfg, start, pool, lam, every):
    """The client's online loop on held-out dials: score each dial, then every
    `every` dials take one anchored step on the window that ends there."""
    block = cfg['block']
    net = torch_net(torch, cfg)
    net.load(start)
    anchor = [p.detach().clone() for p in net.parameters()]
    opt = torch_adam(torch, net, cfg)
    total, n, pending = 0.0, 0, 0
    for row, length in pool.spans:
        i = 0
        while i < length:
            j = min(length, i + every - pending)
            probs = torch_conditional(torch, net, pool, block, [(row, k) for k in range(i, j)])
            total += sum(torch_outcome_loss(p, pool.alive[row + k].item() == 1) for p, k in zip(probs, range(i, j)))
            n += j - i
            pending += j - i
            if pending >= every:
                pending = 0
                torch_step(torch, net, opt, pool, [(row, max(0, j - block), j)], block, anchor, lam)
            i = j
    return total / n if n else 0.0


def torch_fit(torch, cfg, fit, log, table):
    block = cfg['block']
    rng = random.Random(fit['seed'])
    torch.manual_seed(fit['seed'])
    real = TorchPool(torch, fit['train'], cfg, table)
    synth = TorchPool(torch, fit['synthetic'], cfg, table)
    val = TorchPool(torch, fit['val'], cfg, table)
    synth_val = TorchPool(torch, fit['synthetic_val'], cfg, table)
    net = torch_net(torch, cfg)
    net.rec_weight = cfg['rec_loss']
    net.aux_weight = cfg['aux_loss']
    net.moddrop = cfg['moddrop']
    opt = torch_adam(torch, net, cfg)

    def val_loss():
        loss = torch_mean_loss(torch, net, val, block)
        if synth_val.spans:
            loss += torch_mean_loss(torch, net, synth_val, block)
        return loss

    best, best_step, best_loss = net.mats(), 0, val_loss()
    log('start: validation log-loss %.5f, %d real and %d simulated docs' % (best_loss, len(real.spans), len(synth.spans)))
    for step in range(1, fit['steps'] + 1):
        if not real.spans and not synth.spans:
            break
        windows = []
        for _ in range(max(1, fit['batch'])):
            pool = real
            if synth.spans and (not real.spans or rng.random() < fit['synthetic_share']):
                pool = synth
            windows.append((pool, torch_sample(rng, pool, block)))
        loss = 0.0
        for pool in (real, synth):
            mine = [w for p, w in windows if p is pool]
            if mine:
                net.train(True)
                loss = loss + torch_window_loss(torch, net, pool, mine, block, cfg) * len(mine) / len(windows)
        opt.zero_grad()
        loss.backward()
        torch.nn.utils.clip_grad_norm_(net.parameters(), cfg['grad_clip'])
        opt.step()
        if fit['eval_every'] > 0 and step % fit['eval_every'] == 0:
            current = val_loss()
            if current < best_loss:
                best, best_step, best_loss = net.mats(), step, current
            log('step %d: train %.5f, validation %.5f, best %.5f at step %d' % (step, loss.item(), current, best_loss, best_step))
    net.load(best)
    test = TorchPool(torch, fit['test'], cfg, table)
    anchor_loss = {}
    for lam in fit['anchors']:
        anchor_loss[repr(lam)] = torch_replay(torch, cfg, best, test, lam, fit['online_every'])
        log('online replay with anchor %g: %.5f' % (lam, anchor_loss[repr(lam)]))
    report = {
        'best_step': best_step,
        'val_loss': torch_mean_loss(torch, net, val, block),
        'synthetic_val_loss': torch_mean_loss(torch, net, synth_val, block),
        'anchor_loss': anchor_loss,
    }
    return net, report


def torch_serve():
    import warnings
    warnings.filterwarnings('ignore', message='Failed to initialize NumPy')
    import torch
    torch.set_default_dtype(torch.float64)

    def log(msg):
        print(msg, file=sys.stderr, flush=True)

    state = {}
    for line in sys.stdin:
        if not line.strip():
            continue
        req = json.loads(line)
        try:
            op = req['op']
            reply = {}
            if op == 'init':
                torch.set_num_threads(1)
                cfg = req['config']
                net = torch_net(torch, cfg)
                net.load(req['live'])
                frozen = torch_net(torch, cfg)
                frozen.load(req['frozen'])
                state = {'cfg': cfg, 'net': net, 'opt': torch_adam(torch, net, cfg),
                         'anchor': [p.detach().clone() for p in frozen.parameters()]}
            elif op == 'step':
                cfg, net = state['cfg'], state['net']
                pool = TorchPool(torch, req['docs'], cfg, PacketTable(torch, req.get('packets'), cfg))
                windows = [(row, max(0, n - cfg['block']), n) for row, n in pool.spans]
                torch_step(torch, net, state['opt'], pool, windows, cfg['block'], state['anchor'], cfg['anchor'])
                checks = []
                reply = {'params': net.mats(), 'probe': torch_conditional(torch, net, pool, cfg['block'], checks=checks), 'check': checks}
            elif op == 'fit':
                torch.set_num_threads(max(1, (os.cpu_count() or 2) // 2))
                cfg = req['config']
                table = PacketTable(torch, req.get('packets'), cfg)
                net, report = torch_fit(torch, cfg, req['fit'], log, table)
                probe = TorchPool(torch, req['docs'], cfg, table)
                checks = []
                reply = {'params': net.mats(), 'probe': torch_conditional(torch, net, probe, cfg['block'], checks=checks), 'check': checks, 'fit': report}
            elif op == 'novelty':
                cfg = req['config']
                net = torch_net(torch, cfg)
                net.load(req['live'])
                table = PacketTable(torch, req.get('packets'), cfg)
                reply = {'novelty': torch_novelty(torch, net, TorchPool(torch, req['docs'], cfg, table), TorchPool(torch, req['calibration'], cfg, table), cfg)}
            else:
                reply = {'error': 'unknown op %r' % op}
        except Exception as e:
            reply = {'error': '%s: %s' % (type(e).__name__, e)}
        sys.stdout.write(json.dumps(reply) + '\n')
        sys.stdout.flush()


if __name__ == '__main__' and sys.argv[1:2] == ['torchserve']:
    torch_serve()
    raise SystemExit(0)

import numpy as np

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import fast

ARMS = [1, 2, 4, 8]
OK, RESET = len(ARMS), len(ARMS) + 1
VOCAB = len(ARMS) + 3
BOS = VOCAB - 1
PERIOD = 8


def survives(censor, rule, arm_index):
    """Whether a dial on this arm lives through the rule in force."""
    budget = ARMS[arm_index]
    if rule == 0:
        return budget < 3
    return budget > 1 if censor == 'easy' else budget >= 3


def rule_at(dial, offset, period=None):
    return ((dial + offset) // (period or PERIOD)) % 2


def episode(censor, policy, length, offset, rng):
    """Play one run, returning the tokens written and the dials lost."""
    tokens, lost = [BOS], 0
    for dial in range(length):
        arm = policy(tokens)
        alive = survives(censor, rule_at(dial, offset), arm)
        tokens.append(arm)
        tokens.append(OK if alive else RESET)
        if not alive:
            lost += 1
    return tokens, lost


def explorer(rng):
    return lambda _tokens: rng.randrange(len(ARMS))


class UCB1:
    """The controller that ships today, transcribed from selectFromRepertoire."""

    def __init__(self):
        self.sum = [0.0] * len(ARMS)
        self.cnt = [0] * len(ARMS)

    def __call__(self, _tokens):
        for i in range(len(ARMS)):
            if self.cnt[i] == 0:
                return i
        total = sum(self.cnt)
        ln = math.log(total)
        best, score = 0, -math.inf
        for i in range(len(ARMS)):
            norm = (self.sum[i] / self.cnt[i] + 1) / 2
            s = norm + math.sqrt(2 * ln / self.cnt[i])
            if s > score:
                best, score = i, s
        return best

    def observe(self, arm, alive):
        self.sum[arm] += 1.0 if alive else -1.0
        self.cnt[arm] += 1


class DiscountedUCB1(UCB1):
    """UCB1 that forgets, which is the cheap answer to a censor that changes.

    The shipped controller averages an arm over the whole run, so evidence that
    an arm was safe outlives the rule that made it safe. Decaying the counts
    gives the same statistic a memory of about 1/(1-gamma) dials. If this keeps
    up with the network, the network is not buying anything.
    """

    def __init__(self, gamma):
        super().__init__()
        self.gamma = gamma

    def observe(self, arm, alive):
        for i in range(len(ARMS)):
            self.sum[i] *= self.gamma
            self.cnt[i] *= self.gamma
        super().observe(arm, alive)

    def __call__(self, _tokens):
        for i in range(len(ARMS)):
            if self.cnt[i] < 1e-9:
                return i
        return super().__call__(_tokens)


def bandit_episode(censor, length, sched, bandit):
    lost = 0
    for dial in range(length):
        arm = bandit(None)
        alive = survives(censor, sched[dial], arm)
        bandit.observe(arm, alive)
        if not alive:
            lost += 1
    return lost


def ucb1_episode(censor, length, sched):
    """UCB1 needs its own loop because it learns from the outcome, not tokens."""
    bandit, lost = UCB1(), 0
    for dial in range(length):
        arm = bandit(None)
        alive = survives(censor, sched[dial], arm)
        bandit.observe(arm, alive)
        if not alive:
            lost += 1
    return lost


def net_policy(model):
    """Pick the arm the model expects to survive, given what just happened."""

    def choose(tokens):
        best, best_p = 0, -1.0
        for arm in range(len(ARMS)):
            window = (tokens + [arm])[-fast.block_size:]
            logits, _ = model.forward(window)
            p = fast.softmax(logits)[-1]
            score = p[OK] / (p[OK] + p[RESET] + 1e-12)
            if score > best_p:
                best, best_p = arm, score
        return best

    return choose


def corpus(censor, episodes, length, rng):
    """Random play, so every arm is seen under both rules and at every phase."""
    docs = []
    for _ in range(episodes):
        tokens, _ = episode(censor, explorer(rng), length, rng.randrange(PERIOD * 2), rng)
        docs.append(tokens)
    return docs


JOINT_VOCAB = len(ARMS) * 2 + 1
JOINT_BOS = JOINT_VOCAB - 1


def joint(arm, alive):
    """One dial as a single symbol, so the rule sits in the previous token.

    Splitting a dial into two tokens made the model reach across three
    positions to work out which rule was in force - arm, outcome, then the arm
    being asked about. Folded into one symbol it is a plain lookup from the
    last token, which is the shape this model demonstrably learns.
    """
    return arm * 2 + (0 if alive else 1)


def schedule(length, period, seed, jitter):
    """The rule in force at every dial, fixed up front.

    Precomputed so that every policy is judged against the same censor: if each
    one rolled its own switches, a lucky draw would look like a better
    controller. With jitter the rule holds for a geometric time with the same
    mean, which is what a censor that changes when it feels like it looks like.
    """
    rng = random.Random(seed)
    rule = rng.randrange(2)
    out = []
    for _ in range(length):
        out.append(rule)
        if (rng.random() < 1.0 / period) if jitter else (len(out) % period == 0):
            rule = 1 - rule
    return out


def joint_episode(censor, policy, length, sched):
    tokens, lost = [JOINT_BOS], 0
    for dial in range(length):
        arm = policy(tokens)
        alive = survives(censor, sched[dial], arm)
        tokens.append(joint(arm, alive))
        if not alive:
            lost += 1
    return tokens, lost


TRAIN_PERIODS = (4, 20)


def joint_corpus(censor, episodes, length, rng, jitter=False):
    """Every episode gets its own rotation period.

    Trained on a single period the model has no reason to work out where in the
    cycle it is - it can just count to eight, and off that period it is worse
    than the bandit. Mixing the period forces it to read the turn-over out of
    the history instead of assuming one.
    """
    docs = []
    for _ in range(episodes):
        period = rng.randrange(TRAIN_PERIODS[0], TRAIN_PERIODS[1] + 1)
        sched = schedule(length, period, rng.randrange(1 << 30), jitter)
        docs.append(joint_episode(censor, lambda _t: rng.randrange(len(ARMS)),
                                  length, sched)[0])
    return docs


def scores_for(model, tokens, arms):
    """P(survive) per arm, for however many arms the data carries."""
    logits, _ = model.forward(tokens[-fast.block_size:])
    p = fast.softmax(logits)[-1]
    return [p[a * 2] / (p[a * 2] + p[a * 2 + 1] + 1e-12) for a in range(arms)]


def joint_scores(model, tokens):
    return scores_for(model, tokens, len(ARMS))


def joint_policy(model):
    def choose(tokens):
        scores = joint_scores(model, tokens)
        return max(range(len(ARMS)), key=lambda a: scores[a])

    return choose


def joint_accuracy(model, censor, rng, dials=600, period=None, jitter=False):
    right, spread = 0, []
    period = period or PERIOD
    tokens = [JOINT_BOS]
    sched = schedule(dials, period, rng.randrange(1 << 30), jitter)
    for dial in range(dials):
        if dial % 64 == 0:
            tokens = [JOINT_BOS]
        arm = rng.randrange(len(ARMS))
        scores = joint_scores(model, tokens)
        alive = survives(censor, sched[dial], arm)
        right += int((scores[arm] > 0.5) == alive)
        spread.append(max(scores) - min(scores))
        tokens.append(joint(arm, alive))
    return right / dials, sum(spread) / len(spread)


def load_trace(path):
    """Rows the client wrote while dialling for real: when, which arm, did it live.

    Rows whose stage is live_reset are dropped. Those are connections torn down
    after they were already up, which happens when the censor changes its rule
    under a working tunnel - the arm passed the gate, so scoring it as a death
    would teach the opposite of what happened.
    """
    rows, dropped = [], 0
    for line in io.open(path, encoding='utf-8').read().splitlines()[1:]:
        f = line.split(',')
        if len(f) < 5 or not f[0].isdigit():
            continue
        if len(f) > 5 and f[5].strip() == 'live_reset':
            dropped += 1
            continue
        rows.append((int(f[0]), int(f[2]), int(f[4])))
    if dropped:
        print('dropped %d rows torn down after the handshake' % dropped)
    return rows


def trace_docs(rows, gap_ms=30000, bos=JOINT_BOS):
    """Cut the trace where the client went quiet.

    A long silence means the tunnel was parked and the next dial starts a fresh
    situation; stitching across it would teach a turn-over that never happened.
    """
    docs, cur, last = [], [bos], None
    for ms, arm, alive in rows:
        if last is not None and ms - last > gap_ms and len(cur) > 2:
            docs.append(cur)
            cur = [bos]
        cur.append(joint(arm, alive == 1))
        last = ms
    if len(cur) > 2:
        docs.append(cur)
    return docs


def grad_probe(model, bos, tokens=None):
    """Gradient checksums for one fixed history, on the weights being exported.

    probe_go pins the forward pass; this pins the backward one. A trainer that
    runs on the client learns from its own gradients, so a port that drifts
    here degrades the model in the field with nothing to catch it.
    """
    if tokens is None:
        tokens = [bos, 9, 2, 18, 5, 11, 0, 7]
    tokens = tokens[:fast.block_size]
    targets = np.array(tokens[1:] + [tokens[0]])
    logits, cache = model.forward(tokens)
    probs = fast.softmax(logits)
    dlogits = probs.copy()
    dlogits[np.arange(len(targets)), targets] -= 1
    dlogits /= len(targets)
    g = model.backward(cache, dlogits)
    print('gradient checksums, tokens %s:' % tokens)
    for k in sorted(g):
        v = np.asarray(g[k], dtype=float)
        print('		{name: %-14s norm: %.9f, first: %.9f},'
              % ('"' + k + '",', float(np.sqrt((v * v).sum())), float(v.flat[0])))


def run_trace(path):
    """Train on what actually happened on the wire, score on the held-out tail.

    No simulated loss here: a policy cannot be replayed against a log, because
    the log only says what the arm it played did. Prediction accuracy on rows
    the model never saw is the part that is honestly measurable, against the
    baseline of always guessing the commoner outcome.
    """
    rows = load_trace(path)
    if len(rows) < 40:
        raise SystemExit('only %d rows, collect more first' % len(rows))
    # The arm count comes from the trace, not from a constant: a joint arm
    # carries the preset as well as the budget, and a vocabulary sized for the
    # wrong one trains on the wrong symbols without complaining.
    arms = max(arm for _, arm, _ in rows) + 1
    vocab = arms * 2 + 1
    bos = vocab - 1
    cut = int(len(rows) * 0.8)
    train_rows, test_rows = rows[:cut], rows[cut:]
    docs = trace_docs(train_rows, bos=bos)
    model = train_policy(docs, vocab, seed=7, outcome_tokens=None, bos=bos)

    alive_rate = sum(a for _, _, a in train_rows) / float(len(train_rows))
    guess = alive_rate > 0.5
    hist, right, base = [bos], 0, 0
    for _, arm, alive in test_rows:
        scores = scores_for(model, hist, arms)
        right += int((scores[arm] > 0.5) == (alive == 1))
        base += int(guess == (alive == 1))
        hist.append(joint(arm, alive == 1))
    n = len(test_rows)
    print('trace %s: %d rows, %d arms, %d episodes, trained on %d'
          % (path, len(rows), arms, len(docs), len(train_rows)))
    print('  held-out outcome prediction %.1f%%, always-guess-commoner %.1f%%'
          % (100.0 * right / n, 100.0 * base / n))
    target = os.environ.get('EXPORT')
    if target:
        export_go(model, target, '%d dials recorded by the client on the stand' % len(rows),
                  vocab=vocab, arms=arms)
        probe_go(model, random.Random(23), arms=arms, bos=bos,
                 scorer=lambda m, t: scores_for(m, t, arms))
        grad_probe(model, bos)


def export_go(model, path, origin, vocab=JOINT_VOCAB, arms=len(ARMS)):
    """Write the trained policy out as Go source.

    The old exporter in fast.py wrote a shaper into package relay together with
    its size buckets; this one carries a controller into the protocol package,
    where the arm is actually chosen, and nothing else.
    """
    lines = ['// Code generated by neural/mutate.py. DO NOT EDIT.', '',
             'package protocol', '',
             '// Trained on %s.' % origin,
             '// %d parameters: %d layer(s), embd %d, %d heads, window %d.'
             % (model.size(), fast.n_layer, fast.n_embd, fast.n_head, fast.block_size), '',
             'const (',
             '	polVocab = %d' % vocab,
             '	polEmbd  = %d' % fast.n_embd,
             '	polHead  = %d' % fast.n_head,
             '	polBlock = %d' % fast.block_size,
             '	polLayer = %d' % fast.n_layer,
             '	polArms  = %d' % arms,
             ')', '']

    def matrix(name, mat):
        lines.append('var %s = [][]float64{' % name)
        for row in mat:
            lines.append('	{' + ', '.join('%.6f' % v for v in row) + '},')
        lines.append('}')
        lines.append('')

    matrix('polWte', model.p['wte'])
    matrix('polWpe', model.p['wpe'])
    matrix('polLmHead', model.p['lm_head'])
    for part in ('wq', 'wk', 'wv', 'wo', 'fc1', 'fc2'):
        lines.append('var pol%s = [][][]float64{' % part.capitalize())
        for i in range(fast.n_layer):
            lines.append('	{')
            for row in model.p['%d.%s' % (i, part)]:
                lines.append('		{' + ', '.join('%.6f' % v for v in row) + '},')
            lines.append('	},')
        lines.append('}')
        lines.append('')
    io.open(path, 'w', encoding='utf-8').write(chr(10).join(lines))
    print('exported %d parameters to %s' % (model.size(), path))


def probe_go(model, rng, arms=len(ARMS), bos=JOINT_BOS, scorer=joint_scores):
    """Fixed histories and the scores the Python model gives them.

    Pasted into the Go test so the port is held to these numbers: a forward pass
    that drifts from the trainer is worse than no forward pass at all.
    """
    print('probe cases for the Go test:')
    for length in (1, 5, 17, 32):
        hist = [bos]
        for _ in range(length):
            hist.append(rng.randrange(arms * 2))
        window = hist[-fast.block_size:]
        scores = scorer(model, hist)
        print('		{tokens: []int{%s}, want: []float64{%s}},'
              % (', '.join(str(t) for t in window),
                 ', '.join('%.6f' % v for v in scores)))


def run_joint(censor):
    rng = random.Random(7)
    jitter = os.environ.get('SWITCH') == 'jitter'
    docs = joint_corpus(censor, 60, 64, rng, jitter)
    model = train_policy(docs, JOINT_VOCAB, seed=7, outcome_tokens=None)
    period = int(os.environ.get('EVAL_PERIOD', 0)) or PERIOD
    acc, spread = joint_accuracy(model, censor, random.Random(11), period=period, jitter=jitter)
    trials, length = 12, 200
    scheds = [schedule(length, period, 500 + i, jitter) for i in range(trials)]
    net = joint_policy(model)
    net_lost = sum(joint_episode(censor, net, length, sc)[1] for sc in scheds)
    ucb_lost = sum(ucb1_episode(censor, length, sc) for sc in scheds)
    dials = trials * length
    print("  joint encoding: outcome prediction %.1f%% (chance 50), spread %.3f"
          % (100.0 * acc, spread))
    print(chr(10) + "censor %s (joint): %d dials, periods %d-%d, tested on %d, switching %s"
          % (censor, dials, TRAIN_PERIODS[0], TRAIN_PERIODS[1], period,
             "random" if jitter else "clockwork"))
    rows = [('ucb1', ucb_lost)]
    for gamma in (0.99, 0.95, 0.9):
        lost = sum(bandit_episode(censor, length, sc, DiscountedUCB1(gamma)) for sc in scheds)
        rows.append(('ucb1 g=%.2f' % gamma, lost))
    rows.append(('network', net_lost))
    for name, lost in rows:
        print("  %-11s lost %5d  (%5.1f%% of dials)" % (name, lost, 100.0 * lost / dials))
    target = os.environ.get('EXPORT')
    if target:
        export_go(model, target, 'the %s censor, periods %d-%d'
                  % (censor, TRAIN_PERIODS[0], TRAIN_PERIODS[1]))
        probe_go(model, random.Random(23))


def train_policy(docs, vocab, seed=7, outcome_tokens=(OK, RESET), bos=JOINT_BOS, model=None):
    """Train the policy on its own terms rather than through fast.train.

    Two things differ from the generic trainer, and both were costing the whole
    signal. fast.windows cuts a document at fixed multiples of the window, so an
    arm token always lands on the same parity of position; at inference the
    history is whatever length it happens to be, the parity floats, and the
    model reads a position for something it never meant. Cutting at a random
    offset instead makes it parity-blind, which is what serving needs.

    The second is the loss. Half the targets are the arm we chose at random,
    which nothing in the history predicts, so the gradient spent on them is
    noise that drowns the part we want. Only outcome targets are scored here.
    """
    rng = np.random.default_rng(seed)
    if model is None:
        model = fast.Model(vocab, rng)
    steps = int(os.environ.get('STEPS', 0)) or 6000
    pool = [d for d in docs if len(d) > 4]
    for t in range(steps):
        d = pool[int(rng.integers(len(pool)))]
        start = int(rng.integers(0, max(1, len(d) - 2)))
        inp = d[start:start + fast.block_size]
        tgt = d[start + 1:start + 1 + len(inp)]
        inp = inp[:len(tgt)]
        if len(inp) < 2:
            continue
        targets = np.array(tgt)
        if outcome_tokens is None:
            mask = targets != bos
        else:
            mask = np.isin(targets, outcome_tokens)
        if not mask.any():
            continue
        logits, cache = model.forward(inp)
        probs = fast.softmax(logits)
        dlogits = probs.copy()
        dlogits[np.arange(len(targets)), targets] -= 1
        dlogits[~mask] = 0.0
        dlogits /= int(mask.sum())
        model.step(model.backward(cache, dlogits), t, steps)
        if t % 1000 == 0 or t == steps - 1:
            hit = probs[np.arange(len(targets)), targets][mask]
            loss = -np.log(np.maximum(hit, 1e-12)).mean()
            print("step %5d / %d | outcome loss %.4f" % (t + 1, steps, loss), end=chr(13))
    print()
    return model


def arm_scores(model, tokens):
    """P(survive) the model gives each arm for this history."""
    out = []
    for arm in range(len(ARMS)):
        window = (tokens + [arm])[-fast.block_size:]
        logits, _ = model.forward(window)
        p = fast.softmax(logits)[-1]
        out.append(p[OK] / (p[OK] + p[RESET] + 1e-12))
    return out


def accuracy(model, censor, rng, dials=600):
    """How often the model calls the outcome of the arm actually played.

    Separates two failures that look alike in the policy numbers: a model that
    cannot predict, and one that predicts but is being asked wrongly. Chance
    is 50 per cent.
    """
    right = total = 0
    tokens, offset = [BOS], rng.randrange(PERIOD * 2)
    spread = []
    for dial in range(dials):
        if dial % 64 == 0:
            tokens, offset = [BOS], rng.randrange(PERIOD * 2)
        arm = rng.randrange(len(ARMS))
        scores = arm_scores(model, tokens)
        alive = survives(censor, rule_at(dial, offset), arm)
        right += int((scores[arm] > 0.5) == alive)
        total += 1
        spread.append(max(scores) - min(scores))
        tokens.append(arm)
        tokens.append(OK if alive else RESET)
    return right / total, sum(spread) / len(spread)


# ---- the fingerprint and the budget judged together ----
#
# A censor reads the hello fingerprint only when the hello arrives whole; a
# fragmented one hides it and shows up as a packet count instead. So a small
# budget exposes the preset and a large one trips the packet rule, and what
# survives is a pair, not either axis on its own. That is the case the shipped
# controller cannot represent: preset and budget sit on separate bandit
# contexts, and neither sees the other half of the arm it is being judged on.

GRID_PRESETS = 3
GRID_BUDGETS = [1, 2, 4, 8]
GRID_PQ = 2
GRID_BLOCK = GRID_PRESETS * len(GRID_BUDGETS)
GRID_ARMS = GRID_BLOCK * GRID_PQ
GRID_VOCAB = GRID_ARMS * 2 + 1
GRID_BOS = GRID_VOCAB - 1


def grid_arm(preset, budget_index, pq=0):
    return pq * GRID_BLOCK + preset * len(GRID_BUDGETS) + budget_index


def grid_parts(arm):
    within = arm % GRID_BLOCK
    return within // len(GRID_BUDGETS), within % len(GRID_BUDGETS), arm // GRID_BLOCK


def arm_features(arm, presets=GRID_PRESETS):
    preset, b, pq = grid_parts(arm)
    budget = GRID_BUDGETS[b]
    f = [0.0] * (presets + 2)
    if 0 <= preset < presets:
        f[preset] = 1.0
    f[presets] = math.log2(max(budget, 1)) / math.log2(GRID_BUDGETS[-1])
    f[presets + 1] = float(pq)
    return f


class PointerModel:
    def __init__(self, arms, rng, presets=GRID_PRESETS):
        self.arms = arms
        self.presets = presets
        self.feat = np.array([arm_features(a, presets) for a in range(arms)])
        feat_dim = self.feat.shape[1]
        self.n_cand = arms * 2 + 1
        self.bos = self.n_cand - 1
        self.cand_arm = np.array([c // 2 for c in range(arms * 2)])
        self.cand_out = np.array([c % 2 for c in range(arms * 2)])

        def m(a, b):
            return rng.normal(0, 0.02, size=(a, b))

        self.body = fast.Model(self.n_cand, rng)
        self.pf = {
            'win': m(fast.n_embd, feat_dim), 'oin': m(2, fast.n_embd), 'bos_in': m(1, fast.n_embd),
            'wout': m(2 * fast.n_embd, feat_dim), 'oout': m(2, fast.n_embd), 'bos_out': m(1, fast.n_embd),
        }
        self.p = {k: v for k, v in self.body.p.items() if k not in ('wte', 'lm_head')}
        self.p.update(self.pf)
        self.mm = {k: np.zeros_like(v) for k, v in self.p.items()}
        self.vv = {k: np.zeros_like(v) for k, v in self.p.items()}

    def size(self):
        return sum(v.size for v in self.p.values())

    def _outcome_proj(self, o):
        e = fast.n_embd
        return self.feat @ self.pf['wout'][o * e:(o + 1) * e].T

    def _embeddings(self):
        wte = np.empty((self.n_cand, fast.n_embd))
        wte[:self.arms * 2] = (self.feat @ self.pf['win'].T)[self.cand_arm] + self.pf['oin'][self.cand_out]
        wte[self.bos] = self.pf['bos_in'][0]
        head = np.empty((self.n_cand, fast.n_embd))
        arm_out = np.stack([self._outcome_proj(0), self._outcome_proj(1)])
        head[:self.arms * 2] = arm_out[self.cand_out, self.cand_arm] + self.pf['oout'][self.cand_out]
        head[self.bos] = self.pf['bos_out'][0]
        return wte, head

    def forward(self, tokens):
        self.body.p['wte'], self.body.p['lm_head'] = self._embeddings()
        return self.body.forward(tokens)

    def backward(self, cache, dlogits):
        gb = self.body.backward(cache, dlogits)
        g = {k: gb[k] for k in self.p if k in gb}
        arm_lm, arm_wte = gb['lm_head'][:self.arms * 2], gb['wte'][:self.arms * 2]
        e = fast.n_embd
        g['win'] = arm_wte.T @ self.feat[self.cand_arm]
        g['wout'] = np.zeros_like(self.pf['wout'])
        g['oout'] = np.zeros_like(self.pf['oout'])
        g['oin'] = np.zeros_like(self.pf['oin'])
        for o in (0, 1):
            sel = self.cand_out == o
            g['wout'][o * e:(o + 1) * e] = arm_lm[sel].T @ self.feat[self.cand_arm[sel]]
            g['oout'][o] = arm_lm[sel].sum(0)
            g['oin'][o] = arm_wte[sel].sum(0)
        g['bos_out'] = gb['lm_head'][self.bos][None, :]
        g['bos_in'] = gb['wte'][self.bos][None, :]
        return g

    def step(self, g, t, steps):
        lr = fast.learning_rate * (1 - t / steps)
        for kk in self.p:
            self.mm[kk] = fast.beta1 * self.mm[kk] + (1 - fast.beta1) * g[kk]
            self.vv[kk] = fast.beta2 * self.vv[kk] + (1 - fast.beta2) * g[kk] ** 2
            mh = self.mm[kk] / (1 - fast.beta1 ** (t + 1))
            vh = self.vv[kk] / (1 - fast.beta2 ** (t + 1))
            self.p[kk] -= lr * mh / (np.sqrt(vh) + fast.eps_adam)


def pointer_gradcheck():
    rng = np.random.default_rng(0)
    m = PointerModel(3, rng)
    tokens = [m.bos, 0, 3, 4, 1]
    targets = np.array([0, 3, 4, 1, m.bos])

    def loss():
        logits, _ = m.forward(tokens)
        return -np.log(fast.softmax(logits)[np.arange(len(targets)), targets]).mean()

    logits, cache = m.forward(tokens)
    probs = fast.softmax(logits)
    d = probs.copy()
    d[np.arange(len(targets)), targets] -= 1
    d /= len(targets)
    g = m.backward(cache, d)

    eps, worst, checked = 1e-6, 0.0, 0
    print("pointer | arms %d | cand %d | params %d" % (m.arms, m.n_cand, m.size()))
    for name in sorted(m.p):
        for i, j in ((0, 0), (m.p[name].shape[0] - 1, m.p[name].shape[1] - 1)):
            m.p[name][i, j] += eps
            hi = loss()
            m.p[name][i, j] -= 2 * eps
            lo = loss()
            m.p[name][i, j] += eps
            num = (hi - lo) / (2 * eps)
            err = abs(num - g[name][i, j]) / max(abs(num), 1e-6)
            worst = max(worst, err)
            checked += 1
    print("checked %d entries | worst relative error %.2e" % (checked, worst))
    if worst > 1e-3:
        raise SystemExit("pointer gradients disagree with the numeric estimate")


def grid_survives(mode, rule, arm):
    """Both axes decide, so neither can be tuned without the other.

    grid      the rules share a safe pair (preset 1, budget up to 2)
    gridhard  the safe sets are disjoint, so no fixed pair survives both
    """
    preset, b, _ = grid_parts(arm)
    budget = GRID_BUDGETS[b]
    if mode == 'grid':
        if rule == 0:
            return preset in (0, 1) and budget <= 4
        return preset in (1, 2) and budget <= 2
    if rule == 0:
        return preset in (0, 1) and budget <= 2
    return preset == 2 and budget >= 4


def grid_joint(arm, alive):
    return arm * 2 + (0 if alive else 1)


def ucb_pick(total, cnt):
    """The formula selectFromRepertoire ships, over whatever arms it is given."""
    for i in range(len(cnt)):
        if cnt[i] == 0:
            return i
    ln = math.log(sum(cnt))
    best, score = 0, -math.inf
    for i in range(len(cnt)):
        norm = (total[i] / cnt[i] + 1) / 2
        s = norm + math.sqrt(2 * ln / cnt[i])
        if s > score:
            best, score = i, s
    return best


def grid_flat_ucb1(mode, length, sched):
    """One bandit over every pair. Honest, but it has 12 arms to explore."""
    total, cnt, lost = [0.0] * GRID_ARMS, [0] * GRID_ARMS, 0
    for dial in range(length):
        arm = ucb_pick(total, cnt)
        alive = grid_survives(mode, sched[dial], arm)
        total[arm] += 1.0 if alive else -1.0
        cnt[arm] += 1
        lost += 0 if alive else 1
    return lost


def grid_axis_ucb1(mode, length, sched):
    """A bandit per axis, which is what the client does today: the preset on one
    context, the budget on another, both handed the same outcome."""
    sizes = (GRID_PRESETS, len(GRID_BUDGETS))
    total = [[0.0] * n for n in sizes]
    cnt = [[0] * n for n in sizes]
    lost = 0
    for dial in range(length):
        pick = [ucb_pick(total[ax], cnt[ax]) for ax in range(len(sizes))]
        arm = grid_arm(pick[0], pick[1])
        alive = grid_survives(mode, sched[dial], arm)
        reward = 1.0 if alive else -1.0
        for ax in range(len(sizes)):
            total[ax][pick[ax]] += reward
            cnt[ax][pick[ax]] += 1
        lost += 0 if alive else 1
    return lost


def grid_scores(model, tokens):
    logits, _ = model.forward(tokens[-fast.block_size:])
    p = fast.softmax(logits)[-1]
    return [p[a * 2] / (p[a * 2] + p[a * 2 + 1] + 1e-12) for a in range(GRID_ARMS)]


def grid_net_policy(model):
    def choose(tokens):
        scores = grid_scores(model, tokens)
        return max(range(GRID_ARMS), key=lambda a: scores[a])

    return choose


def grid_episode(mode, policy, length, sched):
    tokens, lost = [GRID_BOS], 0
    for dial in range(length):
        arm = policy(tokens)
        alive = grid_survives(mode, sched[dial], arm)
        tokens.append(grid_joint(arm, alive))
        if not alive:
            lost += 1
    return tokens, lost


def grid_corpus(mode, episodes, length, rng, jitter=False):
    docs = []
    for _ in range(episodes):
        period = rng.randrange(TRAIN_PERIODS[0], TRAIN_PERIODS[1] + 1)
        sched = schedule(length, period, rng.randrange(1 << 30), jitter)
        tokens = [GRID_BOS]
        for dial in range(length):
            arm = rng.randrange(GRID_ARMS)
            tokens.append(grid_joint(arm, grid_survives(mode, sched[dial], arm)))
        docs.append(tokens)
    return docs


def grid_accuracy(model, mode, rng, dials=600, period=None, jitter=False):
    period = period or PERIOD
    sched = schedule(dials, period, rng.randrange(1 << 30), jitter)
    tokens, right, spread = [GRID_BOS], 0, []
    for dial in range(dials):
        if dial % 64 == 0:
            tokens = [GRID_BOS]
        arm = rng.randrange(GRID_ARMS)
        scores = grid_scores(model, tokens)
        alive = grid_survives(mode, sched[dial], arm)
        right += int((scores[arm] > 0.5) == alive)
        spread.append(max(scores) - min(scores))
        tokens.append(grid_joint(arm, alive))
    return right / dials, sum(spread) / len(spread)


def export_pointer_go(model, path, origin):
    e = fast.n_embd
    feat_dim = model.feat.shape[1]
    lines = ['// Code generated by neural/mutate.py. DO NOT EDIT.', '',
             'package protocol', '',
             '// Trained on %s.' % origin,
             '// %d parameters: %d layer(s), embd %d, %d heads, window %d.'
             % (model.size(), fast.n_layer, e, fast.n_head, fast.block_size), '',
             'const (',
             '	polEmbd    = %d' % e,
             '	polHead    = %d' % fast.n_head,
             '	polBlock   = %d' % fast.block_size,
             '	polLayer   = %d' % fast.n_layer,
             '	polArms    = %d' % model.arms,
             '	polFeatDim = %d' % feat_dim,
             ')', '']

    def matrix(name, mat):
        lines.append('var %s = [][]float64{' % name)
        for row in np.asarray(mat):
            lines.append('	{' + ', '.join('%.6f' % v for v in row) + '},')
        lines.append('}')
        lines.append('')

    matrix('polWin', model.pf['win'])
    matrix('polOin', model.pf['oin'])
    matrix('polBosIn', model.pf['bos_in'])
    matrix('polWout', model.pf['wout'])
    matrix('polOout', model.pf['oout'])
    matrix('polBosOut', model.pf['bos_out'])
    matrix('polWpe', model.body.p['wpe'])
    for part in ('wq', 'wk', 'wv', 'wo', 'fc1', 'fc2'):
        lines.append('var pol%s = [][][]float64{' % part.capitalize())
        for i in range(fast.n_layer):
            lines.append('	{')
            for row in model.body.p['%d.%s' % (i, part)]:
                lines.append('		{' + ', '.join('%.6f' % v for v in row) + '},')
            lines.append('	},')
        lines.append('}')
        lines.append('')
    io.open(path, 'w', encoding='utf-8').write(chr(10).join(lines))
    print('exported %d parameters to %s' % (model.size(), path))


def pointer_probe_go(model, rng):
    print('probe cases for the Go test:')
    for length in (1, 5, 17, 32):
        hist = [model.bos]
        for _ in range(length):
            hist.append(rng.randrange(model.arms * 2))
        window = hist[-fast.block_size:]
        scores = grid_scores(model, hist)
        print('		{tokens: []int{%s}, want: []float64{%s}},'
              % (', '.join(str(t) for t in window),
                 ', '.join('%.6f' % v for v in scores)))


def pointer_score_arm(model, tokens, feat_vec):
    _, cache = model.forward(tokens[-fast.block_size:])
    x_last = cache[5][-1]
    fv = np.array(feat_vec)
    e = fast.n_embd
    s_ok = x_last @ (fv @ model.pf['wout'][:e].T + model.pf['oout'][0])
    s_dead = x_last @ (fv @ model.pf['wout'][e:2 * e].T + model.pf['oout'][1])
    return 1.0 / (1.0 + math.exp(-(s_ok - s_dead)))


def run_ptrgrid(mode):
    rng = random.Random(7)
    jitter = os.environ.get('SWITCH') == 'jitter'
    os.environ.setdefault('STEPS', '12000')
    docs = grid_corpus(mode, 120, 96, rng, jitter)
    pm = PointerModel(GRID_ARMS, np.random.default_rng(7))
    model = train_policy(docs, GRID_VOCAB, seed=7, outcome_tokens=None, bos=GRID_BOS, model=pm)
    period = int(os.environ.get('EVAL_PERIOD', 0)) or PERIOD
    acc, spread = grid_accuracy(model, mode, random.Random(11), period=period, jitter=jitter)
    trials, length = 12, 200
    scheds = [schedule(length, period, 500 + i, jitter) for i in range(trials)]
    net = grid_net_policy(model)
    rows = [('axis ucb1', sum(grid_axis_ucb1(mode, length, sc) for sc in scheds)),
            ('flat ucb1', sum(grid_flat_ucb1(mode, length, sc) for sc in scheds)),
            ('pointer', sum(grid_episode(mode, net, length, sc)[1] for sc in scheds))]
    dials = trials * length
    print("  outcome prediction %.1f%% (chance 50), spread between arms %.3f"
          % (100.0 * acc, spread))
    print("  pointer scores preset 1 across budgets (3 was never a trained arm):")
    hist = [GRID_BOS]
    for b in (1, 2, 3, 4, 8):
        feat = [0.0, 1.0, 0.0, math.log2(b) / math.log2(GRID_BUDGETS[-1])]
        print("    budget %2d -> P(survive) %.3f%s" % (b, pointer_score_arm(model, hist, feat),
                                                       "  <- unseen" if b == 3 else ""))
    print(chr(10) + "censor %s: %d arms, %d dials, period %d"
          % (mode, GRID_ARMS, dials, period))
    for name, lost in rows:
        print("  %-10s lost %5d  (%5.1f%% of dials)" % (name, lost, 100.0 * lost / dials))
    target = os.environ.get('EXPORT')
    if target:
        export_pointer_go(model, target, 'the %s censor, %d presets x %d budgets'
                          % (mode, GRID_PRESETS, len(GRID_BUDGETS)))
        pointer_probe_go(model, random.Random(23))
        grad_probe(model, model.bos)


def measured_arm_index(arm_id):
    preset = {'c': 0, 'f': 1, 's': 2}[arm_id[0]]
    pq = 1 if arm_id.endswith('q') else 0
    digit = arm_id[1:-1] if pq else arm_id[1:]
    b = GRID_BUDGETS.index(int(digit))
    return grid_arm(preset, b, pq)


def load_measured(path):
    blocks, surv = [], {}
    for row in csv.DictReader(io.open(path, encoding='utf-8')):
        if row['block'] not in blocks:
            blocks.append(row['block'])
        surv[(row['block'], measured_arm_index(row['arm']))] = float(row['survival'])
    return blocks, surv


def run_ptrmeasured(path):
    rng = random.Random(7)
    os.environ.setdefault('STEPS', '16000')
    blocks, surv = load_measured(path)
    nb = len(blocks)
    period, length, episodes = 12, 96, 160
    docs = []
    for _ in range(episodes):
        order = list(range(nb))
        rng.shuffle(order)
        tokens = [GRID_BOS]
        for dial in range(length):
            b = blocks[order[(dial // period) % nb]]
            arm = rng.randrange(GRID_ARMS)
            alive = rng.random() < surv.get((b, arm), 0.5)
            tokens.append(grid_joint(arm, alive))
        docs.append(tokens)

    pm = PointerModel(GRID_ARMS, np.random.default_rng(7))
    model = train_policy(docs, GRID_VOCAB, seed=7, outcome_tokens=None, bos=GRID_BOS, model=pm)

    print('trained on %d regimes x %d arms (3 presets x 4 budgets x drop-PQ), no censor mode on the input' % (nb, GRID_ARMS))
    d0 = grid_net_policy(model)([GRID_BOS])
    dp, db, dq = grid_parts(d0)
    print('default pick (empty history): %s b%d%s\n' % (('chrome', 'firefox', 'safari')[dp], GRID_BUDGETS[db], ' drop-PQ' if dq else ''))
    print('net pick per regime (history-keyed) vs empirical best:\n')
    gap = 0.0
    net = grid_net_policy(model)
    for b in blocks:
        reachable = [a for a in range(GRID_ARMS) if (b, a) in surv]
        emp = max(reachable, key=lambda a: surv[(b, a)])
        hist = [GRID_BOS]
        for _ in range(GRID_PQ * len(GRID_BUDGETS)):
            a = net(hist)
            hist.append(grid_joint(a, rng.random() < surv.get((b, a), 0.5)))
        pick = net(hist)
        pv, ev = surv.get((b, pick), 0.0), surv[(b, emp)]
        gap += ev - pv
        preset, bi, pq = grid_parts(pick)
        tag = '%s b%d%s' % (('chrome', 'firefox', 'safari')[preset], GRID_BUDGETS[bi], ' drop-PQ' if pq else '')
        flag = '' if pick == emp or pv >= ev else '  (emp %.2f)' % ev
        print('  %-10s -> %-18s survival %.2f%s' % (b, tag, pv, flag))
    print('\nmean gap to the mode-aware oracle: %.3f' % (gap / nb))

    target = os.environ.get('EXPORT')
    if target:
        export_pointer_go(model, target, 'the measured %d-regime stand matrix, %d presets x %d budgets x drop-PQ'
                          % (nb, GRID_PRESETS, len(GRID_BUDGETS)))
        pointer_probe_go(model, random.Random(23))
        grad_probe(model, model.bos)


def run_grid(mode):
    rng = random.Random(7)
    jitter = os.environ.get('SWITCH') == 'jitter'
    os.environ.setdefault('STEPS', '12000')
    docs = grid_corpus(mode, 120, 96, rng, jitter)
    model = train_policy(docs, GRID_VOCAB, seed=7, outcome_tokens=None, bos=GRID_BOS)
    period = int(os.environ.get('EVAL_PERIOD', 0)) or PERIOD
    acc, spread = grid_accuracy(model, mode, random.Random(11), period=period, jitter=jitter)
    trials, length = 12, 200
    scheds = [schedule(length, period, 500 + i, jitter) for i in range(trials)]
    net = grid_net_policy(model)
    rows = [('axis ucb1', sum(grid_axis_ucb1(mode, length, sc) for sc in scheds)),
            ('flat ucb1', sum(grid_flat_ucb1(mode, length, sc) for sc in scheds)),
            ('network', sum(grid_episode(mode, net, length, sc)[1] for sc in scheds))]
    dials = trials * length
    print("  outcome prediction %.1f%% (chance 50), spread between arms %.3f"
          % (100.0 * acc, spread))
    print(chr(10) + "censor %s: %d arms (%d presets x %d budgets), %d dials, period %d, switching %s"
          % (mode, GRID_ARMS, GRID_PRESETS, len(GRID_BUDGETS), dials, period,
             "random" if jitter else "clockwork"))
    for name, lost in rows:
        print("  %-10s lost %5d  (%5.1f%% of dials)" % (name, lost, 100.0 * lost / dials))
    target = os.environ.get('EXPORT')
    if target:
        export_go(model, target, 'the %s censor, %d presets x %d budgets'
                  % (mode, GRID_PRESETS, len(GRID_BUDGETS)),
                  vocab=GRID_VOCAB, arms=GRID_ARMS)
        probe_go(model, random.Random(23), arms=GRID_ARMS, bos=GRID_BOS,
                 scorer=grid_scores)


def main(censor):
    rng = random.Random(7)
    docs = corpus(censor, 60, 64, rng)
    os.environ.setdefault('STEPS', '4000')
    model = train_policy(docs, VOCAB, seed=7)

    trials, length = 12, 200
    offsets = [random.Random(100 + i).randrange(PERIOD * 2) for i in range(trials)]

    net = net_policy(model)
    net_lost = sum(episode(censor, net, length, off, rng)[1] for off in offsets)
    ucb_lost = sum(ucb1_episode(censor, length, off) for off in offsets)
    rand_lost = sum(episode(censor, explorer(rng), length, off, rng)[1] for off in offsets)

    acc, spread = accuracy(model, censor, random.Random(11))
    print("  outcome prediction %.1f%% (chance 50), mean spread between arms %.3f"
          % (100.0 * acc, spread))
    dials = trials * length
    print(f"\ncensor {censor}: {dials} dials over {trials} runs, rule flips every {PERIOD}")
    for name, lost in (('random', rand_lost), ('ucb1', ucb_lost), ('network', net_lost)):
        print(f"  {name:8s} lost {lost:5d}  ({100.0 * lost / dials:5.1f}% of dials)")


if __name__ == '__main__':
    if len(sys.argv) > 1 and sys.argv[1] == 'ptrcheck':
        pointer_gradcheck()
        raise SystemExit(0)
    if len(sys.argv) > 1 and sys.argv[1] in ('ptrgrid', 'ptrgridhard'):
        run_ptrgrid('grid' if sys.argv[1] == 'ptrgrid' else 'gridhard')
        raise SystemExit(0)
    if len(sys.argv) > 2 and sys.argv[1] == 'ptrmeasured':
        run_ptrmeasured(sys.argv[2])
        raise SystemExit(0)
    if len(sys.argv) > 1 and sys.argv[1] in ('grid', 'gridhard'):
        run_grid(sys.argv[1])
        raise SystemExit(0)
    if len(sys.argv) > 2 and sys.argv[1] == 'trace':
        run_trace(sys.argv[2])
        raise SystemExit(0)
    if len(sys.argv) > 2 and sys.argv[2] == 'joint':
        run_joint(sys.argv[1])
        raise SystemExit(0)
    main(sys.argv[1] if len(sys.argv) > 1 else 'easy')
