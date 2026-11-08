import os       # os.path.exists
import math     # math.log, math.exp
import random   # random.seed, random.choices, random.gauss, random.shuffle
random.seed(42) # Let there be order among chaos

# Let there be a Dataset `docs`: list[str] of documents.
#
# Three things a passive classifier can see, each a sequence, each a "document"
# here. Everything below turns one of them into text so the model underneath
# stays exactly the character-level GPT it was written as:
#
#   hello  - the extensions a ClientHello carries, in order (its JA3 shape)
#   flow   - the sizes of the TLS records a connection sends
#   timing - the gaps between those records
#
# One symbol per token, so the tokenizer needs no changes.
import sys, glob, struct

size_bounds = [0, 64, 128, 256, 512, 1024, 2048, 4096, 8192, 16000]
# Gaps are logarithmic by nature: most records follow the previous one within
# microseconds, and the interesting structure — a server pausing to think — lives
# decades away. A grid that puts nearly everything in its first bucket teaches the
# model only that bucket, and it then generates one endless burst.
gap_bounds  = [0, 10, 30, 100, 300, 1000, 3000, 10000, 30000, 100000, 300000, 1000000]  # microseconds

def as_text(seq, buckets):
    """Map a sequence of integers onto printable characters, one per token."""
    out = []
    for v in seq:
        i = 0
        while i < len(buckets) - 1 and v >= buckets[i + 1]:
            i += 1
        out.append(chr(33 + i))
    return ''.join(out)

def tls_records(buf):
    """Take whole TLS records off the front of a reassembled stream, returning
    them and whatever is left over.

    Records do not respect packet boundaries: on a 1500-byte link a 16KB record
    spans a dozen packets. Parsing each packet on its own reports the link's MTU
    as if it were the record size, which makes any capture taken over ethernet
    look nothing like one taken over loopback — and the difference is the
    measurement, not the traffic."""
    out, i = [], 0
    while i + 5 <= len(buf):
        if buf[i] not in (0x14, 0x15, 0x16, 0x17):
            return out, b''          # not TLS (or we lost sync): stop for good
        size = 5 + (buf[i + 3] << 8 | buf[i + 4])
        if size <= 5 or size > 16640:
            return out, b''
        if i + size > len(buf):
            break                    # record continues in a later packet
        out.append((buf[i], size))
        i += size
    return out, buf[i:]

def hello_extensions(record):
    """Extension types of a ClientHello, in the order the browser sent them."""
    b = record[5:] if record[:1] == b'\x16' else record
    if len(b) < 42 or b[0] != 0x01:
        return []
    i = 38                                  # handshake header, version, random
    i += 1 + b[i]                           # session id
    if i + 2 > len(b): return []
    i += 2 + (b[i] << 8 | b[i + 1])         # cipher suites
    if i + 1 > len(b): return []
    i += 1 + b[i]                           # compression methods
    if i + 2 > len(b): return []
    end = i + 2 + (b[i] << 8 | b[i + 1])
    i += 2
    types = []
    while i + 4 <= min(end, len(b)):
        types.append(b[i] << 8 | b[i + 1])
        i += 4 + (b[i + 2] << 8 | b[i + 3])
    return types

def read_pcap(path):
    """Yield (timestamp, tcp_payload) from a classic pcap. No dependencies:
    the format is a header and a list of records, and we only need one field."""
    with open(path, 'rb') as f:
        blob = f.read()
    if len(blob) < 24:
        return
    magic = blob[:4]
    if magic == b'\xd4\xc3\xb2\xa1':   endian, nano = '<', False
    elif magic == b'\xa1\xb2\xc3\xd4': endian, nano = '>', False
    elif magic == b'\x4d\x3c\xb2\xa1': endian, nano = '<', True
    elif magic == b'\xa1\xb2\x3c\x4d': endian, nano = '>', True
    else:
        return
    link = struct.unpack(endian + 'I', blob[20:24])[0]
    # 276 is LINUX_SLL2, what `tcpdump -i any` writes on current tcpdump. Without
    # it every packet was skipped and the capture came out empty, which surfaced
    # downstream as a loss of nan rather than as "I cannot read this file".
    offsets = {1: 14, 113: 16, 276: 20, 101: 0, 12: 0}
    if link not in offsets:
        raise SystemExit(f"{path}: link type {link} is not one this reads")
    off = offsets[link]
    i = 24
    while i + 16 <= len(blob):
        ts_sec, ts_frac, caplen, _ = struct.unpack(endian + 'IIII', blob[i:i + 16])
        i += 16
        pkt, i = blob[i:i + caplen], i + caplen
        if len(pkt) < off + 20:
            continue
        ip = pkt[off:]
        if ip[0] >> 4 != 4:
            continue
        ihl = (ip[0] & 0x0f) * 4
        if ip[9] != 6 or len(ip) < ihl + 20:
            continue
        tcp = ip[ihl:]
        data = tcp[(tcp[12] >> 4) * 4:]
        if data:
            flow = (ip[12:16], ip[16:20], tcp[0:2], tcp[2:4])
            seq = struct.unpack('!I', tcp[4:8])[0]
            yield ts_sec + ts_frac / (1e9 if nano else 1e6), flow, seq, data

def reassemble(segments):
    """Put one direction of a connection back in order, by sequence number.

    Appending payloads in capture order is only correct on a link that never
    retransmits and never reorders — which is to say, on the loopback we test
    over and not on the internet we are pretending to be. A single retransmitted
    segment appends its bytes twice, the TLS parser loses framing, and every
    record after it is gone. Measured on a real capture that was 86% of
    connections, against 0% of our own: the reference we were comparing against
    was mostly wreckage, and the shape it seemed to have was the wreckage's.

    Returns the bytes and, for each one, when it arrived — a hole ends the
    stream, since nothing after it can be framed with confidence."""
    segments.sort(key=lambda s: s[0])
    out, times, expect = bytearray(), [], None
    for seq, ts, data in segments:
        if expect is None:
            expect = seq
        if seq + len(data) <= expect:
            continue                      # already have these bytes
        if seq > expect:
            break                         # a hole: stop, the rest cannot be framed
        out += data[expect - seq:]
        expect = seq + len(data)
        times.append((len(out), ts))
    return bytes(out), times

def time_of(times, offset):
    """When the byte at this offset arrived."""
    for end, ts in times:
        if offset <= end:
            return ts
    return times[-1][1] if times else 0.0

def docs_hello(paths):
    """One document per collected ClientHello."""
    docs, vocab = [], {}
    for path in paths:
        with open(path, 'rb') as f:
            types = hello_extensions(f.read())
        if not types:
            continue
        for t in types:
            vocab.setdefault(t, len(vocab))
        docs.append(''.join(chr(33 + vocab[t]) for t in types))
    return docs

def flow_dir(flow):
    """Which way this half of the connection runs. A client sends small requests
    and a server sends the page back, so the two directions have nothing to do
    with each other — mixing them into one corpus describes neither. Port 443 is
    the server side."""
    _, _, sport, dport = flow
    return 'down' if int.from_bytes(sport, 'big') == 443 else 'up'

def raw_flows(paths, direction='down'):
    """Per connection, the size of every application record and the gap before
    it, in bytes and microseconds. The unbucketed truth everything else is
    derived from."""
    out = []
    for path in paths:
        segments = {}
        for ts, flow, seq, payload in read_pcap(path):
            if direction != 'both' and flow_dir(flow) != direction:
                continue
            segments.setdefault(flow, []).append((seq, ts, payload))
        for segs in segments.values():
            stream, times = reassemble(segs)
            records, _ = tls_records(stream)
            sizes, gaps, offset, last = [], [], 0, None
            for ctype, size in records:
                offset += size
                if ctype != 0x17:
                    continue
                ts = time_of(times, offset)
                sizes.append(size)
                gaps.append(0 if last is None else int((ts - last) * 1e6))
                last = ts
            if sizes:
                out.append((sizes, gaps))
    return out

def docs_flow(paths, timing, direction='down'):
    """One document per TCP connection, in one direction: its record sizes, or
    the gaps between them. Per connection and not per capture — a window that
    runs across the boundary between two connections describes neither."""
    docs = []
    for sizes, gaps in raw_flows(paths, direction):
        if len(sizes) < 4:
            continue
        docs.append(as_text(gaps, gap_bounds) if timing else as_text(sizes, size_bounds))
    return docs

def load_docs(kind, paths):
    if kind == 'hello':
        return docs_hello(paths)
    base, _, direction = kind.partition('-')
    if base in ('flow', 'timing'):
        return docs_flow(paths, timing=(base == 'timing'), direction=direction or 'down')
    raise SystemExit(f"unknown kind: {kind}")

# eval mode learns what real traffic looks like, then reports how surprised it is
# by ours. A generator only shows what it can produce; the surprise is the number
# that says whether a classifier trained on real traffic would pick us out.
mode = sys.argv[1] if len(sys.argv) > 1 else 'hello'
held_out, ours_docs = [], []
if mode == 'eval':
    if len(sys.argv) < 5:
        raise SystemExit("usage: neural.py eval <hello|flow|timing> <real-glob> <ours-glob>")
    kind = sys.argv[2]
    docs = load_docs(kind, sorted(glob.glob(sys.argv[3])))
    feature = kind
    ours_docs = load_docs(kind, sorted(glob.glob(sys.argv[4])))
    if not ours_docs:
        raise SystemExit("no documents on our side — nothing to compare")
    random.shuffle(docs)
    cut = max(1, len(docs) // 5)  # keep some real traffic back as the control
    held_out, docs = docs[:cut], docs[cut:]
    print(f"mode: eval/{kind} | train {len(docs)} | held-out real {len(held_out)} | ours {len(ours_docs)}")
else:
    paths = sorted(glob.glob(sys.argv[2])) if len(sys.argv) > 2 else \
            sorted(glob.glob('core/protocol/fingerprint/seed_fingerprints/*.bin'))
    docs = load_docs(mode, paths)
    feature = mode
    random.shuffle(docs)
    print(f"mode: {mode} | num docs: {len(docs)} | files: {len(paths)}")
if not docs:
    raise SystemExit("no documents — nothing to learn from")

# Let there be a Tokenizer to translate strings to sequences of integers ("tokens") and back
#
# For the bucketed features the alphabet is every bucket, not the ones this corpus
# happened to contain: Go sends mBucketOf(size) in as a token id, so the id of a
# bucket must be the bucket itself. A capture missing one shifts every id above it.
if feature.startswith('flow') or feature.startswith('timing'):
    uchars = [chr(33 + i) for i in range(len(gap_bounds if feature.startswith('timing') else size_bounds))]
else:
    uchars = sorted(set(''.join(docs))) # unique characters in the dataset become token ids 0..n-1
BOS = len(uchars) # token id for a special Beginning of Sequence (BOS) token
vocab_size = len(uchars) + 1 # total number of unique tokens, +1 is for BOS
print(f"vocab size: {vocab_size}")

# Let there be Autograd to recursively apply the chain rule through a computation graph
class Value:
    __slots__ = ('data', 'grad', '_children', '_local_grads') # Python optimization for memory usage

    def __init__(self, data, children=(), local_grads=()):
        self.data = data                # scalar value of this node calculated during forward pass
        self.grad = 0                   # derivative of the loss w.r.t. this node, calculated in backward pass
        self._children = children       # children of this node in the computation graph
        self._local_grads = local_grads # local derivative of this node w.r.t. its children

    def __add__(self, other):
        other = other if isinstance(other, Value) else Value(other)
        return Value(self.data + other.data, (self, other), (1, 1))

    def __mul__(self, other):
        other = other if isinstance(other, Value) else Value(other)
        return Value(self.data * other.data, (self, other), (other.data, self.data))

    def __pow__(self, other): return Value(self.data**other, (self,), (other * self.data**(other-1),))
    def log(self): return Value(math.log(self.data), (self,), (1/self.data,))
    def exp(self): return Value(math.exp(self.data), (self,), (math.exp(self.data),))
    def relu(self): return Value(max(0, self.data), (self,), (float(self.data > 0),))
    def __neg__(self): return self * -1
    def __radd__(self, other): return self + other
    def __sub__(self, other): return self + (-other)
    def __rsub__(self, other): return other + (-self)
    def __rmul__(self, other): return self * other
    def __truediv__(self, other): return self * other**-1
    def __rtruediv__(self, other): return other * self**-1

    def backward(self):
        topo = []
        visited = set()
        def build_topo(v):
            if v not in visited:
                visited.add(v)
                for child in v._children:
                    build_topo(child)
                topo.append(v)
        build_topo(self)
        self.grad = 1
        for v in reversed(topo):
            for child, local_grad in zip(v._children, v._local_grads):
                child.grad += local_grad * v.grad

# Initialize the parameters, to store the knowledge of the model
n_layer = 1     # depth of the transformer neural network (number of layers)
n_embd = 16     # width of the network (embedding dimension)
block_size = 16 # maximum context length of the attention window (note: the longest name is 15 characters)
n_head = 4      # number of attention heads
head_dim = n_embd // n_head # derived dimension of each head
matrix = lambda nout, nin, std=0.02: [[Value(random.gauss(0, std)) for _ in range(nin)] for _ in range(nout)]
state_dict = {'wte': matrix(vocab_size, n_embd), 'wpe': matrix(block_size, n_embd), 'lm_head': matrix(vocab_size, n_embd)}
for i in range(n_layer):
    state_dict[f'layer{i}.attn_wq'] = matrix(n_embd, n_embd)
    state_dict[f'layer{i}.attn_wk'] = matrix(n_embd, n_embd)
    state_dict[f'layer{i}.attn_wv'] = matrix(n_embd, n_embd)
    state_dict[f'layer{i}.attn_wo'] = matrix(n_embd, n_embd)
    state_dict[f'layer{i}.mlp_fc1'] = matrix(4 * n_embd, n_embd)
    state_dict[f'layer{i}.mlp_fc2'] = matrix(n_embd, 4 * n_embd)
params = [p for mat in state_dict.values() for row in mat for p in row] # flatten params into a single list[Value]
print(f"num params: {len(params)}")

# Define the model architecture: a function mapping tokens and parameters to logits over what comes next
# Follow GPT-2, blessed among the GPTs, with minor differences: layernorm -> rmsnorm, no biases, GeLU -> ReLU
def linear(x, w):
    return [sum(wi * xi for wi, xi in zip(wo, x)) for wo in w]

def softmax(logits):
    max_val = max(val.data for val in logits)
    exps = [(val - max_val).exp() for val in logits]
    total = sum(exps)
    return [e / total for e in exps]

def rmsnorm(x):
    ms = sum(xi * xi for xi in x) / len(x)
    scale = (ms + 1e-8) ** -0.5  # same epsilon as fast.py and the Go port
    return [xi * scale for xi in x]

def gpt(token_id, pos_id, keys, values):
    tok_emb = state_dict['wte'][token_id] # token embedding
    pos_emb = state_dict['wpe'][pos_id] # position embedding
    x = [t + p for t, p in zip(tok_emb, pos_emb)] # joint token and position embedding
    x = rmsnorm(x) # note: not redundant due to backward pass via the residual connection

    for li in range(n_layer):
        # 1) Multi-head Attention block
        x_residual = x
        x = rmsnorm(x)
        q = linear(x, state_dict[f'layer{li}.attn_wq'])
        k = linear(x, state_dict[f'layer{li}.attn_wk'])
        v = linear(x, state_dict[f'layer{li}.attn_wv'])
        keys[li].append(k)
        values[li].append(v)
        x_attn = []
        for h in range(n_head):
            hs = h * head_dim
            q_h = q[hs:hs+head_dim]
            k_h = [ki[hs:hs+head_dim] for ki in keys[li]]
            v_h = [vi[hs:hs+head_dim] for vi in values[li]]
            attn_logits = [sum(q_h[j] * k_h[t][j] for j in range(head_dim)) / head_dim**0.5 for t in range(len(k_h))]
            attn_weights = softmax(attn_logits)
            head_out = [sum(attn_weights[t] * v_h[t][j] for t in range(len(v_h))) for j in range(head_dim)]
            x_attn.extend(head_out)
        x = linear(x_attn, state_dict[f'layer{li}.attn_wo'])
        x = [a + b for a, b in zip(x, x_residual)]
        # 2) MLP block
        x_residual = x
        x = rmsnorm(x)
        x = linear(x, state_dict[f'layer{li}.mlp_fc1'])
        x = [xi.relu() for xi in x]
        x = linear(x, state_dict[f'layer{li}.mlp_fc2'])
        x = [a + b for a, b in zip(x, x_residual)]

    logits = linear(x, state_dict['lm_head'])
    return logits

# Let there be Adam, the blessed optimizer and its buffers
learning_rate, beta1, beta2, eps_adam = 0.01, 0.85, 0.99, 1e-8
m = [0.0] * len(params) # first moment buffer
v = [0.0] * len(params) # second moment buffer

# A connection carries hundreds of records and the attention window holds sixteen,
# so a document has to be cut into windows. Training on only the first one — which
# is what this did — threw away most of every capture and taught the model nothing
# about what a connection looks like past its opening exchange. The cut matches the
# runtime: mCache in Go clears its window when full and carries on from position
# zero. See windows() in fast.py, which does the same.
def encode(doc):
    return [BOS] + [uchars.index(ch) for ch in doc if ch in uchars] + [BOS]

def windows(tokens):
    out = []
    for i in range(0, len(tokens) - 1, block_size):
        inp = tokens[i:i + block_size]
        out.append((inp, tokens[i + 1:i + 1 + len(inp)]))
    return out

batches = [w for doc in docs for w in windows(encode(doc)) if len(w[0]) == len(w[1])]
random.shuffle(batches)
print(f"windows: {len(batches)}")

# Repeat in sequence
num_steps = 1000 # number of training steps
for step in range(num_steps):

    # Take a single window of one document: its tokens, and the same shifted by one
    tokens, targets = batches[step % len(batches)]
    n = len(tokens)

    # Forward the token sequence through the model, building up the computation graph all the way to the loss
    keys, values = [[] for _ in range(n_layer)], [[] for _ in range(n_layer)]
    losses = []
    for pos_id in range(n):
        logits = gpt(tokens[pos_id], pos_id, keys, values)
        probs = softmax(logits)
        loss_t = -probs[targets[pos_id]].log()
        losses.append(loss_t)
    loss = (1 / n) * sum(losses) # final average loss over the document sequence. May yours be low.

    # Backward the loss, calculating the gradients with respect to all model parameters
    loss.backward()

    # Adam optimizer update: update the model parameters based on the corresponding gradients
    lr_t = learning_rate * (1 - step / num_steps) # linear learning rate decay
    for i, p in enumerate(params):
        m[i] = beta1 * m[i] + (1 - beta1) * p.grad
        v[i] = beta2 * v[i] + (1 - beta2) * p.grad ** 2
        m_hat = m[i] / (1 - beta1 ** (step + 1))
        v_hat = v[i] / (1 - beta2 ** (step + 1))
        p.data -= lr_t * m_hat / (v_hat ** 0.5 + eps_adam)
        p.grad = 0

    print(f"step {step+1:4d} / {num_steps:4d} | loss {loss.data:.4f}", end='\r')

# Evaluation: how surprised is a model of real traffic by ours
def doc_loss(doc):
    total, count = 0.0, 0
    for tokens, targets in windows(encode(doc)):
        if len(tokens) != len(targets):
            continue
        keys, values = [[] for _ in range(n_layer)], [[] for _ in range(n_layer)]
        for pos_id in range(len(tokens)):
            logits = gpt(tokens[pos_id], pos_id, keys, values)
            probs = softmax(logits)
            total += -probs[targets[pos_id]].log().data
            count += 1
    return total / count if count else None

def mean_loss(ds):
    vals = [l for l in (doc_loss(d) for d in ds) if l is not None]
    return sum(vals) / len(vals) if vals else float('nan')

if mode == 'eval':
    # Two baselines that learn nothing, to show the model did. Guessing uniformly
    # costs log(V) per token; guessing from how often each class appears costs the
    # entropy of that distribution. A model below both has learned the dependence
    # on context, not just the mix.
    counts = {}
    total_tokens = 0
    for d in docs:
        for ch in d:
            counts[ch] = counts.get(ch, 0) + 1
            total_tokens += 1
    uniform = math.log(vocab_size)
    frequency = -sum((c / total_tokens) * math.log(c / total_tokens) for c in counts.values())

    real_loss, our_loss = mean_loss(held_out), mean_loss(ours_docs)
    print(f"\n--- did it learn anything? (on held-out real traffic it never saw) ---")
    print(f"guessing uniformly:        {uniform:.4f}")
    print(f"guessing by frequency:     {frequency:.4f}")
    print(f"the model:                 {real_loss:.4f}")
    if real_loss < frequency:
        print(f"-> learned: {frequency - real_loss:.4f} nats/token better than knowing only the class mix")
    else:
        print("-> NOT learning: no better than counting how often each class appears")
    print(f"\n--- eval ---")
    print(f"loss on held-out real traffic: {real_loss:.4f}")
    print(f"loss on our traffic:           {our_loss:.4f}")
    gap = our_loss - real_loss
    print(f"gap: {gap:+.4f} nats/token — how much less likely our traffic is under a model of real traffic")
    # The distance from zero is what matters, in either direction. A negative gap
    # is not a pass: it means our stream is *more* predictable than real traffic,
    # which is its own signature — a constant record size scores far below real
    # and is trivially spotted. Judging on the signed value called that
    # indistinguishable.
    if abs(gap) < 0.1:
        print("Indistinguishable by this feature: a model of real traffic is no more surprised by us.")
    elif gap < 0:
        print("Clearly distinguishable — our traffic is too regular to be real by this feature.")
    elif gap < 0.5:
        print("Mildly distinguishable.")
    else:
        print("Clearly distinguishable — this feature gives us away.")
    raise SystemExit(0)

# Export: hand the trained weights to Go, which does the forward pass in the
# datapath. Training stays here; inference there is plain arithmetic.
export_path = os.environ.get('EXPORT')
if export_path:
    def go_matrix(mat):
        rows = [', '.join(f'{p.data:.6f}' for p in row) for row in mat]
        return '{\n' + ''.join(f'\t{{{r}}},\n' for r in rows) + '}'
    pre = os.environ.get('PREFIX', 'm')
    bounds = gap_bounds if feature.startswith('timing') else size_bounds
    blist = ', '.join(str(x) for x in bounds)
    with open(export_path, 'w') as f:
        f.write('// Code generated by neural/neural.py. DO NOT EDIT.\n\npackage relay\n\n')
        f.write(f'// Trained on {len(docs)} documents of real traffic, mode {mode}.\n')
        f.write(f'const {pre}Vocab, {pre}Embd, {pre}Head, {pre}Block = {vocab_size}, {n_embd}, {n_head}, {block_size}\n\n')
        f.write(f'var {pre}Bounds = []int{{{blist}}}\n\n')
        for name, mat in state_dict.items():
            f.write(f'var {pre}_{name.replace(".", "_")} = [][]float64{go_matrix(mat)}\n\n')
    # A reference the Go port can be checked against: same history, same numbers.
    for hist in ([], [0], [0, 5], [5, 5, 5]):
        keys, values = [[] for _ in range(n_layer)], [[] for _ in range(n_layer)]
        for pos, tok in enumerate([BOS] + hist):
            logits = gpt(tok, pos, keys, values)
        probs = softmax(logits)
        print("probe " + str(hist) + ": " + ' '.join(f'{p.data:.4f}' for p in probs))
    print(f"\nexported weights to {export_path}")
    raise SystemExit(0)

# Inference: may the model babble back to us
temperature = 0.5 # in (0, 1], control the "creativity" of generated text, low to high
print("\n--- inference (new, hallucinated names) ---")
for sample_idx in range(20):
    keys, values = [[] for _ in range(n_layer)], [[] for _ in range(n_layer)]
    token_id = BOS
    sample = []
    for pos_id in range(block_size):
        logits = gpt(token_id, pos_id, keys, values)
        probs = softmax([l / temperature for l in logits])
        token_id = random.choices(range(vocab_size), weights=[p.data for p in probs])[0]
        if token_id == BOS:
            break
        sample.append(uchars[token_id])
    print(f"sample {sample_idx+1:2d}: {''.join(sample)}")
