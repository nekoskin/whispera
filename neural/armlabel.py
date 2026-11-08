"""Label each dial arm by how distinguishable its traffic is from real TLS.

Input is a directory of classic pcaps: one reference capture of real traffic
(real.pcap) and one capture per arm (arm-<n>.pcap). For every arm it runs the
same three checks the stand censor uses and writes arm,scores to stdout as CSV,
so the policy trainer can prefer arms that blend in, not only arms that survive.

Pure standard library, like neural.py — no third-party packages.
"""

import argparse
import glob
import os
import struct


def read_pcap(path):
    """Yield (flow, seq, direction, payload) for every TCP segment with data.

    direction is 'up' toward port 443 (client->server) or 'down' back."""
    with open(path, 'rb') as f:
        blob = f.read()
    if len(blob) < 24:
        return
    magic = blob[:4]
    endian = '<' if magic in (b'\xd4\xc3\xb2\xa1', b'\x4d\x3c\xb2\xa1') else '>'
    link = struct.unpack(endian + 'I', blob[20:24])[0]
    offset = {1: 14, 113: 16, 276: 20, 101: 0, 12: 0}.get(link)
    if offset is None:
        raise SystemExit(f'{path}: link type {link} is not one this reads')
    i = 24
    while i + 16 <= len(blob):
        _, _, caplen, _ = struct.unpack(endian + 'IIII', blob[i:i + 16])
        i += 16
        pkt = blob[i:i + caplen]
        i += caplen
        if len(pkt) < offset + 20:
            continue
        ip = pkt[offset:]
        if ip[0] >> 4 != 4:
            continue
        ihl = (ip[0] & 0x0f) * 4
        if ip[9] != 6 or len(ip) < ihl + 20:
            continue
        total = struct.unpack('!H', ip[2:4])[0]
        tcp = ip[ihl:total] if total else ip[ihl:]
        if len(tcp) < 20:
            continue
        data = tcp[(tcp[12] >> 4) * 4:]
        sport, dport = struct.unpack('!HH', tcp[0:4])
        seq = struct.unpack('!I', tcp[4:8])[0]
        if dport == 443:
            flow, direction = (ip[12:16], ip[16:20], sport), 'up'
        elif sport == 443:
            flow, direction = (ip[16:20], ip[12:16], dport), 'down'
        else:
            continue
        yield flow, seq, direction, bytes(data)


def reassemble(segments):
    """One direction of a connection, ordered by sequence number; a hole ends it."""
    segments.sort(key=lambda s: s[0])
    out, expect = bytearray(), None
    for seq, data in segments:
        if expect is None:
            expect = seq
        if seq + len(data) <= expect:
            continue
        if seq > expect:
            break
        out += data[expect - seq:]
        expect = seq + len(data)
    return bytes(out)


def tls_records(buf):
    """Whole TLS records off the front of a reassembled stream: (type, wire size)."""
    out, i = [], 0
    while i + 5 <= len(buf):
        if buf[i] not in (0x14, 0x15, 0x16, 0x17):
            return out
        size = 5 + (buf[i + 3] << 8 | buf[i + 4])
        if size <= 5 or size > 16640:
            return out
        if i + size > len(buf):
            break
        out.append((buf[i], size))
        i += size
    return out


def connections(path):
    """Group segments into connections, each with its up/down records in order."""
    up, down, order = {}, {}, {}
    for flow, seq, direction, data in read_pcap(path):
        if not data:
            continue
        (up if direction == 'up' else down).setdefault(flow, []).append((seq, data))
        order.setdefault(flow, []).append((direction, len(data)))
    conns = []
    for flow in order:
        conns.append({
            'up': tls_records(reassemble(up.get(flow, []))),
            'down': tls_records(reassemble(down.get(flow, []))),
            'order': order[flow],
        })
    return conns


SIZE_BUCKETS = [(0, 64), (64, 128), (128, 256), (256, 512), (512, 1024),
                (1024, 2048), (2048, 4096), (4096, 8192), (8192, 16000), (16000, 16641)]


def size_histogram(conns):
    """Fraction of application records in each wire-size bucket, both directions."""
    sizes = [sz for c in conns for way in ('up', 'down') for t, sz in c[way] if t == 0x17]
    total = len(sizes) or 1
    return [sum(lo <= s < hi for s in sizes) / total for lo, hi in SIZE_BUCKETS]


def total_variation(p, q):
    """0 when two histograms match, 1 when they are disjoint."""
    return 0.5 * sum(abs(a - b) for a, b in zip(p, q))


def fragmented_rate(conns, limit):
    """Share of connections whose hello spans >= limit up packets before a reply."""
    fired = seen = 0
    for c in conns:
        before, replied = 0, False
        for direction, _ in c['order']:
            if direction == 'down':
                replied = True
                break
            before += 1
        if before == 0:
            continue
        seen += 1
        if before >= limit:
            fired += 1
    return fired / seen if seen else 0.0


def first_flight_rate(conns, hello_lo, cert_min, window):
    """Share of connections showing an up flight >= hello_lo then a down flight
    >= cert_min within the first `window` application records: the encapsulated
    handshake burst."""
    fired = seen = 0
    for c in conns:
        flights, budget = [], window
        for direction, size in c['order']:
            if budget <= 0:
                break
            budget -= 1
            if flights and flights[-1][0] == direction:
                flights[-1][1] += size
            else:
                flights.append([direction, size])
        if not flights:
            continue
        seen += 1
        for a, b in zip(flights, flights[1:]):
            if a[0] == 'up' and a[1] >= hello_lo and b[0] == 'down' and b[1] >= cert_min:
                fired += 1
                break
    return fired / seen if seen else 0.0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('dir', help='directory with real.pcap and arm-<n>.pcap')
    ap.add_argument('--reference', default='real.pcap', help='real-traffic capture inside dir')
    ap.add_argument('--packet-limit', type=int, default=3, help='hello packets that trip the fragmented-handshake check')
    ap.add_argument('--hello-lo', type=int, default=400, help='up flight bytes that count as an inner hello')
    ap.add_argument('--cert-min', type=int, default=1200, help='down flight bytes that count as a cert burst')
    ap.add_argument('--window', type=int, default=40, help='leading application records the first-flight check looks at')
    ap.add_argument('--weight-size', type=float, default=1.0)
    ap.add_argument('--weight-firstflight', type=float, default=1.0)
    ap.add_argument('--weight-fragmented', type=float, default=1.0)
    ap.add_argument('--as-config', type=float, metavar='WEIGHT',
                    help='instead of CSV, print a client policy: block with this selection weight')
    args = ap.parse_args()

    ref_path = os.path.join(args.dir, args.reference)
    reference = size_histogram(connections(ref_path))

    weights = [args.weight_size, args.weight_firstflight, args.weight_fragmented]
    weight_sum = sum(weights) or 1.0

    rows = []
    for path in sorted(glob.glob(os.path.join(args.dir, 'arm-*.pcap'))):
        arm = os.path.basename(path)[len('arm-'):-len('.pcap')]
        conns = connections(path)
        size_tvd = total_variation(size_histogram(conns), reference)
        first_flight = first_flight_rate(conns, args.hello_lo, args.cert_min, args.window)
        fragmented = fragmented_rate(conns, args.packet_limit)
        combined = (weights[0] * size_tvd + weights[1] * first_flight + weights[2] * fragmented) / weight_sum
        rows.append((arm, size_tvd, first_flight, fragmented, combined))

    if args.as_config is None:
        print('arm,size_tvd,first_flight,fragmented,distinguishability')
        for arm, size_tvd, first_flight, fragmented, combined in rows:
            print(f'{arm},{size_tvd:.4f},{first_flight:.4f},{fragmented:.4f},{combined:.4f}')
        return

    # The config array is positional in arm order, so arms must be 0..n-1.
    ordered = sorted(rows, key=lambda r: int(r[0]))
    for i, r in enumerate(ordered):
        if int(r[0]) != i:
            raise SystemExit(f'arms must be numbered 0..n-1 with no gaps; found {r[0]}')
    print('policy:')
    print(f'  distinguishability_weight: {args.as_config}')
    print('  distinguishability:')
    for r in ordered:
        print(f'    - {r[4]:.4f}')


if __name__ == '__main__':
    main()
