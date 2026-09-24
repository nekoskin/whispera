import csv
import os
import struct
import sys
from collections import defaultdict

OUT = sys.argv[1] if len(sys.argv) > 1 else "out"
PCAP = sys.argv[2] if len(sys.argv) > 2 else os.path.join(OUT, "dump.pcap")
REPORT = os.path.join(OUT, "report.md")


def packets(path):
    with open(path, "rb") as f:
        gh = f.read(24)
        if len(gh) < 24:
            return
        magic = struct.unpack("<I", gh[:4])[0]
        if magic == 0xA1B2C3D4:
            endian, nano = "<", False
        elif magic == 0xD4C3B2A1:
            endian, nano = ">", False
        elif magic == 0xA1B23C4D:
            endian, nano = "<", True
        elif magic == 0x4D3CB2A1:
            endian, nano = ">", True
        else:
            raise SystemExit(f"not a classic pcap: magic {magic:#x}")
        link = struct.unpack(endian + "I", gh[20:24])[0]
        while True:
            hdr = f.read(16)
            if len(hdr) < 16:
                return
            ts_s, ts_frac, incl, _orig = struct.unpack(endian + "IIII", hdr)
            data = f.read(incl)
            if len(data) < incl:
                return
            ts = ts_s + (ts_frac / 1e9 if nano else ts_frac / 1e6)
            yield ts, link, data


def tcp_payload(link, data):
    if link == 1:
        if len(data) < 14 or struct.unpack("!H", data[12:14])[0] != 0x0800:
            return None
        ip = data[14:]
    elif link == 101:
        ip = data
    else:
        return None
    if len(ip) < 20 or (ip[0] >> 4) != 4:
        return None
    ihl = (ip[0] & 0x0F) * 4
    if ip[9] != 6:
        return None
    src = ".".join(str(b) for b in ip[12:16])
    dst = ".".join(str(b) for b in ip[16:20])
    total = struct.unpack("!H", ip[2:4])[0]
    tcp = ip[ihl:total] if total else ip[ihl:]
    if len(tcp) < 20:
        return None
    sport, dport = struct.unpack("!HH", tcp[:4])
    off = (tcp[12] >> 4) * 4
    flags = tcp[13]
    return (src, sport, dst, dport), tcp[off:], flags


def percentile(values, p):
    if not values:
        return 0
    s = sorted(values)
    i = min(len(s) - 1, max(0, int(round((len(s) - 1) * p))))
    return s[i]


def main():
    if not os.path.exists(PCAP):
        raise SystemExit(f"no dump at {PCAP}")

    streams = defaultdict(bytes)
    records = defaultdict(list)
    first_seen, last_seen = {}, {}
    bytes_fwd = defaultdict(int)
    syns = []

    for ts, link, data in packets(PCAP):
        parsed = tcp_payload(link, data)
        if not parsed:
            continue
        key, payload, flags = parsed
        if flags & 0x02 and not flags & 0x10:
            syns.append((ts, key))
        if not payload:
            continue
        first_seen.setdefault(key, ts)
        last_seen[key] = ts
        bytes_fwd[key] += len(payload)
        buf = streams[key] + payload
        while len(buf) >= 5:
            n = struct.unpack("!H", buf[3:5])[0]
            if buf[0] not in (0x14, 0x15, 0x16, 0x17) or n > 20000:
                buf = b""
                break
            if len(buf) < 5 + n:
                break
            records[key].append((ts, buf[0], n))
            buf = buf[5 + n:]
        streams[key] = buf

    lines = ["# Whispera e2e: дамп трафика", ""]
    lines.append(f"Пакетов разобрано в {len(first_seen)} потоках, TCP-соединений открыто: {len(syns)}.")
    lines.append("")

    if syns:
        t0 = syns[0][0]
        buckets = defaultdict(int)
        for ts, _ in syns:
            buckets[int((ts - t0) // 10) * 10] += 1
        lines.append("## Новые соединения по 10-секундным окнам")
        lines.append("")
        lines.append("| секунда | открыто |")
        lines.append("|---|---|")
        for b in sorted(buckets):
            lines.append(f"| {b} | {buckets[b]} |")
        lines.append("")

    lines.append("## Потоки: размеры TLS-записей и паузы")
    lines.append("")
    lines.append("| поток | записей | первая data-запись | медиана | p90 | пауза p50, мс | пауза p90, мс | байт |")
    lines.append("|---|---|---|---|---|---|---|---|")
    for key in sorted(records, key=lambda k: -len(records[k]))[:20]:
        recs = records[key]
        data_recs = [(ts, n) for ts, t, n in recs if t == 0x17]
        sizes = [n for _, n in data_recs]
        gaps = [
            (data_recs[i][0] - data_recs[i - 1][0]) * 1000
            for i in range(1, len(data_recs))
        ]
        src, sport, dst, dport = key
        first = sizes[0] if sizes else 0
        lines.append(
            f"| {src}:{sport}→{dst}:{dport} | {len(recs)} | {first} | "
            f"{percentile(sizes, 0.5)} | {percentile(sizes, 0.9)} | "
            f"{percentile(gaps, 0.5):.1f} | {percentile(gaps, 0.9):.1f} | {bytes_fwd[key]} |"
        )
    lines.append("")

    all_sizes = [n for key in records for ts, t, n in records[key] if t == 0x17]
    if all_sizes:
        hist = defaultdict(int)
        for n in all_sizes:
            hist[(n // 1000) * 1000] += 1
        lines.append("## Гистограмма размеров data-записей (шаг 1000 байт)")
        lines.append("")
        lines.append("| размер | записей |")
        lines.append("|---|---|")
        for b in sorted(hist):
            lines.append(f"| {b}–{b + 999} | {hist[b]} |")
        lines.append("")

    lines.append("## Мелкие записи (заполнитель тишины)")
    lines.append("")
    lines.append("| поток | мелких записей | байт | медиана размера | медиана паузы, мс | кбит/с |")
    lines.append("|---|---|---|---|---|---|")
    for key in sorted(records, key=lambda k: -len(records[k]))[:20]:
        small = [(ts, n) for ts, t, n in records[key] if t == 0x17 and n < 2000]
        if len(small) < 3:
            continue
        sizes = [n for _, n in small]
        gaps = [(small[i][0] - small[i - 1][0]) * 1000 for i in range(1, len(small))]
        span = small[-1][0] - small[0][0]
        rate = (sum(sizes) * 8 / 1000 / span) if span > 0 else 0
        src, sport, dst, dport = key
        lines.append(
            f"| {src}:{sport}→{dst}:{dport} | {len(small)} | {sum(sizes)} | "
            f"{percentile(sizes, 0.5)} | {percentile(gaps, 0.5):.0f} | {rate:.1f} |"
        )
    lines.append("")

    # One file per user when the run is scaled, a single one when it is not.
    files = [os.path.join(OUT, n) for n in sorted(os.listdir(OUT))
             if n.startswith("events-") and n.endswith(".csv")]
    if not files and os.path.exists(os.path.join(OUT, "events.csv")):
        files = [os.path.join(OUT, "events.csv")]
    if files:
        rows = []
        for path in files:
            rows.extend(csv.DictReader(open(path)))
        ok = sum(1 for r in rows if r["http_code"] == "200")
        reshapes = [r for r in rows if r["action"] == "reshape"]
        lines.append("## Проба и реакция клиента")
        lines.append("")
        lines.append(f"Проб: {len(rows)}, успешных: {ok}, перестроений формы: {len(reshapes)}.")
        lines.append("")
        if rows:
            gaps, run = [], 0
            for r in rows:
                if r["http_code"] == "200":
                    if run:
                        gaps.append(run)
                    run = 0
                else:
                    run += 1
            if run:
                gaps.append(run)
            if gaps:
                worst = max(gaps)
                lines.append(
                    f"Самый долгий провал: {worst} проб подряд "
                    f"(~{worst * int(rows[0].get('probe_every', 2) or 2)} с)."
                )
                lines.append("")
        lines.append("| время | код | пауза, мс | pad_min | pad_max | действие |")
        lines.append("|---|---|---|---|---|---|")
        for r in rows:
            lines.append(
                f"| {r['ts']} | {r['http_code']} | {r['probe_ms']} | "
                f"{r['pad_min']} | {r['pad_max']} | {r['action']} |"
            )
        lines.append("")

    censor_log = os.path.join(OUT, "censor.log")
    if os.path.exists(censor_log):
        text = open(censor_log, errors="ignore").read().splitlines()
        rules = [l for l in text if l.startswith("rule:") or " rule:" in l]
        drops = [l for l in text if "DROP" in l]
        passes = [l for l in text if "PASS" in l]
        lines.append("## Цензор")
        lines.append("")
        lines.append(f"Смен правила: {len(rules)}, пропущено потоков: {len(passes)}, вырезано: {len(drops)}.")
        lines.append("")
        for l in rules:
            lines.append(f"- {l.strip()}")
        lines.append("")

    open(REPORT, "w", encoding="utf-8").write("\n".join(lines))
    print(f"report: {REPORT}")
    print(f"pcap:   {PCAP}")


if __name__ == "__main__":
    main()
