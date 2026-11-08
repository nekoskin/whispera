"""Run every measurement we care about and print one table.

Doing this by hand is what made a day of work slow, and worse, it made single
runs look like results: twice a number that turned out to be noise was almost
taken for an improvement. So every variant is measured several times and the
spread is printed next to the mean. A difference smaller than the spread is not
a difference.

    python neural/report.py <real.pcap> <ours.pcap> [<ours2.pcap> ...]

Each "ours" file is a variant — capture them with different flags set on the
server, name the files after what was on, and the table will say which won.
"""

import os
import subprocess
import sys
import statistics
import re

KINDS = ('flow', 'flow-up', 'timing')
REPEATS = int(os.environ.get('REPEATS', '3'))

GAP = re.compile(r'gap: ([+-][\d.]+)')
LEARNED = re.compile(r'-> learned: ([\d.]+)')
HELD = re.compile(r'the model:\s+([\d.]+)')


def measure(kind, real, ours, seed):
    """One eval run. The seed changes between repeats: with a fixed one every
    repeat trains the same model on the same order and the spread comes out zero,
    which reads as certainty where there is none."""
    env = dict(os.environ, SEED=str(seed))
    run = subprocess.run(
        [sys.executable, os.environ.get('TRAINER', 'neural/fast.py'), 'eval', kind, real, ours],
        capture_output=True, text=True, env=env)
    out = run.stdout
    gap = GAP.search(out)
    if not gap:
        # Say why, instead of reporting an empty cell: a missing file and a
        # capture with nothing in it are different problems.
        why = (run.stderr.strip() or out.strip() or 'no output').splitlines()[-1]
        return None, why[:60]
    learned = LEARNED.search(out)
    return (float(gap.group(1)), float(learned.group(1)) if learned else 0.0), None


def main():
    if len(sys.argv) < 3:
        raise SystemExit(__doc__)
    real, variants = sys.argv[1], sys.argv[2:]
    missing = [p for p in [real] + variants if not os.path.exists(p)]
    if missing:
        raise SystemExit("no such file: " + ", ".join(missing))

    print(f"reference: {os.path.basename(real)}   repeats: {REPEATS}\n")
    header = f"{'variant':<24}{'feature':<10}{'gap':>18}{'judge learned':>16}"
    print(header)
    print('-' * len(header))

    for path in variants:
        name = os.path.splitext(os.path.basename(path))[0]
        for kind in KINDS:
            results = [measure(kind, real, path, 42 + i) for i in range(REPEATS)]
            runs = [r for r, _ in results if r]
            if not runs:
                why = next((w for _, w in results if w), 'no output')
                print(f"{name:<24}{kind:<10}{'failed: ' + why:>18}")
                continue
            gaps = [r[0] for r in runs]
            mean = statistics.mean(gaps)
            spread = statistics.pstdev(gaps) if len(gaps) > 1 else 0.0
            learned = statistics.mean(r[1] for r in runs)
            print(f"{name:<24}{kind:<10}{mean:>11.2f} ±{spread:<5.2f}{learned:>15.2f}")
        print()

    print("gap: how much less likely our traffic is under a model of real traffic,")
    print("     in nats per record. 0 means indistinguishable by that feature, and")
    print("     the distance from 0 is what counts in either direction: a negative")
    print("     gap means our stream is more predictable than real traffic, which")
    print("     gives us away just as surely.")
    print("judge learned: how much better than guessing by frequency the judge got")
    print("     on traffic it never saw. Near 0 means the judge is useless and the")
    print("     gap beside it means nothing.")


if __name__ == '__main__':
    main()
