"""which compilers write the game's bytes: tiny.py's candidates under every compiler.

  python -I tools/local/ccsweep.py [--flags "..."]

run tools/tiny.py first: its candidates (build/<version>/tiny/*.cpp, every
function it could read, in each variant) are compiled with each compiler of
toolchain/armcc and the installed one. a function counts for a compiler when
one of its variants matches. the table says how many each compiler matches,
and build/<version>/ccsweep.txt lists the functions that tell compilers apart
(matched by some, not by all), with the compilers that match them.
"""
import argparse
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import config
import match

LINE = re.compile(r"^//! (\S+) (\S+)", re.M)


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--flags")
    p.add_argument("--cc", nargs="*", help="only these compilers")
    a = p.parse_args()
    files = sorted((config.BUILD / "tiny").glob("*.cpp"))
    if not files:
        raise SystemExit("no candidates: run tools/tiny.py")
    sources = [(f, LINE.findall(f.read_text(encoding="utf-8"))) for f in files]
    ccs = a.cc or config.compilers()
    won = {cc: set() for cc in ccs}
    everything = set()
    for cc in ccs:
        for path, items in sources:
            for (where, sym), result in zip(items, match.check_many(path, items, cc, a.flags, lint=False)):
                everything.add(where)
                if result[0] == "match":
                    won[cc].add(where)
        print(f"{cc:10} {len(won[cc]):6} of {len(everything)}", flush=True)
    if len(ccs) == 1:
        return
    some = set().union(*won.values())
    common = set.intersection(*won.values())
    apart = sorted(some - common)
    with open(config.BUILD / "ccsweep.txt", "w", encoding="utf-8", newline="\n") as f:
        for where in apart:
            f.write(f"{where} {' '.join(cc for cc in ccs if where in won[cc])}\n")
    print(f"matched by every compiler: {len(common)}; by some only: {len(apart)} (build/{config.VERSION}/ccsweep.txt)")
    groups = {}
    for where in apart:
        key = tuple(cc for cc in ccs if where in won[cc])
        groups[key] = groups.get(key, 0) + 1
    for key, n in sorted(groups.items(), key=lambda kv: -kv[1])[:12]:
        print(f"  {n:5} only by: {' '.join(key)}")


if __name__ == "__main__":
    main()
