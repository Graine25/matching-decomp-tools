"""maps the functions of the main version onto another version of the game.

  python -I tools/versions.py um-v1.2      # config/um-v1.2/map.csv

Ultra Sun and Ultra Moon are one program built twice: the same functions in the same
order, a few of them different, and everything after a function that changed size moved
by the difference. this walks the main version's table (config/<version>/functions.csv)
and finds each function in the other version's files (orig/<other>/): at the same place,
or moved; then compares the two, word by word:

  same     every byte equal, at the same address
  moved    equal but for what moving changes: the distance of a branch or call, an
           address in the function's pool that is a little off (the thing it names moved)
  differs  anything else: this function is not the same code in the two versions
           (or is Thumb code that changed in any way: those are not compared word by word)

columns: module, start (the main version's), other (the other version's), status.
a source that matches a `same` or `moved` function is that function's source in both
versions; a `differs` one needs the version told apart in the source. addresses only.
"""
import csv
import json
import struct
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import config
import functable

REACH = 0x1000          # how far, in bytes, a function is looked for when it is not where expected


def words(data, at, size):
    return struct.unpack_from(f"<{size // 4}I", data, at)


def compare(a, b, lo, hi):
    """'same', 'moved' or None for two functions' words; lo..hi: the program's addresses."""
    moved = False
    for x, y in zip(a, b):
        if x == y:
            continue
        if (x >> 24) == (y >> 24) and (x >> 24) & 0x0E == 0x0A and (x >> 28) != 0xF:
            moved = True                                    # b, bl: the target moved
        elif lo <= x < hi and lo <= y < hi and abs(x - y) < 0x8000:
            moved = True                                    # an address in the pool
        else:
            return None
    return "moved" if moved else "same"


def main():
    if len(sys.argv) != 2 or sys.argv[1].startswith("-"):
        print(__doc__.strip())
        raise SystemExit(0 if "--help" in sys.argv else "name the other version, as its folder in orig/")
    other = sys.argv[1]
    there = config.ROOT / "orig" / other
    if not (there / "exefs" / "code.bin").exists():
        raise SystemExit(f"no {there}")
    rows, count, size = [], Counter(), Counter()
    for module, funcs in functable.table().items():
        if module == "code.bin":
            a, b, base = (config.ORIG / "exefs" / "code.bin").read_bytes(), (there / "exefs" / "code.bin").read_bytes(), 0x100000
            lo, hi = base, base + len(a) + 0x400000
        else:
            a, b, base = (config.ORIG / "romfs" / f"{module}.cro").read_bytes(), (there / "romfs" / f"{module}.cro").read_bytes(), 0
            lo, hi = 0, len(a)
        whole = a == b
        delta = 0
        for start, (end, _, mode, kind, _) in sorted(funcs.items()):
            if kind == "stub":
                continue
            n = (end - start) & ~3
            at = (start & ~1) - base
            status = None
            if whole:
                status = "same"
            elif mode != "arm" or n < 4:
                equal = a[at:at + (end - start)] == b[at + delta:at + delta + (end - start)]
                status = "differs" if not equal else "moved" if delta else "same"
            else:
                mine = words(a, at, n)
                for d in sorted(range(delta - REACH, delta + REACH + 4, 4), key=lambda d: abs(d - delta)):
                    if at + d < 0 or at + d + n > len(b):
                        continue
                    got = compare(mine, words(b, at + d, n), lo, hi)
                    if got:
                        status = got if d == 0 else "moved"
                        delta = d
                        break
                    if n < 16:
                        break                               # too short to look for elsewhere
                status = status or "differs"
            rows.append((module, f"{start:08X}", f"{start + delta:08X}", status))
            count[status] += 1
            size[status] += end - start
    out = config.ROOT / "config" / other
    out.mkdir(parents=True, exist_ok=True)
    with open(out / "map.csv", "w", encoding="utf-8", newline="") as f:
        w = csv.writer(f, lineterminator="\n")
        w.writerow(("module", "start", "other", "status"))
        w.writerows(rows)
    total, total_size = sum(count.values()), sum(size.values())
    for status in ("same", "moved", "differs"):
        print(f"{status:8} {count[status]:6} functions {100 * count[status] / total:6.2f}%  {size[status]:9} bytes {100 * size[status] / total_size:6.2f}%")
    report = config.BUILD / "report.json"
    if report.exists():
        status_of = {(m, int(s, 16)): st for m, s, _, st in rows}
        mine = Counter()
        for r in json.loads(report.read_text(encoding="utf-8")):
            if r["status"] == "match":
                module, _, addr = r["where"].rpartition(":")
                mine[status_of.get((module or "code.bin", int(addr, 16)), "not in the table")] += 1
        print(f"of the {sum(mine.values())} matched functions, in {other}: " + ", ".join(f"{v} {k}" for k, v in mine.most_common()))
    print(f"wrote {out / 'map.csv'}")


if __name__ == "__main__":
    main()
