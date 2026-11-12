"""function starts that IDA has and the table (from Ghidra) does not: candidates for
config/<version>/extra_starts.txt.

    py -3.12 tools/local/ida.py starts all           # first: IDA's starts
    python -I tools/local/idastarts.py               # build/us-v1.2/ida/extra_starts.txt, every program
    python -I tools/local/idastarts.py --apply       # and adds them to config/<version>/extra_starts.txt

a start of IDA's inside an ARM function of the table is taken when the function that holds
it cannot reach it: following that function from its entry (every branch inside it, every
fall-through; a return or an unconditional jump ends a path), the address is never
executed. then it is not part of that function, whatever Ghidra joined. a function with a
jump table (a computed pc) is left alone: its paths are not all known this way.
the others are only counted.
"""
import bisect
import csv
import sys
from collections import Counter, defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import config


def reach(image, start, end):
    """the addresses the function at start executes within [start, end), or None when it
    computes its pc (a jump table)."""
    seen, work = set(), [start]
    while work:
        at = work.pop()
        while start <= at < end and at not in seen:
            seen.add(at)
            w = image.word(at)
            cond = w >> 28
            always = cond == 0xE
            if cond == 0xF:
                at += 4
                continue
            if (w & 0x0F000000) == 0x0A000000:                      # b
                off = w & 0xFFFFFF
                target = at + 8 + 4 * (off - 0x1000000 if off & 0x800000 else off)
                if start <= target < end:
                    work.append(target)
                if always:
                    break
            elif (w & 0x0FFFFFF0) == 0x012FFF10:                    # bx
                if always:
                    break
            elif (w & 0x0E108000) == 0x08108000:                    # ldm with pc
                if always:
                    break
            elif (w & 0x0C10F000) == 0x0410F000:                    # ldr pc, ...
                if (w >> 16) & 0xF == 0xF:
                    return None                                     # from a table after the instruction
                if always:
                    break
            elif (w & 0x0C00F000) == 0x0000F000 and (w & 0x0E000090) != 0x00000090 \
                    and ((w >> 21) & 0xF) not in (8, 9, 10, 11):    # a data operation into pc
                if ((w >> 21) & 0xF) == 13 and not w & 0x02000000 and (w & 0xFFF) == 0xE:
                    if always:                                      # mov pc, lr
                        break
                else:
                    return None                                     # add pc, pc, rX: a jump table
            at += 4
    return seen


def main():
    with open(config.CONFIG / "functions.csv", encoding="utf-8", newline="") as f:
        table = defaultdict(dict)
        for r in csv.DictReader(f):
            if r["kind"] != "stub":
                table[r["module"]][int(r["start"], 16)] = r
    count, out = Counter(), []
    for program, rows in sorted(table.items()):
        listed = config.BUILD / "ida" / f"{program.replace('.', '_')}.starts.txt"
        if not listed.exists():
            count["programs without IDA's starts"] += 1
            continue
        ida = sorted((int(p[0], 16), p[2] if len(p) > 2 else "arm")
                     for p in (line.split() for line in listed.read_text(encoding="utf-8").splitlines()) if p)
        starts = sorted(rows)
        image = config.Image(program)
        reached = {}
        for a, mode in ida:
            if a in rows or a & 3 or mode != "arm":
                continue
            i = bisect.bisect_right(starts, a) - 1
            if i < 0:
                continue
            r = rows[starts[i]]
            start, end = starts[i], int(r["end"], 16)
            if not start < a < end or r["mode"] != "arm":
                continue
            if start not in reached:
                reached[start] = reach(image, start, end)
            seen = reached[start]
            library = r["library"].rstrip("?") or "unknown"
            if seen is None:
                count["left out: its function has a jump table"] += 1
            elif a in seen:
                count["left out: its function reaches it"] += 1
            else:
                count[f"taken, {library}"] += 1
                out.append(f"{program} {a:08X}    # IDA; not reached from {start:08X} ({library})")
    path = config.BUILD / "ida" / "extra_starts.txt"
    path.write_text("\n".join(out) + "\n", encoding="utf-8", newline="\n")
    for k, v in sorted(count.items()):
        print(f"{v:6} {k}")
    print(f"{len(out)} starts in {path}")
    if "--apply" in sys.argv:
        target = config.CONFIG / "extra_starts.txt"
        have = target.read_text(encoding="utf-8").splitlines() if target.exists() else []
        known = {tuple(line.split("#")[0].split()[:2]) for line in have}
        new = [line for line in out if tuple(line.split("#")[0].split()[:2]) not in known]
        target.write_text("\n".join(have + new) + "\n", encoding="utf-8", newline="\n")
        print(f"{len(new)} added to {target}")


if __name__ == "__main__":
    main()
