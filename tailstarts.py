"""function starts that the linker hid: a tail call to the function placed right after is a NOP
(`mov r0, r0`, PLAN.md "The linker's NOPs"), so Ghidra runs the two functions together.

    python -I tools/tailstarts.py            counts, and the starts in build/<version>/tailstarts.txt
    python -I tools/tailstarts.py --apply    and adds them to config/<version>/extra_starts.txt
                                             (then tools/refresh.py --table)

a NOP is such a tail call when the function reaches it with lr not saved: from the entry (lr
holds the return address), through every branch and fall-through, a push of lr saves it and
a pop into lr gives it back. a call (bl) the linker made a NOP needs lr saved, so a NOP
reached with lr free can only be the last instruction of its function, and the next word is
another function. it is taken only when:
- every path reaches that NOP with lr free (a NOP reached both ways, a bl with lr free, or a
  computed pc, and the function is left alone);
- the code before it, followed on its own, branches into the rest only at the new start (a
  conditional tail call to the same next function), never past it.
the rest is then looked at the same way. ARM code of the game, gfl2, nw, middleware and
unknown functions; the SDK's and the compiler's library hold hand-written assembly.
"""
import csv
import sys
from collections import Counter, defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import config

NOP = 0xE1A00000
SKIP = ("sdk", "armlib")


def analyze(image, start, end):
    """(tail NOPs, targets of branches that leave [start, end)) of the code at start, or None
    when its paths cannot be followed with certainty."""
    seen, tails, out = {}, set(), set()
    work = [(start, False)]
    while work:
        at, saved = work.pop()
        while True:
            if not start <= at < end:
                out.add(at)
                break
            if at in seen:
                if seen[at] != saved:
                    return None                                     # reached with lr saved and free
                break
            seen[at] = saved
            w = image.word(at)
            cond = w >> 28
            always = cond == 0xE
            if cond == 0xF:                                         # blx, pld...: not followed
                if (w & 0xFE000000) == 0xFA000000 and not saved:
                    return None
                at += 4
                continue
            if w == NOP:
                if not saved:
                    tails.add(at)                                   # the tail call: the path ends
                    break
                at += 4
                continue
            if (w & 0x0F000000) == 0x0B000000:                      # bl
                if not saved:
                    return None
                at += 4
                continue
            if (w & 0x0F000000) == 0x0A000000:                      # b
                off = w & 0xFFFFFF
                target = at + 8 + 4 * (off - 0x1000000 if off & 0x800000 else off)
                work.append((target, saved))
                if always:
                    break
                at += 4
                continue
            if (w & 0x0FFF4000) == 0x092D4000 or (w & 0x0FFFF000) == 0x052DE000:   # push lr, str lr, [sp, #-n]!
                if not always:
                    return None
                at += 4
                saved = True
                continue
            if (w & 0x0E108000) == 0x08108000:                      # ldm with pc: a return
                if always:
                    break
                at += 4
                continue
            if (w & 0x0FFFC000) == 0x08BD4000 or (w & 0x0FFFF000) == 0x049DE000:   # pop lr, ldr lr, [sp], #n
                if not always:
                    return None
                at += 4
                saved = False
                continue
            if (w & 0x0FFFFFF0) == 0x012FFF10:                      # bx
                if always:
                    break
                at += 4
                continue
            if (w & 0x0C10F000) == 0x0410F000:                      # ldr pc, ...
                if (w >> 16) & 0xF == 0xF or (w >> 16) & 0xF != 0xD:
                    return None
                if always:
                    break
                at += 4
                continue
            if (w & 0x0C00F000) == 0x0000F000 and (w & 0x0E000090) != 0x00000090 \
                    and ((w >> 21) & 0xF) not in (8, 9, 10, 11):    # a data operation into pc
                if ((w >> 21) & 0xF) == 13 and not w & 0x02000000 and (w & 0xFFF) == 0xE:
                    if always:                                      # mov pc, lr
                        break
                    at += 4
                    continue
                return None                                         # add pc, pc, rX: a jump table
            if (w & 0x0FFFFFF0) == 0x012FFF30 and not saved:       # blx rX with lr free
                return None
            at += 4
    return tails, out


def split(image, start, end):
    """the starts hidden in [start, end)."""
    found = analyze(image, start, end)
    if found is None:
        return []
    tails, _ = found
    later = sorted(t + 4 for t in tails if t + 4 < end)
    if not later:
        return []
    cut = later[0]
    first = analyze(image, start, cut)
    if first is None or cut - 4 not in first[0]:
        return []
    if any(cut < t < end for t in first[1]):
        return []                                                   # jumps into the middle of the rest
    return [cut] + split(image, cut, end)


def main():
    config.options(__doc__, "--apply")
    table = defaultdict(list)
    with open(config.CONFIG / "functions.csv", encoding="utf-8", newline="") as f:
        for r in csv.DictReader(f):
            if r["kind"] != "stub":
                table[r["module"]].append(r)
    count, out = Counter(), []
    for program, rows in sorted(table.items()):
        try:
            image = config.Image(program)
        except FileNotFoundError:
            continue
        for r in rows:
            library = r["library"].rstrip("?") or "unknown"
            if r["mode"] != "arm" or library in SKIP:
                continue
            start, end = int(r["start"], 16), int(r["end"], 16)
            starts = split(image, start, end)
            for s in starts:
                count[f"{'code.bin' if program == 'code.bin' else 'modules'}, {library}"] += 1
                out.append(f"{program} {s:08X}    # a tail call made a NOP; split from {start:08X} ({library})")
            count["functions split"] += bool(starts)
    path = config.BUILD / "tailstarts.txt"
    path.parent.mkdir(parents=True, exist_ok=True)
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
