"""function starts that Ghidra missed after a function's end: code that the function before
never reaches, so Ghidra ran the two together.

    python -I tools/unreached.py            counts, and the starts in build/<version>/unreached.txt
    python -I tools/unreached.py --apply    and adds them to config/<version>/extra_starts.txt
                                            (then tools/refresh.py --table)

each ARM function of the table is followed from its entry (every branch inside it, every
fall-through; a return or an unconditional jump ends a path); the words its pc-relative
loads read are its pool. after the last word it reaches or reads, a start is taken at the
first word that looks like the entry of another function:
- an unconditional instruction (data processing, load or store, or a push), whose own
  paths end in a return or a jump, with nothing unexplained in between;
- it never jumps back into the code before it (then it is the same function's);
- like an entry: no callee-saved register (r4 to r11, d8 to d15) read, and no stack taken
  back, before a push saves them.
a function with a jump table (a computed pc) is left alone, and so are the SDK's and the
compiler's library (hand-written assembly). checked by hand on samples (2026-11-12).
"""
import csv
import sys
from collections import Counter, defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import config
from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM
from capstone import arm as A

md = Cs(CS_ARCH_ARM, CS_MODE_ARM)
md.detail = True
SAVED = ({getattr(A, f"ARM_REG_R{i}") for i in range(4, 10)}
         | {A.ARM_REG_R10, A.ARM_REG_R11, A.ARM_REG_SB, A.ARM_REG_SL, A.ARM_REG_FP}
         | {getattr(A, f"ARM_REG_D{i}") for i in range(8, 16)} | {getattr(A, f"ARM_REG_S{i}") for i in range(16, 32)})
SKIP = ("sdk", "armlib")


def target(at, w):
    off = w & 0xFFFFFF
    return at + 8 + 4 * (off - 0x1000000 if off & 0x800000 else off)


def reach(image, start, end):
    """the addresses the code at start executes within [start, end), or None when it computes
    its pc (a jump table)."""
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
                t = target(at, w)
                if start <= t < end:
                    work.append(t)
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
                    return None
                if always:
                    break
            elif (w & 0x0C00F000) == 0x0000F000 and (w & 0x0E000090) != 0x00000090 \
                    and ((w >> 21) & 0xF) not in (8, 9, 10, 11):    # a data operation into pc
                if ((w >> 21) & 0xF) == 13 and not w & 0x02000000 and (w & 0xFFF) == 0xE:
                    if always:                                      # mov pc, lr
                        break
                else:
                    return None
            at += 4
    return seen


def pool_of(image, seen):
    """the words the reached code reads with a pc-relative load."""
    pool = set()
    for a in seen:
        w = image.word(a)
        if (w & 0x0F7F0000) == 0x051F0000:                              # ldr rX, [pc, #off]
            off = w & 0xFFF
            pool.add(a + 8 + (off if w & 0x00800000 else -off))
        elif (w & 0x0F3F0F00) in (0x0D1F0A00, 0x0D1F0B00):              # vldr: a float, or a double
            off = (w & 0xFF) * 4
            t = a + 8 + (off if w & 0x00800000 else -off)
            pool |= {t, t + 4} if (w & 0x0F00) == 0x0B00 else {t}
    return pool


def starts_clean(image, addrs):
    """like a function's entry: no callee-saved register read and no stack taken back before
    a push saves them (in address order, a rough look)."""
    pushed = set()
    for a in addrs:
        for i in md.disasm(image.data[a - image.base:a - image.base + 4], a):
            read, wrote = i.regs_access()
            if i.id in (A.ARM_INS_PUSH, A.ARM_INS_VPUSH) or (i.id == A.ARM_INS_STMDB and i.operands[0].reg == A.ARM_REG_SP) \
                    or (image.word(a) & 0x0FFF0FFF) == 0x052D0004:          # str rX, [sp, #-4]!: a push of one
                pushed |= {o.reg for o in i.operands if o.type == A.ARM_OP_REG}
                continue
            if i.id == A.ARM_INS_POP or (i.id == A.ARM_INS_ADD and i.operands[0].reg == A.ARM_REG_SP):
                if not pushed:
                    return False
            for r in read:
                if r in SAVED and r not in pushed and r not in wrote:
                    return False
            for r in wrote:
                if r in SAVED:
                    pushed.add(r)          # written here first: its own value from now on
    return True


def hidden_start(image, start, end):
    """the start of another function in [start, end) after what the code at start reaches, or None."""
    seen = reach(image, start, end)
    if not seen:
        return None
    pool = pool_of(image, seen)
    rest = [a for a in range(start, end, 4) if a not in seen and a not in pool]
    if not rest or rest[0] < max(seen):
        return None
    for a in rest:
        w = image.word(a)
        if w >> 28 != 0xE or not ((w & 0x0FFF0000) == 0x092D0000 or (w & 0x0E000000) in (0, 0x02000000, 0x04000000)):
            continue
        more = reach(image, a, end)
        if not more or len(more) < 2:
            continue
        if any((image.word(x) & 0x0E000000) == 0x0A000000 and image.word(x) >> 28 != 0xF
               and start <= target(x, image.word(x)) < a for x in more):
            continue                                                    # it jumps back: one function
        ends = any(image.word(x) == 0xE12FFF1E or (image.word(x) & 0x0FFF8000) == 0x08BD8000
                   or ((image.word(x) & 0x0F000000) == 0x0A000000 and image.word(x) >> 28 == 0xE) for x in more)
        if ends and all(x in more or x in pool or image.word(x) for x in range(a, max(more) + 4, 4)) \
                and starts_clean(image, sorted(more)):
            return a
    return None


def main():
    config.options(__doc__, "--apply")
    rows = defaultdict(list)
    with open(config.CONFIG / "functions.csv", encoding="utf-8", newline="") as f:
        for r in csv.DictReader(f):
            if r["kind"] != "stub" and r["mode"] == "arm" and r["library"].rstrip("?") not in SKIP:
                rows[r["module"]].append(r)
    count, out = Counter(), []
    for program, rs in sorted(rows.items()):
        try:
            image = config.Image(program)
        except FileNotFoundError:
            continue
        for r in rs:
            start = int(r["start"], 16)
            found = hidden_start(image, start, int(r["end"], 16))
            if found is None:
                continue
            library = r["library"].rstrip("?") or "unknown"
            count[f"{'code.bin' if program == 'code.bin' else 'modules'}, {library}"] += 1
            out.append(f"{program} {found:08X}    # code after the end of {start:08X} that nothing in it reaches ({library})")
    path = config.BUILD / "unreached.txt"
    path.write_text("\n".join(out) + "\n", encoding="utf-8", newline="\n")
    for k, v in sorted(count.items()):
        print(f"{v:6} {k}")
    print(f"{len(out)} starts in {path}")
    if "--apply" in sys.argv:
        target_path = config.CONFIG / "extra_starts.txt"
        have = target_path.read_text(encoding="utf-8").splitlines() if target_path.exists() else []
        known = {tuple(line.split("#")[0].split()[:2]) for line in have}
        new = [line for line in out if tuple(line.split("#")[0].split()[:2]) not in known]
        target_path.write_text("\n".join(have + new) + "\n", encoding="utf-8", newline="\n")
        print(f"{len(new)} added to {target_path}")


if __name__ == "__main__":
    main()
