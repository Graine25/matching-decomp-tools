"""return types from the callers: what the code after each call does with the result.

  python -I tools/callers.py         # config/<version>/calls.csv

a mangled name has no return type, and a header's `void` stops whoever writes a function
that uses the result. but every caller shows it: after a `bl` the result is in r0 (s0 for
a float: floats come back in VFP registers here), and the instructions that follow read it,
or overwrite it first. for every call to a function the game names (its exports, called
directly in the executable or through a module's import stubs), the value is followed
through the instructions after the call, in the same block, copies to other registers
included, until it is used, overwritten, or the block ends:

  deref     an address of a load or store (`ldr r1, [r0, #8]`)     a pointer
  this:X    the first argument of a member function of class X      a pointer to X
  arg:T     the first argument of a function whose parameter is T   T
  float     s0 or d0 read before written                            f32 (f64 for d0)
  test      compared with 0 only                                    bool, or a pointer
  byte      stored as a byte (strb)                                 u8 or bool
  half      stored as a half word (strh)                            u16
  word      arithmetic, an index, compared with a constant          a 32-bit integer
  store     stored as a word (str)                                  a 32-bit value or a pointer
  signed / unsigned   the condition of a branch after a compare
  unused    overwritten before it is read                           (says nothing)

the callers tell the kind (a pointer, an integer, a float) but not the width: a caller
uses a u8 as an int without narrowing it. the width is in the function's own code: what
it writes to r0 last before each return (ldrb, and #0xff, uxtb: u8; ldrsb, sxtb: s8; ldrh,
uxth: u16; ldrsh, sxth: s16; mov #0 / #1 only: bool; a word load or arithmetic: 32 bits).
an integer gets that width when every return agrees; a function only tested by its callers
is bool when its returns are only 0 and 1.

columns: mangled, demangled, calls (sites read), evidence (counts), returns (what the
function's own returns write to r0), type (the decision, empty when there is none), why. tools/headers.py takes the type for a function whose own
code does not show it (its shown returns), marked as a guess from the callers; returns.csv
overrides both. a function whose callers never read the result stays `void`.

decision: float if any caller reads s0; else a pointer if any dereferences it or passes
it as this (a pointer to X when every such call names the same class X); else u8, u16, a
32-bit integer (s32 if a signed compare follows, u32 otherwise) by the widest use; bool
when it is only tested or stored as a byte and the name asks (Is, Has, Can, Check...);
nothing when it is only stored as a word or only tested.
"""
import csv
import re
import struct
import sys
from collections import Counter, defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import config
import classify
import fields as fieldslib
import headers

PATH = config.CONFIG / "calls.csv"
ENUMS = set()                          # the enums of enums.csv, filled by main()
WINDOW = 16                            # instructions read after a call
ASKS = re.compile(r"(?:Is|Has|Can|Check|Exist|Enable|Need|Was|Did|Should)[A-Z0-9_]")

try:
    from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM
    from capstone import arm as A
except ImportError:                    # the tool needs it; the other tools do not
    Cs = None

SIGNED = set()
UNSIGNED = set()


def setup():
    md = Cs(CS_ARCH_ARM, CS_MODE_ARM)
    md.detail = True
    SIGNED.update({A.ARM_CC_GT, A.ARM_CC_LT, A.ARM_CC_GE, A.ARM_CC_LE})
    UNSIGNED.update({A.ARM_CC_HI, A.ARM_CC_LO, A.ARM_CC_HS, A.ARM_CC_LS})
    return md


def reg_index(reg):
    """0..15 for r0..pc, None for any other register."""
    if A.ARM_REG_R0 <= reg <= A.ARM_REG_R12:
        return reg - A.ARM_REG_R0
    return {A.ARM_REG_SP: 13, A.ARM_REG_LR: 14, A.ARM_REG_PC: 15}.get(reg)


def floats(reg):
    return reg in (A.ARM_REG_S0, A.ARM_REG_D0) or (hasattr(A, "ARM_REG_Q0") and reg == A.ARM_REG_Q0)


def follow(md, data, at, base, call_target):
    """what the code after the call at `at` does with the result: one observation, or None.
    call_target(address) gives the first parameter of a callee: ('this', class),
    ('arg', type) or ('none',) when it takes none, or None when it is not known."""
    holding = {0}                       # the registers that hold the result
    float_live = True                   # s0 still holds a float result
    pc = at + 4
    insns = md.disasm(data[pc - base:pc - base + 4 * WINDOW], pc)
    pending_compare = False
    for insn in insns:
        read, written = insn.regs_access()
        read_idx = {reg_index(r) for r in read} - {None}
        written_idx = {reg_index(r) for r in written} - {None}
        conditional = insn.cc not in (A.ARM_CC_AL, getattr(A, "ARM_CC_INVALID", -1))
        if pending_compare and conditional:
            return "signed" if insn.cc in SIGNED else "unsigned" if insn.cc in UNSIGNED else "word"
        if float_live:
            if any(floats(r) for r in read):
                return "float64" if any(r == A.ARM_REG_D0 for r in read) else "float"
            if any(floats(r) for r in written):
                float_live = False
        name = insn.mnemonic
        used = read_idx & holding
        if name in ("bl", "blx") and insn.operands and insn.operands[0].type == A.ARM_OP_IMM:
            if 0 not in holding:
                # kept in a register the callee preserves: still there after the call
                holding -= {1, 2, 3, 12}
                float_live = False
                if not holding:
                    return None
                continue
            first = call_target(insn.operands[0].imm)
            if first is None:
                return None
            return "unused" if first[0] == "none" else f"{first[0]}:{first[1]}"
        if used:
            if name.startswith(("cmp", "cmn", "tst", "teq")):
                imm = [o for o in insn.operands if o.type == A.ARM_OP_IMM]
                if imm and imm[0].imm == 0 and name.startswith(("cmp", "tst")):
                    return "test"
                pending_compare = True
                continue
            for o in insn.operands:
                if o.type == A.ARM_OP_MEM:
                    if reg_index(o.mem.base) in holding:
                        return "deref"
                    if o.mem.index and reg_index(o.mem.index) in holding:
                        return "word"
            if name.startswith("str") and insn.operands and reg_index(insn.operands[0].reg) in holding:
                return "byte" if name.startswith("strb") else "half" if name.startswith("strh") else \
                    None if name.startswith("strd") else "store"
            if name in ("mov", "cpy") and len(insn.operands) == 2 and insn.operands[1].type == A.ARM_OP_REG \
                    and not conditional and insn.operands[1].shift.type == 0:
                holding |= written_idx
                continue
            if name.startswith(("push", "stm")):
                return None
            if 15 in written_idx:
                return "returned"
            return "word"
        if 15 in written_idx or name in ("b", "bx", "blx", "bl"):
            if conditional:
                continue                # a branch on one path: the other goes on here
            return "returned" if (name == "bx" or name.startswith(("pop", "ldm"))) and 0 in holding else None
        if conditional and written_idx & holding:
            return None                 # overwritten on one path only
        holding -= written_idx
        if not holding:
            return "unused"
    return None


def returns_of(image, start, end):
    """Counter of what the function's code writes to r0 last before each return: u8, s8,
    u16, s16, bool (0 or 1), const (another constant), word, call (a callee's result), or
    unknown. only plain ARM code; a return found at most 8 instructions after that write."""
    out = Counter()
    if start & 3:
        return out
    words = [image.word(a) for a in range(start, end - 3, 4)]
    for i, w in enumerate(words):
        cond = w >> 28
        is_return = w == 0xE12FFF1E or ((w & 0x0FFF8000) == 0x08BD8000 and cond == 0xE)
        if not is_return:
            continue
        kind = "unknown"
        for j in range(i - 1, max(-1, i - 9), -1):
            x = words[j]
            c = x >> 28
            if (x & 0x0E000000) == 0x0A000000:              # a branch or a call
                kind = "call" if (x & 0x0F000000) == 0x0B000000 and c == 0xE else "unknown"
                break
            writes = None
            if (x & 0x0C000000) == 0 and not ((x & 0x0E000090) == 0x00000090) and ((x >> 21) & 0xF) not in (8, 9, 10, 11):
                writes = (x >> 12) & 0xF
            elif (x & 0x0C000000) == 0x04000000 and (x & 0x00100000):
                writes = (x >> 12) & 0xF
            elif (x & 0x0E1000F0) in (0x001000B0, 0x001000D0, 0x001000F0) or (x & 0x0FA003F0) == 0x06A00070:
                writes = (x >> 12) & 0xF
            elif (x & 0x0E100000) == 0x08100000 and (x & 1):
                kind = "unknown"
                break
            if writes != 0:
                continue
            if (x & 0x0FF00000) in (0x03A00000, 0x03E00000):  # mov / mvn rd, #imm
                imm = x & 0xFF
                rot = ((x >> 8) & 0xF) * 2
                value = ((imm >> rot) | (imm << (32 - rot))) & 0xFFFFFFFF
                if (x & 0x0FF00000) == 0x03E00000:
                    value = ~value & 0xFFFFFFFF
                kind = "bool" if value in (0, 1) else "const"
                if c != 0xE and kind == "bool" and j > 0 and (words[j - 1] & 0x0FF00000) in (0x03A00000,) \
                        and (words[j - 1] >> 12) & 0xF == 0 and (words[j - 1] & 0xFF) in (0, 1):
                    kind = "bool"
                elif c != 0xE and kind == "bool":
                    kind = "bool"           # movne r0, #1 after a compare: a condition
                break
            if (x & 0x0C500000) == 0x04500000:
                kind = "u8"                 # ldrb
            elif (x & 0x0E1000F0) == 0x001000B0:
                kind = "u16"
            elif (x & 0x0E1000F0) == 0x001000D0:
                kind = "s8"
            elif (x & 0x0E1000F0) == 0x001000F0:
                kind = "s16"
            elif (x & 0x0FFF0FF0) == 0x06EF0070 or (x & 0x0FF00FFF) == 0x020000FF:
                kind = "u8"
            elif (x & 0x0FFF0FF0) == 0x06AF0070:
                kind = "s8"
            elif (x & 0x0FFF0FF0) == 0x06FF0070:
                kind = "u16"
            elif (x & 0x0FFF0FF0) == 0x06BF0070:
                kind = "s16"
            elif (x & 0x0FE00FF0) == 0x01A00000:
                kind = "unknown"            # mov r0, rX: a copy, not followed
            else:
                kind = "word"
            if c != 0xE:
                kind = "unknown" if kind != "bool" else kind
            if any(reads_r0(words[k]) for k in range(j + 1, i)):
                kind = "unknown"            # read again before the return: a temporary, maybe
            break
        out[kind] += 1
    return out


def reads_r0(x):
    """whether an ARM instruction may read r0 (rough: any register field that is r0, so a
    pop or an immediate can say yes; the callers of this only lose a guess by it)."""
    if (x & 0x0E000000) == 0x08000000:                 # ldm / stm: the base, or a stored r0
        return (x >> 16) & 0xF == 0 or (not (x & 0x00100000) and x & 1)
    if (x & 0x0C000000) == 0x04000000:                 # ldr / str
        return (x >> 16) & 0xF == 0 or (not (x & 0x00100000) and (x >> 12) & 0xF == 0) or \
            ((x & 0x02000000) and x & 0xF == 0)
    if (x & 0x0C000000) == 0:                          # data processing, multiplies, half word loads and stores
        op = (x >> 21) & 0xF
        rn = (x >> 16) & 0xF == 0 and op not in (13, 15)    # mov and mvn have no rn
        rm = not (x & 0x02000000) and x & 0xF == 0
        return rn or rm or ((x & 0x0E1000F0) in (0x000000B0,) and (x >> 12) & 0xF == 0)
    return False


def width(returns, asks):
    """the integer type the returns show, or None."""
    kinds = {k for k, n in returns.items() if n} - {"unknown", "call", "const"}
    if not kinds or "word" in kinds:
        return None if not kinds else "word"
    if kinds == {"bool"}:
        return "bool"
    narrow = kinds - {"bool"}
    if len(narrow) == 1:
        t = next(iter(narrow))
        return "bool" if t == "u8" and asks else t
    return None


def first_parameter(rows, classes):
    """{mangled: ('this', class) | ('arg', type) | ('none',)}: what a callee takes in r0."""
    out = {}
    for r in rows:
        d = r["demangled"]
        sig = headers.signature(d) if r["mangled"].startswith("_Z") else None
        if not sig or "(" not in d:
            continue
        owner = d[:d.index("(")].rpartition("::")[0]
        if owner in classes and r["mangled"].startswith("_ZN"):
            out[r["mangled"]] = ("this", owner)          # a member function (or a static one: not in the name)
        elif sig[0]:
            t = headers.type_name(sig[0][0])
            out[r["mangled"]] = ("arg", sig[0][0]) if t is not None else None
        else:
            out[r["mangled"]] = ("none",)
    return out


def decide(name, seen, ancestors=lambda c: set(), returns=None):
    """(type or None, why) from the observations of one function's callers. the uses vote by
    kind: a pointer (deref, this, a pointer argument), an integer (arithmetic, a compare, a
    narrow store, an integer argument) or a float; storing a word, testing against 0 and not
    reading it say nothing of the kind. one caller can be misread (a static function taken
    for a member one), so the kind with the most uses wins."""
    this = Counter({k.split(":", 1)[1]: n for k, n in seen.items() if k.startswith("this:")})
    args = Counter({k.split(":", 1)[1]: n for k, n in seen.items() if k.startswith("arg:")})
    pointer_args = Counter({a: n for a, n in args.items() if "*" in a or "&" in a})
    value_args = Counter({a: n for a, n in args.items() if a not in pointer_args})
    as_float = seen.get("float", 0) + seen.get("float64", 0)
    as_pointer = seen.get("deref", 0) + sum(this.values()) + sum(pointer_args.values())
    as_integer = sum(seen.get(k, 0) for k in ("word", "half", "byte", "signed", "unsigned")) + sum(value_args.values())
    if as_float > max(as_pointer, as_integer):
        return ("f64" if seen.get("float64", 0) > seen.get("float", 0) else "f32"), "callers read s0 after the call"
    if as_pointer > as_integer:
        total = sum(this.values())
        if total >= 3 or total * 2 >= as_pointer:      # a dereference agrees with any class
            # the class all the classes it is the this of (but the rare ones) are, or derive from
            kept = [c for c, n in this.items() if n * 10 >= total]
            for c in sorted(kept, key=lambda c: -this[c]):
                if all(k == c or c in ancestors(k) for k in kept):
                    return f"{c} *", f"passed as this of {c}" + (" (or of a class derived from it)" if len(kept) > 1 else "")
            top, n = this.most_common(1)[0]
            if n * 4 >= total * 3:
                return f"{top} *", f"passed as this of {top} by most callers"
        if pointer_args and sum(pointer_args.values()) * 2 >= as_pointer:
            t, n = pointer_args.most_common(1)[0]
            if n * 4 >= sum(pointer_args.values()) * 3 and "&" not in t:
                return t, "passed on as an argument of that type"
        return "void *", "used as a pointer"
    short = name.rsplit("::", 1)[-1]
    asks = bool(ASKS.match(short))
    if as_integer:
        if value_args:
            t, n = value_args.most_common(1)[0]
            named = headers.type_name(t)
            if named and named[0] and (n * 2 >= as_integer or (named[0] in ENUMS and n >= 3 and n * 10 >= as_integer)):
                return t, "passed on as an argument of that type"
        if returns in ("u8", "s8", "u16", "s16", "bool"):
            return returns, "used as an integer; the width is what its own returns write"
        if seen.get("word") or seen.get("signed") or seen.get("unsigned") or value_args:
            if seen.get("signed", 0) > seen.get("unsigned", 0):
                return "s32", "compared as signed"
            return "u32", "used as a 32-bit integer"
        if seen.get("half"):
            return "u16", "stored as a half word"
        return ("bool" if asks else "u8"), "stored as a byte"
    if seen.get("test") and asks:
        return "bool", "only tested, and the name asks"
    if seen.get("test") and returns == "bool":
        return "bool", "only tested, and it returns only 0 and 1"
    return None, "only stored as a word or tested" if seen.get("store") or seen.get("test") else "not read"


def main():
    config.options(__doc__)
    if Cs is None:
        raise SystemExit("capstone is needed (pip install capstone)")
    md = setup()
    import enums
    ENUMS.update(enums.load())
    m = classify.load()
    classes = set(m.parents) | fieldslib.named_classes(m.parents)
    with open(config.CONFIG / "signatures.csv", encoding="utf-8", newline="") as f:
        rows = list(csv.DictReader(f))
    demangled = {r["mangled"]: r["demangled"] for r in rows}
    by_address = {int(r["address"], 16) & ~1: r["mangled"] for r in rows if r["mangled"].startswith("_Z")}
    params = first_parameter(rows, classes)
    address_of = {r["mangled"]: int(r["address"], 16) for r in rows}
    import functable
    table = functable.table().get("code.bin", {})
    main_image = config.Image()

    seen = defaultdict(Counter)
    programs = [("code.bin", config.Image())]
    for path in sorted((config.ORIG / "romfs").glob("*.cro")):
        try:
            programs.append((path.stem, config.Image(path.stem)))
        except (OSError, ValueError, struct.error):
            continue
    for name, image in programs:
        start, size = image.text, image.text_size
        data = image.data
        words = struct.unpack_from(f"<{size // 4}I", data, start - image.base)

        def resolve(target):
            if name == "code.bin":
                return by_address.get(target)
            if not image.in_code(target) or image.word(target) != 0xE51FF004:
                return None
            loaded = image.reloc(target + 4)
            return loaded[1][0] if loaded and loaded[0] == "name" else None

        def call_target(target):
            mangled = resolve(target)
            return params.get(mangled) if mangled else None

        for i, w in enumerate(words):
            if (w & 0x0F000000) != 0x0B000000 or (w >> 28) != 0xE:
                continue
            off = w & 0xFFFFFF
            at = start + 4 * i
            mangled = resolve(at + 8 + 4 * (off - 0x1000000 if off & 0x800000 else off))
            if not mangled:
                continue
            got = follow(md, data, at, image.base, call_target)
            if got:
                seen[mangled][got] += 1
    out, decided = [], Counter()
    for mangled in sorted(seen):
        d = demangled.get(mangled, "")
        name = d[:d.index("(")] if "(" in d else d
        addr = address_of.get(mangled)
        own = Counter()
        if addr is not None and addr in table:
            own = returns_of(main_image, addr, table[addr][0])
        t, why = decide(name, seen[mangled], m.up, width(own, bool(ASKS.match(name.rsplit("::", 1)[-1]))))
        if t:
            decided[t if t in ("f32", "f64", "bool", "u8", "s8", "u16", "s16", "u32", "s32", "void *") or "*" not in t
                    else "a pointer to a class"] += 1
        evidence = " ".join(f"{k}:{n}" for k, n in sorted(seen[mangled].items()))
        out.append((mangled, d, sum(seen[mangled].values()), evidence, " ".join(f"{k}:{n}" for k, n in sorted(own.items())),
                    t or "", why))
    with open(PATH, "w", encoding="utf-8", newline="") as f:
        w = csv.writer(f, lineterminator="\n")
        w.writerow(("mangled", "demangled", "calls", "evidence", "returns", "type", "why"))
        w.writerows(out)
    print(f"{len(out)} named functions with calls read; {sum(decided.values())} with a return type: "
          + ", ".join(f"{n} {t}" for t, n in decided.most_common()))
    print(f"wrote {PATH}")


def load():
    """{mangled: (type, why)} of calls.csv's decisions."""
    if not PATH.exists():
        return {}
    with open(PATH, encoding="utf-8", newline="") as f:
        return {r["mangled"]: (r["type"], r["why"]) for r in csv.DictReader(f) if r["type"]}


if __name__ == "__main__":
    main()
