"""the game's enums: which named types are passed by value, and how wide each one is.

  python -I tools/enums.py          # config/<version>/enums.csv

a mangled name gives the type of each parameter, but not what the type is. a named type
passed by value that is not a class (no type information, no member functions, nothing
named inside it) is an enum. its size is not in any name either, and it matters: armcc
makes an enum as small as its values allow (1, 2 or 4 bytes, signed or not), and a caller
narrows a value to that size before the call (`and r1, r1, #0xff` for an unsigned byte,
`lsl #16` then `asr #16` for a signed half word). so the callers say it:

  for every call (bl) to a function the game names, in the executable and through a
  module's import stubs, the last instruction before it that writes the register of
  each enum parameter is read:

    and #0xff, uxtb, lsl #24 + lsr #24   1 byte, unsigned
    sxtb, lsl #24 + asr #24              1 byte, signed
    uxth, lsl #16 + lsr #16              2 bytes, unsigned
    sxth, lsl #16 + asr #16              2 bytes, signed
    ldr, or arithmetic not narrowed      4 bytes (a narrower enum would have been narrowed)
    mov / mvn of a constant              a value it has (a negative one: signed)

  a register is only known when every parameter before it takes one register (a member
  function's this is r0: whether a function is static is not in its name, so an exported
  member function is taken to have this; the votes of all its callers decide).

a struct can be passed by value too (gfl2::math::Vector3). a type that some name also has
behind a pointer or reference is taken for an enum only when its callers narrow it (it is
then 1 or 2 bytes, no struct of the game's); else it is `struct?` and stays a class.

columns: name, kind (enum, or struct?), size (1, 2, 4; empty: no caller said), signed,
evidence (the counts), uses (parameters of that type in the names), largest (the largest
constant seen), smallest.
tools/headers.py writes each enum with two placeholder values that give it that size;
the real values are not known. a type with no evidence is written at the size most
enums with evidence have, and says so.
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
import cro as crolib
import fields as fieldslib
import headers

PATH = config.CONFIG / "enums.csv"
LOOK_BACK = 8                         # instructions before a call that are read
ONE_REGISTER = {"bool", "char", "signed char", "unsigned char", "short", "unsigned short", "int", "unsigned int",
                "long", "unsigned long", "wchar_t"}


def enum_types(rows, classes):
    """{type: number of parameters} of the named types passed by value that are not classes,
    and {mangled: (registers of each parameter or None, [(index, type)])} of the functions
    with one."""
    scopes = set()                    # what holds a name (a function's or a parameter type's) is no enum
    pointed = set()                   # what some name has behind a pointer or reference
    for r in rows:
        d = r["demangled"]
        sig = headers.signature(d) if r["mangled"].startswith("_Z") else None
        names = [d[:d.index("(")]] if "(" in d else []
        for p in sig[0] if sig else ():
            t = headers.type_name(p)
            if t and t[0]:
                names.append(t[0])
                if t[1]:
                    pointed.add(t[0])
        for name in names:
            parts = name.split("::")
            scopes |= {"::".join(parts[:i]) for i in range(1, len(parts))}
    sigs, uses = {}, Counter()
    for r in rows:
        d = r["demangled"]
        sig = headers.signature(d) if r["mangled"].startswith("_Z") else None
        if not sig or "<" in d or "operator" in d:
            continue
        found = []
        for i, p in enumerate(sig[0]):
            t = headers.type_name(p)
            if t and t[0] and not t[1] and t[0] not in classes and t[0] not in scopes:
                found.append((i, t[0]))
        if found:
            sigs[r["mangled"]] = (sig[0], found)
            for _, t in found:
                uses[t] += 1
    return uses, sigs, pointed


def registers(params, member, enums, pointed=()):
    """the register of each parameter, None from the first one that does not take exactly one
    (a type that may be a struct has its first register, and nothing after it is known)."""
    out, reg = [], 1 if member else 0
    for p in params:
        t = headers.type_name(p)
        if " ".join(p.replace("const", "").split()) in ("float", "double"):
            out.append(None)                # in a VFP register (s0, d0...): the core ones are not used
            continue
        one = t is not None and (t[1] or (t[0] is None and " ".join(p.replace("const", "").split()) in ONE_REGISTER)
                                 or (t[0] in enums))
        if not one or reg > 3:
            out += [None] * (len(params) - len(out))
            break
        out.append(reg)
        reg += 1
        if t[0] in pointed and not t[1]:
            out += [None] * (len(params) - len(out))
            break
    return out


def writer(w):
    """the register an ARM data-processing or load instruction writes, or None."""
    if (w >> 28) == 0xF:
        return None
    extra = (w & 0x0E000090) == 0x00000090                         # multiplies and the half word, double loads
    if (w & 0x0E1000F0) in (0x001000B0, 0x001000D0, 0x001000F0) or (w & 0x0E1000F0) == 0x000000D0:
        return (w >> 12) & 0xF                                      # ldrh, ldrsb, ldrsh, ldrd (and rd + 1)
    if extra:
        return None
    if (w & 0x0C000000) == 0x00000000:                              # data processing
        op = (w >> 21) & 0xF
        if op in (8, 9, 10, 11):                    # tst, teq, cmp, cmn
            return None
        return (w >> 12) & 0xF
    if (w & 0x0C100000) == 0x04100000:              # ldr, ldrb
        return (w >> 12) & 0xF
    if (w & 0x0FA003F0) == 0x06A00070:              # sxtb, sxth, uxtb, uxth (and their add forms)
        return (w >> 12) & 0xF
    return None


def classify_write(words, i, reg):
    """what the instruction words[i] (which writes reg) says of the value's width."""
    w = words[i]
    if (w & 0x0FFF0000) in (0x059F0000, 0x051F0000):                # ldr rd, [pc, #n]: a constant of the pool
        at = i + 2 + ((w & 0xFFF) if w & 0x00800000 else -(w & 0xFFF)) // 4
        return ("value", words[at]) if 0 <= at < len(words) and not (w & 3) else None
    if (w & 0x0E1000F0) == 0x000000D0:                              # ldrd: a 64-bit value, not one parameter
        return None
    if (w & 0x0FFF0FF0) == 0x06EF0070:
        return "u1"
    if (w & 0x0FFF0FF0) == 0x06AF0070:
        return "s1"
    if (w & 0x0FFF0FF0) == 0x06FF0070:
        return "u2"
    if (w & 0x0FFF0FF0) == 0x06BF0070:
        return "s2"
    if (w & 0x0FF00FFF) == 0x020000FF:                              # and rd, rn, #0xff
        return "u1"
    if (w & 0x0FF00000) == 0x02000000:                              # and with another mask: its range, not a width
        return "load"
    if (w & 0x0FE00000) == 0x01A00000 and (w & 0x10) == 0:          # mov rd, rm, shift #n
        kind, amount = (w >> 5) & 3, (w >> 7) & 0x1F
        if amount in (24, 16) and kind in (1, 2) and i > 0:
            prev = words[i - 1]
            rm = w & 0xF
            if (prev & 0x0FE00070) == 0x01A00000 and ((prev >> 12) & 0xF) == rm and ((prev >> 7) & 0x1F) == amount:
                return ("u" if kind == 1 else "s") + ("1" if amount == 24 else "2")
        if amount == 0 and ((w >> 5) & 3) == 0:
            return "copy"
        return "word"
    if (w & 0x0FF00000) == 0x03A00000:                              # mov rd, #imm
        imm = w & 0xFF
        rot = ((w >> 8) & 0xF) * 2
        return ("value", ((imm >> rot) | (imm << (32 - rot))) & 0xFFFFFFFF)
    if (w & 0x0FF00000) == 0x03E00000:                              # mvn rd, #imm
        imm = w & 0xFF
        rot = ((w >> 8) & 0xF) * 2
        value = ~(((imm >> rot) | (imm << (32 - rot))) & 0xFFFFFFFF) & 0xFFFFFFFF
        return ("value", value)
    if (w & 0x0C500000) == 0x04100000:                              # ldr (word)
        return "word"
    if (w & 0x0C500000) == 0x04500000 or (w & 0x0E1000F0) in (0x001000B0, 0x001000D0, 0x001000F0):
        return "load"                                               # ldrb, ldrh, ldrsb, ldrsh: says nothing alone
    if (w & 0x0C000000) == 0x00000000:
        return "word"                                               # arithmetic, not narrowed
    return None


def evidence_at(words, i, reg):
    """the evidence of the value in reg at the call words[i]: the last write in the block."""
    for j in range(i - 1, max(-1, i - 1 - LOOK_BACK), -1):
        w = words[j]
        if (w & 0x0E000000) == 0x0A000000 or (w & 0x0FFFFFF0) == 0x012FFF10 or (w >> 28) == 0xF:
            return None                                             # a branch: the block began after it
        if (w >> 28) != 0xE:
            return None                                             # a conditional write: not followed
        if (w & 0x0E000000) == 0x08000000:                          # ldm/stm: a pop or a block load
            if (w & 0x00100000) and (w >> reg) & 1:
                return None
            continue
        if writer(w) == reg:
            return classify_write(words, j, reg)
    return None


def collect():
    m = classify.load()
    classes = set(m.parents) | fieldslib.named_classes(m.parents)
    with open(config.CONFIG / "signatures.csv", encoding="utf-8", newline="") as f:
        rows = list(csv.DictReader(f))
    uses, sigs, pointed = enum_types(rows, classes)
    enums = set(uses)
    plan = {}                                                       # mangled -> [(register, type)]
    demangled = {r["mangled"]: r["demangled"] for r in rows}
    for mangled, (params, found) in sigs.items():
        d = demangled[mangled]
        qualified = d[:d.index("(")]
        owner = qualified.rpartition("::")[0]
        member = owner in classes
        regs = registers(params, member, enums, pointed)
        plan[mangled] = [(regs[i], t) for i, t in found if regs[i] is not None]
    by_address = {int(r["address"], 16) & ~1: r["mangled"] for r in rows if r["mangled"] in plan}

    votes = defaultdict(Counter)
    values = defaultdict(list)
    programs = [("code.bin", config.Image())]
    for path in sorted((config.ORIG / "romfs").glob("*.cro")):
        try:
            programs.append((path.stem, config.Image(path.stem)))
        except (OSError, ValueError, struct.error):
            continue
    for name, image in programs:
        start, size = image.text, image.text_size
        words = struct.unpack_from(f"<{size // 4}I", image.data, start - image.base)
        for i, w in enumerate(words):
            if (w & 0x0F000000) != 0x0B000000 or (w >> 28) != 0xE:
                continue
            off = w & 0xFFFFFF
            target = start + 4 * i + 8 + 4 * (off - 0x1000000 if off & 0x800000 else off)
            if name == "code.bin":
                mangled = by_address.get(target)
            else:
                if not image.in_code(target) or image.word(target) != 0xE51FF004:
                    continue
                loaded = image.reloc(target + 4)
                mangled = loaded[1][0] if loaded and loaded[0] == "name" else None
            if mangled not in plan:
                continue
            for reg, t in plan[mangled]:
                got = evidence_at(words, i, reg)
                if got is None or got in ("copy", "load"):
                    continue
                if isinstance(got, tuple):
                    values[t].append(got[1])
                else:
                    votes[t][got] += 1
    return uses, votes, values, pointed


def decide(votes, values):
    """(size or None, signed) from a type's evidence."""
    narrow = {k: n for k, n in votes.items() if k[0] in "us"}
    negative = any(v & 0x80000000 for v in values)
    if narrow:
        width = Counter()
        for k, n in narrow.items():
            width[int(k[1])] += n
        size = width.most_common(1)[0][0]
        signed = sum(n for k, n in narrow.items() if k[0] == "s" and int(k[1]) == size) > \
            sum(n for k, n in narrow.items() if k[0] == "u" and int(k[1]) == size) or negative
        return size, signed
    # without narrowing: 4 bytes when values were passed as they were, more than once (one
    # call can be a parameter taken for another, a static member function read as a member)
    big = sum(1 for v in values if (v & 0xFFFFFFFF) > 0xFFFF and not (v & 0x80000000))
    if votes.get("word", 0) + big >= 2:
        return 4, True
    return None, negative


def load():
    """{name: (size, signed, seen)} of the enums of enums.csv; empty when there is none. seen is False
    when no caller told the size: then it is the smallest that holds the constants passed,
    from one byte, unsigned unless one was negative (most enums with evidence are u8)."""
    if not PATH.exists():
        return {}
    out = {}
    with open(PATH, encoding="utf-8", newline="") as f:
        for r in csv.DictReader(f):
            if r["kind"] != "enum":
                continue
            signed = r["signed"] == "yes"
            if r["size"]:
                out[r["name"]] = (int(r["size"]), signed, True)
                continue
            hi = int(r["largest"]) if r["largest"] else 0
            lo = int(r["smallest"]) if r["smallest"] else 0
            signed = signed or lo < 0
            size = next(s for s in (1, 2, 4) if (-(1 << (8 * s - 1)) <= lo and hi < (1 << (8 * s - 1)) if signed
                                                  else hi < (1 << (8 * s))) or s == 4)
            out[r["name"]] = (size, signed, False)
    return out


def definition(name, size, signed):
    """the body of an enum of that size: two placeholder values, the real ones not known."""
    short = name.rsplit("::", 1)[-1]
    if signed:
        low, high = {1: ("-0x80", "0x7F"), 2: ("-0x8000", "0x7FFF"), 4: ("-0x7FFFFFFF - 1", "0x7FFFFFFF")}[size]
    else:
        low, high = "0", {1: "0xFF", 2: "0xFFFF", 4: "0xFFFFFFFFu"}[size]
    return f"enum {short} {{ {short}_placeholder_low = {low}, {short}_placeholder_high = {high} }};"


def main():
    config.options(__doc__)
    uses, votes, values, pointed = collect()
    rows, sizes, structs = [], Counter(), 0
    for t in sorted(uses):
        size, signed = decide(votes[t], values[t])
        narrowed = any(k[0] in "us" for k in votes[t])
        kind = "enum" if t not in pointed or narrowed else "struct?"
        if kind != "enum":
            structs += 1
        elif size:
            sizes[size, signed] += 1
        signed_values = [v - (1 << 32) if v & 0x80000000 else v for v in values[t]]
        rows.append((t, kind, size or "", "yes" if signed else "no",
                     " ".join(f"{k}:{n}" for k, n in sorted(votes[t].items())), uses[t],
                     max(signed_values) if signed_values else "", min(signed_values) if signed_values else ""))
    with open(PATH, "w", encoding="utf-8", newline="") as f:
        w = csv.writer(f, lineterminator="\n")
        w.writerow(("name", "kind", "size", "signed", "evidence", "uses", "largest", "smallest"))
        w.writerows(rows)
    known = sum(1 for r in rows if r[1] == "enum" and r[2])
    print(f"{len(rows)} named types passed by value that are not classes: {structs} may be structs (behind a "
          f"pointer too, never narrowed); {len(rows) - structs} enums, {known} with a size from their callers: "
          + ", ".join(f"{n} {'s' if s else 'u'}{8 * size}" for (size, s), n in sizes.most_common()))
    print(f"wrote {PATH}")


if __name__ == "__main__":
    main()
