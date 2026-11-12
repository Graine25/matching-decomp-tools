"""the data members of the game's classes, read from how their functions use `this`.

  python -I tools/fields.py            # config/<version>/fields.csv

a member function gets `this` in r0. every load and store through it says that the class
has something at that offset, and how wide: ldrb a byte, ldrsh a signed half, ldr a word,
vldr a float. this follows `this` through each function whose class is known (copies in
other registers, `add rX, this, #n`, every path: where two paths meet only what both agree
on is kept) and collects those accesses.

whose function is whose:
- a virtual function is its class's (tools/classify.py; not the thunks of a second base,
  whose `this` is not the object's start);
- a constructor or destructor (ctors.csv), when it stores to offset 0 of r0 (the vtable):
  that tells it from a function with a constructor inlined;
- an exported member function, when its first parameter is not a pointer or reference: a
  static one could not read through r0 then. this includes classes without type
  information that the exports show to be classes (named_classes).

an access belongs to the class or to one of its bases: it is given to the base whose
known extent holds it (bases come first in an object), else to the class. a base that
another base follows in some class is no larger than the distance between the two.

a pointer member's class shows also where the object is made: the word a constructor's call
returns, stored right after it to this + n (`bl Y::Y` then `str r0, [this, #n]`), says the member
at n points to a Y (the destructors that delete it through its vtable need that type).

an object inside the class shows another way: `add r0, this, #n` and then a call to a
constructor, a destructor or a member function of a known class says that an object of
that class lies at n (when n is not where a base of the class is).

columns: class, offset (hex), width (bytes), type (u unsigned or unknown, s signed,
f float, p pointer: the loaded word is used as an address, or passed as `this` to a member
function (then `of` is the class most of those calls agree on), o an object of the class in
`of`, its width the least that class is known to take), functions (how many show it), of.
the names and the real types are not known from this: tools/headers.py writes them as
`field_<offset>`, marked as guesses. addresses and counts only, nothing of the game's code.
"""
import csv
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import classify
import config

PATH = config.CONFIG / "fields.csv"
FIELDS = ["class", "offset", "width", "type", "functions", "of"]
SCRATCH = (0, 1, 2, 3, 12, 14)
LIMIT = 0x8000          # an offset over this is not a member of anything here


def ror(value, bits):
    bits %= 32
    return ((value >> bits) | (value << (32 - bits))) & 0xFFFFFFFF


def step(w, state, loaded, record):
    """one instruction: (state, loaded) after it. state: register -> offset from this.
    loaded: register -> offset of the member it was loaded from. record(offset, width, type)."""
    cond = w >> 28
    if cond == 0xF:
        return state, loaded
    always = cond == 0xE
    state, loaded = dict(state), dict(loaded)

    def kill(*regs):
        for r in regs:
            state.pop(r, None)
            loaded.pop(r, None)

    def base(rn):
        if rn in loaded:
            record(loaded[rn], 4, "p")

    top = (w >> 25) & 7
    if top == 5:                                                    # b, bl
        if w & 0x01000000:
            kill(*SCRATCH)
    elif (w & 0x0FFFFFD0) == 0x012FFF10:                            # bx, blx register
        base(w & 0xF)
        if w & 0x20:
            kill(*SCRATCH)
    elif top in (0, 1) and not (top == 0 and (w & 0x90) == 0x90):   # data processing
        op, rn, rd = (w >> 21) & 0xF, (w >> 16) & 0xF, (w >> 12) & 0xF
        s = w & 0x00100000
        if op in (8, 9, 10, 11):
            if not s:
                if top == 1 and op in (8, 10):                      # movw, movt
                    kill(rd)
                elif (w & 0x0FFF0FF0) == 0x016F0F10:                # clz
                    kill(rd)
        elif op == 13 and top == 0 and (w & 0xFF0) == 0 and always and (w & 0xF) in state:
            src = state[w & 0xF]
            kill(rd)
            state[rd] = src                                         # mov rd, rm
        elif op == 4 and top == 1 and always and rn in state:
            off = state[rn] + ror(w & 0xFF, 2 * ((w >> 8) & 0xF))   # add rd, rn, #imm
            kill(rd)
            if off < LIMIT:
                state[rd] = off
        else:
            kill(rd)
    elif top == 0:                                                  # multiplies, halfword and signed loads
        sh = (w >> 5) & 3
        if sh == 0:
            kill((w >> 16) & 0xF)
            if w & 0x00800000:
                kill((w >> 12) & 0xF)
        else:
            p, u, imm, wb, load = w & 0x01000000, w & 0x00800000, w & 0x00400000, w & 0x00200000, w & 0x00100000
            rn, rd = (w >> 16) & 0xF, (w >> 12) & 0xF
            off = ((w >> 4) & 0xF0) | (w & 0xF)
            double = not load and sh in (2, 3)
            base(rn)
            if rn in state and p and not wb and imm and u:
                at = state[rn] + off
                if double:
                    record(at, 4, "u")
                    record(at + 4, 4, "u")
                elif sh == 1:
                    record(at, 2, "u")
                elif sh == 2:
                    record(at, 1, "s")
                else:
                    record(at, 2, "s")
            if load:
                kill(rd)
            elif sh == 2:                                           # ldrd
                kill(rd, rd + 1)
            if wb or not p:
                kill(rn)
    elif top in (2, 3):                                             # ldr, str, ldrb, strb
        p, u, byte, wb, load = w & 0x01000000, w & 0x00800000, w & 0x00400000, w & 0x00200000, w & 0x00100000
        rn, rd = (w >> 16) & 0xF, (w >> 12) & 0xF
        base(rn)
        at = None
        if rn in state and top == 2 and p and not wb and u:
            at = state[rn] + (w & 0xFFF)
            record(at, 1 if byte else 4, "u")
        moved = None
        if rn in state and top == 2 and not p and u and always and rn != rd:
            record(state[rn], 1 if byte else 4, "u")            # str rX, [rn], #n: at rn, then rn += n
            moved = state[rn] + (w & 0xFFF)
        if load:
            kill(rd)
            if at is not None and not byte and always:
                loaded[rd] = at
        if wb or not p:
            kill(rn)
            if moved is not None and moved < LIMIT:
                state[rn] = moved
    elif top == 4:                                                  # ldm, stm
        rn = (w >> 16) & 0xF
        base(rn)
        if w & 0x00100000:
            kill(*[r for r in range(16) if w & (1 << r)])
        if w & 0x00200000:
            kill(rn)
    elif (w & 0x0F200E00) == 0x0D000A00:                            # vldr, vstr
        rn = (w >> 16) & 0xF
        base(rn)
        if rn in state and w & 0x00800000:
            at = state[rn] + 4 * (w & 0xFF)
            if w & 0x100:
                record(at, 8, "f")
            else:
                record(at, 4, "f")
    elif (w & 0x0FF00F10) == 0x0E100A10 or (w & 0x0FF00F10) == 0x0E100B10:   # vmov to a core register
        kill((w >> 12) & 0xF)
    elif (w & 0x0FF00FD0) == 0x0C500B10:                            # vmov two core registers from a double
        kill((w >> 12) & 0xF, (w >> 16) & 0xF)
    return state, loaded


def successors(w, at, start, end):
    """the addresses after an instruction inside the function, or None for a computed pc."""
    cond = w >> 28
    if cond == 0xF:
        return [at + 4]
    always = cond == 0xE
    nxt = [] if always else [at + 4]
    if (w & 0x0F000000) == 0x0A000000:
        off = w & 0xFFFFFF
        target = at + 8 + 4 * (off - 0x1000000 if off & 0x800000 else off)
        return nxt + ([target] if start <= target < end else [])
    if (w & 0x0FFFFFF0) == 0x012FFF10 or (w & 0x0E108000) == 0x08108000:
        return nxt
    if (w & 0x0C10F000) == 0x0410F000:
        return None if (w >> 16) & 0xF == 0xF else nxt
    if (w & 0x0C00F000) == 0x0000F000 and (w & 0x0E000090) != 0x00000090 and ((w >> 21) & 0xF) not in (8, 9, 10, 11):
        if ((w >> 21) & 0xF) == 13 and not w & 0x02000000 and (w & 0xFFF) == 0xE:
            return nxt
        return None
    return [at + 4]


def meet(a, b):
    return {k: v for k, v in a.items() if b.get(k) == v}


def accesses(image, start, end, this=0):
    """[(offset, width, type)] of the accesses through this, whether offset 0 is stored to,
    [(offset, address called)] of the calls made with this + offset in r0, and [(offset,
    address called)] of the calls made with the word loaded from this + offset in r0; None when
    the function cannot be followed. this: its register (r1 when the function returns a
    struct by value: r0 is then where the result goes)."""
    states = {start: ({this: 0}, {})}
    work = [start]
    rounds = 0
    while work:
        rounds += 1
        if rounds > 200000:
            return None
        at = work.pop()
        if not start <= at < end:
            continue
        w = image.word(at)
        after = step(w, *states[at], lambda *a: None)
        nxt = successors(w, at, start, end)
        if nxt is None:
            return None
        for n in nxt:
            if not start <= n < end:
                continue
            if n not in states:
                states[n] = after
                work.append(n)
            else:
                merged = (meet(states[n][0], after[0]), meet(states[n][1], after[1]))
                if merged != states[n]:
                    states[n] = merged
                    work.append(n)
    found, stores_vtable, calls, points, made = set(), False, set(), set(), set()
    for at, (state, loaded) in states.items():
        w = image.word(at)
        step(w, state, loaded, lambda off, width, kind: found.add((off, width, kind)))
        # str rX, [this, #0]
        if (w & 0x0F700FFF) == 0x05000000 and state.get((w >> 16) & 0xF) == 0:
            stores_vtable = True
        # bl with this + n in r0
        if (w & 0x0F000000) == 0x0B000000 and (w >> 28) == 0xE and state.get(0):
            off = w & 0xFFFFFF
            calls.add((state[0], at + 8 + 4 * (off - 0x1000000 if off & 0x800000 else off)))
        # bl with a member's value in r0: the member points to an object of the callee's class
        if (w & 0x0F000000) == 0x0B000000 and (w >> 28) == 0xE and 0 in loaded and 0 not in state:
            off = w & 0xFFFFFF
            points.add((loaded[0], at + 8 + 4 * (off - 0x1000000 if off & 0x800000 else off)))
        # bl, then its result stored to this + n before r0 is written again: what the callee
        # returns is kept in that member (collect() keeps it when the callee is a constructor)
        if (w & 0x0F000000) == 0x0B000000 and (w >> 28) == 0xE:
            off = w & 0xFFFFFF
            target = at + 8 + 4 * (off - 0x1000000 if off & 0x800000 else off)
            for nxt in (at + 4, at + 8):
                if nxt not in states or not start <= nxt < end:
                    break
                v = image.word(nxt)
                rn, rd = (v >> 16) & 0xF, (v >> 12) & 0xF
                if (v & 0xFFF00000) == 0xE5800000 and rd == 0 and states[nxt][0].get(rn) == 0:
                    made.add((v & 0xFFF, target))         # str r0, [this, #n]
                    break
                if (v >> 28) != 0xE or rd == 0 or (v & 0x0E000000) in (0x0A000000, 0x08000000):
                    break                                 # r0 written, a branch, or conditional
    return found, stores_vtable, calls, points, made


def first_parameter_is_value(demangled):
    """a member function's name with parameters: is the first one not a pointer or reference
    (or are there none)? None when it cannot be told."""
    found = re.match(r"^(.*?)\((.*)\)( const)?$", demangled)
    if not found or "<" in found.group(1) or "operator" in found.group(1):
        return None
    params = found.group(2)
    if params in ("", "void"):
        return True
    depth, first = 0, ""
    for c in params:
        depth += c in "<("
        depth -= c in ">)"
        if c == "," and depth == 0:
            break
        first += c
    return not any(x in first for x in "*&[")


def named_classes(known=()):
    """classes the game has no type information for but names in its exports: a qualifier
    with a constructor or destructor (A::B::B, A::B::~B) or a const member function is a
    class, not a namespace. from signatures.csv, which tools/headers.py writes."""
    out = set()
    path = config.CONFIG / "signatures.csv"
    if not path.exists():
        return out
    with open(path, encoding="utf-8", newline="") as f:
        for r in csv.DictReader(f):
            d = r["demangled"]
            if not r["mangled"].startswith("_ZN") or "(" not in d or "<" in d or "operator" in d:
                continue
            cls, _, last = d[:d.index("(")].rpartition("::")
            if not cls or cls in known:
                continue
            if last.lstrip("~") == cls.rsplit("::", 1)[-1] or r["mangled"].startswith("_ZNK"):
                out.add(cls)
    return out


def struct_returns(m):
    """the virtual slots ((class that introduces it, slot)) and the exported functions (mangled)
    that config/<version>/returns.csv says return a struct by value: a named type that is not
    behind a pointer or reference and is not an enum (config/<version>/enums.csv)."""
    path, enums = config.CONFIG / "returns.csv", set()
    if (config.CONFIG / "enums.csv").exists():
        with open(config.CONFIG / "enums.csv", encoding="utf-8", newline="") as f:
            enums = {r["name"] for r in csv.DictReader(f) if r.get("kind", "enum") == "enum"}
    slots, names = set(), set()
    if not path.exists():
        return slots, names
    builtin = {"void", "bool", "char", "signed", "unsigned", "short", "int", "long", "float", "double", "wchar_t",
               "u8", "s8", "u16", "s16", "u32", "s32", "u64", "s64", "f32", "f64"}
    with open(path, encoding="utf-8", newline="") as f:
        for r in csv.DictReader(f):
            t = r["type"].strip()
            words = set(re.findall(r"[A-Za-z_][\w:]*", t))
            if not t or "*" in t or "&" in t or words <= builtin or t.lstrip(":") in enums:
                continue
            if "#" in r["key"]:
                cls, _, slot = r["key"].rpartition("#")
                slots.add((cls, int(slot)))
            else:
                names.add(r["key"])
    return slots, names


def collect():
    """{class: {(offset, width, type): number of functions}} and
    {class: {(offset, class of the object there): number of functions}}."""
    m = classify.load()
    by_slot, by_name = struct_returns(m)
    images = {}
    sizes = {(r["module"], int(r["start"], 16)): int(r["end"], 16) for r in m.rows}
    todo = {}                                                       # (module, start) -> (class, must store the vtable)
    classes = set(m.parents) | named_classes(m.parents)
    with open(config.CONFIG / "signatures.csv", encoding="utf-8", newline="") as f:
        for r in csv.DictReader(f):
            d = r["demangled"]
            if not r["mangled"].startswith("_ZN") or "::" not in d or first_parameter_is_value(d) is not True:
                continue
            cls = d[:d.index("(")].rsplit("::", 1)[0]
            if cls in classes:
                todo[("code.bin", int(r["address"], 16))] = (cls, False, 1 if r["mangled"] in by_name else 0)
    constructors = set()                # (module, start) of every constructor, and the import stubs of one
    with open(config.CONFIG / "ctors.csv", encoding="utf-8", newline="") as f:
        for r in csv.DictReader(f):
            if r["kind"] == "ctor":
                constructors.add((r["module"], int(r["function"], 16)))
            if r["top"] == "0":
                todo.setdefault((r["module"], int(r["function"], 16)), (r["class"], True, 0))
    for r in m.rows:
        if r["kind"] == "stub" and "::" in r["name"]:
            owner, _, last = r["name"].rpartition("::")
            if last == owner.rsplit("::", 1)[-1]:
                constructors.add((r["module"], int(r["start"], 16)))
    for r in m.rows:
        if r["class"] and r["slot"] and not r["slot"].startswith("-") and r["method"] != "shared" and r["mode"] == "arm":
            this = 0
            if r["slot"].isdigit() and (m.introducer(r["class"], int(r["slot"])), int(r["slot"])) in by_slot:
                this = 1
            todo[(r["module"], int(r["start"], 16))] = (r["class"], False, this)

    # what a call lands on: a function of a known class, or in a module the import stub of
    # a constructor or destructor (A::B::B, A::B::~B)
    lands = {where: cls for where, (cls, _, _) in todo.items()}
    # an import stub lands on a member function when every export of that name takes this
    # (its first parameter is not a pointer or reference: a static one could not take r0 so)
    methods = defaultdict(set)
    with open(config.CONFIG / "signatures.csv", encoding="utf-8", newline="") as f:
        for r in csv.DictReader(f):
            d = r["demangled"]
            if r["mangled"].startswith("_ZN") and "(" in d and "<" not in d[:d.index("(")]:
                methods[d[:d.index("(")]].add(first_parameter_is_value(d))
    for r in m.rows:
        if r["kind"] == "stub" and "::" in r["name"]:
            cls, _, last = r["name"].rpartition("::")
            if cls in classes and (last.lstrip("~") == cls.rsplit("::", 1)[-1] or methods.get(r["name"]) == {True}):
                lands[(r["module"], int(r["start"], 16))] = cls
    seen, objects, pointers = defaultdict(Counter), defaultdict(Counter), defaultdict(Counter)
    used = skipped = 0
    for (module, start), (cls, need_vtable, this) in sorted(todo.items()):
        end = sizes.get((module, start))
        if end is None or start & 3:
            continue
        if module not in images:
            images[module] = config.Image(module)
        got = accesses(images[module], start, end, this)
        if got is None or (need_vtable and not got[1]):
            skipped += 1
            continue
        used += 1
        for access in got[0]:
            if 0 <= access[0] < LIMIT:
                seen[cls][access] += 1
        base_offsets = {at for _, at in m.parents.get(cls, [])}
        for off, target in got[2]:
            inner = lands.get((module, target))
            if inner and inner != cls and 0 < off < LIMIT and off not in base_offsets:
                objects[cls][(off, inner)] += 1
        for off, target in got[3]:
            inner = lands.get((module, target))
            if inner and 0 <= off < LIMIT:
                pointers[cls][(off, inner)] += 1
        for off, target in got[4]:
            inner = lands.get((module, target))
            if inner and (module, target) in constructors and 0 < off < LIMIT and off not in base_offsets:
                pointers[cls][(off, inner)] += 1
    print(f"{used} functions followed ({skipped} left out: a computed jump, or a constructor inlined in another function)")
    return m, seen, objects, pointers


def main():
    config.options(__doc__)
    m, seen, objects, pointers = collect()
    parents = m.parents

    order, done = [], set()

    def visit(cls):
        if cls in done:
            return
        done.add(cls)
        for b, _ in parents.get(cls, []):
            visit(b)
        order.append(cls)
    for cls in sorted(set(parents) | set(seen)):
        visit(cls)

    # a base ends before the base after it: where a class has two bases, the second one's
    # offset bounds the first one's size, whatever a stray access says
    cap = {}
    for cls, bases in parents.items():
        ordered = sorted(bases, key=lambda b: b[1])
        for (b, at), (_, after) in zip(ordered, ordered[1:]):
            if after > at:
                cap[b] = min(cap.get(b, LIMIT), after - at)

    # the extent of each class from its own evidence, bases first; then every access to its owner
    extent, own = {}, defaultdict(Counter)

    def owner(cls, off):
        """(the class an offset of cls belongs to, the offset in it)."""
        for b, at in parents.get(cls, []):
            if at <= off < at + extent.get(b, 0):
                return owner(b, off - at)
        return cls, off

    for cls in order:
        bases = parents.get(cls, [])
        size = max([at + extent.get(b, 0) for b, at in bases], default=0)
        if cls in m.primary:
            size = max(size, 4)
        for (off, width, _), _n in seen.get(cls, {}).items():
            if owner(cls, off)[0] == cls and off + width <= cap.get(cls, LIMIT):
                size = max(size, off + width)
        extent[cls] = size
    for cls in order:
        for (off, width, kind), n in seen.get(cls, {}).items():
            who, at = owner(cls, off)
            if at + width <= cap.get(who, LIMIT):
                own[who][(at, width, kind)] += n
    # the class a pointer member points to: what the calls made with its value agree on
    pointee = defaultdict(Counter)
    for cls in order:
        for (off, inner), n in pointers.get(cls, {}).items():
            who, at = owner(cls, off)
            pointee[(who, at)][inner] += n
    inside = defaultdict(Counter)
    for cls in order:
        for (off, inner), n in objects.get(cls, {}).items():
            who, at = owner(cls, off)
            if at and who != inner and at + max(extent.get(inner, 0), 4) <= cap.get(who, LIMIT):
                inside[who][(at, inner)] += n

    rows = []
    for cls in sorted(set(own) | set(inside)):
        by_offset = defaultdict(Counter)
        for (off, width, kind), n in own[cls].items():
            by_offset[off][(width, kind)] += n
        chosen = {}
        for off, votes in by_offset.items():
            widths = Counter()
            for (width, _), n in votes.items():
                widths[width] += n
            width = max(widths, key=lambda k: (widths[k], k))
            kinds = {kind for (w_, kind) in votes if w_ == width}
            kind = "f" if "f" in kinds else "p" if "p" in kinds else "s" if "s" in kinds else "u"
            if off % min(width, 4) == 0 and not (cls in m.primary and off < 4):
                chosen[off] = (width, kind, widths[width])
        # objects first (the class most seen at an offset), then the most seen; one that
        # overlaps one already taken is dropped
        taken = []
        best = {}
        for (off, inner), n in inside.get(cls, {}).items():
            if off % 4 == 0 and (off not in best or n > best[off][1]):
                best[off] = (inner, n)
        for off, (inner, n) in sorted(best.items(), key=lambda kv: (-kv[1][1], kv[0])):
            width = max(extent.get(inner, 0), 4)
            if all(off + width <= o or o + w_ <= off for o, w_, _, _, _ in taken):
                taken.append((off, width, "o", n, inner))
        for off, (width, kind, n) in sorted(chosen.items(), key=lambda kv: (-kv[1][2], kv[0])):
            if all(off + width <= o or o + w_ <= off for o, w_, _, _, _ in taken):
                taken.append((off, width, kind, n, ""))
        for k, (off, width, kind, n, inner) in enumerate(sorted(taken)):
            votes = pointee.get((cls, off))
            if not inner and width == 4 and kind in ("p", "u") and votes:
                best, hits = votes.most_common(1)[0]
                if hits * 3 >= sum(votes.values()) * 2:     # two thirds of the calls agree
                    kind, inner = "p", best
            rows.append({"class": cls, "offset": f"{off:X}", "width": width, "type": kind, "functions": n, "of": inner})
    with open(PATH, "w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, FIELDS, lineterminator="\n")
        w.writeheader()
        w.writerows(rows)
    kinds = Counter(r["type"] for r in rows)
    print(f"{len(rows)} members of {len({r['class'] for r in rows})} classes: {kinds['o']} objects, {kinds['p']} pointers, {kinds['f']} floats, "
          f"{kinds['s']} signed, {kinds['u']} other; wrote {PATH}")


def load():
    """{class: [(offset, width, type, functions, class of an object)]} of fields.csv ({} without the file)."""
    out = defaultdict(list)
    if PATH.exists():
        with open(PATH, encoding="utf-8", newline="") as f:
            for r in csv.DictReader(f):
                out[r["class"]].append((int(r["offset"], 16), int(r["width"]), r["type"], int(r["functions"]), r.get("of") or ""))
    return out


if __name__ == "__main__":
    main()
