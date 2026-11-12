"""gives each function its class, its virtual slot and its library.

  python -I tools/classify.py

reads config/<version>/functions.csv, classes.csv and vtables.csv (tools/rtti.py)
and fills four columns of functions.csv:

  class    the class a virtual function belongs to: of the classes whose vtables
           hold it, the one all the others derive from. empty when it is in the
           vtables of unrelated classes (a function they share).
  slot     its place in that class's vtable; "top:slot" in a secondary vtable.
  method   its name there. a slot has one name down a hierarchy: when any class
           of it has that slot named (an export of the game, a name of ours), the
           others get it; else vfN. ~ is a destructor.
  kind     stub for a module's import stubs (not functions to write; library
           import). the other kinds are functable.py's.
  library  whose code it is: game, gfl2 (the engine), sdk (nn::), nw
           (NintendoWare), middleware, armlib (the compiler's library). from the
           namespace of its name or class; in code.bin also from its place, since
           the linker keeps a library together: a function between two of the same
           library is marked with a ? (sdk?), and so is one that only code of one
           library calls. empty: not known.

only game and gfl2 are to be decompiled; the rest is library code, counted apart.
"""
import csv
import re
import struct
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import config

FIELDS = ["module", "start", "end", "body", "mode", "kind", "name", "class", "slot", "method", "library"]
LIBRARY = config.LIBRARIES           # project.toml's [libraries]: first namespace -> library
FILES = config.LIBRARY_FILES          # project.toml's [library_files]
C_LIBRARY = re.compile(r"^(?:__aeabi|__ARM|__rt_|_printf|_scanf|__cxa_|_ll_|__fpl|__mathlib|__hardfp|__softfp|_btod|__btod|_fp_|__2s|__c89)")
TARGET = tuple(config.OWN) + tuple(f"{o}?" for o in config.OWN) + ("",)


def components(mangled):
    """the names of a mangled nested name (_ZN3app2ui6UIView4DrawEv -> app, ui, UIView, Draw)."""
    s = re.sub(r"^_ZThn\d+_", "_Z", mangled)
    m = re.match(r"_ZNK?", s)
    if not m:
        m = re.match(r"_Z(\d+)", s)
        return [s[m.end():m.end() + int(m.group(1))]] if m else None
    i, out = m.end(), []
    while i < len(s):
        c = s[i]
        if c.isdigit():
            n = re.match(r"\d+", s[i:])
            size = int(n.group())
            out.append(s[i + n.end():i + n.end() + size])
            i += n.end() + size
        elif c == "I":                     # template arguments: skipped
            depth, i = 1, i + 1
            while i < len(s) and depth:
                if s[i].isdigit():
                    n = re.match(r"\d+", s[i:])
                    i += n.end() + int(n.group())
                    continue
                depth += s[i] in "IN"
                depth -= s[i] == "E"
                i += 1
        elif s[i:i + 2] in ("C1", "C2", "C3"):
            out.append(out[-1] if out else "ctor")
            i += 2
        elif s[i:i + 2] in ("D0", "D1", "D2"):
            out.append("~" + (out[-1] if out else ""))
            i += 2
        elif c == "E":
            return out
        else:
            return out or None
    return out or None


def plain(name):
    """a demangled name without its template arguments."""
    while "<" in name:
        new = re.sub(r"<[^<>]*>", "", name)
        if new == name:
            break
        name = new
    return name


def top_namespace(name):
    if not name:
        return None
    m = re.search(r"_GLOBAL__N__\d+_(\w+?)_(?:cpp|c|h)_", name)
    if m:
        return "file:" + m.group(1)
    if name.startswith("_Z"):
        parts = components(name)
        return parts[0] if parts and len(parts) > 1 else ("St" if re.match(r"_ZNK?St", name) else None)
    name = plain(name)
    if "::" in name:
        return name.split("::")[0]
    m = re.match(r"Z?N?K?(\d+)", name)     # a mangled type name left as it was
    if m:
        return name[m.end():m.end() + int(m.group(1))]
    return None


def library_of(name):
    ns = top_namespace(name)
    if ns is None:
        return "armlib" if name and C_LIBRARY.match(name) else ""
    if ns.startswith("file:"):
        return FILES.get(ns[5:], "")
    if ns.startswith("switchD_") or ns.startswith("_"):
        return LIBRARY.get(ns, "")
    return LIBRARY.get(ns, "game")


def basename(name):
    if not name:
        return None
    if name.startswith("_Z"):
        parts = components(name)
        return parts[-1] if parts and len(parts) > 1 else None
    name = plain(name)
    return name.rsplit("::", 1)[1] if "::" in name else None


class Model:
    """the tables, and what follows from them: each class's bases and primary vtable, and
    the name of each slot down its hierarchy."""


def load(interfaces=False):
    """the model. interfaces: also give a primary vtable to each class the tables have none for
    (an abstract class whose own vtable the compiler never wrote: a listener, an interface)
    when some class has it as a base at an offset other than 0: that class's vtable for the
    base there is the base's layout, slot for slot (its targets are that class's). for the
    headers only; the columns of functions.csv come from the game's own vtables."""
    path = config.CONFIG / "functions.csv"
    with open(path, encoding="utf-8", newline="") as f:
        rows = [{k: r.get(k, "") or "" for k in FIELDS} for r in csv.DictReader(f)]
    index = {(r["module"], int(r["start"], 16)): r for r in rows}

    parents = {}
    with open(config.CONFIG / "classes.csv", encoding="utf-8", newline="") as f:
        for r in csv.DictReader(f):
            bases = [(b.rsplit(":", 1)[0], int(b.rsplit(":", 1)[1])) for b in r["bases"].split()]
            if r["class"] not in parents or len(bases) > len(parents[r["class"]]):
                parents[r["class"]] = bases

    def ancestors(cls, seen=None):
        seen = seen if seen is not None else set()
        for base, _ in parents.get(cls, []):
            if base not in seen:
                seen.add(base)
                ancestors(base, seen)
        return seen

    known = {}
    def up(cls):
        if cls not in known:
            known[cls] = ancestors(cls)
        return known[cls]

    vtables = {}       # (module, vtable) -> (class, top, [(target, name)])
    with open(config.CONFIG / "vtables.csv", encoding="utf-8", newline="") as f:
        for r in csv.DictReader(f):
            v = vtables.setdefault((r["module"], r["vtable"]), (r["class"], int(r["top"]), []))
            v[2].append((r["target"], r["name"]))

    # each class's primary vtable: the longest one with top 0
    primary = {}
    for (module, _), (cls, top, slots) in vtables.items():
        if top == 0 and len(slots) > len(primary.get(cls, (None, []))[1]):
            primary[cls] = (module, slots)
    if interfaces:
        secondary = {}                      # (class, offset of a base) -> (module, slots)
        for (module, _), (cls, top, slots) in vtables.items():
            if top < 0:
                secondary.setdefault((cls, -top), (module, slots))
        seen = {}
        for cls, bases in parents.items():
            for base, at in bases:
                if at > 0 and base not in primary and (cls, at) in secondary:
                    seen.setdefault(base, []).append(secondary[cls, at])
        for base, found in seen.items():
            # the length most of them agree on, and the first table of that length
            length = Counter(len(slots) for _, slots in found).most_common(1)[0][0]
            primary[base] = next((module, slots) for module, slots in found if len(slots) == length)

    def introducer(cls, i):
        while True:
            base = next((b for b, off in parents.get(cls, []) if off == 0), None)
            if base is None or base not in primary or len(primary[base][1]) <= i:
                return cls
            cls = base

    def target_function(target):
        m = re.fullmatch(r"([\w.]+):([0-9A-F]{8})", target)
        return (m.group(1), int(m.group(2), 16)) if m else None

    # the name of each slot, down its hierarchy
    votes = {}
    for cls, (module, slots) in primary.items():
        for i, (target, name) in enumerate(slots):
            where = target_function(target)
            known_name = index[where]["name"] if where in index else name
            base = basename(known_name)
            if base:
                votes.setdefault((introducer(cls, i), i), Counter())[("~" if base.startswith("~") else base)] += 1
    # the code's own word: a slot whose function frees the object (calls operator delete) right
    # after a slot whose function does not is the deleting destructor (D0) after the complete one
    # (D1). this names the destructor of a class whose first slot is another function (an
    # interface with a virtual first), which no name and no vtable store tells
    deleting = deleters(index)
    named = set(votes)                  # a slot a name gives is never renamed by this
    for cls, (module, slots) in primary.items():
        for i in range(len(slots) - 1):
            first, second = target_function(slots[i][0]), target_function(slots[i + 1][0])
            keys = [(introducer(cls, k), k) for k in (i, i + 1)]
            if any(k in named for k in keys):
                continue
            if first in index and second in index and deleting.get(second) and deleting.get(first) is False:
                for key in keys:
                    votes.setdefault(key, Counter())["~"] += 1
    slot_name = {key: c.most_common(1)[0][0] for key, c in votes.items()}

    m = Model()
    m.rows, m.index, m.parents, m.vtables, m.primary = rows, index, parents, vtables, primary
    m.slot_name, m.introducer, m.target_function, m.up = slot_name, introducer, target_function, up
    return m


def deleters(index):
    """{(module, start): whether the function ends by freeing its object} for the ARM functions of
    the table: its last instruction a tail call (b) to `operator delete` (or to a module's import
    stub of it), the function nothing else or `this` put back in r0 just before (a deleting
    destructor: `mov r0, r4; pop {r4, lr}; b operator delete`). a function that deletes something
    else on its way (a member) is not one."""
    targets = {k for k, r in index.items() if r["name"] in ("operator.delete", "operator delete")}
    out, images = {}, {}
    for (module, start), r in index.items():
        if r["mode"] != "arm" or r["kind"] == "stub":
            continue
        end = int(r["end"], 16)
        if end - start > 512:
            out[(module, start)] = None             # too long to be a destructor worth naming so
            continue
        if module not in images:
            try:
                images[module] = config.Image(module)
            except OSError:
                images[module] = None
        image = images[module]
        if image is None:
            continue
        words = [image.word(at) for at in range(start, end, 4)]
        last = None                     # the last branch: the function's end (a pool may follow)
        for n, w in enumerate(words):
            if (w & 0x0F000000) == 0x0A000000 and (w >> 28) == 0xE:
                last = n
            if (w & 0x0FFFFFFF) in (0x012FFF1E,) or (w & 0x0FFF8000) == 0x08BD8000:
                break                   # bx lr, pop {..., pc}: a return before any tail call
        found = False
        if last is not None:
            w = words[last]
            off = w & 0xFFFFFF
            t = start + 4 * last + 8 + 4 * (off - 0x1000000 if off & 0x800000 else off)
            if (module, t) in targets:
                # nothing else, or r0 set again from a saved register (this) shortly before
                found = last == 0 or any((x & 0x0FFFF000) == 0x01A00000 and (x & 0xF) in (4, 5, 6, 7)
                                         for x in words[max(0, last - 3):last])
        out[(module, start)] = found
    return out


def dtors():
    """{(module, start): class} of the destructors tools/ctors.py found."""
    out = {}
    path = config.CONFIG / "ctors.csv"
    if path.exists():
        with open(path, encoding="utf-8", newline="") as f:
            for r in csv.DictReader(f):
                if r["kind"] == "dtor":
                    out[(r["module"], int(r["function"], 16))] = r["class"]
    return out


def table_targets(image, start, end):
    """where the jump tables of a function lead: for a `ldrlo pc, [pc, rX, lsl #2]` the
    addresses in the table after it, for an `addls pc, pc, rX, lsl #2` the branches after it.
    the number of cases is the constant of the cmp just before."""
    targets = set()
    for at in range(start, end, 4):
        w = image.word(at)
        loads = (w & 0x0FFFFFF0) == 0x079FF100
        adds = (w & 0x0FFFFFF0) == 0x008FF100
        if not loads and not adds:
            continue
        cond, count = w >> 28, None
        for back in range(at - 4, max(start - 4, at - 20), -4):
            c = image.word(back)
            if (c & 0x0FF0F000) == 0x03500000 and (c >> 16) & 0xF == (w & 0xF):
                rot = 2 * ((c >> 8) & 0xF)
                value = (((c & 0xFF) >> rot) | ((c & 0xFF) << (32 - rot))) & 0xFFFFFFFF if rot else c & 0xFF
                count = value if cond == 3 else value + 1 if cond == 9 else None
                break
        if not count or count > 1024:
            continue
        for k in range(count):
            entry = at + 8 + 4 * k
            if loads:
                if image.name == "code.bin":
                    targets.add(image.word(entry))
                else:
                    loaded = image.reloc(entry)
                    if loaded and loaded[0] == "here":
                        targets.add(loaded[1])
            else:
                b = image.word(entry)
                if (b & 0xFF000000) == 0xEA000000:
                    off = b & 0xFFFFFF
                    targets.add(entry + 8 + 4 * (off - 0x1000000 if off & 0x800000 else off))
    return targets


def join_cases(rows):
    """a function with a jump table whose cases lie in the functions after it: Ghidra cut
    them off. each piece that a table of the function leads into or past is put back, as long
    as nothing says it is a function of its own (a name, a call to it, a place in a vtable)."""
    by_module = {}
    for r in rows:
        by_module.setdefault(r["module"], []).append(r)
    own = set()
    vt = config.CONFIG / "vtables.csv"
    if vt.exists():
        with open(vt, encoding="utf-8", newline="") as f:
            for r in csv.DictReader(f):
                module, _, addr = r["target"].rpartition(":")
                if module and re.fullmatch(r"[0-9A-Fa-f]{8}", addr):
                    own.add((module.removesuffix(".cro"), int(addr, 16) & ~1))
    joined, gone = 0, set()
    for module, funcs in by_module.items():
        image = config.Image(module)
        lo = min(int(r["start"], 16) for r in funcs if r["kind"] != "stub")
        hi = max(int(r["end"], 16) for r in funcs if r["kind"] != "stub")
        for at in range(lo, hi - 3, 4):
            w = image.word(at)
            if (w & 0x0F000000) == 0x0B000000 and (w >> 28) != 0xF:           # bl
                off = w & 0xFFFFFF
                own.add((module, at + 8 + 4 * (off - 0x1000000 if off & 0x800000 else off)))
        i = 0
        while i < len(funcs):
            r = funcs[i]
            if r["kind"] == "stub" or r["mode"] != "arm":
                i += 1
                continue
            start = int(r["start"], 16)
            while i + 1 < len(funcs):
                end = int(r["end"], 16)
                nxt = funcs[i + 1]
                ns = int(nxt["start"], 16)
                if ns != end or nxt["name"] or nxt["kind"] == "stub" or nxt["mode"] != "arm" or (module, ns) in own:
                    break
                if not any(t >= end for t in table_targets(image, start, end) if lo <= t < hi):
                    break
                r["end"] = nxt["end"]
                r["body"] = str(int(r["end"], 16) - start)
                gone.add(id(nxt))
                del funcs[i + 1]
                joined += 1
            i += 1
    return [r for r in rows if id(r) not in gone], joined


def tidy():
    """three corrections to the table as Ghidra gives it:
    - the zero padding at the end of a module's code (up to a page) is not part of its last
      function: a function ends where 32 or more bytes of zeros that the loader does not
      fill begin;
    - nnroControlObject_, the SDK's entry of every module, is one function of 172 bytes with
      a jump table; Ghidra cuts its five cases off as functions. they are put back;
    - so are the cases of any other function with a jump table (join_cases)."""
    import cro as crolib
    path = config.CONFIG / "functions.csv"
    with open(path, encoding="utf-8", newline="") as f:
        rows = [{k: r.get(k, "") or "" for k in FIELDS} for r in csv.DictReader(f)]
    data, relocated, trimmed, merged, out = {}, {}, 0, 0, []
    i = 0
    while i < len(rows):
        r = rows[i]
        module = r["module"]
        if module != "code.bin" and r["kind"] != "stub":
            if module not in data:
                c = crolib.Cro(config.ORIG / "romfs" / f"{module}.cro")
                data[module] = c.data
                relocated[module] = set(c.internal()) | set(c.imports())
            start, end = int(r["start"], 16), int(r["end"], 16)
            at = end
            while at - 4 >= start and data[module][at - 4:at] == b"\0\0\0\0" and (at - 4) not in relocated[module]:
                at -= 4
            if end - at >= 32:
                r["end"] = f"{at:08X}"
                trimmed += end - at
            if r["name"] == "nnroControlObject_" and int(r["end"], 16) - start == 40:
                cases = rows[i + 1:i + 6]
                if len(cases) == 5 and all(c["module"] == module and not c["name"] for c in cases):
                    last = cases[-1]
                    le, ls = int(last["end"], 16), int(last["start"], 16)
                    at = le
                    while at - 4 >= ls and data[module][at - 4:at] == b"\0\0\0\0" and (at - 4) not in relocated[module]:
                        at -= 4
                    if le - at >= 32:
                        trimmed += le - at
                        le = at
                    r["end"], r["body"], r["library"] = f"{le:08X}", str(le - start), "sdk"
                    merged += 1
                    i += 5
        out.append(r)
        i += 1
    out, joined = join_cases(out)
    if trimmed or merged or joined:
        with open(path, "w", encoding="utf-8", newline="") as f:
            w = csv.DictWriter(f, FIELDS, lineterminator="\n")
            w.writeheader()
            w.writerows(out)
        print(f"tidied: {trimmed} bytes of padding taken off the functions before it, {merged} nnroControlObject_ put back together, "
              f"{joined} pieces of functions with a jump table put back")


def main():
    config.options(__doc__)
    tidy()
    m = load()
    rows, index, vtables, primary = m.rows, m.index, m.vtables, m.primary
    slot_name, introducer, target_function, up = m.slot_name, m.introducer, m.target_function, m.up
    path = config.CONFIG / "functions.csv"
    destructors = dtors()

    # where each function is a virtual
    seen = {}
    for (module, _), (cls, top, slots) in vtables.items():
        for i, (target, _) in enumerate(slots):
            where = target_function(target)
            if where in index:
                seen.setdefault(where, []).append((cls, top, i))
    owned = shared = 0
    for where, places in seen.items():
        classes = {c for c, _, _ in places}
        owners = [c for c in classes if all(o == c or c in up(o) for o in classes)]
        row = index[where]
        if len(owners) != 1:
            shared += 1
            row["class"], row["slot"], row["method"] = "", "", "shared"
            continue
        owned += 1
        owner = owners[0]
        _, top, i = min((p for p in places if p[0] == owner), key=lambda p: (p[1] != 0, p[2]))
        row["class"] = owner
        row["slot"] = str(i) if top == 0 else f"{top}:{i}"
        if top == 0:
            method = slot_name.get((introducer(owner, i), i))
            if destructors.get(where) == owner:
                method = "~"
            row["method"] = ("~" + plain(owner).rsplit("::", 1)[-1] if method == "~" else method) if method else f"vf{i}"
        else:
            row["method"] = ""

    # import stubs: `ldr pc, [pc, #-4]` and a word the loader fills. the module's way to
    # call out; nothing to write, so they are not counted as functions to do
    data = {}
    for r in rows:
        if r["module"] != "code.bin":
            if r["module"] not in data:
                data[r["module"]] = (config.ORIG / "romfs" / f"{r['module']}.cro").read_bytes()
            if struct.unpack_from("<I", data[r["module"]], int(r["start"], 16))[0] == 0xE51FF004:
                r["kind"] = "stub"

    # nothing here comes from a scan of anyone's libraries: a library is told by the names the
    # game itself has, by position and by who calls it

    # libraries
    for r in rows:
        if r["kind"] == "stub":
            r["library"] = "import"
            continue
        if r["name"] == "nnroControlObject_":
            r["library"] = "sdk"
            continue
        lib = library_of(r["name"]) or library_of(r["class"] + "::x" if r["class"] else "")
        if not lib and r["module"] != "code.bin":
            lib = "game?"
        r["library"] = lib
    code = sorted((r for r in rows if r["module"] == "code.bin"), key=lambda r: int(r["start"], 16))
    sure = [(i, r["library"]) for i, r in enumerate(code) if r["library"] and r["method"] != "shared"]
    before, last = [None] * len(code), None
    j = 0
    for i in range(len(code)):
        while j < len(sure) and sure[j][0] <= i:
            last = sure[j][1]
            j += 1
        before[i] = last
    after, nxt = [None] * len(code), None
    j = len(sure) - 1
    for i in range(len(code) - 1, -1, -1):
        while j >= 0 and sure[j][0] >= i:
            nxt = sure[j][1]
            j -= 1
        after[i] = nxt
    for i, r in enumerate(code):
        if not r["library"] and before[i] and before[i] == after[i]:
            r["library"] = before[i] + "?"

    # by its callers: a function that only library code of one kind calls is that library's
    # (a template the library instantiates, a helper of its own). marked with a ? as well.
    import bisect
    image = config.Image()
    starts = [int(r["start"], 16) for r in code]
    callers = {}
    for i, r in enumerate(code):
        if r["mode"] != "arm":
            continue
        for at in range(starts[i], int(r["end"], 16), 4):
            w = image.word(at)
            if (w & 0x0E000000) != 0x0A000000 or (w >> 28) == 0xF:        # b, bl
                continue
            off = w & 0xFFFFFF
            target = at + 8 + 4 * (off - 0x1000000 if off & 0x800000 else off)
            j = bisect.bisect_left(starts, target)
            if j < len(starts) and starts[j] == target and j != i:
                callers.setdefault(j, set()).add(i)
    by_callers = 0
    changed = True
    while changed:
        changed = False
        for j, who in callers.items():
            if code[j]["library"]:
                continue
            libs = {code[i]["library"].rstrip("?") for i in who}
            if len(libs) == 1 and libs <= {"sdk", "nw", "middleware", "armlib"}:
                code[j]["library"] = libs.pop() + "?"
                by_callers += 1
                changed = True
    print(f"library by callers: {by_callers} functions that only one library calls")

    with open(path, "w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, FIELDS, lineterminator="\n")
        w.writeheader()
        w.writerows(rows)

    named = sum(1 for r in rows if r["method"] and not r["method"].startswith("vf") and r["method"] != "shared" and not r["name"])
    print(f"virtual functions: {owned} with a class ({named} of the unnamed ones got a method's name), {shared} shared by unrelated classes")
    count, size = Counter(), Counter()
    for r in rows:
        count[r["library"]] += 1
        size[r["library"]] += int(r["end"], 16) - int(r["start"], 16)
    total = sum(size.values())
    print(f"{'library':12} {'functions':>10} {'KiB':>8} {'share':>6}")
    for lib in sorted(count, key=lambda k: -size[k]):
        print(f"{lib or '(unknown)':12} {count[lib]:10} {size[lib] / 1024:8.0f} {100 * size[lib] / total:5.1f}%")
    target = sum(size[k] for k in size if k in TARGET)
    print(f"to decompile (game, gfl2, unknown): {sum(count[k] for k in count if k in TARGET)} functions, "
          f"{target / 1024:.0f} KiB ({100 * target / total:.1f}%)")


if __name__ == "__main__":
    main()
