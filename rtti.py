"""the classes the game names itself: its run-time type information.

  python -I tools/rtti.py

the game is built with RTTI, so every class with a virtual function left a
type_info object: its mangled name, and its base classes with their offsets.
each vtable points at its class's type_info, so the virtual functions of
every class are known by slot. this reads all of it, from the executable and
from each module (through the relocations and imports the loader would
apply), and writes:

  config/<version>/classes.csv   module, typeinfo, class, base:offset ...
  config/<version>/vtables.csv   module, vtable, top, class, slot, target, name
      top: offset of this vtable's subobject in the class (0: the primary one)
      target: the function of the slot (module:address, or the imported name)
      name: the function's name in functions.csv, when it has one

names and addresses only.
"""
import csv
import re
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import config
import cro as crolib
import functable

KINDS = {"_ZTVN10__cxxabiv117__class_type_infoE": "class",
         "_ZTVN10__cxxabiv120__si_class_type_infoE": "si",
         "_ZTVN10__cxxabiv121__vmi_class_type_infoE": "vmi"}


def demangle(name):
    """a type's mangled name as C++, when it is a plain or nested name; else as it is."""
    def parts(s):
        out = []
        while s and s[0].isdigit():
            m = re.match(r"\d+", s)
            n = int(m.group())
            out.append(s[m.end():m.end() + n])
            s = s[m.end() + n:]
        return out, s
    if name.startswith("N") and name.endswith("E"):
        names, rest = parts(name[1:-1])
        return "::".join(names) if names and not rest else name
    names, rest = parts(name)
    return names[0] if len(names) == 1 and not rest else name


def neg(v):
    return v - (1 << 32) if v & 0x80000000 else v


class Space:
    """one program's words as they are once loaded: (kind, value) per address.
    kind: 'raw' (a number), 'here' (an address in this program), 'name' (an imported
    symbol + addend), 'far' ((module, address) + addend)."""

    def word(self, at):
        raise NotImplementedError


class Executable(Space):
    def __init__(self, static):
        self.name = "code.bin"
        self.image = config.Image()
        self.exports = static.exports()
        im = self.image
        self.ranges = [(im.ro, im.ro + im.ro_size), (im.rw, im.rw + im.rw_size)]
        self.limit = im.rw + im.rw_size + im.bss_size

    def word(self, at):
        v = self.image.word(at)
        if self.image.text <= v < self.limit:
            return "here", v
        return "raw", v

    def string(self, at):
        d = self.image.data
        start = at - self.image.base
        return d[start:d.index(b"\0", start)].decode("ascii", "replace")

    def is_code(self, at):
        return self.image.in_text(at & ~1)

    def kinds(self):
        return {self.exports[n] + 8: k for n, k in KINDS.items() if n in self.exports}

    def named(self, name):
        return self.exports.get(name)


class Module(Space):
    def __init__(self, cro, others):
        self.cro, self.name, self.others = cro, cro.path.stem, others
        self.internal = cro.internal()
        self.imports = cro.imports()
        segs = [s for s in cro.segments if s[2] in (1, 2) and s[1]]
        self.ranges = [(s[0], s[0] + s[1]) for s in segs]

    def word(self, at):
        if at in self.internal:
            return "here", self.internal[at]
        if at in self.imports:
            source, symbol, addend = self.imports[at]
            if source is None:
                return "name", (symbol, addend)
            other = self.others.get(source)
            where = other.tag(symbol) if other else None
            return "far", ((other.path.stem if other else source, where), addend)
        return "raw", self.cro.u32(at)

    def string(self, at):
        return self.cro.string(at)

    def is_code(self, at):
        return self.cro.in_code(at & ~1)


def scan(space, kinds_by_address):
    """(classes, vtables) of a program. classes: {typeinfo: (name, [(base ref, offset)])};
    a base ref is ('here', address), ('name', symbol) or ('far', (module, address)).
    vtables: [(vtable, top, class ref, [slot words])]."""
    classes = {}
    for lo, hi in space.ranges:
        for at in range(lo, hi - 8, 4):
            kind, v = space.word(at)
            if kind == "here":
                what = kinds_by_address.get(v)
            elif kind == "name":
                what = KINDS.get(v[0]) if v[1] == 8 else None
            else:
                what = None
            if not what:
                continue
            k2, name_at = space.word(at + 4)
            if k2 != "here":
                continue
            try:
                name = space.string(name_at)
            except (ValueError, IndexError):
                continue
            if not re.fullmatch(r"[A-Za-z0-9_]+", name):
                continue
            bases = []
            if what == "si":
                bases.append((space.word(at + 8), 0))
            elif what == "vmi":
                count = space.word(at + 12)[1]
                if not isinstance(count, int) or count > 32:
                    continue
                for i in range(count):
                    flags = space.word(at + 20 + 8 * i)[1]
                    bases.append((space.word(at + 16 + 8 * i), neg(flags) >> 8 if isinstance(flags, int) else 0))
            classes[at] = (name, [((k, v[0] if k in ("name", "far") else v), off) for (k, v), off in bases])
    vtables = []
    for lo, hi in space.ranges:
        for at in range(lo + 4, hi - 4, 4):
            kind, v = space.word(at)
            if kind == "here" and v in classes:
                ref = ("here", v)
            elif kind == "name" and v[0].startswith("_ZTI") and v[1] == 0:
                ref = ("name", v[0])
            else:
                continue
            k0, top = space.word(at - 4)
            if k0 != "raw" or not (top == 0 or top >= 0xFFFF0000):
                continue
            slots, slot = [], at + 4
            while slot < hi:
                k, t = space.word(slot)
                if k == "here" and space.is_code(t):
                    slots.append(("here", t))
                elif k in ("name", "far") and not (k == "name" and t[0].startswith("_ZT")):
                    slots.append((k, t[0]))
                else:
                    break
                slot += 4
            if slots:
                vtables.append((at + 4, neg(top), ref, slots))
    return classes, vtables


def main():
    config.options(__doc__)
    mods = crolib.modules(config.ORIG / "romfs")
    static = mods.pop("static", None) or next(m for m in mods.values() if m.path.suffix == ".crs")
    mods = {n: m for n, m in mods.items() if m.path.suffix == ".cro"}
    exe = Executable(static)
    spaces = [exe] + [Module(m, mods) for m in mods.values()]
    found = {}
    for space in spaces:
        found[space.name] = scan(space, exe.kinds() if space is exe else {})
        print(f"{space.name}: {len(found[space.name][0])} classes, {len(found[space.name][1])} vtables", flush=True)

    # a base or a vtable's class, as a name
    names_at = {(module, at): demangle(name) for module, (classes, _) in found.items() for at, (name, _) in classes.items()}
    static_at = {addr: n for n, addr in exe.exports.items() if n.startswith("_ZTI")}

    def class_name(module, ref):
        kind, v = ref
        if kind == "here":
            return names_at.get((module, v), f"?{v:08X}")
        if kind == "name":
            return demangle(v[4:]) if v.startswith("_ZTI") else v
        return names_at.get(v, f"?{v[0]}:{v[1]:08X}" if v[1] is not None else f"?{v[0]}")

    table = functable.table()
    with open(config.CONFIG / "classes.csv", "w", encoding="utf-8", newline="") as f:
        w = csv.writer(f, lineterminator="\n")
        w.writerow(("module", "typeinfo", "class", "bases"))
        for module, (classes, _) in found.items():
            for at in sorted(classes):
                name, bases = classes[at]
                w.writerow((module, f"{at:08X}", demangle(name),
                            " ".join(f"{class_name(module, ref)}:{off}" for ref, off in bases)))
    slots_total, targets, unnamed = 0, set(), set()
    with open(config.CONFIG / "vtables.csv", "w", encoding="utf-8", newline="") as f:
        w = csv.writer(f, lineterminator="\n")
        w.writerow(("module", "vtable", "top", "class", "slot", "target", "name"))
        for module, (_, vtables) in found.items():
            funcs = table.get(module, {})
            for vtable, top, ref, slots in vtables:
                cls = class_name(module, ref)
                for i, (kind, t) in enumerate(slots):
                    slots_total += 1
                    if kind == "here":
                        entry = funcs.get(t & ~1)
                        target, name = f"{module}:{t & ~1:08X}", entry[4] if entry else ""
                        targets.add((module, t & ~1))
                        if entry and not entry[4]:
                            unnamed.add((module, t & ~1))
                    elif kind == "name":
                        target, name = t, t
                    else:
                        target, name = (f"{t[0]}:{t[1]:08X}" if t[1] is not None else t[0]), ""
                    w.writerow((module, f"{vtable:08X}", top, cls, i, target, name))
    classes_total = sum(len(c) for c, _ in found.values())
    unique = len({demangle(n) for c, _ in found.values() for n, _ in c.values()})
    based = sum(1 for c, _ in found.values() for _, b in c.values() if b)
    print(f"{classes_total} type infos ({unique} different classes, {based} with bases), "
          f"{sum(len(v) for _, v in found.values())} vtables, {slots_total} slots")
    print(f"{len(targets)} functions are a virtual of a class; {len(unnamed)} of them had no name")


if __name__ == "__main__":
    main()
