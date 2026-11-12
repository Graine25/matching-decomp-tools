"""the functions that write a class's vtable into an object: constructors and destructors.

  python -I tools/ctors.py

an object becomes a class's when its first word is set to that class's vtable.
only constructors and destructors do that, so a function whose literal pool
holds a vtable's address is one of them (or has one inlined). this finds them,
in the executable and in every module, and writes

  config/<version>/ctors.csv   module, function, class, vtable, top, kind

kind: dtor when the function is itself in that class's vtable (a class's
destructors are virtual slots of it); else ctor, which also covers a function
that builds an object of the class in place (the constructor inlined in it).
addresses and names only.
"""
import bisect
import csv
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import config
import cro as crolib
import functable


def main():
    config.options(__doc__)
    table = functable.table()
    vtables, slots = {}, {}
    with open(config.CONFIG / "vtables.csv", encoding="utf-8", newline="") as f:
        for r in csv.DictReader(f):
            key = (r["module"], int(r["vtable"], 16))
            vtables[key] = (r["class"], int(r["top"]))
            slots.setdefault((r["module"], r["class"]), set()).add(r["target"])
    by_module = {}
    for (module, vtable), info in vtables.items():
        by_module.setdefault(module, {})[vtable] = info

    rows = []
    for module, mine in sorted(by_module.items()):
        funcs = table.get(module, {})
        starts = sorted(funcs)
        refs = []     # (address of the pool word, vtable)
        if module == "code.bin":
            image = config.Image()
            words = struct.unpack_from(f"<{image.text_size // 4}I", image.data, 0)
            refs = [(image.text + 4 * i, w) for i, w in enumerate(words) if w in mine]
        else:
            c = crolib.Cro(config.ORIG / "romfs" / f"{module}.cro")
            refs = [(at, v) for at, v in c.internal().items() if v in mine and c.in_code(at)]
        seen = set()
        for at, vtable in sorted(refs):
            i = bisect.bisect_right(starts, at) - 1
            if i < 0 or at >= funcs[starts[i]][0]:
                continue
            start = starts[i]
            if (start, vtable) in seen:
                continue
            seen.add((start, vtable))
            cls, top = mine[vtable]
            kind = "dtor" if f"{module}:{start:08X}" in slots.get((module, cls), ()) else "ctor"
            rows.append((module, f"{start:08X}", cls, f"{vtable:08X}", top, kind))
    with open(config.CONFIG / "ctors.csv", "w", encoding="utf-8", newline="") as f:
        w = csv.writer(f, lineterminator="\n")
        w.writerow(("module", "function", "class", "vtable", "top", "kind"))
        w.writerows(rows)
    ctor = {(r[0], r[1]) for r in rows if r[5] == "ctor"}
    dtor = {(r[0], r[1]) for r in rows if r[5] == "dtor"}
    classes = {r[2] for r in rows}
    print(f"{len(rows)} references to {len({(r[0], r[3]) for r in rows})} of {len(vtables)} vtables: "
          f"{len(dtor)} destructors, {len(ctor)} constructors or functions with one inlined, {len(classes)} classes")


if __name__ == "__main__":
    main()
