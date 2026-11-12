"""twins: functions that are the same code but for constants, offsets and addresses.

  python -I tools/twins.py            the families, and what one source would give
  python -I tools/twins.py --apply    write the twins of matched functions, keep what matches

two functions have the same shape when their instructions are equal once the
immediates, the offsets, the branch targets and the pool are left out (the
same template with another type, the same getter in another class). a matched
function's source then fits its twins with the values put in, and the
compiler says whether it does: only matches are kept, in src/<program>/generated/twins_NNN.cpp
(a file's static initializer, which is alone in its file: src/<program>/units/).

without --apply it only counts, into build/<version>/twins.txt: the families
with no member written yet, largest first. writing one of a family gives the
rest, so that list is where a hand or a model is best spent.

run tools/progress.py first: the matched functions are read from its report.
"""
import argparse
import json
import re
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import config
import functable
import match

CHUNK = 300
TARGET = tuple(config.OWN) + ("",)


def ror(v, n):
    return ((v >> n) | (v << (32 - n))) & 0xFFFFFFFF


def shape(image, start, end, body):
    """(the function with its values left out, the values) or None when it cannot be read."""
    out, values = [], []
    for at in range(start, end, 4):
        try:
            w = image.word(at)
        except struct.error:
            return None
        if at - start >= body:                              # the pool
            loaded = image.reloc(at)
            if loaded is None:
                out.append("P")
                values.append(w)
            elif loaded[0] == "here":
                out.append("Pa")
                values.append(loaded[1])
            else:
                out.append(("Pn", str(loaded[1])))          # an import: part of the shape
            continue
        if (w & 0x0E000000) == 0x0A000000 and w >> 28 != 0xF:
            out.append(w & 0xFF000000)
            values.append(match.branch_target(w, at))
        elif (w & 0x0E000000) == 0x02000000:                # data processing, immediate
            out.append(w & 0xFFFFF000)
            values.append(ror(w & 0xFF, 2 * ((w >> 8) & 15)))
        elif (w & 0x0E000000) == 0x04000000 and (w >> 16) & 15 != 15:
            out.append(w & 0xFFFFF000)
            values.append(w & 0xFFF)
        elif (w & 0x0E400090) == 0x00400090 and (w >> 16) & 15 != 15:
            out.append(w & 0xFFFFF0F0)
            values.append(((w >> 4) & 0xF0) | (w & 0xF))
        elif (w & 0x0F200F00) == 0x0D000A00 and (w >> 16) & 15 != 15:
            out.append(w & 0xFFFFFF00)
            values.append((w & 0xFF) * 4)
        else:
            out.append(w)
    return tuple(out), values


def source_of(path, where):
    """(the lines before the first function, the function's text) of a source."""
    text = Path(path).read_text(encoding="utf-8", errors="replace")
    first = re.search(r"^\s*//!", text, re.M)
    m = re.search(rf"^\s*//!\s*{re.escape(where)}\s+\S+[^\n]*\n(.*?)(?=^\s*//!|\Z)", text, re.M | re.S)
    if not m or not first:
        return None
    body = m.group(1).rstrip().split("\n")
    while body and (body[-1].strip().startswith("//") or not body[-1].strip()):
        body.pop()                                          # the next function's comment
    head = [l for l in text[:first.start()].split("\n") if l.strip() and not l.strip().startswith("//")]
    return head, "\n".join(body) + "\n"


def substitute(text, mapping, old_module, new_module):
    """the text with each value of mapping replaced: numbers, and the addresses in names."""
    def name(m):
        v = int(m.group(2), 16)
        return m.group(1) + f"{mapping.get(v, v):08X}"

    def number(m):
        token = m.group(0)
        v = int(token, 16) if token.lower().startswith("0x") else int(token)
        if v not in mapping or mapping[v] == v:
            return token
        new = mapping[v]
        return f"0x{new:X}" if token.lower().startswith("0x") or new >= 10 else str(new)

    parts = re.split(r"(\b(?:sub|data|f|t)_(?:[A-Za-z]\w*?_)?[0-9A-Fa-f]{8}\b)", text)
    for i, part in enumerate(parts):
        if i % 2:
            part = re.sub(r"^((?:sub|data|f|t)_(?:[A-Za-z]\w*?_)?)([0-9A-Fa-f]{8})$", name, part)
            if old_module != new_module:
                part = part.replace(f"_{old_module}_", f"_{new_module}_")
            parts[i] = part
        else:
            parts[i] = re.sub(r"\b0[xX][0-9A-Fa-f]+\b|\b\d+\b", number, part)
    return "".join(parts)


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--apply", action="store_true")
    a = p.parse_args()
    report = config.BUILD / "report.json"
    if not report.exists():
        raise SystemExit("run tools/progress.py first")
    matched = {}
    for r in json.loads(report.read_text(encoding="utf-8")):
        if r["status"] == "match":
            module, _, off = r["where"].rpartition(":")
            matched[(module or "code.bin", int(off, 16))] = r

    families = {}
    for module, funcs in functable.table().items():
        image = match.parse_where(f"{module}:0" if module != "code.bin" else "0")[0]
        for start, (end, body, mode, kind, name) in funcs.items():
            if mode != "arm" or kind in ("stub", "lib") or end - start < 8:
                continue
            if functable.library(module, start).rstrip("?") not in TARGET and (module, start) not in matched:
                continue
            s = shape(image, start, end, body)
            if s:
                families.setdefault(s[0], []).append((module, start, end, s[1]))

    open_families, reachable = [], []
    for key, members in families.items():
        done = [m for m in members if (m[0], m[1]) in matched]
        todo = [m for m in members if (m[0], m[1]) not in matched]
        if done and todo:
            reachable.append((done, todo))
        elif not done and len(todo) > 1:
            open_families.append(todo)
    open_families.sort(key=lambda f: -len(f) * (f[0][2] - f[0][1]))
    with open(config.BUILD / "twins.txt", "w", encoding="utf-8", newline="\n") as f:
        f.write("# families of unwritten twins: members, bytes each, then where they are\n")
        for fam in open_families:
            where = " ".join(f"{m}:{s:08X}" if m != "code.bin" else f"{s:08X}" for m, s, _, _ in fam[:40])
            f.write(f"{len(fam)} {fam[0][2] - fam[0][1]} {where}\n")
    saved = sum((len(f) - 1) * (f[0][2] - f[0][1]) for f in open_families)
    print(f"twins of matched functions, not written yet: {sum(len(t) for _, t in reachable)} in {len(reachable)} families")
    print(f"families with nothing written: {len(open_families)}, {sum(len(f) for f in open_families)} functions; "
          f"writing one of each gives the other {sum(len(f) - 1 for f in open_families)} ({saved // 1024} KiB)")
    for fam in open_families[:8]:
        print(f"  {len(fam):5} x {fam[0][2] - fam[0][1]:5} bytes, e.g. "
              f"{fam[0][0] + ':' if fam[0][0] != 'code.bin' else ''}{fam[0][1]:08X}")
    if not a.apply:
        return

    # candidates: the matched twin's source with the values of each unwritten one
    candidates = []
    for done, todo in reachable:
        for module, start, end, values in todo:
            for d_module, d_start, _, d_values in done:
                # a function found by a symbol of the compiler's (a static initializer) has no
                # addresses in its source: it fits the executable and the modules alike
                named = not re.search(r"[0-9A-Fa-f]{8}", matched[(d_module, d_start)]["symbol"])
                if ((d_module == "code.bin") != (module == "code.bin") and not named) or len(d_values) != len(values):
                    continue
                mapping, ok = {d_start: start}, True
                for old, new in zip(d_values, values):
                    if named:
                        break
                    if mapping.setdefault(old, new) != new:
                        ok = False
                        break
                    mapping.setdefault(~old & 0xFFFFFFFF, ~new & 0xFFFFFFFF)
                if not ok:
                    continue
                r = matched[(d_module, d_start)]
                src = source_of(config.ROOT / r["source"], r["where"])
                if not src:
                    continue
                head, text = src
                where = f"0x{start:08X}" if module == "code.bin" else f"{module}:0x{start:08X}"
                ours = f"sub_{start:08X}" if module == "code.bin" else f"f_{module}_{start:08X}"
                # a function the compiler names itself (a file's static initializer) keeps the
                # symbol it is found by, and can only be alone in its file
                alone = not re.search(r"[0-9A-Fa-f]{8}", r["symbol"])
                candidates.append((module, start, where, r["symbol"] if alone else ours,
                                   [substitute(l, mapping, d_module, module) for l in head],
                                   substitute(text, mapping, d_module, module), alone))
                break
    print(f"{len(candidates)} candidates", flush=True)

    def write(path, group, note):
        seen, head = set(), []
        for c in group:
            for line in c[4]:
                if line not in seen:
                    seen.add(line)
                    head.append(line)
        includes = [l for l in head if l.lstrip().startswith("#")]
        used = set(re.findall(r"[A-Za-z_]\w*", "".join(c[5] for c in group)))
        rest = []                                           # only the declarations these functions name
        for l in head:
            names = re.findall(r"\b(?:(?:sub|data|f|t)_\w+|_Z\w+)", l)
            if not l.lstrip().startswith("#") and (not names or used.intersection(names)):
                rest.append(l)
        with open(path, "w", encoding="utf-8", newline="\n") as f:
            f.write(f"// {note}\n\n" + "".join(l + "\n" for l in includes) + "\n" + "".join(l + "\n" for l in rest) + "\n")
            for c in group:
                f.write(f"//! {c[2]} {c[3]}\n{c[5]}\n")

    work = config.BUILD / "twins"
    work.mkdir(parents=True, exist_ok=True)
    won = []
    single = [c for c in candidates if c[6]]
    for n, c in enumerate(single):
        path = work / f"unit_{c[0].replace('.', '_')}_{c[1]:08X}.cpp"
        write(path, [c], "candidate of tools/twins.py")
        if match.check_many(path, [(c[2], c[3])])[0][0] == "match":
            out = config.program_dir(c[0]) / "units" / f"unit_{c[1]:08X}.cpp"
            out.parent.mkdir(parents=True, exist_ok=True)
            write(out, [c], f"a file of {c[0]}, known so far only by its static initializer (written by tools/twins.py)")
            won.append(c)
        if n % 200 == 199:
            print(f"  {n + 1} of {len(single)} files, {len(won)} match", flush=True)
    alone_won = len(won)
    by_module = {}
    for c in candidates:
        if not c[6]:
            by_module.setdefault(c[0], []).append(c)
    for size in (CHUNK, 1):                                 # alone, a twin is not inlined into its caller
        left = {}
        for module, group in by_module.items():
            for n in range(0, len(group), size):
                part = group[n:n + size]
                path = work / f"{module.replace('.', '_')}_{size}_{n // size:04}.cpp"
                write(path, part, "candidates of tools/twins.py")
                for c, result in zip(part, match.check_many(path, [(c[2], c[3]) for c in part])):
                    if result[0] == "match":
                        won.append(c)
                    else:
                        left.setdefault(module, []).append(c)
        by_module = {m: g for m, g in left.items()}
        if sum(len(g) for g in by_module.values()) > 400:
            break
    grouped = {}
    for c in won[alone_won:]:
        grouped.setdefault(c[0], []).append(c)
    for module, group in grouped.items():
        out = config.program_dir(module) / "generated"
        out.mkdir(parents=True, exist_ok=True)
        n = len(list(out.glob("twins_*.cpp")))
        for i in range(0, len(group), CHUNK):
            write(out / f"twins_{n + i // CHUNK:03}.cpp", group[i:i + CHUNK],
                  "written by tools/twins.py: the source of a matched twin with this function's values; each matches")
    print(f"{len(won)} of {len(candidates)} match: {alone_won} unit files (src/<program>/units), {len(won) - alone_won} functions (src/<program>/generated)")


if __name__ == "__main__":
    main()
