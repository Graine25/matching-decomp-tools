"""a class's function that the compiler put in several programs (an inline function, a
destructor, a template: each module has its own copy): the same source, checked at each copy.

    python -I tools/copies.py            what would be written
    python -I tools/copies.py --apply    writes them

for every function that matches from a written source (not src/<program>/generated) and whose
class and method functions.csv knows, the functions of the same class, method and size in
the other programs that have no source yet are its candidates. the source file is copied to
the same path under each such program (src/<Module>/<the rest of the path>), its `//!` lines
pointing at that program's copies (a function with no copy there keeps no `//!` line), and
kept only where every `//!` line left says MATCH. a file that is there already is left alone.
"""
import csv
import json
import re
import sys
import tempfile
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import config
import match

MARK = re.compile(r"^([ \t]*//![ \t]*)(\S+)([ \t]+\S+[^\n]*)$", re.M)


def where_of(module, start):
    return f"0x{start:08X}" if module == "code.bin" else f"{module}:0x{start:08X}"


def main():
    config.options(__doc__, "--apply")
    rows = {}
    by_kind = defaultdict(list)
    with open(config.CONFIG / "functions.csv", encoding="utf-8", newline="") as f:
        for r in csv.DictReader(f):
            if r["kind"] == "stub" or not r["class"] or not r["method"]:
                continue
            start, end = int(r["start"], 16), int(r["end"], 16)
            rows[(r["module"], start)] = r
            by_kind[(r["class"], r["method"], end - start)].append((r["module"], start))
    report = json.load(open(config.BUILD / "report.json", encoding="utf-8"))
    have = set()
    for r in report:
        module, _, off = r["where"].rpartition(":")
        have.add((module or "code.bin", int(off, 16)))
    sources = defaultdict(set)
    for r in report:
        if r["status"] == "match" and "/generated/" not in r["source"].replace("\\", "/"):
            sources[r["source"]].add(r["where"])
    written = tried = 0
    for source, wheres in sorted(sources.items()):
        parts = Path(source).as_posix().split("/")
        if len(parts) < 3 or parts[0] != "src":
            continue
        own = "code.bin" if parts[1] == "main" else parts[1]
        rest = "/".join(parts[2:])
        text = (config.ROOT / source).read_text(encoding="utf-8")
        # each //! of the file: its function's kind, and where that kind has a copy without a source
        copies = defaultdict(dict)                    # program -> {where here: where there}
        for m in MARK.finditer(text):
            module, _, off = m.group(2).rpartition(":")
            key = (module or "code.bin", int(off, 16))
            r = rows.get(key)
            if r is None:
                continue
            kind = (r["class"], r["method"], int(r["end"], 16) - key[1])
            for other in by_kind[kind]:
                if other[0] != own and other not in have:
                    copies[other[0]].setdefault(m.group(2), where_of(*other))
        for program, mapping in sorted(copies.items()):
            target = config.program_dir(program) / rest
            if target.exists():
                continue

            def point(m):
                there = mapping.get(m.group(2))
                return f"{m.group(1)}{there}{m.group(3)}" if there else "// " + m.group(0).strip().lstrip("/! ") + " (elsewhere)"
            new = MARK.sub(point, text)
            items = [(m.group(2), m.group(3).split()[0]) for m in MARK.finditer(new)]
            if not items:
                continue
            tried += 1
            with tempfile.TemporaryDirectory() as tmp:
                cand = Path(tmp) / Path(rest).name
                cand.write_text(new, encoding="utf-8")
                results = match.check_many(cand, items)
            if all(r[0] == "match" for r in results):
                written += 1
                print(f"{target.relative_to(config.ROOT).as_posix()}: {', '.join(w for w, _ in items)}")
                if "--apply" in sys.argv:
                    target.parent.mkdir(parents=True, exist_ok=True)
                    target.write_text(new, encoding="utf-8", newline="\n")
    print(f"{written} of {tried} copies match" + ("" if "--apply" in sys.argv else " (not written: --apply)"))


if __name__ == "__main__":
    main()
