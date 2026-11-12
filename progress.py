"""checks every function of src/ and reports.

  python -I tools/progress.py [--all] [folder or file ...]

a source names what it holds in lines of the form
  //! <where> <symbol or part of it> [cc=<compiler>] [flags=<flags, _ for spaces>]
(<where> as in match.py). each is compiled and compared; the table goes to
build/<version>/report.txt and report.json (which tools/status.py draws) and
the totals are printed. a match by a trick is "hack" and is not counted.
MATCH_VERSION=um-v1.2 checks the same sources against Ultra Moon (see match.py);
its report is build/um-v1.2/.

only what changed is compiled again: a file's result is kept (build/<version>/
progress_cache.json) for as long as the file, every header it includes, the
table's entries for its functions, the compiler and flags, and the judge itself
(match.py, honest.py, config.py and their lists) are the same. the files that
do need compiling are done side by side. --all forgets the kept results.
"""
import hashlib
import json
import os
import re
import sys
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import config
import match

# one line: a //! without a symbol is an error of its function (the symbol must not be read
# from the next line)
LINE = re.compile(r"^[ \t]*(?://|/\*)![ \t]*(\S+)(?:[ \t]+(?!\w+=)(\S+))?((?:[ \t]+\w+=\S+)*)", re.M)
INCLUDE = re.compile(r'^\s*#\s*include\s*"([^"]+)"', re.M)
CACHE = config.BUILD / "progress_cache.json"


def check_file(name):
    """every //! function of one source: [(where, symbol, result, tricks)]."""
    source = Path(name)
    groups = {}
    for where, sym, extra in LINE.findall(source.read_text(encoding="utf-8", errors="replace")):
        opts = dict(o.split("=", 1) for o in extra.split())
        groups.setdefault((opts.get("cc"), opts.get("flags", "").replace("_", " ") or None), []).append((where, sym))
    checked = []
    for (cc, flags), items in groups.items():
        for (where, sym), result in zip(items, match.check_many(source, items, cc, flags)):
            checked.append((where, sym, list(result), list(match.last_hacks)))
    return checked


class Keys:
    """what a file's result depends on, as one hash."""

    def __init__(self):
        import functable
        judge = hashlib.sha1()
        tools = Path(__file__).resolve().parent
        for f in (tools / "match.py", tools / "honest.py", tools / "config.py",
                  config.CONFIG / "flagsets.txt", config.CONFIG / "honest_allow.txt", config.CONFIG / "symbols.txt",
                  config.ROOT / "config" / config.VERSION / "map.csv"):
            judge.update(f.read_bytes() if f.exists() else b"-")
        judge.update(f"{config.DEFAULT_CC}|{config.DEFAULT_FLAGS}|{config.compiler(config.DEFAULT_CC)[0]}".encode())
        self.judge = judge.hexdigest()
        self.table = functable.table()
        self.headers = {}

    def header(self, path, stack=()):
        """the hash of a header and of all it includes."""
        if path in self.headers:
            return self.headers[path]
        if path in stack or not path.exists():
            return "-"
        data = path.read_bytes()
        h = hashlib.sha1(data)
        for inc in INCLUDE.findall(data.decode("utf-8", errors="replace")):
            for base in (path.parent, config.ROOT / "include"):
                if (base / inc).exists():
                    h.update(self.header((base / inc).resolve(), stack + (path,)).encode())
                    break
        self.headers[path] = h.hexdigest()
        return self.headers[path]

    def of(self, source):
        text = source.read_text(encoding="utf-8", errors="replace")
        h = hashlib.sha1(self.judge.encode())
        h.update(self.header(source.resolve()).encode())
        for where, _, _ in LINE.findall(text):
            module, _, addr = where.rpartition(":")
            try:
                entry = self.table.get(module or "code.bin", {}).get(int(addr, 16))
            except ValueError:
                entry = None
            h.update(repr(entry).encode())
        return h.hexdigest()


def main():
    config.options(__doc__, "--all", paths=True)
    roots = [Path(a) for a in sys.argv[1:] if a != "--all"] or [config.ROOT / "src"]
    files = []
    for root in roots:
        files += [root] if root.is_file() else sorted(f for f in root.rglob("*") if f.suffix in (".c", ".cpp"))
    rows, totals, size, records = [], {}, {}, []
    cache = {}
    if CACHE.exists() and "--all" not in sys.argv:
        try:
            cache = json.loads(CACHE.read_text(encoding="utf-8"))
        except ValueError:
            cache = {}
    keys = Keys()
    key_of = {str(f): keys.of(f) for f in files}
    todo = [name for name, key in key_of.items() if cache.get(name, {}).get("key") != key]
    if todo:
        workers = max(1, min(len(todo) // 8 + 1, (os.cpu_count() or 4) - 2))
        if workers > 1:
            with ProcessPoolExecutor(max_workers=workers) as pool:
                results = list(pool.map(check_file, todo, chunksize=8))
        else:
            results = [check_file(name) for name in todo]
        for name, checked in zip(todo, results):
            cache[name] = {"key": key_of[name], "checked": checked}
        config.BUILD.mkdir(parents=True, exist_ok=True)
        CACHE.write_text(json.dumps(cache), encoding="utf-8")
    print(f"{len(files)} files: {len(todo)} compiled, {len(files) - len(todo)} unchanged")
    for source in files:
        for where, sym, (status, diffs, opens, nbytes), hacks in cache[str(source)]["checked"]:
            totals[status] = totals.get(status, 0) + 1
            size[status] = size.get(status, 0) + nbytes
            rows.append(f"{status:7} {where:22} {nbytes:6} {diffs:4} {opens:3}  {source.relative_to(config.ROOT).as_posix()}  {sym}")
            records.append(dict(status=status, where=where, bytes=nbytes, symbol=sym, hacks=hacks,
                                source=source.relative_to(config.ROOT).as_posix()))
            if status != "match":
                print(rows[-1] + ("  [" + ", ".join(hacks) + "]" if hacks else ""))
    config.BUILD.mkdir(parents=True, exist_ok=True)
    (config.BUILD / "report.txt").write_text("status  where                   bytes diff open  source  symbol\n" + "\n".join(rows) + "\n",
                                             encoding="utf-8")
    (config.BUILD / "report.json").write_text(json.dumps(records, indent=1), encoding="utf-8")
    # a function two sources match counts once (the same address in two files)
    matched = {}
    for r in records:
        if r["status"] == "match":
            matched.setdefault(r["where"], r["bytes"])
    twice = totals.get("match", 0) - len(matched)
    if twice:
        print(f"{twice} matches of functions another source also matches (counted once)")
    totals["match"], size["match"] = len(matched), sum(matched.values())
    for status in ("match", "hack", "match?", "differ", "error"):
        if status in totals:
            print(f"{status:7} {totals[status]:6} functions {size[status]:8} bytes")
    import functable
    known = functable.counted()[0]
    if known:
        print(f"functions: {totals.get('match', 0)} of {known} matched")
    done = size.get("match", 0)
    total = target = 0
    for module, funcs in functable.table().items():
        for start, (end, _, _, kind, _) in funcs.items():
            if kind == "stub":
                continue
            total += end - start
            if config.own(functable.library(module, start)):
                target += end - start
    if total:
        print(f"matched: {done} of {total} bytes of code, import stubs left out ({100 * done / total:.4f}%)")
        own = 0
        for where, nbytes in matched.items():
            module, _, off = where.rpartition(":")
            if config.own(functable.library(module or "code.bin", int(off, 16))):
                own += nbytes
        print(f"of the game's own code ({', '.join(config.OWN)}, unknown): {own} of {target} bytes ({100 * own / target:.4f}%)")


if __name__ == "__main__":
    main()
