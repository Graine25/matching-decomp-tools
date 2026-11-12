"""the function table, from the Ghidra project.

  python -I tools/functable.py            writes config/<version>/functions.csv
  python -I tools/functable.py --census   only prints the numbers of the file there

needs the Ghidra server (tools/local/ghidra_server.py serve, run with the
Python of a venv that has pyghidra). a line per function: module, start, end, body, mode, kind, name.

- start: address in code.bin, file offset in a module (as Ghidra has them).
- end: the next function's start, or the end of the code: the function with
  its literal pool. this is the size match.py asks of a source.
- body: bytes of instructions, as Ghidra sees the function, without the pool.
- mode: arm or thumb. kind: thunk or -.
- name: Ghidra's (the game's exports demangled, ours), empty when it has none.

- class, slot, method, library: filled by tools/classify.py (see there).

addresses and names only: nothing of the game's code is in the file. starts
that Ghidra misses go in config/<version>/extra_starts.txt (module address
[thumb]), and are merged here.
"""
import csv
import json
import re
import socket
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import config

PORT = 18970
PATH = config.CONFIG / "functions.csv"
UNNAMED = re.compile(r"^(?:[ft]_|FUN_|thunk_FUN_|SUB_|LAB_)[0-9A-Fa-f_]*$|^[ft]_\w+_[0-9A-Fa-f]{8}$")


def query(args):
    try:
        with socket.create_connection(("127.0.0.1", PORT), timeout=600) as conn:
            conn.sendall((json.dumps(args) + "\n").encode())
            data = b""
            while chunk := conn.recv(65536):
                data += chunk
    except ConnectionRefusedError:
        raise SystemExit("no Ghidra server: start tools/local/ghidra_server.py serve (see CLAUDE.md)")
    return data.decode("utf-8", "replace")


def code_range(module):
    """(start, end) of a module's code, in the addresses Ghidra uses."""
    if module == "code.bin":
        image = config.Image()
        return image.text, image.text + image.text_size
    head = (config.ORIG / "romfs" / f"{module}.cro").read_bytes()[:0xC0]
    start, size = struct.unpack_from("<II", head, 0xB0)
    return start, start + size


def extra_starts():
    out = {}
    path = config.CONFIG / "extra_starts.txt"
    if path.exists():
        for line in path.read_text(encoding="utf-8").splitlines():
            parts = line.split("#")[0].split()
            if len(parts) >= 2:
                out.setdefault(parts[0], []).append((int(parts[1], 16), "thumb" if "thumb" in parts[2:] else "arm"))
    return out


def build():
    programs = [p.strip().rsplit("/", 1)[-1] for p in query(["programs"]).splitlines() if p.strip().startswith("/")]
    extra, rows = extra_starts(), []
    for program in programs:
        module = program[:-4] if program.endswith(".cro") else program
        try:
            lo, hi = code_range(module)
        except FileNotFoundError:
            print(f"{program}: not in orig/, skipped")
            continue
        funcs = {}
        for line in query(["table", program]).splitlines():
            parts = line.split(" ", 5)
            if len(parts) < 6 or not re.fullmatch(r"[0-9A-F]+", parts[0]):
                continue
            start = int(parts[0], 16)
            if lo <= start < hi:
                funcs[start] = [int(parts[1], 16), int(parts[2]), parts[3], parts[4], parts[5].strip()]
        for start, mode in extra.get(module, []):
            funcs.setdefault(start, [start, 0, mode, "-", ""])
        starts = sorted(funcs)
        for i, start in enumerate(starts):
            body_end, body, mode, kind, name = funcs[start]
            end = starts[i + 1] if i + 1 < len(starts) else hi
            if UNNAMED.match(name):
                name = ""
            rows.append((module, f"{start:08X}", f"{end:08X}", body, mode, kind, name))
        print(f"{module}: {len(starts)}", flush=True)
    PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(PATH, "w", encoding="utf-8", newline="") as f:
        w = csv.writer(f, lineterminator="\n")
        w.writerow(("module", "start", "end", "body", "mode", "kind", "name", "class", "slot", "method", "library"))
        w.writerows(r + ("", "", "", "") for r in rows)
    print("class, slot, method and library are empty: run tools/rtti.py, then tools/classify.py")


_table = None
_library = None


def counted():
    """(functions, bytes) that are code to account for: everything but the import stubs."""
    n = size = 0
    for funcs in table().values():
        for start, (end, body, mode, kind, name) in funcs.items():
            if kind != "stub":
                n += 1
                size += end - start
    return n, size


def library(module, start):
    """the library column of a function ('' when unknown or without the table)."""
    global _library
    if _library is None:
        _library = {}
        if PATH.exists():
            with open(PATH, encoding="utf-8", newline="") as f:
                for r in csv.DictReader(f):
                    _library[(r["module"], int(r["start"], 16))] = r.get("library") or ""
    return _library.get((module, start), "")


def table():
    """{module: {start: (end, body, mode, kind, name)}} of functions.csv, or {} when there is none."""
    global _table
    if _table is None:
        _table = {}
        if PATH.exists():
            with open(PATH, encoding="utf-8", newline="") as f:
                for r in csv.DictReader(f):
                    _table.setdefault(r["module"], {})[int(r["start"], 16)] = (int(r["end"], 16), int(r["body"]), r["mode"], r["kind"], r["name"])
    return _table


def census():
    t = table()
    if not t:
        raise SystemExit(f"no {PATH}")
    total = named = thumb = thunks = 0
    bins = [(0, 16), (16, 64), (64, 256), (256, 1024), (1024, 4096), (4096, 1 << 30)]
    count, size = [0] * len(bins), [0] * len(bins)
    for module, funcs in t.items():
        for start, (end, body, mode, kind, name) in funcs.items():
            total += 1
            named += bool(name)
            thumb += mode == "thumb"
            thunks += kind == "thunk"
            for i, (lo, hi) in enumerate(bins):
                if lo < end - start <= hi:
                    count[i] += 1
                    size[i] += end - start
    code = len(t.get("code.bin", {}))
    print(f"{total} functions: {code} in code.bin, {total - code} in {len(t) - 1} modules")
    print(f"named {named}, thumb {thumb}, thunks {thunks}")
    print(f"{'bytes':>14} {'functions':>10} {'share':>6} {'KiB':>8} {'share':>6}")
    for (lo, hi), n, s in zip(bins, count, size):
        label = f"{lo + 1}-{hi}" if hi < 1 << 30 else f"over {lo}"
        print(f"{label:>14} {n:10} {100 * n / total:5.1f}% {s / 1024:8.0f} {100 * s / sum(size):5.1f}%")


if __name__ == "__main__":
    config.options(__doc__, "--census")
    if "--census" not in sys.argv:
        build()
    census()
