"""paths and the target's layout. every tool imports this.

the tools are the matching-decomp-tools repository; the decomp they work on is the folder
that holds a project.toml (the current folder or one above it, or MATCH_PROJECT): its
versions, compiler, flags and libraries are there, and everything else is its folders
(orig/, config/, src/, include/, build/, toolchain/).

one version is the main one (MAIN): its addresses are the ones in the sources (`//!` lines,
sub_<address> names), in symbols.txt and in the function table, and the tables under
config/<MAIN>/ are its. MATCH_VERSION picks the version the judge compares with
(orig/<version>/, reports in build/<version>/); another version than the main one is reached
through config/<version>/map.csv (tools/versions.py), so a source names the main version's
address and is checked against the other's code. sources are compiled with GAME_VERSION set
to the version's id (include/version.h): the switch for the functions that differ.
"""
import bisect
import csv
import hashlib
import os
import re
import struct
import sys
from pathlib import Path


def read_toml(path):
    """the subset of TOML project.toml uses: [sections], key = "string" | integer | ["strings"]."""
    out, section = {}, {}
    out[""] = section
    for raw in Path(path).read_text(encoding="utf-8").splitlines():
        line = raw.split(" #")[0].strip() if not raw.strip().startswith("#") else ""
        if not line:
            continue
        m = re.fullmatch(r"\[([^\]]+)\]", line)
        if m:
            section = out.setdefault(m.group(1).strip(), {})
            continue
        m = re.fullmatch(r'("[^"]*"|[\w.-]+)\s*=\s*(.+)', line)
        if not m:
            raise SystemExit(f"{path}: cannot read: {raw}")
        key, value = m.group(1).strip('"'), m.group(2).strip()
        if value.startswith('"'):
            section[key] = value[1:value.rindex('"')]
        elif value.startswith("["):
            section[key] = re.findall(r'"([^"]*)"', value)
        else:
            section[key] = int(value, 0)
    return out


def find_root():
    if os.environ.get("MATCH_PROJECT"):
        return Path(os.environ["MATCH_PROJECT"]).resolve()
    here = Path.cwd().resolve()
    for folder in (here, *here.parents):
        if (folder / "project.toml").exists():
            return folder
    raise SystemExit("no project.toml here or above: run the tools from a decomp's folder (or set MATCH_PROJECT)")


ROOT = find_root()
PROJECT = read_toml(ROOT / "project.toml")
# project.local.toml (beside it, kept out of git): one person's machine, e.g. [paths] and
# [ghidra]. its keys take the place of project.toml's, section by section.
if (ROOT / "project.local.toml").exists():
    for _section, _keys in read_toml(ROOT / "project.local.toml").items():
        PROJECT.setdefault(_section, {}).update(_keys)
MAIN = PROJECT["project"]["main"]
OWN = tuple(PROJECT["project"].get("own", ["game"]))     # the libraries to decompile
VERSION = os.environ.get("MATCH_VERSION", MAIN)
# each version's own number (the one the game's data carries): GAME_VERSION in a source
GAME_VERSIONS = dict(PROJECT.get("versions", {MAIN: 0}))
if VERSION not in GAME_VERSIONS:
    raise SystemExit(f"MATCH_VERSION={VERSION}: not a version of the project ({', '.join(GAME_VERSIONS)})")
ORIG = ROOT / "orig" / MAIN                 # the main version's files: what the tables describe
TARGET = ROOT / "orig" / VERSION            # the files the judge compares with
BUILD = ROOT / "build" / VERSION
CONFIG = ROOT / "config" / MAIN
TOOLCHAIN = ROOT / "toolchain"
LIBRARIES = dict(PROJECT.get("libraries", {}))           # first namespace of a name -> library
LIBRARY_FILES = dict(PROJECT.get("library_files", {}))   # a source file's name -> library
PATHS = {k: (ROOT / v).resolve() for k, v in PROJECT.get("paths", {}).items()}


def own(library):
    """whether a function of this library (functions.csv's column; '?' when inferred, '' when
    unknown) is one to decompile."""
    return library.rstrip("?") in OWN + ("", "unknown")


# compilers: decomp.me's set (toolchain/armcc/<version>/<build>/bin/armcc.exe), and nothing
# else (the owner, 2026-11-12: no compiler that came with a console's SDK)
ARMCC_SET = TOOLCHAIN / "armcc"

# the compiler and options that give the game's bytes: project.toml's [compiler], found by
# compiling the same sources under every build and flag set and comparing with the game
DEFAULT_CC = os.environ.get("MATCH_CC", PROJECT["compiler"]["default"])
DEFAULT_FLAGS = PROJECT["compiler"]["flags"]


def options(doc, *flags, paths=False):
    """stops a tool that was given something it does not know, before it does anything: a
    tool that rewrites files must not run because of a mistyped or made-up option (--help
    included: it prints the tool's text and stops). paths: plain arguments are allowed."""
    for arg in sys.argv[1:]:
        if arg in flags or (paths and not arg.startswith("-")):
            continue
        print((doc or "").strip())
        raise SystemExit(0 if arg in ("--help", "-h") else f"unknown argument: {arg}")


def program_dir(module):
    """where a program's sources are: src/main for the executable (code.bin), src/<Module> for
    a module. inside: the unit's own files by namespace, units/ (one file per translation
    unit found), generated/ (what tools/tiny.py and tools/twins.py write)."""
    return ROOT / "src" / ("main" if module == "code.bin" else module)


def compiler(cc):
    """(path of armcc.exe, environment) of a compiler of the set: '<version>/<build>'."""
    env = dict(os.environ)
    # the compiler's own headers (its C++ library is headers): ARMCC41INC for 4.1, ARMCC5INC for 5.x
    include = ARMCC_SET / cc / "include"
    if include.exists():
        version = cc.split("/")[0].replace(".", "")
        env["ARMCC5INC" if version.startswith("5") else f"ARMCC{version[:2]}INC"] = str(include)
    return ARMCC_SET / cc / "bin" / "armcc.exe", env


def compilers():
    """every compiler found, by name."""
    found = []
    if ARMCC_SET.exists():
        for exe in sorted(ARMCC_SET.glob("*/*/bin/armcc.exe")):
            found.append(f"{exe.parent.parent.parent.name}/{exe.parent.parent.name}")
    return found


def version_define(version=None):
    """the compiler's option that tells a source which version it is built for."""
    return f"-DGAME_VERSION={GAME_VERSIONS[version or VERSION]}"


_maps = {}


def version_map(version, module):
    """[(main start, start in version, status)] of a program's functions, by main start, from
    config/<version>/map.csv (tools/versions.py); empty for the main version."""
    if version == MAIN:
        return []
    if version not in _maps:
        path = ROOT / "config" / version / "map.csv"
        if not path.exists():
            raise SystemExit(f"no {path}: run tools/versions.py {version}")
        rows = {}
        with open(path, encoding="utf-8", newline="") as f:
            for r in csv.DictReader(f):
                rows.setdefault(r["module"], []).append((int(r["start"], 16), int(r["other"], 16), r["status"]))
        _maps[version] = {m: sorted(v) for m, v in rows.items()}
    return _maps[version].get(module[:-4] if module.endswith(".cro") else module, [])


class Image:
    """a program as loaded: code.bin with the exheader's segments, or a CRO module. version:
    whose files (the main version's by default); its words are read at its own addresses,
    and translate() turns a main version's address into one of it."""

    def __init__(self, name="code.bin", version=None):
        self.name = name
        self.version = version or MAIN
        self.orig = ROOT / "orig" / self.version
        if name == "code.bin":
            self.data = (self.orig / "exefs" / "code.bin").read_bytes()
            ex = (self.orig / "exheader.bin").read_bytes()
            self.text, _, self.text_size = struct.unpack_from("<III", ex, 0x10)
            self.ro, _, self.ro_size = struct.unpack_from("<III", ex, 0x20)
            self.rw, _, self.rw_size = struct.unpack_from("<III", ex, 0x30)
            self.bss_size = struct.unpack_from("<I", ex, 0x3C)[0]
            self.base = self.text
        else:
            # a module is addressed by its file offsets, as Ghidra's program of it has them
            path = self.orig / "romfs" / (name if name.endswith(".cro") else name + ".cro")
            self.data = path.read_bytes()
            self.base = 0
            # CRO0 header: code offset and size at 0xB0, data at 0xB8 (3dbrew, "CRO0")
            self.text, self.text_size = struct.unpack_from("<II", self.data, 0xB0)
            self.ro = self.rw = self.ro_size = self.rw_size = self.bss_size = 0

    def word(self, addr):
        return struct.unpack_from("<I", self.data, addr - self.base)[0]

    def reloc(self, addr):
        """what the loader writes into a module's word: ('here', file offset it points to),
        ('name', (imported symbol, addend)), ('far', ...) for another module's, or None when
        the word is not relocated. always None in code.bin, whose words are final."""
        if self.name == "code.bin":
            return None
        if not hasattr(self, "_internal"):
            import cro
            c = cro.Cro(self.orig / "romfs" / (self.name if self.name.endswith(".cro") else self.name + ".cro"))
            self._internal, self._imports, self._cro = c.internal(), c.imports(), c
        if addr in self._internal:
            return "here", self._internal[addr]
        if addr in self._imports:
            source, symbol, addend = self._imports[addr]
            return ("name", (symbol, addend)) if source is None else ("far", (source, symbol, addend))
        return None

    def in_code(self, addr):
        if self.name == "code.bin":
            return self.in_text(addr)
        self.reloc(0)
        return self._cro.in_code(addr)

    def segment_kind(self, addr):
        """the kind of the module's segment an address is in: 0 code, 1 constant data, 2 data,
        3 bss; None outside all of them."""
        self.reloc(0)
        for start, size, kind in self._cro.segments:
            if size and start <= addr < start + size:
                return kind
        return 3 if addr >= len(self.data) else None

    def bytes(self, addr, size):
        return self.data[addr - self.base:addr - self.base + size]

    def translate(self, addr):
        """a main version's address as this version's. code: by the function that holds it
        (version_map); a module's data: by its segment (same index, its own start); the
        executable's data does not move between the versions (the segments are the same)."""
        if self.version == MAIN:
            return addr
        rows = version_map(self.version, self.name)
        if not hasattr(self, "_main_code"):
            if self.name == "code.bin":
                main = Image(self.name)
                self._main_code = (main.text, main.text + main.text_size)
                self._segments = None
            else:
                import cro
                main = cro.Cro(ORIG / "romfs" / (self.name if self.name.endswith(".cro") else self.name + ".cro"))
                ours = cro.Cro(self.orig / "romfs" / (self.name if self.name.endswith(".cro") else self.name + ".cro"))
                self._main_code = (main.segments[0][0], main.segments[0][0] + main.segments[0][1])
                self._segments = list(zip(main.segments, ours.segments))
            self._starts = [r[0] for r in rows]
        if self._main_code[0] <= addr < self._main_code[1] and rows:
            i = bisect.bisect_right(self._starts, addr) - 1
            if i >= 0:
                return rows[i][1] + addr - rows[i][0]
            return addr
        for (start, size, _), (other, _, _) in self._segments or ():
            if size and start <= addr < start + size:
                return other + addr - start
        return addr

    def status(self, addr):
        """'same', 'moved' or 'differs' (versions.py) of the main version's function at addr in
        this version; 'same' for the main version, None when the map does not have it."""
        if self.version == MAIN:
            return "same"
        if not hasattr(self, "_status"):
            self._status = {start: status for start, _, status in version_map(self.version, self.name)}
        return self._status.get(addr)

    def in_text(self, addr):
        return self.text <= addr < self.text + self.text_size

    def sha256(self):
        return hashlib.sha256(self.data).hexdigest()
