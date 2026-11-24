"""the byte check: compile a source with armcc and compare one function with the game's.

  python -I tools/match.py show  <where> [words]         the game's code at an address
  python -I tools/match.py check <source> <where> [--sym NAME] [--cc CC] [--flags "..."]
  python -I tools/match.py sweep <source> <where> [--sym NAME]   every compiler x flag set

<where> is an address of code.bin (0x003D6790) or Module:offset (Battle:0x4F508), always the
main version's (Ultra Sun). MATCH_VERSION=um-v1.2 compares with Ultra Moon instead: every
address, the function's and its callees', goes through config/um-v1.2/map.csv, and the source
is compiled with GAME_VERSION of that version (include/version.h).
CC is a build of the set in toolchain/armcc ('5.04/b82', '4.1/b1049').

a word under a relocation is not compared as bytes: the call's target or the
address loaded must be the symbol's. a symbol's address comes from
config/<version>/symbols.txt or from its name (sub_003D6790, data_0066A000,
f_Battle_00000FE0). a relocation whose symbol has no address is listed as
unverified, and the function is then 'match?' and not 'match'. the function
must also be as long as the game's (config/<version>/functions.csv, from
tools/functable.py): a source that compiles to the first part of it differs.

the linker's own changes are modelled, as the game shows them (inlined(), probes/linkinline):
a bl to a function that only returns is a NOP (`mov r0, r0`) in the game, a bl to a function of
one plain instruction and a return is that instruction, and a tail call (`b`) to the function
placed right after is a NOP. the callee must still be named; any other call is compared as one.

Thumb code (functions.csv's mode) is compared half word by half word, a call (bl, or blx
to ARM code) by its target and a word of the pool like ARM's. the source must be compiled
as Thumb (--thumb in a flag set of config/<version>/flagsets.txt); ARM code for a Thumb
function, or the other way round, differs.
"""
import argparse
import bisect
import os
import re
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import config
import functable
import honest

R_ARM_PC24, R_ARM_ABS32, R_ARM_REL32, R_ARM_CALL, R_ARM_JUMP24 = 1, 2, 3, 28, 29
BRANCHES = (R_ARM_PC24, R_ARM_CALL, R_ARM_JUMP24)

C_FLAGS = "--c99 --gnu"
CPP_FLAGS = "--cpp --gnu --force_new_nothrow --no_rtti --no_rtti_data --no_exceptions"

# what sweep tries, after the compilers: the options seen to change code in other 3DS games
FLAG_SETS = [
    config.DEFAULT_FLAGS,
    "--cpu=MPCore --fpmode=fast --apcs=/interwork -O3 -Otime",
    "--cpu=MPCore --fpmode=fast --apcs=/interwork -O3 -Ospace --split_sections",
    "--cpu=MPCore --fpmode=fast --apcs=/interwork -O2 -Otime --split_sections",
    "--cpu=MPCore --fpmode=fast --apcs=/interwork -O2 -Ospace --split_sections",
    "--cpu=MPCore --fpmode=fast --apcs=/interwork/fpic -O3 -Otime --split_sections",
    "--cpu=MPCore.no_vfp --fpmode=fast --apcs=/interwork -O3 -Otime --split_sections",
    "--cpu=MPCore --fpmode=ieee_no_fenv --apcs=/interwork -O3 -Otime --split_sections",
    "--cpu=MPCore --fpmode=fast --apcs=/interwork -O3 -Otime --split_sections --forceinline --data_reorder",
]


class Object:
    """an ELF relocatable as armcc writes it (ELF32, little endian, REL)."""

    def __init__(self, path):
        d = self.data = Path(path).read_bytes()
        if d[:4] != b"\x7fELF":
            raise SystemExit(f"{path}: not an ELF object")
        shoff, = struct.unpack_from("<I", d, 0x20)
        shentsize, shnum, shstrndx = struct.unpack_from("<HHH", d, 0x2E)
        self.sections = []
        for i in range(shnum):
            name, kind, flags, addr, off, size, link, info, align, entsize = struct.unpack_from("<10I", d, shoff + i * shentsize)
            self.sections.append(dict(name=name, kind=kind, off=off, size=size, link=link, info=info, entsize=entsize))
        names = self.sections[shstrndx]
        for s in self.sections:
            s["name"] = self._str(names, s["name"])
        self.symbols, self.relocs = [], {}
        for s in self.sections:
            if s["kind"] == 2:  # SHT_SYMTAB
                strings = self.sections[s["link"]]
                for i in range(s["size"] // 16):
                    name, value, size, info, other, shndx = struct.unpack_from("<IIIBBH", d, s["off"] + i * 16)
                    self.symbols.append(dict(name=self._str(strings, name), value=value, size=size, kind=info & 15,
                                             bind=info >> 4, section=shndx))
        for s in self.sections:
            if s["kind"] == 9:  # SHT_REL
                table = self.relocs.setdefault(s["info"], {})
                for i in range(s["size"] // 8):
                    off, info = struct.unpack_from("<II", d, s["off"] + i * 8)
                    table[off] = (info & 0xFF, self.symbols[info >> 8])

    def _str(self, section, off):
        start = section["off"] + off
        return self.data[start:self.data.index(b"\0", start)].decode("latin1")

    def content(self, index):
        s = self.sections[index]
        return b"" if s["kind"] == 8 else self.data[s["off"]:s["off"] + s["size"]]

    def functions(self):
        return [s for s in self.symbols if s["kind"] == 2 and 0 < s["section"] < len(self.sections)]

    def function(self, wanted=None, hint=None):
        funcs = self.functions()
        if wanted:
            picked = [f for f in funcs if f["name"] == wanted] or [f for f in funcs if wanted in f["name"]]
        else:
            picked = [f for f in funcs if hint and hint in f["name"].upper()] or [f for f in funcs if f["bind"] == 1] or funcs
        if not picked:
            raise SystemExit("no function in the object" + (f" named like {wanted}" if wanted else ""))
        if len(picked) > 1 and not wanted and not (hint and hint in picked[0]["name"].upper()):
            names = ", ".join(f["name"] for f in picked[:8])
            print(f"note: {len(picked)} functions in the object ({names}); taking {picked[0]['name']} (use --sym)")
        return picked[0]

    def body(self, func):
        """(bytes, relocations by offset, thumb) of a function: to the next function of its
        section or the section's end, so its literal pool is part of it."""
        index = func["section"]
        start = func["value"] & ~1
        later = [f["value"] & ~1 for f in self.functions() if f["section"] == index and (f["value"] & ~1) > start]
        end = min(later) if later else self.sections[index]["size"]
        relocs = {off - start: r for off, r in self.relocs.get(index, {}).items() if start <= off < end}
        return self.content(index)[start:end], relocs, bool(func["value"] & 1)


_images = {}


def parse_where(text, version=None):
    """(image, address) of a <where>: the main version's image, unless a version is named;
    the address is always the main version's."""
    module, _, off = text.rpartition(":")
    module = module or "code.bin"
    version = version or config.MAIN
    if (module, version) not in _images:
        _images[module, version] = config.Image(module, version)
    return _images[module, version], int(off, 16)


def locate(text):
    """(image, address there, main version's address) of a <where> in the version compared
    with (MATCH_VERSION)."""
    image, addr = parse_where(text, config.VERSION)
    return image, image.translate(addr), addr


_symbols = None
_exports = None


def symbol_address(name, image):
    """(module or None, address) of a symbol, or None when it has none."""
    global _symbols
    if _symbols is None:
        _symbols = {}
        path = config.CONFIG / "symbols.txt"
        if path.exists():
            for line in path.read_text(encoding="utf-8").splitlines():
                m = re.match(r"\s*([^#\s=]+)\s*=\s*(?:(\w+):)?(?:0x)?([0-9A-Fa-f]+)", line)
                if m:
                    _symbols[m.group(1)] = (m.group(2), int(m.group(3), 16))
    if name in _symbols:
        module, addr = _symbols[name]
        return module, (image.translate(addr) if module in (None, image.name, image.name[:-4]) else addr)
    # the executable's own exported names (static.crs): what the modules import by name
    global _exports
    if _exports is None:
        _exports = {}
        static = config.ORIG / "romfs" / "static.crs"
        if static.exists():
            import cro
            _exports = cro.Cro(static).exports()
    if image.name == "code.bin" and name in _exports:     # a module reaches them by import
        return (None, image.translate(_exports[name]))
    # the address in the name, also inside a C++ mangled one (_Z12sub_003D6790Ph)
    m = re.search(r"(?:sub|data|f|t)_(?:[A-Za-z]\w*?_)?([0-9A-Fa-f]{8})", name)
    if m:
        return (None, image.translate(int(m.group(1), 16)))
    # a class's vtable (_ZTV<class>): where the game's RTTI puts that class's vtable in this
    # program (config/<version>/vtables.csv has its address point, 8 bytes in)
    if name.startswith("_ZTV"):
        at = vtable_address(name[4:], image.name[:-4] if image.name.endswith(".cro") else image.name)
        if at is not None:
            return (None, image.translate(at - 8))
    # a virtual destructor: where the class's vtable in this program says it is
    at = destructor_address(name, image.name[:-4] if image.name.endswith(".cro") else image.name)
    if at is not None:
        return (None, image.translate(at))
    # a complete-object constructor or destructor (C1, D1) of a class with no virtual base is
    # its base-object one (C2, D2): armcc calls the first, the game exports the second
    m = re.fullmatch(r"(_Z.*[CD])1(E.*)", name)
    if m:
        return symbol_address(f"{m.group(1)}2{m.group(2)}", image)
    return None


_vtables = None


def mangle_class(name):
    """the Itanium mangling of a plain class name (A::B::C -> N1A1B1CE), None for a template."""
    parts = name.split("::")
    if not all(re.fullmatch(r"[A-Za-z_]\w*", p) for p in parts):
        return None
    body = "".join(f"{len(p)}{p}" for p in parts)
    return body if len(parts) == 1 else f"N{body}E"


def vtable_address(mangled, module):
    """the address point of the primary vtable of a class (mangled type name) in a program."""
    global _vtables
    if _vtables is None:
        _vtables = {}
        path = config.CONFIG / "vtables.csv"
        if path.exists():
            import csv
            with open(path, encoding="utf-8", newline="") as f:
                for r in csv.DictReader(f):
                    key = mangle_class(r["class"])
                    if key and r["top"] == "0":
                        _vtables.setdefault((r["module"], key), set()).add(int(r["vtable"], 16))
    found = _vtables.get((module, mangled), set())
    return next(iter(found)) if len(found) == 1 else None


_dtor_slots = None


def destructor_address(name, module):
    """the address of a virtual destructor (_ZN<class>D0Ev, D1Ev, D2Ev) in a program, from the
    class's primary vtable there: slot 0 the complete one (D1, which is D2 without virtual
    bases), slot 1 the deleting one (D0). only when the table names that slot's function a
    destructor of the class (functions.csv's method `~<class>`)."""
    global _dtor_slots
    m = re.fullmatch(r"_ZN((?:\d+[A-Za-z_]\w*?)+)D([012])Ev", name)
    if not m:
        return None
    parts, pos, body = [], 0, m.group(1)
    while pos < len(body):
        n = re.match(r"\d+", body[pos:])
        length = int(n.group(0))
        pos += len(n.group(0))
        parts.append(body[pos:pos + length])
        pos += length
    if pos != len(body):
        return None
    cls = "::".join(parts)
    if _dtor_slots is None:
        _dtor_slots = {}
        import csv
        methods = {}
        with open(config.CONFIG / "functions.csv", encoding="utf-8", newline="") as f:
            for r in csv.DictReader(f):
                methods[(r["module"], int(r["start"], 16))] = r["method"]
        with open(config.CONFIG / "vtables.csv", encoding="utf-8", newline="") as f:
            for r in csv.DictReader(f):
                if r["top"] != "0" or r["slot"] not in ("0", "1"):
                    continue
                target_module, _, addr = r["target"].rpartition(":")
                if target_module != r["module"] or not re.fullmatch(r"[0-9A-Fa-f]+", addr):
                    continue
                at = int(addr, 16)
                if not methods.get((target_module, at), "").startswith("~"):
                    continue
                _dtor_slots.setdefault((r["module"], r["class"], int(r["slot"])), set()).add(at)
    found = _dtor_slots.get((module, cls, 1 if m.group(2) == "0" else 0), set())
    return next(iter(found)) if len(found) == 1 else None


def branch_target(word, pc):
    imm = word & 0xFFFFFF
    imm = imm - 0x1000000 if imm & 0x800000 else imm
    target = pc + 8 + (imm << 2)
    if (word >> 28) == 0xF:  # blx: bit 24 is the half word
        target += (word >> 23) & 2
    return target & 0xFFFFFFFF


R_ARM_THM_CALL, R_ARM_THM_JUMP24 = 10, 30


def thumb_call_target(first, second, pc):
    """the target of a Thumb bl / blx (two half words; ARMv6: an 11-bit high and an 11-bit
    low part), and whether it is a blx (to ARM code: the target is word aligned)."""
    high = first & 0x7FF
    high = high - 0x800 if high & 0x400 else high
    target = pc + 4 + (high << 12) + ((second & 0x7FF) << 1)
    blx = (second >> 11) == 0x1D
    return (target & ~3 if blx else target) & 0xFFFFFFFF, blx


def compare_thumb(image, addr, code, relocs, obj):
    """compare() for Thumb code: half words, with a call (two half words) checked by its
    target, and a word of the pool by what compare() checks for an ARM one."""
    out, off = [], 0
    half = lambda data, at: struct.unpack_from("<H", data, at)[0]
    while off + 2 <= len(code):
        if off in relocs and relocs[off][0] in (R_ARM_THM_CALL, R_ARM_THM_JUMP24) and off + 4 <= len(code):
            kind, sym = relocs[off]
            name = sym["name"] or obj.sections[sym["section"]]["name"]
            mine = (half(code, off), half(code, off + 2))
            raw = image.bytes(addr + off, 4)
            theirs = (half(raw, 0), half(raw, 2))
            is_call = (theirs[0] >> 11) == 0x1E and (theirs[1] >> 11) in (0x1F, 0x1D)
            if not is_call or (mine[0] >> 11) != 0x1E:
                out.append((off, "diff", f"{theirs[0]:04X}{theirs[1]:04X} / {mine[0]:04X}{mine[1]:04X} (call to {name})"))
            else:
                target, blx = thumb_call_target(*theirs, addr + off)
                where = symbol_address(sym["name"], image) if sym["name"] else None
                if where is None:
                    stub = image.reloc(target + 4) if image.name != "code.bin" and image.in_code(target) else None
                    if stub and image.word(target) == 0xE51FF004 and stub[0] == "name":
                        if stub[1] != (sym["name"], 0):
                            out.append((off, "diff", f"call to {name}, the game's goes to the stub of {stub[1][0]}"))
                    else:
                        out.append((off, "open", f"call to {name}: the game's goes to {target:08X}"))
                elif target & ~1 != where[1] & ~1:
                    out.append((off, "diff", f"call to {name} = {where[1]:08X}, the game's goes to {target:08X}"))
            off += 4
            continue
        if off in relocs and off + 4 <= len(code):
            out += [(off + o, k, t) for o, k, t in compare(image, addr + off, code[off:off + 4], {0: relocs[off]}, obj)]
            off += 4
            continue
        mine, theirs = half(code, off), half(image.bytes(addr + off, 2), 0)
        if mine != theirs:
            out.append((off, "diff", f"{theirs:04X} / {mine:04X}"))
        off += 2
    return out


NOP, BX_LR, MOV_PC_LR = 0xE1A00000, 0xE12FFF1E, 0xE1A0F00E
_modes = {}


def code_mode(image, addr):
    """'arm' or 'thumb' for a function start of this image (at its own address), else None."""
    key = (image.name, image.version)
    if key not in _modes:
        module = image.name[:-4] if image.name.endswith(".cro") else image.name
        _modes[key] = {image.translate(start): entry[2] for start, entry in functable.table().get(module, {}).items()}
    return _modes[key].get(addr)


def inlined(image, target):
    """the word armlink writes in place of a bl to target, when it inlines the call, else None.

    the linker's branch inlining, as the game shows it (probes/linkinline): no bl of the game
    goes to a function that only returns (1,139 in code.bin, 2,577 in the modules), and only
    21 of some 77,000 go to one of an instruction and a return, those whose instruction is a
    NOP or VFP; a `b` (a tail call) is never replaced. so a bl to a function that only returns
    is a NOP, and one to a function of one plain instruction is that instruction, both under
    the bl's condition (the game has `movmi r0, r0`). a call to another program (an import
    stub) is a call."""
    mode = code_mode(image, target & ~1)
    if mode == "thumb":
        return NOP if image.bytes(target & ~1, 2) == b"\x70\x47" else None
    if mode != "arm":
        return None
    returns = (BX_LR, MOV_PC_LR)
    first = image.word(target)
    if first in returns:
        return NOP
    if image.word(target + 4) not in returns or first >> 28 != 0xE or first == NOP:
        return None
    if (first >> 26) & 3 == 3 or (first >> 25) & 7 == 5:      # coprocessor (VFP), branch
        return None
    if (first >> 16) & 0xF == 15 or (first >> 12) & 0xF == 15:  # reads or writes pc
        return None
    return first


def compare(image, addr, code, relocs, obj):
    """[(offset, kind, text)] of what differs or is unverified; kind is 'diff' or 'open'."""
    out = []
    for off in range(0, len(code) & ~3, 4):
        mine, = struct.unpack_from("<I", code, off)
        theirs = image.word(addr + off)
        if off not in relocs:
            if mine != theirs:
                out.append((off, "diff", f"{theirs:08X} / {mine:08X}"))
            continue
        kind, sym = relocs[off]
        name = sym["name"] or obj.sections[sym["section"]]["name"]
        where = symbol_address(sym["name"], image) if sym["name"] else None
        if (kind in BRANCHES and where is not None and where[0] in (None, image.name, image.name[:-4])
                and theirs != mine):
            if (mine & 0x0F000000) == 0x0B000000:
                # a bl the linker inlined (inlined()): the game has the callee's instruction
                put = inlined(image, where[1])
                if put is not None and theirs == (mine & 0xF0000000) | (put & 0x0FFFFFFF):
                    continue
            elif mine >> 24 == 0xEA and theirs == NOP and where[1] & ~1 == addr + off + 4:
                # a tail call to the function the linker put right after this one: the
                # branch to the next word is a NOP (in the game's own code no `b` to the next
                # word is left, and 773 functions end in a NOP)
                continue
        if kind in BRANCHES:
            # same condition and bl/b; a bl to Thumb code is linked as blx
            if (mine >> 24) != (theirs >> 24) and not ((theirs >> 25) == 0x7D and (mine >> 24) == 0xEB):
                out.append((off, "diff", f"{theirs:08X} / {mine:08X} (branch to {name})"))
            elif where is None:
                # in a module a call out goes through an import stub: `ldr pc, [pc, #-4]` and a
                # word the loader fills with the symbol. the stub must be this symbol's
                target = branch_target(theirs, addr + off)
                stub = image.reloc(target + 4) if image.name != "code.bin" and image.in_code(target) else None
                if stub and image.word(target) == 0xE51FF004 and stub[0] == "name":
                    if stub[1] != (sym["name"], 0):
                        out.append((off, "diff", f"branch to {name}, the game's goes to the stub of {stub[1][0]}"))
                else:
                    out.append((off, "open", f"branch to {name}: the game's goes to {target:08X}"))
            elif branch_target(theirs, addr + off) & ~1 != where[1] & ~1:
                out.append((off, "diff", f"branch to {name} = {where[1]:08X}, the game's goes to {branch_target(theirs, addr + off):08X}"))
        elif kind == R_ARM_ABS32 and image.name != "code.bin":
            # a module's word is filled by the loader: compare with what it would write
            loaded = image.reloc(addr + off)
            if loaded is None:
                out.append((off, "diff", f"address of {name}: the game's word is not relocated ({theirs:08X})"))
            elif loaded[0] == "here":
                local = sym["bind"] == 0 and 0 < sym["section"] < len(obj.sections)
                if where is None and local:
                    # a static of this file has no name to check: it must at least be data of
                    # the same kind in the module (written data for .data and .bss, else constant)
                    kind = image.segment_kind(loaded[1])
                    mine_kind = obj.sections[sym["section"]]["name"]
                    wanted = (1,) if mine_kind.startswith((".constdata", ".conststring", ".rodata")) else (2, 3)
                    if kind not in wanted:
                        out.append((off, "diff", f"address of a static in {mine_kind}, the game's {loaded[1]:08X} is not such data"))
                    elif kind == 1:
                        # constant data (a string): the game's bytes there must be ours
                        data = obj.content(sym["section"])[sym["value"] + mine:]
                        end = data.find(b"\0")
                        data = data[:end + 1] if 0 <= end < 256 else data[:16]
                        if image.bytes(loaded[1], len(data)) != data:
                            out.append((off, "diff", f"constant data of this file differs from the game's at {loaded[1]:08X}"))
                elif where is None:
                    out.append((off, "open", f"address of {name}: the game's is {loaded[1]:08X}"))
                elif (where[1] + mine) & 0xFFFFFFFF != loaded[1]:
                    out.append((off, "diff", f"address of {name}+{mine:#x} = {where[1] + mine:08X}, the game's is {loaded[1]:08X}"))
            elif loaded[0] == "name":
                if (sym["name"], mine) != loaded[1]:
                    out.append((off, "diff", f"address of {name}+{mine:#x}, the game imports {loaded[1][0]}+{loaded[1][1]:#x}"))
            else:
                out.append((off, "open", f"address of {name}: the game takes it from module {loaded[1][0]}"))
        elif kind == R_ARM_ABS32:
            if where is not None:
                if (where[1] + mine) & 0xFFFFFFFF != theirs:
                    out.append((off, "diff", f"address of {name}+{mine:#x} = {where[1] + mine:08X}, the game's is {theirs:08X}"))
            elif sym["section"] and 0 < sym["section"] < len(obj.sections) and obj.content(sym["section"]) and image.name == "code.bin":
                # data of this object (a string, a constant): the game's bytes there must be the same
                data = obj.content(sym["section"])[sym["value"] + mine:][:16]
                if image.bytes(theirs, len(data)) != data:
                    out.append((off, "diff", f"data of {name} differs from the game's at {theirs:08X}"))
            else:
                out.append((off, "open", f"address of {name}: the game's is {theirs:08X}"))
        else:
            out.append((off, "open", f"relocation {kind} to {name}"))
    return out


def size_check(image, addr, size, main=None):
    """the function must be the game's whole function: from its start to the next one's
    (functions.csv; in another version, the same two starts through the map). without the
    table nothing is checked. main: the main version's address of the function."""
    table = functable.table()
    if not table:
        return []
    module = image.name[:-4] if image.name.endswith(".cro") else image.name
    main = addr if main is None else main
    entry = table.get(module, {}).get(main)
    if entry is None:
        return [(0, "open", f"{main:08X} is not a function start of functions.csv (extra_starts.txt?)")]
    end, body = image.translate(entry[0]), entry[1]
    body += (end - addr) - (entry[0] - main)
    if size == end - addr:
        return []
    if body <= size < end - addr:
        return [(size, "open", f"ours ends at {addr + size:08X}, the next known function starts at {end:08X}: "
                               f"a function Ghidra misses (extra_starts.txt), or ours is short")]
    return [(min(size, end - addr), "diff", f"size: the game's function is {end - addr} bytes ({body} of instructions), ours {size}")]


def mode_check(image, main, thumb):
    """ours must be the game's kind of code (functions.csv's mode: arm or thumb)."""
    module = image.name[:-4] if image.name.endswith(".cro") else image.name
    entry = functable.table().get(module, {}).get(main)
    if entry is None or entry[2] == ("thumb" if thumb else "arm"):
        return []
    return [(0, "diff", f"the game's function is {entry[2]} code, ours {'thumb' if thumb else 'arm'} (--thumb or --arm)")]


def compile_source(source, cc, flags, out):
    exe, env = config.compiler(cc)
    if not exe.exists():
        raise SystemExit(f"compiler {cc} not found at {exe} (see README, Toolchain)")
    source = Path(source)
    lang = C_FLAGS if source.suffix == ".c" else CPP_FLAGS
    cmd = [str(exe), "-c", *lang.split(), *flags.split(), config.version_define(), "-I", str(config.ROOT / "include"),
           "-I", str(source.parent), str(source), "-o", str(out)]
    r = subprocess.run(cmd, env=env, capture_output=True, text=True)
    return r.returncode == 0 and Path(out).exists(), (r.stdout + r.stderr).strip()


def next_start(image, addr):
    """the next address after addr that a bl in the text goes to (a rough function table)."""
    if not hasattr(image, "starts"):
        words = struct.unpack_from(f"<{image.text_size // 4}I", image.data, image.text - image.base)
        starts = set()
        for i, w in enumerate(words):
            if (w & 0x0F000000) == 0x0B000000 and (w >> 28) != 0xF:
                t = branch_target(w, image.text + i * 4)
                if image.in_text(t):
                    starts.add(t)
        image.starts = sorted(starts)
    i = bisect.bisect_right(image.starts, addr)
    return image.starts[i] if i < len(image.starts) else None


def disasm(code, addr, thumb=False):
    try:
        from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_THUMB
    except ImportError:
        return {}
    md = Cs(CS_ARCH_ARM, CS_MODE_THUMB if thumb else CS_MODE_ARM)
    return {i.address - addr: f"{i.mnemonic} {i.op_str}" for i in md.disasm(code, addr)}


last_hacks = []


def check(source, where, sym=None, cc=None, flags=None, quiet=False, keep=None, lint=True):
    """(status, differing words, open relocations, size): status is match, hack (a match by
    a trick, see honest.py; the tricks are left in last_hacks), match?, differ, error."""
    global last_hacks
    last_hacks = honest.reasons(source, "", cc, flags) if lint else []
    image, addr, main = locate(where)
    cc, flags = cc or config.DEFAULT_CC, flags or config.DEFAULT_FLAGS
    with tempfile.TemporaryDirectory() as tmp:
        out = Path(keep) if keep else Path(tmp) / "unit.o"
        ok, log = compile_source(source, cc, flags, out)
        if not ok:
            if not quiet:
                print(log)
            return "error", 0, 0, 0
        if lint:
            last_hacks = honest.reasons(source, log, cc, flags)
        obj = Object(out)
        func = obj.function(sym, f"{main:08X}")
        code, relocs, thumb = obj.body(func)
    found = mode_check(image, main, thumb) + (compare_thumb if thumb else compare)(image, addr, code, relocs, obj) \
        + size_check(image, addr, len(code), main)
    diffs = [f for f in found if f[1] == "diff"]
    opens = [f for f in found if f[1] == "open"]
    status = "differ" if diffs else "match?" if opens else "hack" if last_hacks else "match"
    if not quiet:
        there = "" if config.VERSION == config.MAIN else f" ({config.VERSION}: {addr:08X}, {image.status(main) or 'not in the map'})"
        print(f"{func['name']} at {where}{there}: {len(code)} bytes, {cc}, {flags}")
        if diffs:
            mine, theirs = disasm(code, addr, thumb), disasm(image.bytes(addr, len(code)), addr, thumb)
            print(f"  {len(diffs)} of {len(code) // (2 if thumb else 4)} {'half words' if thumb else 'words'} differ (the game's / ours):")
            for off, _, text in diffs[:40]:
                print(f"  +{off:04X}  {text}")
                if off in theirs or off in mine:
                    print(f"         {theirs.get(off, '?'):40} / {mine.get(off, '?')}")
        for off, _, text in opens[:20]:
            print(f"  +{off:04X}  unverified: {text}")
        if last_hacks:
            print(f"  tricks in the source (tools/honest.py): {', '.join(last_hacks)}")
        print(f"RESULT: {status.upper()}")
    return status, len(diffs), len(opens), len(code)


# results of check_many kept in build/<version>/check_cache/, by what they depend on: the
# source and every header it includes, the compiler and flags, the version, the functions'
# entries in the table, and what the judge reads (this file, honest.py, config.py, the flag
# sets, the allowed tricks, symbols.txt, the vtables and the destructors' names). a tool that
# checks the same candidate again gets its result without a compile.
_INCLUDE = re.compile(r'^\s*#\s*include\s*"([^"]+)"', re.M)
_stamp = None
_header_keys = {}


def judge_stamp():
    global _stamp
    if _stamp is None:
        import hashlib
        h = hashlib.sha1()
        tools = Path(__file__).resolve().parent
        for f in (tools / "match.py", tools / "honest.py", tools / "config.py",
                  config.CONFIG / "flagsets.txt", config.CONFIG / "honest_allow.txt", config.CONFIG / "symbols.txt",
                  config.CONFIG / "vtables.csv", config.ROOT / "config" / config.VERSION / "map.csv"):
            h.update(f.read_bytes() if f.exists() else b"-")
        path = config.CONFIG / "functions.csv"
        if path.exists():                       # the destructors' names (destructor_address)
            import csv
            with open(path, encoding="utf-8", newline="") as f:
                for r in csv.DictReader(f):
                    if r["method"].startswith("~"):
                        h.update(f"{r['module']}:{r['start']}:{r['class']}|".encode())
        _stamp = h.hexdigest()
    return _stamp


_found_includes = {}


def _include(inc, folder, extra):
    """where an #include "inc" of a file in folder lands (its folder, the -I folders given,
    then include/), as a normalized path string, or None. remembered: on Windows a stat or a
    resolve costs more than the hashing."""
    key = (inc, folder, extra)
    if key not in _found_includes:
        _found_includes[key] = None
        for base in (folder, *extra, str(config.ROOT / "include")):
            candidate = os.path.join(base, inc)
            if os.path.isfile(candidate):
                _found_includes[key] = os.path.normcase(os.path.normpath(os.path.abspath(candidate)))
                break
    return _found_includes[key]


def text_key(text, folder, extra=()):
    """header_key of a file's text given in memory, as if it were in folder."""
    import hashlib
    h = hashlib.sha1(text.encode("utf-8"))
    for inc in _INCLUDE.findall(text):
        found = _include(inc, folder, extra)
        if found:
            h.update(header_key(found, ("<text>",), extra).encode())
    return h.hexdigest()


def header_key(path, stack=(), extra=()):
    """a hash of a file and of every header it includes (path: a normalized string). a header's
    hash is remembered for the run; the file a tool checks is read each time."""
    key = (path, extra)
    if key in _header_keys:
        return _header_keys[key]
    if path in stack:
        return "-"
    import hashlib
    try:
        with open(path, "rb") as f:
            data = f.read()
    except OSError:
        return "-"
    h = hashlib.sha1(data)
    folder = os.path.dirname(path)
    for inc in _INCLUDE.findall(data.decode("utf-8", errors="replace")):
        found = _include(inc, folder, extra)
        if found:
            h.update(header_key(found, stack + (path,), extra).encode())
    if stack:                           # a header: the same for the whole run
        _header_keys[key] = h.hexdigest()
    return h.hexdigest()


def cache_key(source, items, cc, flags, lint, text=None):
    """the key of a check's result. text: the source's text when it is not on disk yet."""
    import hashlib
    extra = tuple(os.path.normcase(os.path.abspath(p)) for p in re.findall(r"-I\s*(\S+)", flags))
    h = hashlib.sha1(judge_stamp().encode())
    h.update(f"{cc}|{flags}|{config.version_define()}|{lint}|".encode())
    path = os.path.normcase(os.path.abspath(str(source)))
    if text is None:
        h.update(header_key(path, (), extra).encode())
    else:
        h.update(text_key(text, os.path.dirname(path), extra).encode())
    table = functable.table()
    for where, sym in items:
        module, _, addr = where.rpartition(":")
        try:
            entry = table.get(module or "code.bin", {}).get(int(addr, 16))
        except ValueError:
            entry = None
        h.update(f"{where}|{sym}|{entry!r}|".encode())
    return h.hexdigest()


_db = None


def cache_db():
    """the results kept, one SQLite file (build/<version>/check_cache.sqlite): one open for a
    whole run instead of one per result, and the processes of check_parallel share it."""
    global _db
    if _db is None:
        import sqlite3
        config.BUILD.mkdir(parents=True, exist_ok=True)
        _db = sqlite3.connect(str(config.BUILD / "check_cache.sqlite"), timeout=60)
        _db.execute("PRAGMA journal_mode=WAL")
        _db.execute("CREATE TABLE IF NOT EXISTS kept (key TEXT PRIMARY KEY, value TEXT)")
    return _db


def cache_get(key):
    import json
    row = cache_db().execute("SELECT value FROM kept WHERE key = ?", (key,)).fetchone()
    if not row:
        return None
    data = json.loads(row[0])
    return [tuple(r) for r in data["results"]], data["hacks"]


def cache_put(key, results, hacks):
    import json
    db = cache_db()
    db.execute("INSERT OR REPLACE INTO kept VALUES (?, ?)", (key, json.dumps({"results": results, "hacks": hacks})))
    db.commit()


def check_many(source, items, cc=None, flags=None, lint=True):
    """one compile for many functions of a source: [(status, differing words, open
    relocations, size)] for each (where, symbol). the source's tricks are left in last_hacks.
    kept in build/<version>/check_cache.sqlite (see judge_stamp)."""
    global last_hacks
    cc, flags = cc or config.DEFAULT_CC, flags or config.DEFAULT_FLAGS
    key = cache_key(source, items, cc, flags, lint)
    got = cache_get(key)
    if got is not None:
        results, last_hacks = got
        return results
    results = check_many_compiled(source, items, cc, flags, lint)
    cache_put(key, results, last_hacks)
    return results


def _check_job(job):
    """a worker's check: compiled, not kept (the main process keeps them all at once)."""
    source, items, cc, flags, lint, key = job
    cc, flags = cc or config.DEFAULT_CC, flags or config.DEFAULT_FLAGS
    results = check_many_compiled(source, items, cc, flags, lint)
    return results, list(last_hacks)


def cache_put_many(rows):
    """[(key, results, tricks)] kept in one transaction."""
    import json
    db = cache_db()
    db.executemany("INSERT OR REPLACE INTO kept VALUES (?, ?)",
                   [(k, json.dumps({"results": r, "hacks": h})) for k, r, h in rows])
    db.commit()


def check_parallel(jobs, cc=None, flags=None, lint=True, workers=None):
    """check_many on many sources at once: jobs [(source, items)] or [(source, items, text)]
    -> [(results, tricks)], in order. with a text, the file is written only when its result
    is not kept already. the sources must be different files."""
    out, todo = [None] * len(jobs), []
    cc_, flags_ = cc or config.DEFAULT_CC, flags or config.DEFAULT_FLAGS
    prepared = []
    for n, job in enumerate(jobs):                      # what the cache has, without a process
        src, items = str(job[0]), list(job[1])
        text = job[2] if len(job) > 2 else None
        key = cache_key(src, items, cc_, flags_, lint, text)
        got = cache_get(key)
        if got is not None:
            out[n] = got
            continue
        if text is not None:
            Path(src).write_text(text, encoding="utf-8", newline="\n")
        prepared.append((src, items, cc, flags, lint, key))
        todo.append(n)
    workers = workers or max(1, min(len(todo), (os.cpu_count() or 4) - 2))
    if workers <= 1 or len(todo) <= 1:
        for n, job in zip(todo, prepared):
            out[n] = _check_job(job)
    else:
        from concurrent.futures import ProcessPoolExecutor
        with ProcessPoolExecutor(max_workers=workers) as pool:
            for n, result in zip(todo, pool.map(_check_job, prepared, chunksize=1)):
                out[n] = result
    cache_put_many([(job[5], out[n][0], out[n][1]) for n, job in zip(todo, prepared)])
    return out


def check_many_compiled(source, items, cc, flags, lint=True):
    """check_many without the cache."""
    global last_hacks
    last_hacks = []
    with tempfile.TemporaryDirectory() as tmp:
        out = Path(tmp) / "unit.o"
        ok, log = compile_source(source, cc, flags, out)
        if not ok:
            last_hacks = [log.splitlines()[0][:200] if log else "compile error"]
            return [("error", 0, 0, 0)] * len(items)
        if lint:
            last_hacks = honest.reasons(source, log, cc, flags)
        obj = Object(out)
    funcs = obj.functions()
    by_name = {}
    for f in funcs:
        by_name.setdefault(f["name"], f)
    results = []
    for where, sym in items:
        image, addr, main = locate(where)
        func = (by_name.get(sym) or next((f for f in funcs if sym in f["name"]), None)) if sym else None
        if func is None:
            results.append(("error", 0, 0, 0))
            continue
        code, relocs, thumb = obj.body(func)
        found = mode_check(image, main, thumb) + (compare_thumb if thumb else compare)(image, addr, code, relocs, obj) \
            + size_check(image, addr, len(code), main)
        diffs = sum(1 for f in found if f[1] == "diff")
        opens = len(found) - diffs
        results.append(("differ" if diffs else "match?" if opens else "hack" if last_hacks else "match", diffs, opens, len(code)))
    return results


def show(where, words):
    """the game's code there: by default the whole function, with what each pool word and
    each call is once the module is loaded (the imported name, or the address it points to)."""
    image, addr, main = locate(where)
    module = image.name[:-4] if image.name.endswith(".cro") else image.name
    entry = functable.table().get(module, {}).get(main)
    thumb = entry is not None and entry[2] == "thumb"
    if entry is not None:
        entry = (image.translate(entry[0]), entry[1] + image.translate(entry[0]) - addr - (entry[0] - main)) + tuple(entry[2:])
    if config.VERSION != config.MAIN:
        print(f"{config.VERSION}: {main:08X} is {addr:08X} here ({image.status(main) or 'not in the map'})")
    if words is None:
        words = (entry[0] - addr + 3) // 4 if entry else 32
    body = entry[1] if entry else words * 4
    code = image.bytes(addr, words * 4)
    text = disasm(code, addr, thumb)
    if thumb:
        # half words; a word of the pool is shown with what the loader writes there, like ARM's
        off = 0
        while off < len(code):
            h, = struct.unpack_from("<H", code, off)
            loaded = image.reloc(addr + off) if (addr + off) % 4 == 0 else None
            if loaded and off + 4 <= len(code):
                w, = struct.unpack_from("<I", code, off)
                print(f"{addr + off:08X}  {w:08X}  -> {loaded[1]}")
                off += 4
                continue
            note = text.get(off, "") if off < body else ("pool" if off >= body else "")
            if note.startswith(("bl ", "blx ")) and off + 4 <= len(code):
                h2, = struct.unpack_from("<H", code, off + 2)
                target, _ = thumb_call_target(h, h2, addr + off)
                stub = image.reloc(target + 4) if image.name != "code.bin" and image.in_code(target) else None
                if stub and image.word(target) == 0xE51FF004 and stub[0] == "name":
                    note += f"   ; {stub[1][0]}"
            print(f"{addr + off:08X}  {h:04X}      {note}")
            off += 2
        return
    for off in range(0, len(code), 4):
        w, = struct.unpack_from("<I", code, off)
        note = text.get(off, "") if off < body else ""
        loaded = image.reloc(addr + off)
        if loaded:
            note = f"-> {loaded[1]:08X}" if loaded[0] == "here" else f"-> {loaded[1][0]}" + (f"+{loaded[1][1]:#x}" if loaded[1][1] else "") \
                if loaded[0] == "name" else f"-> {loaded[1]}"
        elif off >= body:
            raw = code[off:off + 4]
            note = "pool " + (repr(raw.rstrip(b"\0").decode("ascii")) if all(32 <= c < 127 or c == 0 for c in raw) and raw.strip(b"\0") else "")
        elif (w & 0x0E000000) == 0x0A000000 and image.name != "code.bin":
            target = branch_target(w, addr + off)
            stub = image.reloc(target + 4) if image.in_code(target) and image.word(target) == 0xE51FF004 else None
            if stub and stub[0] == "name":
                note += f"   ; {stub[1][0]}"
        print(f"{addr + off:08X}  {w:08X}  {note}")


def sweep(source, where, sym):
    ccs = config.compilers()
    if not ccs:
        raise SystemExit("no compiler found (see README, Toolchain)")
    rows = []
    for cc in ccs:
        for flags in FLAG_SETS:
            status, diffs, opens, size = check(source, where, sym, cc, flags, quiet=True, lint=False)
            rows.append((status != "match", status != "match?", diffs, cc, flags, status, size))
            print(f"{status:7} {diffs:4} words differ  {size:5} bytes  {cc:10} {flags}", flush=True)
    rows.sort()
    print("\nbest:", rows[0][5], rows[0][3], rows[0][4])


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("show")
    s.add_argument("where")
    s.add_argument("words", nargs="?", type=int)
    for name in ("check", "sweep"):
        s = sub.add_parser(name)
        s.add_argument("source")
        s.add_argument("where")
        s.add_argument("--sym")
        if name == "check":
            s.add_argument("--cc")
            s.add_argument("--flags")
            s.add_argument("--keep", help="write the object here")
    a = p.parse_args()
    if a.cmd == "show":
        show(a.where, a.words)
    elif a.cmd == "check":
        status = check(a.source, a.where, a.sym, a.cc, a.flags, keep=a.keep)[0]
        sys.exit(0 if status == "match" else 1)
    else:
        sweep(a.source, a.where, a.sym)


if __name__ == "__main__":
    main()
