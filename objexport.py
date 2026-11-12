"""objects for objdiff: each source's compiled object (base) and the game's functions it names (target).

    python -I tools/objexport.py [src/... (files or folders)] [--jobs 8] [--report]

objdiff (github.com/encounter/objdiff) compares an object with an object, function by function,
by symbol name. the decomp's judge is tools/match.py, which compares with the game itself; this
gives people objdiff's view of the same thing, and its progress report.

for every source with `//!` lines: the source is compiled (the project's compiler and flags) to
build/<version>/objdiff/base/<source>.o, and build/<version>/objdiff/target/<source>.o is
written: each function a `//!` line names, with the game's bytes, under the symbol the base
object gives it, ARM or Thumb mapping symbols, and the relocations the linker resolved in the
game put back: a call or branch out of the function, a word of the literal pool that holds an
address (code.bin), a word the module loader fills (a module), a call through an import stub
to the imported name. a relocation's symbol is the base object's name for the same address when
there is one, else the project's names (an export's, symbols.txt's, sub_/f_/data_<address>).
calls the linker made NOPs, and Thumb code other than its calls, stay as they are.
objdiff.json at the project's root lists the units. the objects hold game bytes: build/ only.
"""
import argparse
import json
import os
import re
import shutil
import struct
import subprocess
import sys
import tempfile
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import config
import functable
import match

R_ARM_ABS32, R_ARM_CALL, R_ARM_JUMP24, R_ARM_THM_CALL = 2, 28, 29, 10
MARK = re.compile(r"^[ \t]*//![ \t]*(\S+)[ \t]+(\S+)", re.M)


def our_name(image, addr, code):
    """the project's name for an address of a program."""
    module = image.name[:-4] if image.name.endswith(".cro") else image.name
    if module == "code.bin":
        return f"{'sub' if code else 'data'}_{addr:08X}"
    return f"{'f' if code else 'data'}_{module}_{addr:08X}"


class Writer:
    """an ELF32 little-endian ARM relocatable object with a section per function, named as
    armcc names them with --split_sections (i.<symbol>), each with its .rel section."""

    def __init__(self):
        self.funcs = []       # [name, bytearray, thumb, [(offset, type, symbol)], [(mapping name, offset)]]
        self.undefined = []   # names, in order

    def function(self, name, data, thumb, size=None, section=None):
        # size: the symbol's, its instructions without the literal pool after them, as armcc's;
        # section: the base object's section of the same symbol (a D1 lives in its D2's section)
        self.funcs.append([name, bytearray(data), thumb, [], [("$t" if thumb else "$a", 0)], size or len(data),
                           section or "i." + name])
        return 0

    @property
    def text(self):
        return self.funcs[-1][1]

    def data_mark(self, at):
        self.funcs[-1][4].append(("$d", at))

    def reloc(self, offset, kind, name):
        if name not in self.undefined and name not in {f[0] for f in self.funcs}:
            self.undefined.append(name)
        self.funcs[-1][3].append((offset, kind, name))

    def bytes(self):
        strtab, shstr = bytearray(b"\0"), bytearray(b"\0")

        def string(table, s):
            at = len(table)
            table.extend(s.encode("latin1") + b"\0")
            return at
        # sections: 0 null, then per function its code and its .rel, then .symtab .strtab .shstrtab
        code_index = {f[0]: 1 + 2 * k for k, f in enumerate(self.funcs)}
        n_sections = 1 + 2 * len(self.funcs) + 3
        symtab_index = n_sections - 3
        symbols = [b"\0" * 16]
        for f in self.funcs:
            for mark, at in f[4]:
                symbols.append(struct.pack("<IIIBBH", string(strtab, mark), at, 0, 0, 0, code_index[f[0]]))
        first_global = len(symbols)
        index = {}
        for f in self.funcs:
            index[f[0]] = len(symbols)
            symbols.append(struct.pack("<IIIBBH", string(strtab, f[0]), 1 if f[2] else 0, f[5], (1 << 4) | 2, 0,
                                       code_index[f[0]]))
        for name in self.undefined:
            index[name] = len(symbols)
            symbols.append(struct.pack("<IIIBBH", string(strtab, name), 0, 0, (1 << 4) | 0, 0, 0))
        blobs, specs = [], []
        for f in self.funcs:
            blobs.append(bytes(f[1]))
            specs.append((string(shstr, f[6]), 1, 6, 0, 0, 4, 0))
            blobs.append(b"".join(struct.pack("<II", off, (index[name] << 8) | kind) for off, kind, name in f[3]))
            specs.append((string(shstr, ".rel" + f[6]), 9, 0, symtab_index, code_index[f[0]], 4, 8))
        blobs.append(b"".join(symbols))
        specs.append((string(shstr, ".symtab"), 2, 0, symtab_index + 1, first_global, 4, 16))
        blobs.append(bytes(strtab))
        specs.append((string(shstr, ".strtab"), 3, 0, 0, 0, 1, 0))
        name_shstrtab = string(shstr, ".shstrtab")
        blobs.append(bytes(shstr))
        specs.append((name_shstrtab, 3, 0, 0, 0, 1, 0))
        body, offsets = bytearray(), []
        for blob in blobs:
            while (52 + len(body)) % 4:
                body += b"\0"
            offsets.append(52 + len(body))
            body += blob
        while (52 + len(body)) % 4:
            body += b"\0"
        shoff = 52 + len(body)
        header = b"\x7fELF" + bytes([1, 1, 1, 0]) + b"\0" * 8
        header += struct.pack("<HHIIIIIHHHHHH", 1, 40, 1, 0, 0, shoff, 0x05000000, 52, 0, 0, 40, n_sections, n_sections - 1)
        sections = [struct.pack("<10I", *([0] * 10))]
        for (name, kind, flags, link, info, align, entsize), off, blob in zip(specs, offsets, blobs):
            sections.append(struct.pack("<10I", name, kind, flags, 0, off, len(blob), link, info, align, entsize))
        return header + bytes(body) + b"".join(sections)


def pool_words(image, start, end):
    """the words of a function's literal pool: what its pc-relative loads read."""
    out = set()
    for at in range(start, end, 4):
        w = image.word(at)
        if (w & 0x0F7F0000) == 0x051F0000:
            off = w & 0xFFF
            t = at + 8 + (off if w & 0x00800000 else -off)
            if start <= t < end:
                out.add(t)
        elif (w & 0x0F3F0F00) in (0x0D1F0A00, 0x0D1F0B00):
            off = (w & 0xFF) * 4
            t = at + 8 + (off if w & 0x00800000 else -off)
            if start <= t < end:
                out |= {t, t + 4} if (w & 0x0F00) == 0x0B00 else {t}
    return out


def export_function(writer, image, where, symbol, names, section=None):
    """the game's function at where into the writer, under symbol, its relocations put back."""
    _, addr, main = match.locate(where)
    module = image.name[:-4] if image.name.endswith(".cro") else image.name
    entry = functable.table().get(module, {}).get(main)
    if entry is None:
        return False
    end = image.translate(entry[0])
    thumb = entry[2] == "thumb"
    data = bytearray(image.bytes(addr, end - addr))
    pool = pool_words(image, addr, end) if not thumb else set()
    size = (min(pool) - addr) if pool else len(data)
    base = writer.function(symbol, bytes(data), thumb, size, section)    # 0: each function is its own section

    def name(target, code=True):
        if target in names:
            return names[target]
        if image.name == "code.bin":
            sym = match.symbol_name(target) if hasattr(match, "symbol_name") else None
            if sym:
                return sym
        return our_name(image, target, code)

    if thumb:
        for off in range(0, len(data) - 2, 2):
            h1, h2 = struct.unpack_from("<HH", data, off)
            if (h1 >> 11) == 0x1E and (h2 >> 11) in (0x1F, 0x1D):
                target, _ = match.thumb_call_target(h1, h2, addr + off)
                if not addr <= target < end:
                    writer.reloc(base + off, R_ARM_THM_CALL, name(target))
        return True
    pool = pool_words(image, addr, end)
    if pool:
        writer.data_mark(base + min(pool) - addr)
    for at in range(addr, end, 4):
        w = image.word(at)
        off = at - addr
        if at in pool:
            if image.name != "code.bin":
                loaded = image.reloc(at)
                if loaded is None:
                    continue
                if loaded[0] == "here":
                    writer.reloc(base + off, R_ARM_ABS32, name(loaded[1], image.in_code(loaded[1])))
                    struct.pack_into("<I", writer.text, base + off, 0)
                elif loaded[0] == "name":
                    writer.reloc(base + off, R_ARM_ABS32, loaded[1][0])
                    struct.pack_into("<I", writer.text, base + off, loaded[1][1] & 0xFFFFFFFF)
            elif image.in_text(w) or image.ro <= w < image.rw + image.rw_size + image.bss_size:
                near = [(w - a, n) for a, n in names.items() if 0 <= w - a <= 64]
                if near and w not in names:
                    addend, sym = min(near)                 # the base's symbol, the rest as the addend
                    writer.reloc(base + off, R_ARM_ABS32, sym)
                    struct.pack_into("<I", writer.text, base + off, addend)
                else:
                    writer.reloc(base + off, R_ARM_ABS32, name(w, image.in_text(w)))
                    struct.pack_into("<I", writer.text, base + off, 0)
            continue
        if (w & 0x0E000000) != 0x0A000000:
            continue
        target = match.branch_target(w, at)
        if addr <= target < end:
            continue
        link = (w & 0x01000000) or (w >> 28) == 0xF
        callee = name(target)
        if image.name != "code.bin" and image.in_code(target) and image.word(target) == 0xE51FF004:
            stub = image.reloc(target + 4)
            if stub and stub[0] == "name":
                callee = stub[1][0]                     # through an import stub: the imported name
        writer.reloc(base + off, R_ARM_CALL if link else R_ARM_JUMP24, callee)
        new = (0xEB000000 if (w >> 28) == 0xF else (w & 0xFF000000)) | 0x00FFFFFE
        struct.pack_into("<I", writer.text, base + off, new)
    return True


def export_source(source, out_base, out_target):
    """compile one source and write its two objects; the number of functions exported."""
    text = Path(source).read_text(encoding="utf-8", errors="replace")
    items = MARK.findall(text)
    if not items:
        return 0
    with tempfile.TemporaryDirectory() as tmp:
        obj_path = Path(tmp) / "unit.o"
        ok, _ = match.compile_source(source, config.DEFAULT_CC, config.DEFAULT_FLAGS, obj_path)
        if not ok:
            return 0
        out_base.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy(obj_path, out_base)
        obj = match.Object(obj_path)
    funcs = obj.functions()
    by_name = {f["name"]: f for f in funcs}
    writer = Writer()
    done = 0
    for where, sym in items:
        func = by_name.get(sym) or next((f for f in funcs if sym in f["name"]), None)
        if func is None:
            continue
        image, _, _ = match.locate(where)
        # the base object's names for the addresses its relocations reach
        names = {}
        _, relocs, _ = obj.body(func)
        for kind, s in relocs.values():
            if s["name"]:
                found = match.symbol_address(s["name"], image)
                if found:
                    names[found[1] & ~1] = s["name"]
        if any(f[6] == obj.sections[func["section"]]["name"] for f in writer.funcs):
            continue                                    # a second symbol of a section already written
        if export_function(writer, image, where, func["name"], names, obj.sections[func["section"]]["name"]):
            done += 1
    out_target.parent.mkdir(parents=True, exist_ok=True)
    out_target.write_bytes(writer.bytes())
    return done


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("paths", nargs="*")
    p.add_argument("--jobs", type=int, default=os.cpu_count() or 4)
    p.add_argument("--report", action="store_true", help="then objdiff-cli report generate")
    a = p.parse_args()
    roots = [Path(x) for x in a.paths] or [config.ROOT / "src"]
    sources = []
    for r in roots:
        sources += [r] if r.is_file() else sorted(list(r.rglob("*.cpp")) + list(r.rglob("*.c")))
    out = config.BUILD / "objdiff"
    units = []
    # every lazily read table now, not by two threads at once
    for module, funcs in functable.table().items():
        if funcs:
            first = min(funcs)
            image, _, _ = match.locate(f"0x{first:08X}" if module == "code.bin" else f"{module}:0x{first:08X}")
            match.symbol_address("_", image)
    match.vtable_address("_", "code.bin")

    def one(src):
        rel = Path(os.path.relpath(src.resolve(), config.ROOT)).with_suffix(".o")
        base, target = out / "base" / rel, out / "target" / rel
        n = export_source(src, base, target)
        return (rel, base, target, n)

    with ThreadPoolExecutor(a.jobs) as pool:
        for rel, base, target, n in pool.map(one, sources):
            if n:
                units.append({"name": rel.with_suffix("").as_posix(),
                              "target_path": os.path.relpath(target, config.ROOT).replace("\\", "/"),
                              "base_path": os.path.relpath(base, config.ROOT).replace("\\", "/"),
                              "metadata": {"progress_categories": [rel.parts[1] if len(rel.parts) > 1 else "main"]}})
    project = {"min_version": "2.0.0", "build_base": False, "build_target": False, "units": units}
    (config.ROOT / "objdiff.json").write_text(json.dumps(project, indent=1) + "\n", encoding="utf-8")
    print(f"{len(units)} units, {sum(1 for _ in units)} objects each side, in {out}; objdiff.json written")
    if a.report:
        cli = config.TOOLCHAIN / "objdiff" / "objdiff-cli-windows-x86_64.exe"
        r = subprocess.run([str(cli), "report", "generate", "-p", str(config.ROOT), "-o", str(out / "report.json")],
                           capture_output=True, text=True)
        print(r.stdout[-2000:], r.stderr[-2000:])


if __name__ == "__main__":
    main()
