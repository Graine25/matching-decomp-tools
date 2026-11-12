"""m2c's C for a function of the game, as a reference of what it does (like Hex-Rays' in the packets).

    python -I tools/local/m2cref.py <where>...            prints it
    python -I tools/local/m2cref.py --out DIR <where>...  one file each (DIR/<where>.c)
    python -I tools/local/m2cref.py --context <where>     prints the C context it gives m2c

m2c (github.com/matt-kempster/m2c, GPL-3.0) is run as an outside program: M2C names its m2c.py
(project.toml [paths] m2c, else ../resources/m2c/m2c.py). nothing of it is copied here. the
target is `ctr`, which only the local fork has (the 3DS: VFP, hard-float arguments); upstream m2c
is run with `arm` instead.

what m2c gets:
- the function's instructions as GNU assembly: branches inside it to labels, calls and tail
  calls to the project's names of their targets (an import stub's to the imported name), the
  words of the literal pool as `.word` of a symbol's name or a number, `add rX, pc, #n` as an
  `adr` of the address's name;
- a C context from the project's tables: a struct per class (its bases' members and its own,
  at their offsets: the names of its header's `// +0x..` lines, else fields.csv), its vtable as
  a struct of function pointers named after the slots, and prototypes for the function and its
  callees: a method's `this` typed by its class, the rest left to m2c (M2C_UNK, a type only the
  fork knows) unless a name gives the parameters.
what comes back has the C++ names put back: classes and functions qualified, `this->vtbl->f(this,
...)` as `this->f(...)`.

a reference, never a draft: AGENTS.md. the output stays in build/ (it is the game's code in
another form), like the rest of a packet.
"""
import csv
import os
import re
import subprocess
import sys
import tempfile
import threading
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import config
import functable
import match
import typecontext
from typecontext import (BUILTIN, SIZE, MEMBER, DEPTH, ident, tables, module_of, name_of, _dm, demangled,
                         head_of, qualifier_of, class_set, members_of, struct_text, slot_names, reads,
                         prototype, declarations)
from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM
from capstone import arm as A


md = Cs(CS_ARCH_ARM, CS_MODE_ARM)
md.detail = True

FALLBACKS = []                  # (where, error) of the functions m2c could not take the context for

def m2c_path():
    if os.environ.get("M2C"):
        return Path(os.environ["M2C"])
    if "m2c" in config.PATHS:
        return config.PATHS["m2c"]
    return config.ROOT.parent / "resources" / "m2c" / "m2c.py"

# ---------------------------------------------------------------- the project's tables

# ---------------------------------------------------------------- the assembly

def assembly(where):
    """(the GNU assembly of a function for m2c, its name, {identifier: display name},
    [(module, address) of what it calls])."""
    image, addr = match.parse_where(where)     # the main version: the tables are its
    main = addr
    module = module_of(image)
    entry = functable.table().get(module, {}).get(main)
    if entry is None or entry[2] != "arm":
        raise SystemExit(f"{where}: not an ARM function of the table")
    end = image.translate(entry[0])
    names = {}

    def named(target, code=True):
        n, display = name_of(image, target, code)
        if display:
            names[n] = display
        return n

    name = named(addr)
    insns = list(md.disasm(image.bytes(addr, end - addr), addr))
    pool, adr = set(), {}
    for i in insns:
        for op in i.operands:
            if op.type == A.ARM_OP_MEM and op.mem.base == A.ARM_REG_PC:
                pool.add(i.address + 8 + op.mem.disp)
        if (i.id in (A.ARM_INS_ADD, A.ARM_INS_SUB) and len(i.operands) == 3 and i.operands[1].type == A.ARM_OP_REG
                and i.operands[1].reg == A.ARM_REG_PC and i.operands[2].type == A.ARM_OP_IMM):
            imm = i.operands[2].imm
            adr[i.address] = i.address + 8 + (imm if i.id == A.ARM_INS_ADD else -imm)
    labels = set()
    for i in insns:
        if i.id == A.ARM_INS_B and i.operands and i.operands[0].type == A.ARM_OP_IMM:
            t = i.operands[0].imm
            if addr <= t < end:
                labels.add(t)
    stop = min({t for t in pool | set(adr.values()) if addr < t < end} | {end})
    lines = [".text", f"glabel {name}", f"{name}:"]
    calls = []
    for i in insns:
        if i.address >= stop:
            break
        if i.address in labels:
            lines.append(f".L{i.address:08X}:")
        text = f"{i.mnemonic} {i.op_str}".strip()
        if i.id in (A.ARM_INS_B, A.ARM_INS_BL, A.ARM_INS_BLX) and i.operands and i.operands[0].type == A.ARM_OP_IMM:
            t = i.operands[0].imm
            if addr <= t < end:
                target = f".L{t:08X}"
            else:
                target = named(t)
                calls.append((module, t, target))
            text = f"{i.mnemonic} {target}"
        elif i.address in adr:
            text = f"adr {i.op_str.split(',')[0]}, {named(adr[i.address], code=False)}"
        elif i.mnemonic.startswith("vmov") and "#" in i.op_str and len(i.operands) == 2 \
                and i.operands[1].type == A.ARM_OP_FP:
            # a float immediate, as its bits (m2c reads no float syntax)
            import struct
            bits = struct.unpack("<I", struct.pack("<f", i.operands[1].fp))[0]
            text = f"{i.mnemonic} {i.op_str.split(',')[0]}, #0x{bits:08X}"
        else:
            for op in i.operands:
                if op.type == A.ARM_OP_MEM and op.mem.base == A.ARM_REG_PC:
                    reg = i.op_str.split(",")[0]
                    text = f"{i.mnemonic} {reg}, .L{i.address + 8 + op.mem.disp:08X}"
        lines.append(f"\t{text}")
    for at in sorted(pool):
        if not addr <= at < end:
            continue
        w = image.word(at)
        value = f"0x{w:08X}"
        if image.name == "code.bin":
            if image.in_text(w):
                value = named(w)
            elif image.ro <= w < image.rw + image.rw_size + image.bss_size:
                value = named(w, code=False)
        else:
            loaded = image.reloc(at)
            if loaded and loaded[0] == "here":
                value = named(loaded[1], image.in_code(loaded[1]))
            elif loaded and loaded[0] == "name":
                value = loaded[1][0] + (f" + {loaded[1][1]}" if loaded[1][1] else "")
        lines += [f".L{at:08X}:", f"\t.word {value}"]
    mangled = [n for _, _, n in calls if n.startswith("_Z")]
    mangled += re.findall(r"\.word (_Z\w+)", "\n".join(lines))
    for n in mangled:
        full = demangled(n)
        if full != n:
            names[n] = head_of(full)
    return "\n".join(lines) + "\n", name, names, calls

# ---------------------------------------------------------------- the context

def context(where, asm=None):
    """the C context for a function, and {identifier: display name} for the output."""
    t = tables()
    image, addr = match.parse_where(where)     # the main version: the tables are its
    main = addr
    module = module_of(image)
    text, name, names, calls = asm or assembly(where)
    row = t.function(module, main) or {}
    wanted = class_set(row.get("class", ""), calls)
    out = ["typedef int M2C_UNK;"] + declarations(wanted)
    for c in sorted(wanted):
        names[ident(c)] = c
        if c in t.slots:
            names[f"{ident(c)}_vtbl"] = f"{c}::vtbl_t"
    protos = {}
    p = prototype(name, module, main, wanted, image)
    if p:
        protos[name] = p
    for m, a, n in calls:
        if n not in protos:
            if n in _dm:                 # an import: its name's signature, its code elsewhere
                p = prototype(n, m, a, wanted, None, _dm[n])
            else:
                p = prototype(n, m, a, wanted, image)
            if p:
                protos[n] = p
    out.extend(protos.values())
    return "\n".join(out) + "\n", names

# ---------------------------------------------------------------- m2c, and its output

def tidy(text, name, names):
    """C++ names back in m2c's output."""
    # a virtual call: obj->vtbl->f(obj, ...) -> obj->f(...)
    text = re.sub(r"(?P<obj>\b[A-Za-z_]\w*(?:->\w+)*)->vtbl->(?P<f>\w+)\((?P=obj)(?:, |(?=\)))",
                  r"\g<obj>->\g<f>(", text)
    text = re.sub(r"\(\*(?P<obj>[A-Za-z_]\w*)\)->unk(?P<off>[0-9A-F]+)\((?P=obj)(?:, |(?=\)))",
                  lambda m: f"{m.group('obj')}->vf{int(m.group('off'), 16) // 4}(", text)
    # the definition's own `...` (the parameters m2c was left to find)
    text = re.sub(r"^(.*\b" + re.escape(name) + r"\(.*?)(?:, \.\.\.|\.\.\.)\)( \{)?$",
                  lambda m: m.group(1).rstrip(", ") + ")" + (m.group(2) or ""), text, flags=re.M)
    for n in sorted(names, key=len, reverse=True):
        text = re.sub(r"\b" + re.escape(n) + r"\b", names[n], text)
    return text

def reference(where, with_context=True):
    asm = assembly(where)
    text, name, names, _ = asm
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "f.s"
        path.write_text(text, encoding="utf-8")
        cmd = [sys.executable, str(m2c_path()), "-t", "ctr", str(path)]
        if with_context:
            ctx, names = context(where, asm)
            (Path(tmp) / "ctx.c").write_text(ctx, encoding="utf-8")
            cmd[2:2] = ["--context", str(Path(tmp) / "ctx.c")]
        r = subprocess.run(cmd, capture_output=True, text=True)
        if r.returncode and with_context:
            FALLBACKS.append((where, (r.stderr or r.stdout).strip().splitlines()[-1:]))
            return reference(where, with_context=False)
    out = (r.stdout or r.stderr).strip()
    return tidy(out, name, names)

def main():
    args = sys.argv[1:]
    out = None
    if not args or args[0] in ("-h", "--help"):
        print(__doc__)
        return
    if args[:1] == ["--context"]:
        for where in args[1:]:
            print(context(where)[0])
        return
    if args[:1] == ["--out"]:
        out, args = Path(args[1]), args[2:]
    for where in args:
        text = reference(where)
        if out:
            out.mkdir(parents=True, exist_ok=True)
            (out / (where.replace(":", "_") + ".c")).write_text(text + "\n", encoding="utf-8")
        else:
            print(f"// {where}\n{text}\n")


if __name__ == "__main__":
    main()
