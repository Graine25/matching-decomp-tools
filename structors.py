"""writes the virtual destructors from the classes' headers and what their code does before the
members and the bases are destroyed, each kept only if it matches.

  python -I tools/structors.py [--module NAME ...] [--dry]

a virtual destructor with an empty body (`X::~X() {}`) is all the compiler's: it stores the
vtable, destroys the members and the bases, and the deleting one (D0) frees the object. so a
class whose header declares its destructor (`virtual ~X();`, not defined there) is tried with
that one line, against the two slots of its primary vtable in each program (config/<version>/
vtables.csv: slot 0 the complete destructor D1, slot 1 the deleting one D0). what matches is
written to src/<program>/generated/dtors_NNN.cpp; what does not stays for a person or an agent
(its body is not empty, or the header lacks a member or a base): build/<version>/
structors_skipped.txt says which.

the body is read from the complete destructor (slot 0), up to the first call of a destructor
(a member's or a base's: the compiler's part, from the header) or the return. what it reads:
a call whose argument is `this`, a member or a global (a function of the class's program,
written as a call of its own name until the function has one, or an import, through
imports.py), a pointer member deleted (`delete this->m;`, the member typed in a header as a
pointer to a class with a virtual destructor), a member set to 0, and `if (this->m) { ... }`
around those. the vtables, the secondary ones too, are the compiler's. a body is read only
when a member's or a base's destructor is called after it, or the class has no base: when a
base's destructor was inlined, what comes before the return may be the base's body, and
writing it as the class's own would put it in the wrong class. anything else (a call the linker removed, other
arguments, branches of its own) leaves the body unread, and the empty body is tried.

a match proves more than the function: the class's bases and the members that have
destructors are as the game has them. only the classes of the libraries to decompile, and
only functions no other source matches yet (build/<version>/report.json, tools/progress.py).
"""
import argparse
import csv
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import config
import imports
import match
import slotargs
from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM
from capstone import arm as A

CHUNK = 40
md = Cs(CS_ARCH_ARM, CS_MODE_ARM)
md.detail = True


class Skip(Exception):
    pass


class Tables:
    def __init__(self):
        self.rows, self.bases, self.vtables = {}, {}, set()
        with open(config.CONFIG / "functions.csv", encoding="utf-8", newline="") as f:
            for r in csv.DictReader(f):
                self.rows[(r["module"], int(r["start"], 16))] = r
        with open(config.CONFIG / "classes.csv", encoding="utf-8", newline="") as f:
            for r in csv.DictReader(f):
                self.bases.setdefault(r["class"], [(b.rsplit(":", 1)[0], int(b.rsplit(":", 1)[1]))
                                                   for b in r["bases"].split() if ":" in b])
        with open(config.CONFIG / "vtables.csv", encoding="utf-8", newline="") as f:
            for r in csv.DictReader(f):
                self.vtables.add((r["module"], int(r["vtable"], 16)))
        self._members, self.images = {}, {}

    def image(self, module):
        if module not in self.images:
            self.images[module] = config.Image(module)
        return self.images[module]

    def own_members(self, cls):
        """{offset: (name, type)} of the `// +0x..` lines of a class's own header."""
        if cls not in self._members:
            found = {}
            path = header_of(cls)
            if path:
                text = path.read_text(encoding="utf-8", errors="replace")
                m = re.search(r"\b(?:class|struct)\s+" + re.escape(cls.split("::")[-1]) + r"\b[^;{]*\{", text)
                for line in (text[m.end():] if m else "").splitlines():
                    mm = re.match(r"\s*(?P<decl>[^;/(){}=]+?);\s*//\s*\+0x(?P<off>[0-9a-fA-F]+)", line)
                    if not mm or line.lstrip().startswith(("virtual", "static", "typedef", "enum")):
                        continue
                    dm = re.match(r"(?P<type>.*?[\s*&])(?P<name>[A-Za-z_]\w*)$", mm.group("decl").strip())
                    if dm and not dm.group("name").startswith("unk_"):
                        found[int(mm.group("off"), 16)] = (dm.group("name"), dm.group("type").strip())
            self._members[cls] = found
        return self._members[cls]

    def members(self, cls, base=0, depth=0):
        """{offset: (name, type)} of a class with its bases' members."""
        out = {}
        if depth > 8:
            return out
        for b, off in self.bases.get(cls, []):
            out.update(self.members(b, base + off, depth + 1))
        for off, v in self.own_members(cls).items():
            out[base + off] = v
        return out


_tables = None


def tables():
    global _tables
    if _tables is None:
        _tables = Tables()
    return _tables


def pool_value(image, at):
    """what a pool word holds once loaded: an address of the program, or the word."""
    if image.name == "code.bin":
        return image.word(at)
    loaded = image.reloc(at)
    if loaded and loaded[0] == "here":
        return loaded[1]
    if loaded:
        raise Skip("an imported address")
    return image.word(at)


def pointee(type_text):
    """the class a member's type points to (`::A::B *`), or None."""
    m = re.fullmatch(r"(?:const\s+)?::?([A-Za-z_]\w*(?:::[A-Za-z_]\w*)*)\s*\*", type_text.strip())
    return m.group(1) if m else None


def read_body(module, start, cls):
    """(statements, includes, declarations) of a destructor's body, or raises Skip."""
    t = tables()
    image = t.image(module)
    row = t.rows.get((module, start))
    if row is None or row["mode"] != "arm":
        raise Skip("not ARM")
    end = int(row["end"], 16)
    insns = list(md.disasm(image.bytes(start, end - start), start))
    members = t.members(cls)
    regs = {A.ARM_REG_R0: ("this", 0)}
    top, includes, decls = [], set(), []
    stmts = top
    block = None                        # an open `if (this->m)`: (its end, the member, its statements)
    checked = None                      # the member compared with 0 last
    ended_by_destructor = False

    def close():
        nonlocal stmts, block
        end_, off_, inner = block
        name_ = member(off_)[0]
        if len(inner) == 1 and inner[0] == f"delete this->{name_};":
            top.append(inner[0])        # delete tests for 0 itself
        else:
            top.append(f"if (this->{name_}) {{ " + " ".join(inner) + " }")
        stmts, block = top, None

    def argument(v):
        """the C++ of a value passed as an argument: this, a member, a global."""
        if v == ("this", 0):
            return "this", "void *"
        if v and v[0] == "field":
            name_, type_ = member(v[1])
            return (f"this->{name_}" if "*" in type_ else f"(void *)this->{name_}"), "void *"
        if v and v[0] == "const":
            if module == "code.bin" and not (image.ro <= v[1] < image.rw + image.rw_size + image.bss_size):
                raise Skip("a constant argument")
            glob = f"data_{v[1]:08X}" if module == "code.bin" else f"data_{module}_{v[1]:08X}"
            d = f'extern "C" u8 {glob};'
            if d not in decls:
                decls.append(d)
            return f"&{glob}", "void *"
        raise Skip("a call with another first argument")

    def member(off):
        if off not in members:
            raise Skip(f"no member at {off:#x}")
        return members[off]

    def ops(x):
        return x.operands

    for x in insns:
        if x.address >= end:
            break
        if block and x.address == block[0]:
            close()
        if block and x.address > block[0]:
            raise Skip("a branch into the block")
        o = ops(x)
        cond = x.cc not in (A.ARM_CC_AL, A.ARM_CC_INVALID)
        if x.id == A.ARM_INS_PUSH:
            continue
        if x.id == A.ARM_INS_POP:
            if any(op.reg == A.ARM_REG_PC for op in o):
                break
            continue
        if x.id == A.ARM_INS_BX and o and o[0].reg == A.ARM_REG_LR:
            break
        if x.id == A.ARM_INS_MOV and len(o) == 2 and o[0].type == A.ARM_OP_REG:
            if o[1].type == A.ARM_OP_REG:
                if o[0].reg == o[1].reg == A.ARM_REG_R0:
                    raise Skip("a call the linker removed")
                regs[o[0].reg] = regs.get(o[1].reg)
            elif o[1].type == A.ARM_OP_IMM:
                regs[o[0].reg] = ("const", o[1].imm & 0xFFFFFFFF)
            continue
        if x.id in (A.ARM_INS_ADD, A.ARM_INS_SUB) and len(o) == 3 and o[2].type == A.ARM_OP_IMM \
                and o[1].type == A.ARM_OP_REG and isinstance(regs.get(o[1].reg), tuple) and regs[o[1].reg][0] == "this":
            n = o[2].imm if x.id == A.ARM_INS_ADD else -o[2].imm
            regs[o[0].reg] = ("this", regs[o[1].reg][1] + n)
            continue
        if x.id == A.ARM_INS_ADD and len(o) == 3 and o[2].type == A.ARM_OP_IMM and o[1].type == A.ARM_OP_REG \
                and isinstance(regs.get(o[1].reg), tuple) and regs[o[1].reg][0] == "const":
            regs[o[0].reg] = ("const", (regs[o[1].reg][1] + o[2].imm) & 0xFFFFFFFF)
            continue
        if x.id == A.ARM_INS_STM and o and o[0].type == A.ARM_OP_REG:
            base = regs.get(o[0].reg)
            values = [regs.get(op.reg) for op in o[1:]]
            if base and base[0] == "this" and all(v and v[0] == "const" and (module, v[1]) in t.vtables for v in values) \
                    and not x.writeback:
                continue                # vtables: the compiler's
            raise Skip("a store of several words")
        if x.id == A.ARM_INS_LDR and len(o) == 2 and o[1].type == A.ARM_OP_MEM:
            mem = o[1].mem
            base = regs.get(mem.base)
            if mem.base == A.ARM_REG_PC:
                regs[o[0].reg] = ("const", pool_value(image, x.address + 8 + mem.disp))
            elif mem.index == 0 and base and base[0] == "this" and base[1] == 0 and not cond:
                regs[o[0].reg] = ("field", mem.disp)
            elif mem.index == 0 and base and base[0] == "field" and mem.disp == 0:
                regs[o[0].reg] = ("vptr", base[1])
            elif mem.index == 0 and base and base[0] == "vptr" and mem.disp == 4:
                regs[o[0].reg] = ("deleting", base[1])
            else:
                raise Skip("a load")
            continue
        if x.id == A.ARM_INS_CMP and len(o) == 2 and o[1].type == A.ARM_OP_IMM and o[1].imm == 0:
            v = regs.get(o[0].reg)
            if not v or v[0] != "field":
                raise Skip("a comparison")
            checked = v[1]
            continue
        if x.id == A.ARM_INS_B and cond:
            if checked is None or x.cc != A.ARM_CC_EQ or block or not o or o[0].type != A.ARM_OP_IMM \
                    or o[0].imm <= x.address:
                raise Skip("a branch")
            block = (o[0].imm, checked, [])
            stmts = block[2]
            continue
        if x.id == A.ARM_INS_BLX and o and o[0].type == A.ARM_OP_REG:
            v = regs.get(o[0].reg)
            if not v or v[0] != "deleting" or v[1] != checked or (cond and x.cc != A.ARM_CC_NE):
                raise Skip("a call through a pointer")
            name, type_text = member(v[1])
            target = pointee(type_text)
            if not target or not header_of(target) or not re.search(
                    r"virtual\s+~" + re.escape(target.split("::")[-1]) + r"\s*\(", header_of(target).read_text(encoding="utf-8", errors="replace")):
                raise Skip("a member deleted whose type is not a class with a virtual destructor")
            parts = target.split("::")
            includes.add("/".join(parts[:-1] + [parts[-1] + ".h"]))
            stmts.append(f"delete this->{name};")
            for r in (A.ARM_REG_R0, A.ARM_REG_R1, A.ARM_REG_R2, A.ARM_REG_R3, A.ARM_REG_R12):
                regs.pop(r, None)
            continue
        if x.id in (A.ARM_INS_STR,) and len(o) == 2 and o[1].type == A.ARM_OP_MEM:
            mem, v = o[1].mem, regs.get(o[0].reg)
            base = regs.get(mem.base)
            if mem.index or not base or base[0] != "this" or cond:
                raise Skip("a store")
            off = base[1] + mem.disp
            if v and v[0] == "const" and (module, v[1]) in t.vtables:
                continue                # a vtable: the compiler's
            if v and v[0] == "const" and v[1] == 0:
                stmts.append(f"this->{member(off)[0]} = 0;")
                continue
            raise Skip("a store")
        if x.id in (A.ARM_INS_BL, A.ARM_INS_B) and o and o[0].type == A.ARM_OP_IMM and not cond:
            target = o[0].imm
            callee = t.rows.get((module, target))
            stub = callee is not None and callee["kind"] == "stub"
            name = (callee or {}).get("name", "")
            if (callee and (callee["method"].startswith("~") or "::~" in name)):
                if block:
                    raise Skip("a destructor called in a block")
                ended_by_destructor = True
                break                   # a member's or a base's destructor: the compiler's part
            arg, _ = argument(regs.get(A.ARM_REG_R0))
            if stub:
                try:
                    imp = imports.resolve(image, target)
                    text = imp.call([arg])
                except imports.Unsupported as why:
                    raise Skip(f"an import: {why}")
                includes.update(imp.includes)
                decls += [d for d in imp.declarations() if not d.startswith("#include") and d not in decls]
                stmts.append(text + ";")
            else:
                if callee is None or callee["mode"] != "arm":
                    raise Skip("a call of something not in the table")
                got = slotargs.args_of(image, target, int(callee["end"], 16))
                if got is None or got[0] > 1 or got[1]:
                    raise Skip("a call with more arguments")
                own = f"sub_{target:08X}" if module == "code.bin" else f"f_{module}_{target:08X}"
                decl = f"void {own}(void *);"
                if decl not in decls:
                    decls.append(decl)
                stmts.append(f"{own}({arg});")
            if x.id == A.ARM_INS_B:
                if block:
                    raise Skip("a tail call in a block")
                break
            for r in (A.ARM_REG_R0, A.ARM_REG_R1, A.ARM_REG_R2, A.ARM_REG_R3, A.ARM_REG_R12):
                regs.pop(r, None)
            continue
        raise Skip(f"an instruction: {x.mnemonic}")
    if block:
        close()
    if top and not ended_by_destructor and t.bases.get(cls):
        # no base's destructor is called: it was inlined, and what was read may be its body
        raise Skip("the base's destructor is inlined here: the body may be the base's")
    return top, includes, decls
PLAIN = re.compile(r"[A-Za-z_]\w*(?:::[A-Za-z_]\w*)*")


def header_of(cls):
    """the header of a class that has one of its own (include/<ns>/<Class>.h), or None."""
    parts = cls.split("::")
    path = config.ROOT / "include" / Path(*parts[:-1], parts[-1] + ".h")
    return path if path.exists() else None


def declares_destructor(path, short):
    """whether a header declares the class's virtual destructor without defining it."""
    text = path.read_text(encoding="utf-8", errors="replace")
    return re.search(r"virtual\s+~" + re.escape(short) + r"\s*\(\s*(?:void\s*)?\)\s*;", text) is not None


def where_of(module, addr):
    return f"0x{addr:08X}" if module == "code.bin" else f"{module}:0x{addr:08X}"


def matched_elsewhere():
    """the functions that some source other than this tool's already matches."""
    path = config.BUILD / "report.json"
    if not path.exists():
        return set()
    out = set()
    for d in json.loads(path.read_text(encoding="utf-8")):
        if d["status"] == "match" and "/generated/dtors_" not in d["source"].replace("\\", "/"):
            out.add(d["where"])
    return out


def candidates(modules):
    """[(module, class, [(where, symbol)])] and the skipped [(where, reason)]."""
    lib = {}
    with open(config.CONFIG / "functions.csv", encoding="utf-8", newline="") as f:
        for r in csv.DictReader(f):
            lib[(r["module"], int(r["start"], 16))] = r["library"]
    slots = {}
    with open(config.CONFIG / "vtables.csv", encoding="utf-8", newline="") as f:
        for r in csv.DictReader(f):
            if r["top"] != "0" or r["slot"] not in ("0", "1"):
                continue
            target_module, _, addr = r["target"].rpartition(":")
            if target_module != r["module"] or not re.fullmatch(r"[0-9A-Fa-f]+", addr):
                continue
            slots.setdefault((r["module"], r["class"]), {}).setdefault(int(r["slot"]), int(addr, 16))
    done = matched_elsewhere()
    found, skipped = [], []
    for (module, cls), s in sorted(slots.items()):
        if modules and module not in modules:
            continue
        items = []
        for slot in (0, 1):
            if slot not in s or not config.own(lib.get((module, s[slot]), "?")):
                continue
            where = where_of(module, s[slot])
            if where in done:
                continue
            items.append((where, slot))
        if not items:
            continue
        reason = None
        if not PLAIN.fullmatch(cls):
            reason = "a template or anonymous class"
        elif header_of(cls) is None:
            reason = "no header of its own"
        elif not declares_destructor(header_of(cls), cls.split("::")[-1]):
            reason = "the header does not declare its destructor out of line"
        if reason:
            skipped += [(w, reason) for w, _ in items]
            continue
        mangled = "".join(f"{len(p)}{p}" for p in cls.split("::"))
        body = ([], set(), [])
        if 0 in s:
            try:
                body = read_body(module, s[0], cls)
            except Skip as why:
                body = ([], set(), [], str(why))
        found.append((module, cls, [(w, mangled + ("D1Ev" if slot == 0 else "D0Ev")) for w, slot in items], body))
    return found, skipped


def source(classes, note):
    lines = [f"// {note}", ""]
    includes, decls = set(), []
    for cls, _, body in classes:
        parts = cls.split("::")
        includes.add("/".join(parts[:-1] + [parts[-1] + ".h"]))
        includes |= body[1]
        decls += [d for d in body[2] if d not in decls]
    lines += [f'#include "{h}"' for h in sorted(includes)] + [""] + decls + ([""] if decls else [])
    for cls, items, body in classes:
        for where, sym in items:
            lines.append(f"//! {where} {sym}")
        head = f"{cls}::~{cls.split('::')[-1]}()"
        if body[0]:
            lines += [head + " {"] + [f"    {st}" for st in body[0]] + ["}"]
        else:
            lines.append(head + " {}")
        lines.append("")
    return "\n".join(lines)


def check(path, classes, note):
    """{where: status} for these classes, compiled together; a chunk that does not compile is
    split until each class is alone."""
    path.write_text(source(classes, note), encoding="utf-8", newline="\n")
    items = [it for _, its, _ in classes for it in its]
    results = match.check_many(path, items)
    if all(r[0] == "error" for r in results) and len(classes) > 1:
        half = len(classes) // 2
        out = check(path, classes[:half], note)
        out.update(check(path, classes[half:], note))
        return out
    return {where: r[0] for (where, _), r in zip(items, results)}


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--module", nargs="*")
    p.add_argument("--dry", action="store_true", help="only count the candidates")
    a = p.parse_args()                  # argparse stops on an unknown argument
    found, skipped = candidates(a.module)
    print(f"{len(found)} classes, {sum(len(i) for _, _, i, _ in found)} destructors to try; {len(skipped)} not", flush=True)
    if a.dry:
        return
    work = config.BUILD / "structors"
    work.mkdir(parents=True, exist_ok=True)
    read = sum(1 for *_, body in found if body[0])
    print(f"bodies read: {read}", flush=True)
    by_module = {}
    for module, cls, items, body in found:
        by_module.setdefault(module, []).append((cls, items, body))
    won = 0
    for module, classes in sorted(by_module.items()):
        status = {}
        for i in range(0, len(classes), CHUNK):
            chunk = classes[i:i + CHUNK]
            status.update(check(work / f"{module.replace('.', '_')}_{i // CHUNK:03}.cpp", chunk,
                                "candidates of tools/structors.py"))
        keep = []
        for cls, items, body in classes:
            good = [(w, s) for w, s in items if status.get(w) == "match"]
            unread = f"; its body: {body[3]}" if len(body) > 3 else ""
            skipped += [(w, f"does not match ({status.get(w, 'error')}){unread}") for w, s in items
                        if status.get(w) != "match"]
            if good:
                keep.append((cls, good, body))
        out = config.program_dir(module) / "generated"
        for old in out.glob("dtors_*.cpp"):
            old.unlink()
        for i in range(0, len(keep), CHUNK):
            out.mkdir(parents=True, exist_ok=True)
            (out / f"dtors_{i // CHUNK:03}.cpp").write_text(
                source(keep[i:i + CHUNK], "written by tools/structors.py: virtual destructors from the headers; each matches"),
                encoding="utf-8", newline="\n")
        won += sum(len(g) for _, g, _ in keep)
        print(f"{module}: {sum(len(g) for _, g, _ in keep)} of {sum(len(i) for _, i, _ in classes)}", flush=True)
    with open(config.BUILD / "structors_skipped.txt", "w", encoding="utf-8", newline="\n") as f:
        f.writelines(f"{where} {why}\n" for where, why in skipped)
    print(f"{won} destructors in src/<program>/generated/dtors_*.cpp; {len(skipped)} left "
          f"(build/{config.VERSION}/structors_skipped.txt)")


if __name__ == "__main__":
    main()
