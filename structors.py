"""writes the virtual destructors and the default constructors from the classes' headers, with
what their code does besides building or destroying the bases and the members, each kept only if
it matches.

  python -I tools/structors.py [--module NAME ...] [--dry]

constructors: a class whose header declares `X();` (tools/headers.py does when ctors.csv has a
constructor of it that reads nothing but this) gets `X::X() { ... }` against each of those
constructors still open. the calls of the bases' and members' constructors come first and are
the compiler's (from the header); then the vtables; what follows is the body, read as for a
destructor, constants stored to members included. a store to a member of a base is never
written: it is the base's constructor, inlined, which the compiler makes from the base's header
(when that header does not define it inline, the source differs, as it should).

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

a base whose header defines virtual functions in the class (inline: its destructor, a slot
with a body) has them emitted again in every program that uses its vtable, by the file of a
class built on it. so in each program its copies (the base's vtable there) are named by `//!`
lines in the file of one derived class this tool writes: one that matches, or else one whose own
function does not match yet (written without its `//!`, and saying so). only the copies that
match are kept.

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
        return {off: v[:2] for off, v in self.owned_members(cls, base, depth).items()}

    def owned_members(self, cls, base=0, depth=0):
        """{offset: (name, type, the class that declares it)} of a class with its bases'."""
        out = {}
        if depth > 8:
            return out
        for b, off in self.bases.get(cls, []):
            out.update(self.owned_members(b, base + off, depth + 1))
        for off, (name, type_) in self.own_members(cls).items():
            out[base + off] = (name, type_, cls)
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


def read_body(module, start, cls, kind="dtor"):
    """(statements, includes, declarations) of a destructor's (kind 'dtor') or a default
    constructor's ('ctor') body, or raises Skip."""
    t = tables()
    owned = t.owned_members(cls)
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
        if x.id in (A.ARM_INS_STRB, A.ARM_INS_STRH) and len(o) == 2 and o[1].type == A.ARM_OP_MEM:
            mem, v = o[1].mem, regs.get(o[0].reg)
            base = regs.get(mem.base)
            if mem.index or not base or base[0] != "this" or cond or not v or v[0] != "const" \
                    or (v[1] != 0 and kind != "ctor"):
                raise Skip("a store")
            off = base[1] + mem.disp
            if off in owned and owned[off][2] != cls:
                if kind == "ctor":
                    continue            # the base's constructor, inlined: the compiler's, from its header
                raise Skip("a store to a base's member")
            width = 1 if x.id == A.ARM_INS_STRB else 2
            stmts.append(f"this->{member(off)[0]} = {v[1] & ((1 << (8 * width)) - 1)};")
            continue
        if x.id in (A.ARM_INS_STR,) and len(o) == 2 and o[1].type == A.ARM_OP_MEM:
            mem, v = o[1].mem, regs.get(o[0].reg)
            base = regs.get(mem.base)
            if mem.index or not base or base[0] != "this" or cond:
                raise Skip("a store")
            off = base[1] + mem.disp
            if v and v[0] == "const" and (module, v[1]) in t.vtables:
                continue                # a vtable: the compiler's
            if v and v[0] == "const" and (v[1] == 0 or kind == "ctor"):
                if off in owned and owned[off][2] != cls:
                    if kind == "ctor":
                        continue        # the base's constructor, inlined: the compiler's, from its header
                    raise Skip("a store to a base's member")
                value = v[1] if v[1] < 0x80000000 else v[1] - 0x100000000
                stmts.append(f"this->{member(off)[0]} = {value};")
                continue
            raise Skip("a store")
        if x.id in (A.ARM_INS_BL, A.ARM_INS_B) and o and o[0].type == A.ARM_OP_IMM and not cond:
            target = o[0].imm
            callee = t.rows.get((module, target))
            stub = callee is not None and callee["kind"] == "stub"
            name = (callee or {}).get("name", "")
            short_of = (callee or {}).get("class", "").rsplit("::", 1)[-1]
            is_ctor = callee is not None and (
                (callee["method"] and callee["method"] == short_of) or
                (name and "::" in name and name.rsplit("::", 1)[1] == name.rsplit("::", 1)[0].rsplit("::", 1)[-1]))
            if kind == "ctor" and is_ctor:
                if top or block:
                    raise Skip("a constructor called after the body")
                if (regs.get(A.ARM_REG_R0) or ("",))[0] != "this":
                    raise Skip("a constructor of something else")
                passed = regs.get(A.ARM_REG_R0)
                for r in (A.ARM_REG_R0, A.ARM_REG_R1, A.ARM_REG_R2, A.ARM_REG_R3, A.ARM_REG_R12):
                    regs.pop(r, None)
                regs[A.ARM_REG_R0] = passed        # a constructor returns its this
                continue
            if kind == "dtor" and (callee and (callee["method"].startswith("~") or "::~" in name)):
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
    if kind == "dtor" and top and not ended_by_destructor and t.bases.get(cls):
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


_elsewhere = None


def matched_elsewhere():
    """the functions that some source other than this tool's already matches (read once)."""
    global _elsewhere
    if _elsewhere is not None:
        return _elsewhere
    path = config.BUILD / "report.json"
    if not path.exists():
        _elsewhere = set()
        return _elsewhere
    out = set()
    for d in json.loads(path.read_text(encoding="utf-8")):
        if d["status"] == "match" and "/generated/dtors_" not in d["source"].replace("\\", "/"):
            out.add(d["where"])
    _elsewhere = out
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


def declares_default_constructor(path, short):
    return re.search(r"^\s+" + re.escape(short) + r"\s*\(\s*\)\s*;", path.read_text(encoding="utf-8", errors="replace"),
                     re.M) is not None


def ctor_candidates(modules):
    """[(module, class, [(where, symbol)], body, 'ctor')] of the open default constructors."""
    t = tables()
    done = matched_elsewhere()
    found, skipped = [], []
    with open(config.CONFIG / "ctors.csv", encoding="utf-8", newline="") as f:
        rows = [r for r in csv.DictReader(f) if r["kind"] == "ctor"]
    for r in rows:
        module, cls, addr = r["module"], r["class"], int(r["function"], 16)
        if modules and module not in modules:
            continue
        row = t.rows.get((module, addr))
        where = where_of(module, addr)
        if row is None or not config.own(row["library"]) or where in done or row["mode"] != "arm":
            continue
        got = slotargs.args_of(t.image(module), addr, int(row["end"], 16))
        if got is None or got[0] > 1 or got[1]:
            continue                    # not a default constructor
        if not PLAIN.fullmatch(cls) or header_of(cls) is None:
            skipped.append((where, "constructor: no header of its own"))
            continue
        if not declares_default_constructor(header_of(cls), cls.split("::")[-1]):
            skipped.append((where, "constructor: the header does not declare X()"))
            continue
        mangled = "".join(f"{len(p)}{p}" for p in cls.split("::"))
        try:
            body = read_body(module, addr, cls, "ctor")
        except Skip as why:
            body = ([], set(), [], str(why))
        found.append((module, cls, [(where, mangled + "C1Ev")], body, "ctor"))
    return found, skipped


def mangled_name(cls):
    return "".join(f"{len(p)}{p}" for p in cls.split("::"))


_inline = {}


def inline_virtuals(cls):
    """{slot: symbol} of the virtual functions a class's header defines in the class."""
    if cls not in _inline:
        out = {}
        path = header_of(cls) if PLAIN.fullmatch(cls) else None
        if path:
            text = path.read_text(encoding="utf-8", errors="replace")
            short, mangled = cls.split("::")[-1], mangled_name(cls)
            if re.search(r"virtual\s+~" + re.escape(short) + r"\s*\(\s*\)\s*\{", text):
                out[0], out[1] = mangled + "D1Ev", mangled + "D0Ev"
            for m in re.finditer(r"virtual\s+[^;{}()]*?\b(\w+)\s*\([^()]*\)[^;{}\n]*\{[^\n]*?//\s*slot\s+(\d+)", text):
                out[int(m.group(2))] = mangled + f"{len(m.group(1))}{m.group(1)}"
        _inline[cls] = out
    return _inline[cls]


def ancestors(cls, depth=0):
    """the classes a class is built on, all the way up (remembered)."""
    if depth == 0 and cls in _ancestors:
        return _ancestors[cls]
    out = []
    if depth > 8:
        return out
    for b, _ in tables().bases.get(cls, []):
        out.append(b)
        out += ancestors(b, depth + 1)
    if depth == 0:
        _ancestors[cls] = out
    return out


_vtable_rows = None
_ancestors = {}


def inline_copies(module, classes):
    """{base: [(where, symbol)]} of the inline virtual functions of the bases of these classes
    that this program has a copy of and no other source matches."""
    wanted = {b for cls, *_ in classes for b in ancestors(cls) if inline_virtuals(b)}
    if not wanted:
        return {}
    done = matched_elsewhere()
    out = {}
    global _vtable_rows
    if _vtable_rows is None:            # read once: {module: [rows of its primary vtables]}
        _vtable_rows = {}
        with open(config.CONFIG / "vtables.csv", encoding="utf-8", newline="") as f:
            for r in csv.DictReader(f):
                if r["top"] == "0":
                    _vtable_rows.setdefault(r["module"], []).append(r)
    if True:
        for r in _vtable_rows.get(module, []):
            if r["class"] not in wanted:
                continue
            sym = inline_virtuals(r["class"]).get(int(r["slot"]))
            target_module, _, addr = r["target"].rpartition(":")
            if not sym or target_module != module or not re.fullmatch(r"[0-9A-Fa-f]+", addr):
                continue
            where = where_of(module, int(addr, 16))
            if where not in done and (where, sym) not in out.get(r["class"], []):
                out.setdefault(r["class"], []).append((where, sym))
    return out


def source(classes, note):
    lines = [f"// {note}", ""]
    includes, decls = set(), []
    for cls, _, body, *_ in classes:
        parts = cls.split("::")
        includes.add("/".join(parts[:-1] + [parts[-1] + ".h"]))
        includes |= body[1]
        decls += [d for d in body[2] if d not in decls]
    lines += [f'#include "{h}"' for h in sorted(includes)] + [""] + decls + ([""] if decls else [])
    for cls, items, body, *rest in classes:
        kind = rest[:1]
        extra = rest[1] if len(rest) > 1 else []
        for base, copies in extra:
            lines.append(f"// {base}'s inline virtual functions, emitted here with its vtable:")
            lines += [f"//! {where} {sym}" for where, sym in copies]
        if not items:
            lines.append("// (this one does not match yet; it is here for the copies above)")
        for where, sym in items:
            lines.append(f"//! {where} {sym}")
        tilde = "" if kind and kind[0] == "ctor" else "~"
        head = f"{cls}::{tilde}{cls.split('::')[-1]}()"
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
    items = [it for _, its, *_ in classes for it in its]
    results = match.check_many(path, items)
    if all(r[0] == "error" for r in results) and len(classes) > 1:
        half = len(classes) // 2
        out = check(path, classes[:half], note)
        out.update(check(path, classes[half:], note))
        return out
    return {where: r[0] for (where, _), r in zip(items, results)}


def write_checked(out, name, entries, note, start=0):
    """writes entries to out/<name>_NNN.cpp, each file checked as written: a file where something
    does not match (two classes' headers that do not go together) is split until each entry is
    alone, and an entry that still does not match is left out. returns (files written, the
    entries kept)."""
    if not entries:
        return start, []
    path = out / f"{name}_{start:03}.cpp"
    path.write_text(source(entries, note), encoding="utf-8", newline="\n")
    items = [it for e in entries for it in e[1]] + [c for e in entries for _, cs in (e[4] if len(e) > 4 else []) for c in cs]
    results = match.check_many(path, items)
    if all(r[0] == "match" for r in results):
        return start + 1, entries
    path.unlink()
    if len(entries) == 1:
        return start, []
    half = len(entries) // 2
    n, first = write_checked(out, name, entries[:half], note, start)
    n, second = write_checked(out, name, entries[half:], note, n)
    return n, first + second


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--module", nargs="*")
    p.add_argument("--dry", action="store_true", help="only count the candidates")
    a = p.parse_args()                  # argparse stops on an unknown argument
    found, skipped = candidates(a.module)
    found = [f + ("dtor",) for f in found]
    ctors, ctor_skipped = ctor_candidates(a.module)
    found += ctors
    skipped += ctor_skipped
    print(f"{sum(1 for f in found if f[4] == 'dtor')} destructors' classes, {len(ctors)} constructors to try; "
          f"{len(skipped)} not", flush=True)
    if a.dry:
        return
    work = config.BUILD / "structors"
    work.mkdir(parents=True, exist_ok=True)
    read = sum(1 for f in found if f[3][0])
    print(f"bodies read: {read}", flush=True)
    by_module = {}
    for module, cls, items, body, kind in found:
        by_module.setdefault(module, []).append((cls, items, body, kind))
    won = 0
    # every program's chunks checked side by side; a chunk that does not compile is split after
    jobs = []
    for module, classes in sorted(by_module.items()):
        for i in range(0, len(classes), CHUNK):
            path = work / f"{module.replace('.', '_')}_{i // CHUNK:03}.cpp"
            jobs.append((module, classes[i:i + CHUNK], path))
    # a chunk that does not compile (two classes' headers that do not go together) is split in
    # two, and the halves of every such chunk are checked side by side, a round at a time
    first = {}
    rounds = 0
    while jobs:
        rounds += 1
        checked = match.check_parallel([(p, [it for _, its, *_ in chunk for it in its],
                                         source(chunk, "candidates of tools/structors.py")) for _, chunk, p in jobs])
        again = []
        for (module, chunk, path), (results, _) in zip(jobs, checked):
            items = [it for _, its, *_ in chunk for it in its]
            if all(r[0] == "error" for r in results) and len(chunk) > 1:
                half = len(chunk) // 2
                again.append((module, chunk[:half], path.with_name(path.stem + "a.cpp")))
                again.append((module, chunk[half:], path.with_name(path.stem + "b.cpp")))
            else:
                first.setdefault(module, {}).update({w: r[0] for (w, _), r in zip(items, results)})
        jobs = again
    print(f"candidates checked in {rounds} rounds", flush=True)
    # 1. per program, what matched, and the hosts each base's inline copies could go in
    keeps, wanted = {}, {}              # module -> keep; (module, base) -> (copies, hosts)
    for module, classes in sorted(by_module.items()):
        status = first.get(module, {})
        keep = []
        for cls, items, body, kind in classes:
            good = [(w, s) for w, s in items if status.get(w) == "match"]
            unread = f"; its body: {body[3]}" if len(body) > 3 else ""
            skipped += [(w, f"does not match ({status.get(w, 'error')}){unread}") for w, s in items
                        if status.get(w) != "match"]
            if good:
                keep.append((cls, good, body, kind))
        keeps[module] = keep
        for base, copies in sorted(inline_copies(module, classes).items()):
            # a host: a class built on the base, one that matches first, destructors before
            # constructors (a constructor may leave the base's vtable out)
            hosts = [e for e in keep if base in ancestors(e[0])]
            hosts += [(c, [], b, k) for c, _, b, k in classes if base in ancestors(c)
                      and not any(c == h[0] and k == h[3] for h in hosts)]
            hosts.sort(key=lambda e: (not e[1], e[3] != "dtor"))
            if hosts:
                wanted[(module, base)] = (copies, [(h[0], h[1], h[2], h[3]) for h in hosts[:6]])

    # 2. the hosts, a round at a time for every program side by side: the first host whose file
    # emits all the copies, else the one that emits the most
    best = {}                           # (module, base) -> (host, good copies, results)
    for round_ in range(6):
        jobs = []
        for n, ((module, base), (copies, hosts)) in enumerate(sorted(wanted.items())):
            done = best.get((module, base))
            if round_ >= len(hosts) or (done and len(done[1]) == len(copies)):
                continue
            host = hosts[round_]
            path = work / f"{module.replace('.', '_')}_inline_{n:03}_{round_}.cpp"
            jobs.append(((module, base), host, copies, path))
        if not jobs:
            break
        checked = match.check_parallel([(p, h[1] + c, source([h + ([(b[1], c)],)], "candidates of tools/structors.py"))
                                        for b, h, c, p in jobs])
        for (key, host, copies, _), (results, _) in zip(jobs, checked):
            good = [c for c, r in zip(copies, results[len(host[1]):]) if r[0] == "match"]
            if key not in best or len(good) > len(best[key][1]):
                best[key] = (host, good, results)
    hosted = {}                         # module -> [entries with their copies]
    for (module, base), (host, good, results) in sorted(best.items()):
        copies = wanted[(module, base)][0]
        skipped += [(w, f"{base}'s inline copy: does not match ({r[0]})")
                    for (w, _), r in zip(copies, results[len(host[1]):]) if r[0] != "match"]
        if good or host[1]:
            keeps[module] = [e for e in keeps[module] if not (e[0] == host[0] and e[3] == host[3])]
            hosted.setdefault(module, []).append(host + ([(base, good)] if good else [],))

    # 3. the files, every program's side by side, each checked as written; one where something
    # does not match is split (write_checked), one at a time
    files = []                          # (module, out folder, name, entries, note)
    note_inline = ("written by tools/structors.py: a class built on a base whose header defines virtual "
                   "functions inline, and the base's copies this file emits; each named one matches")
    note_plain = "written by tools/structors.py: destructors and constructors from the headers; each matches"
    for module in sorted(by_module):
        out = config.program_dir(module) / "generated"
        for old in out.glob("dtors_*.cpp"):
            old.unlink()
        out.mkdir(parents=True, exist_ok=True)
        for i, entry in enumerate(hosted.get(module, [])):
            files.append((module, out, f"dtors_inline_{i:03}", [entry], note_inline))
        for i in range(0, len(keeps[module]), CHUNK):
            files.append((module, out, f"dtors_{i // CHUNK:03}", keeps[module][i:i + CHUNK], note_plain))

    def named(entries):
        return [it for e in entries for it in e[1]] + [c for e in entries for _, cs in (e[4] if len(e) > 4 else [])
                                                      for c in cs]
    checked = match.check_parallel([(out / f"{name}.cpp", named(entries), source(entries, note))
                                    for _, out, name, entries, note in files])
    written = {}
    for (module, out, name, entries, note), (results, _) in zip(files, checked):
        if all(r[0] == "match" for r in results):
            (out / f"{name}.cpp").write_text(source(entries, note), encoding="utf-8", newline="\n")
            kept = entries
        else:
            path = out / f"{name}.cpp"
            if path.exists():
                path.unlink()
            _, kept = write_checked(out, name + "_part", entries, note)
        written.setdefault(module, []).extend(kept)
    for module in sorted(by_module):
        kept = written.get(module, [])
        lost = {w for e in keeps[module] for w, _ in e[1]} - {w for e in kept for w, _ in e[1]}
        skipped += [(w, "matches alone, not beside the other classes of its file") for w in sorted(lost)]
        count = sum(len(e[1]) + sum(len(c) for _, c in (e[4] if len(e) > 4 else [])) for e in kept)
        won += count
        print(f"{module}: {count} of {sum(len(i) for _, i, *_ in by_module[module])}", flush=True)
    with open(config.BUILD / "structors_skipped.txt", "w", encoding="utf-8", newline="\n") as f:
        f.writelines(f"{where} {why}\n" for where, why in skipped)
    print(f"{won} destructors and constructors in src/<program>/generated/dtors_*.cpp; {len(skipped)} left "
          f"(build/{config.VERSION}/structors_skipped.txt)")


if __name__ == "__main__":
    main()
