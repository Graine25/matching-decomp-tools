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
from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM
from capstone import arm as A

md = Cs(CS_ARCH_ARM, CS_MODE_ARM)
md.detail = True

BUILTIN = {"void": "void", "bool": "u8", "char": "s8", "signed char": "s8", "unsigned char": "u8",
           "short": "s16", "unsigned short": "u16", "int": "s32", "unsigned int": "u32", "long": "s32",
           "unsigned long": "u32", "long long": "s64", "unsigned long long": "u64", "float": "f32",
           "double": "f64", "wchar_t": "u16", "u8": "u8", "s8": "s8", "u16": "u16", "s16": "s16",
           "u32": "u32", "s32": "s32", "u64": "u64", "s64": "s64", "f32": "f32", "f64": "f64"}
SIZE = {"u8": 1, "s8": 1, "u16": 2, "s16": 2, "u32": 4, "s32": 4, "f32": 4, "u64": 8, "s64": 8, "f64": 8}
MEMBER = {(1, "u"): "u8", (1, "s"): "s8", (2, "u"): "u16", (2, "s"): "s16", (4, "u"): "u32", (4, "s"): "s32",
          (4, "f"): "f32", (8, "f"): "f64", (8, "u"): "u64", (8, "s"): "s64"}
FALLBACKS = []                  # (where, error) of the functions m2c could not take the context for
DEPTH = 2                       # classes reached from the function's own through members and calls


def m2c_path():
    if os.environ.get("M2C"):
        return Path(os.environ["M2C"])
    if "m2c" in config.PATHS:
        return config.PATHS["m2c"]
    return config.ROOT.parent / "resources" / "m2c" / "m2c.py"


def ident(name):
    """a C identifier for a C++ name (A::B<int>::~C -> A__B_int___dtor_C)."""
    s = name.replace("::", "__").replace("~", "dtor_")
    s = re.sub(r"[^A-Za-z0-9_]", "_", s)
    return s if re.match(r"[A-Za-z_]", s) else "_" + s


# ---------------------------------------------------------------- the project's tables

class Tables:
    def __init__(self):
        self.funcs = {}                  # (module, start) -> row of functions.csv
        with open(config.CONFIG / "functions.csv", encoding="utf-8", newline="") as f:
            for r in csv.DictReader(f):
                self.funcs[r["module"], int(r["start"], 16)] = r
        self.bases = {}                  # class -> [(base, offset)]
        with open(config.CONFIG / "classes.csv", encoding="utf-8", newline="") as f:
            for r in csv.DictReader(f):
                if r["class"] not in self.bases:
                    self.bases[r["class"]] = [(b.rsplit(":", 1)[0], int(b.rsplit(":", 1)[1]))
                                              for b in r["bases"].split() if ":" in b]
        self.slots = {}                  # class -> {slot: (module, address)} of its primary vtable
        self.vtable_at = {}              # (module, address point) -> (class, top)
        seen = {}
        with open(config.CONFIG / "vtables.csv", encoding="utf-8", newline="") as f:
            for r in csv.DictReader(f):
                self.vtable_at.setdefault((r["module"], int(r["vtable"], 16)), (r["class"], int(r["top"])))
                if r["top"] != "0" or seen.setdefault(r["class"], (r["module"], r["vtable"])) != (r["module"], r["vtable"]):
                    continue
                module, _, addr = r["target"].rpartition(":")
                at = (module, int(addr, 16)) if re.fullmatch(r"[0-9A-Fa-f]+", addr) else None   # else an import
                self.slots.setdefault(r["class"], {})[int(r["slot"])] = at
        self.fields = {}                 # class -> {offset: (width, kind, of)}
        with open(config.CONFIG / "fields.csv", encoding="utf-8", newline="") as f:
            for r in csv.DictReader(f):
                self.fields.setdefault(r["class"], {})[int(r["offset"], 16)] = (int(r["width"]), r["type"], r["of"])
        self.signatures = {}             # code.bin address -> demangled, with its parameters
        path = config.CONFIG / "signatures.csv"
        if path.exists():
            with open(path, encoding="utf-8", newline="") as f:
                for r in csv.DictReader(f):
                    self.signatures[int(r["address"], 16) & ~1] = r["demangled"]
        self.classes = set(self.bases) | set(self.slots) | set(self.fields) | \
            {r["class"] for r in self.funcs.values() if r["class"]}
        # the prefixes of the classes that are no class themselves
        self.namespaces = {c.rsplit("::", k)[0] for c in self.classes for k in range(1, c.count("::") + 1)}
        self.namespaces -= self.classes
        self._members = {}

    def function(self, module, addr):
        return self.funcs.get((module, addr))

    def header_members(self, cls):
        """{offset: (C type, name, size)} from the `// +0x..` lines of a top-level class's header."""
        if cls in self._members:
            return self._members[cls]
        found = {}
        parts = cls.split("::")
        path = config.ROOT / "include" / Path(*parts[:-1], parts[-1] + ".h")
        if path.exists():
            text = path.read_text(encoding="utf-8", errors="replace")
            m = re.search(r"\b(?:class|struct)\s+" + re.escape(parts[-1]) + r"\b[^;{]*\{", text)
            body = text[m.end():] if m else ""
            for line in body.splitlines():
                mm = re.match(r"\s*(?P<decl>[^;/(){}]+?);\s*//\s*\+0x(?P<off>[0-9a-fA-F]+)", line)
                if not mm or line.lstrip().startswith(("virtual", "static", "typedef", "enum")):
                    continue
                dm = re.match(r"(?P<type>.*?[\s*&])(?P<name>\w+)\s*(?:\[(?P<n>[^\]]+)\])?\s*$", mm.group("decl"))
                if not dm or dm.group("name").startswith("unk_"):
                    continue
                ctype = self.c_type(dm.group("type"))
                if ctype is None:
                    continue
                count = 1
                if dm.group("n"):
                    try:
                        count = int(dm.group("n"), 0)
                    except ValueError:
                        continue
                size = 4 if ctype.endswith("*") else SIZE.get(ctype)
                if size is None:
                    continue
                found[int(mm.group("off"), 16)] = (ctype, dm.group("name") + (f"[{count:#x}]" if dm.group("n") else ""),
                                                   size * count)
        self._members[cls] = found
        return found

    def c_type(self, cpp, wanted=None):
        """the C of a C++ type of a header or a signature, or None. a pointer to a class this
        context defines is a pointer to its struct; any other named type a void * or an s32."""
        t = re.sub(r"\b(?:const|volatile|struct|class|enum|union)\b", " ", cpp)
        indirect = t.count("*") + t.count("&")
        base = " ".join(t.replace("*", " ").replace("&", " ").split()).lstrip(":")
        if base in BUILTIN:
            c = BUILTIN[base]
            return c + " " + "*" * indirect if indirect else c
        if "<" in base or "(" in base:
            return "void *" if indirect else None
        if indirect:
            if indirect == 1 and base in self.classes and (wanted is None or base in wanted):
                return f"{ident(base)} *"
            return "void *"
        return "s32"                     # an enum, or a class by value (not modelled)


_tables = None
_lock = threading.Lock()


def tables():
    global _tables
    with _lock:
        if _tables is None:
            _tables = Tables()
    return _tables


# ---------------------------------------------------------------- the assembly

def module_of(image):
    return image.name[:-4] if image.name.endswith(".cro") else image.name


def name_of(image, target, code=True):
    """the name of an address for m2c: the function's or import's name as an identifier, else
    sub_/f_/data_ and the address. returns (identifier, display name or None)."""
    module = module_of(image)
    if module != "code.bin" and image.in_code(target) and image.word(target) == 0xE51FF004:
        stub = image.reloc(target + 4)
        if stub and stub[0] == "name":
            return stub[1][0], None
    if code:
        row = tables().function(module, target)
        if row and row["name"]:
            return ident(row["name"]) + f"_{target:X}", row["name"]
    else:
        vt = tables().vtable_at.get((module, target))
        if vt:                           # a vtable's address point, as a constructor stores it
            cls, top = vt
            suffix = f"_{-top:X}" if top else ""
            return f"{ident(cls)}__vtable{suffix}", f"{cls}::vtable" + (f"_for_{-top:#x}" if top else "")
    if module == "code.bin":
        return f"{'sub' if code else 'data'}_{target:08X}", None
    return f"{'f' if code else 'data'}_{module}_{target:08X}", None


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


_dm = {}                       # mangled -> demangled (llvm-cxxfilt)


def demangled(name):
    if name not in _dm:
        import headers
        _dm.update(headers.demangle([name]) or {name: name})
    return _dm.get(name, name)


def head_of(sig):
    """a demangled function's name without its parameters (and const)."""
    text = sig[:-6] if sig.endswith(" const") else sig
    if not text.endswith(")"):
        return text
    depth = 0
    for i in range(len(text) - 1, -1, -1):
        depth += text[i] == ")"
        depth -= text[i] == "("
        if depth == 0:
            return text[:i]
    return text


def qualifier_of(sig):
    """the class or namespace a demangled name is in ('' when none)."""
    head = head_of(sig)
    depth, cut = 0, -1
    for i in range(len(head) - 1):
        depth += head[i] == "<"
        depth -= head[i] == ">"
        if depth == 0 and head[i:i + 2] == "::":
            cut = i
    return head[:cut] if cut >= 0 else ""


# ---------------------------------------------------------------- the context

def class_set(start, calls):
    """the classes the context defines: the function's and its callees', their bases, and what
    their members point to, DEPTH steps out."""
    t = tables()
    owners = [t.function(m, a)["class"] for m, a, _ in calls if t.function(m, a)]
    owners += [qualifier_of(_dm[n]) for _, _, n in calls if n in _dm]
    wanted, frontier = set(), [c for c in [start] + owners if c in t.classes]
    for _ in range(DEPTH + 1):
        nxt = []
        for c in frontier:
            if c in wanted:
                continue
            wanted.add(c)
            todo = [c]
            while todo:                  # bases, all the way up
                for b, _ in t.bases.get(todo.pop(), []):
                    if b not in wanted and b in t.classes:
                        wanted.add(b)
                        todo.append(b)
            for _, kind, of in t.fields.get(c, {}).values():
                if kind == "p" and of in t.classes:
                    nxt.append(of)
            for ctype, _, _ in t.header_members(c).values():
                m = re.match(r"(\w+) \*$", ctype)
                if m:
                    nxt.extend(k for k in t.classes if ident(k) == m.group(1))
        frontier = nxt
    return wanted


def members_of(cls, wanted):
    """{offset: (C type, name, size)} of a class, its bases' members included."""
    t = tables()
    out = {}

    def add(c, base, depth):
        if depth > 8:
            return
        for b, off in t.bases.get(c, []):
            add(b, base + off, depth + 1)
        if c in t.slots and c in wanted:
            out[base] = (f"{ident(c)}_vtbl *", "vtbl" if base == 0 else f"vtbl_{base:X}", 4)
        for off, (width, kind, of) in t.fields.get(c, {}).items():
            if kind == "p":
                ctype = f"{ident(of)} *" if of in wanted else "void *"
                size = 4
            elif kind == "o":
                ctype, size = f"u8", width
            else:
                ctype, size = MEMBER.get((width, kind)), width
            if ctype is None:
                continue
            name = f"field_{off:X}" + (f"[{width:#x}]" if kind == "o" else "")
            out[base + off] = (ctype, name, size)
        for off, (ctype, name, size) in t.header_members(c).items():
            m = re.match(r"(\w+) \*$", ctype)
            if m and not any(ident(k) == m.group(1) for k in wanted):
                ctype = "void *"
            out[base + off] = (ctype, name, size)

    add(cls, 0, 0)
    return out


def struct_text(cls, wanted):
    lines, at, used = [f"struct {ident(cls)} {{"], 0, set()
    members = members_of(cls, wanted)
    for off in sorted(members):
        ctype, name, size = members[off]
        align = 1 if ctype == "u8" else min(size, 4) if not ctype.endswith("*") else 4
        if off < at or off % align:
            continue
        if off > at:
            lines.append(f"    u8 pad_{at:X}[{off - at:#x}];")
        base_name = name.split("[")[0]
        if base_name in used:
            name = name.replace(base_name, f"{base_name}_{off:X}", 1)
        used.add(name.split("[")[0])
        lines.append(f"    {ctype} {name};" if not ctype.endswith("*") else f"    {ctype}{name};")
        at = off + size
    if at == 0:
        lines.append("    u8 pad_0[4];")
    lines.append("};")
    return "\n".join(lines)


SLOT_LINE = re.compile(r"virtual\s+[^;(]*?\b(?P<name>\w+)\s*\((?P<params>[^()]*)\)[^;\n]*;[^\n]*?\bslot\s+(?P<slot>\d+)")


def slot_names(cls, wanted=()):
    """{slot: (name, [C parameter types] or None)} of a class's vtable: the `// slot N` lines
    of its header and of the headers of the bases it shares its vtable with (their names and
    parameters), else functions.csv's method and no parameters."""
    t = tables()
    names = {}
    for slot, target in t.slots.get(cls, {}).items():
        row = t.function(*target) if target else None
        method = (row or {}).get("method") or ""
        if method.startswith("~"):
            method = f"dtor_{slot}"
        names[slot] = (ident(method) if method else f"vf{slot}", None)
    chain, c = [], cls
    while c and c not in chain:             # the primary bases, the root first
        chain.insert(0, c)
        c = next((b for b, off in t.bases.get(c, []) if off == 0), None)
    for c in chain:
        parts = c.split("::")
        path = config.ROOT / "include" / Path(*parts[:-1], parts[-1] + ".h")
        if not path.exists():
            continue
        for m in SLOT_LINE.finditer(path.read_text(encoding="utf-8", errors="replace")):
            params = []
            for p in [p.strip() for p in m.group("params").split(",") if p.strip()]:
                if p == "void":
                    continue
                p = re.sub(r"\s*=.*$", "", p)                       # a default argument
                p = re.sub(r"\s+\w+$", "", p) if re.search(r"[\w*&]\s+\w+$", p) else p   # its name
                ctype = t.c_type(p, wanted)
                if ctype is None:
                    params = None
                    break
                params.append(ctype)
            names[int(m.group("slot"))] = (m.group("name"), params)
    seen = {}
    for slot in sorted(names):
        n, params = names[slot]
        seen[n] = seen.get(n, 0) + 1
        if seen[n] > 1:
            names[slot] = (f"{n}_{slot}", params)
    return names


def reads(image, module, addr):
    """how many of r0-r3 a function of this image reads before it writes them, or None."""
    import slotargs
    entry = functable.table().get(module, {}).get(addr)
    if entry is None or entry[2] != "arm":
        return None
    found = slotargs.args_of(image, image.translate(addr), image.translate(entry[0]))
    return found[0] if found else None


def prototype(ident_name, module, addr, wanted, image=None, sig=None):
    """the C prototype of a function for m2c, or None when nothing is known of it."""
    t = tables()
    row = t.function(module, addr)
    cls = (row or {}).get("class") or ""
    if sig is None and module == "code.bin":
        sig = t.signatures.get(addr)
    params = None
    if sig:
        import headers
        parsed = headers.signature(sig)
        if parsed:
            params = []
            for p in parsed[0]:
                if p == "void":
                    continue
                c = t.c_type(p, wanted)
                if c is None:
                    params = None
                    break
                params.append(c)
    if not cls and sig:
        # a qualified name: a member function (r0 is the object) or a static or free one?
        # first the function's own code: it reads more integer registers than the name has
        # integer parameters (a member), or none and the name has none (not one). then the
        # name: const (a member), a class of the tables (a member, most likely), a namespace
        # (not one). when nothing tells, no prototype: m2c counts the arguments itself, which
        # is better than a `this` too many or too few.
        qualifier = qualifier_of(sig)
        n_int = sum(1 for p in params or [] if not p.startswith("f"))
        read = reads(image, module, addr) if image is not None and params is not None else None
        if not qualifier:
            pass
        elif read is not None and read > n_int:
            cls = qualifier
        elif read == 0 and n_int == 0:
            pass
        elif sig.endswith(" const"):
            cls = qualifier
        elif qualifier in t.classes:
            if n_int + 1 > 4:
                return None              # a static member would put an argument less on the stack
            cls = qualifier
        elif qualifier not in t.namespaces:
            return None
    # a function of a class (functions.csv's column: from its vtable, its constructor or its
    # name) takes the object in r0; a static member would not, which the table cannot tell
    this = [f"{ident(cls) if cls in wanted else 'void'} *this"] if cls else []
    if params is not None:
        args = this + [f"{p} a{i + 1}" for i, p in enumerate(params)]
        return f"M2C_UNK {ident_name}({', '.join(args) if args else 'void'});"
    if this:
        return f"M2C_UNK {ident_name}({this[0]}, ...);"
    return None


def context(where, asm=None):
    """the C context for a function, and {identifier: display name} for the output."""
    t = tables()
    image, addr = match.parse_where(where)     # the main version: the tables are its
    main = addr
    module = module_of(image)
    text, name, names, calls = asm or assembly(where)
    row = t.function(module, main) or {}
    wanted = class_set(row.get("class", ""), calls)
    out = ["typedef int M2C_UNK;"]
    for c in sorted(wanted):
        out.append(f"typedef struct {ident(c)} {ident(c)};")
        names[ident(c)] = c
        if c in t.slots:
            out.append(f"typedef struct {ident(c)}_vtbl {ident(c)}_vtbl;")
            names[f"{ident(c)}_vtbl"] = f"{c}::vtbl_t"
    for c in sorted(wanted):
        if c in t.slots:
            slots = slot_names(c, wanted)
            lines, at = [f"struct {ident(c)}_vtbl {{"], 0
            for slot in sorted(slots):
                if slot * 4 > at:
                    lines.append(f"    u8 pad_{at:X}[{slot * 4 - at:#x}];")
                sname, params = slots[slot]
                rest = "".join(f", {p} a{i + 1}" for i, p in enumerate(params)) if params is not None else ", ..."
                lines.append(f"    M2C_UNK (*{sname})({ident(c)} *this{rest});")
                at = slot * 4 + 4
            lines.append("};")
            out.append("\n".join(lines))
        out.append(struct_text(c, wanted))
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
