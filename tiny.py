"""writes the smallest functions from their instructions, each kept only if it matches.

  python -I tools/tiny.py [--max 32] [--module NAME ...] [--dry]

a function of a few straight instructions (a getter, a setter, a constant, an
empty virtual, a call passed on (also as the NOP the linker made of a tail call
to the next function), a value chosen by one comparison) has one
obvious source. this reads each ARM
function of at most --max bytes in config/<version>/functions.csv, follows its
registers, writes the C++ it stands for, compiles the candidates in batches
and keeps the ones tools/match.py accepts, in src/<program>/generated/tiny_NNN.cpp.
what it cannot read or what does not match is listed, by reason, in
build/<version>/tiny_skipped.txt.

the sources are plain: fields by offset, no classes yet. they hold the place
of the function until its class has a header; the bytes are already proven.
"""
import argparse
import re
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import config
import functable
import match
import slotargs
import imports

CHUNK = 600
INT = {(4, False): "u32", (2, False): "u16", (1, False): "u8", (2, True): "s16", (1, True): "s8"}


class Skip(Exception):
    pass


_md = None


def mnemonic(w):
    global _md
    if _md is None:
        from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM
        _md = Cs(CS_ARCH_ARM, CS_MODE_ARM)
    for i in _md.disasm(w.to_bytes(4, "little"), 0):
        return i.mnemonic
    return "?"


class Fork(Exception):
    """a conditional branch the decisions given do not say which way to take."""


_vtables = None


def vtable_symbols():
    """the data symbols tiny writes for the address points of the game's vtables."""
    global _vtables
    if _vtables is None:
        import csv
        _vtables = set()
        with open(config.CONFIG / "vtables.csv", encoding="utf-8", newline="") as f:
            for r in csv.DictReader(f):
                at = int(r["vtable"], 16)
                _vtables.add(f"data_{at:08X}" if r["module"] == "code.bin" else f"data_{r['module']}_{at:08X}")
    return _vtables


def ror(v, n):
    return ((v >> n) | (v << (32 - n))) & 0xFFFFFFFF


class Function:
    """one function followed instruction by instruction."""

    def __init__(self, image, module, start, end, glob, decisions=None):
        self.image, self.module, self.start, self.end, self.glob = image, module, start, end, glob
        self.decisions = decisions    # one path: the way taken at each conditional branch (None: none allowed)
        self.forks = []               # (flags, condition, taken, statements before it) at each
        self.visited = set()
        self.reg = {i: ("arg", i) for i in range(4)}
        self.reg[12] = ("junk",)
        self.freg = {i: ("farg", i) for i in range(4)}
        self.stores = []          # (target expr, value expr)
        self.pointers = set()     # arguments used as an address
        self.args = set()
        self.fargs = set()
        self.globals = set()      # symbols of the data it names
        self.pool_used = set()
        self.call = None
        self.saved = False        # a frame: lr and some of r4 to r11 pushed at the start
        self.callees = set()      # what it calls with bl (statements in self.stores)
        self.imports = {}         # a callee that is an import stub: its Import (tools/imports.py)
        self.touched = set()      # registers written since the start or the last call
        self.narrow = {}          # argument -> its type, when it is written as a narrower one
        self.flags = None         # (cmp or tst, left, right) of the last comparison
        self.cur = None           # the condition of the instruction being read
        self.run()

    # reading

    def get(self, r):
        if r not in self.reg:
            raise Skip("register")
        e = self.reg[r]
        if e[0] == "junk":
            raise Skip("register")
        return e

    def base(self, e):
        if e[0] == "arg":
            self.pointers.add(e[1])
        return e

    def load(self, kind, rn, off):
        if rn == 15:
            raise Skip("pool")
        return ("load", kind, self.base(self.get(rn)), off, len(self.stores))

    def pool(self, at):
        if not self.start <= at < self.end:
            raise Skip("pool")
        self.pool_used.add(at)
        im = self.image
        if self.module != "code.bin":
            loaded = im.reloc(at)
            if loaded is None:
                return ("const", im.word(at))
            if loaded[0] == "here":
                if im.in_code(loaded[1]):
                    raise Skip("text pointer")
                symbol = f"data_{self.module}_{loaded[1]:08X}"
            elif loaded[0] == "name" and loaded[1][1] == 0 and re.fullmatch(r"[A-Za-z_]\w*", loaded[1][0]):
                symbol = loaded[1][0]
            else:
                raise Skip("module pool")
            self.globals.add(symbol)
            return ("glob", symbol)
        v = im.word(at)
        if im.ro <= v < im.rw + im.rw_size + im.bss_size + 0x1000:
            self.globals.add(f"data_{v:08X}")
            return ("glob", f"data_{v:08X}")
        if im.in_text(v):
            raise Skip("text pointer")
        return ("const", v)

    def run(self):
        pc = self.start
        while True:
            if pc >= self.end:
                raise Skip("no end")
            w = self.image.word(pc)
            self.visited.add(pc)
            pc += 4
            if w == 0xE12FFF1E:
                break
            if self.decisions is not None and w >> 28 not in (0xE, 0xF) and self.flags is not None:
                ret = (w & 0x0FFFFFFF) == 0x012FFF1E or (self.saved and (w & 0x0FFF8000) == 0x08BD8000)
                if (w & 0x0F000000) == 0x0A000000 or ret:
                    # a conditional branch or return: one path takes it, another does not
                    k = len(self.forks)
                    if k >= len(self.decisions):
                        raise Fork()
                    taken = self.decisions[k]
                    self.forks.append((self.flags, w >> 28, taken, len(self.stores)))
                    code = w >> 28
                    for r, e in list(self.reg.items()):
                        if e[0] == "sel" and e[1][0] == self.flags and e[1][1] in (code, code ^ 1):
                            holds = taken if e[1][1] == code else not taken
                            self.reg[r] = e[2] if holds else e[3]
                    if taken and ret:
                        break
                    if taken:
                        target = match.branch_target(w, pc - 4)
                        if target < pc:
                            raise Skip("loop")
                        pc = target
                    continue
            if w == 0xE51FF004 and pc - 4 == self.start:
                raise Skip("import stub")
            if w == match.NOP and pc == self.end:
                # the last word a NOP: the tail call to the function the linker put right
                # after, which it made a NOP (match.py, inlined())
                self.call = self.end
                break
            if w == 0xE320F000:
                continue                                            # the compiler's own nop
            if w == 0xE52DE004 and not self.saved and not self.stores:
                self.saved = True                                   # str lr, [sp, #-4]!: a frame of lr alone
                continue
            if self.saved and w == 0xE49DF004:
                break                                               # ldr pc, [sp], #4: the return
            if self.saved and w == 0xE49DE004 and pc < self.end \
                    and ((self.image.word(pc) & 0xFF000000) == 0xEA000000
                         or (self.image.word(pc) == match.NOP and pc + 4 == self.end)):
                continue                                            # ldr lr, [sp], #4, then the tail call
            # a frame: push {r4..., lr} before any call or store (r3 may be padding), pop {..., pc}
            # to return, pop {..., lr} before a tail call
            if (w & 0xFFFFC000) == 0xE92D4000 and not self.saved and not self.stores and not w & 0x2007:
                self.saved = True
                for r in range(4, 12):
                    if w & (1 << r):
                        self.reg[r] = ("junk",)
                continue
            if self.saved and (w & 0xFFFF8000) == 0xE8BD8000:
                break                                               # pop {..., pc}: the return
            if self.saved and (w & 0xFFFFC000) == 0xE8BD4000 and pc < self.end \
                    and ((self.image.word(pc) & 0xFF000000) == 0xEA000000
                         or (self.image.word(pc) == match.NOP and pc + 4 == self.end)):
                continue                                            # pop {..., lr}, then the tail call
            if (w & 0xFFFFFFF0) in (0xE12FFF30, 0xE12FFF10) and (w & 15) not in (14, 15):
                if (w & 0xFFFFFFF0) == 0xE12FFF30:
                    if not self.saved:
                        raise Skip("call without a frame")
                    self.icall(w & 15)                      # blx rX: a call through a pointer
                    continue
                if self.saved:
                    raise Skip("indirect tail call in a frame")
                self.icall(w & 15)                          # bx rX: the same as the last thing done
                break
            if (w & 0x0F000000) == 0x0B000000:
                if w >> 28 != 0xE:
                    raise Skip("conditional")
                if not self.saved:
                    raise Skip("call without a frame")
                self.bl(match.branch_target(w, pc - 4))
                continue
            self.cur = None
            if w >> 28 != 0xE:
                # an instruction under a condition: a value chosen by the last comparison
                if w >> 28 == 0xF or self.flags is None or (w & 0x0F000000) in (0x0A000000, 0x0B000000) \
                        or (w & 0x0FFFFFF0) == 0x012FFF10:
                    raise Skip("conditional")
                self.cur = (self.flags, w >> 28)
            if (w & 0x0F000000) == 0x0A000000:
                self.call = match.branch_target(w, pc - 4)
                if self.start <= self.call < self.end:
                    raise Skip("loop")              # a branch inside itself is not a tail call
                break
            if (w & 0x0E000000) == 0x02000000 or ((w & 0x0E000010) == 0 and (w & 0x0E000000) == 0):
                self.data_op(w)
            elif (w & 0x0E000000) == 0x04000000:
                p, u, b, wb, l = (w >> 24) & 1, (w >> 23) & 1, (w >> 22) & 1, (w >> 21) & 1, (w >> 20) & 1
                if not p or wb:
                    raise Skip("addressing")
                rn, rd, off = (w >> 16) & 15, (w >> 12) & 15, (w & 0xFFF) * (1 if u else -1)
                kind = INT[(1 if b else 4, False)]
                if l:
                    if rd not in self.writable():
                        raise Skip("register")
                    self.assign(rd, self.pool(pc + 4 + off) if rn == 15 and not b else self.load(kind, rn, off))
                else:
                    self.store(kind, rn, off, self.get(rd))
            elif (w & 0x0F200010) == 0x07000000 and (w >> 5) & 3 == 0:
                # ldr / str / ldrb / strb rd, [rn, rm, lsl #n]: the element rm of an array at rn
                u, b, l = (w >> 23) & 1, (w >> 22) & 1, (w >> 20) & 1
                rn, rd, rm, amount = (w >> 16) & 15, (w >> 12) & 15, w & 15, (w >> 7) & 31
                if not u or 15 in (rn, rm):
                    raise Skip("addressing")
                index = self.get(rm)
                if amount:
                    index = ("shift", "<<", index, amount)
                address = ("op", "+", self.base(self.get(rn)), index)
                kind = INT[(1 if b else 4, False)]
                if l:
                    if rd not in self.writable():
                        raise Skip("register")
                    self.assign(rd, ("load", kind, address, 0, len(self.stores)))
                else:
                    value = self.get(rd)
                    if value[0] == "glob" and value[1] in vtable_symbols():
                        raise Skip("vtable")
                    self.check_fresh(value)
                    self.stores.append((("load", kind, address, 0, len(self.stores)), value, self.cur))
            elif (w & 0x0E400090) == 0x00400090:
                p, u, wb, l, sh = (w >> 24) & 1, (w >> 23) & 1, (w >> 21) & 1, (w >> 20) & 1, (w >> 5) & 3
                if not p or wb or sh == 0 or (not l and sh != 1):
                    raise Skip("addressing")
                rn, rd = (w >> 16) & 15, (w >> 12) & 15
                off = (((w >> 4) & 0xF0) | (w & 0xF)) * (1 if u else -1)
                kind = {1: "u16", 2: "s8", 3: "s16"}[sh]
                if l:
                    if rd not in self.writable():
                        raise Skip("register")
                    self.assign(rd, self.load(kind, rn, off))
                else:
                    self.store(kind, rn, off, self.get(rd))
            elif (w & 0x0FE00000) in (0x08800000,) and (w >> 16) & 15 != 13 and not w & 0x8000:
                rn, l = (w >> 16) & 15, (w >> 20) & 1          # ldmia / stmia rn, {...}: words in a row
                regs = [r for r in range(15) if w & (1 << r)]
                if l:
                    loads = [(r, self.load("u32", rn, 4 * k)) for k, r in enumerate(regs)]
                    for r, e in loads:
                        if r not in self.writable():
                            raise Skip("register")
                        self.assign(r, e)
                else:
                    for k, r in enumerate(regs):
                        self.store("u32", rn, 4 * k, self.get(r))
            elif (w & 0x0FBF03F0) in (0x06AF0070, 0x06EF0070, 0x06BF0070, 0x06FF0070) and not w & 0x0C00:
                rd, rm = (w >> 12) & 15, w & 15             # sxtb, uxtb, sxth, uxth
                if rd not in self.writable():
                    raise Skip("register")
                kind = {0x06AF0070: "s8", 0x06EF0070: "u8", 0x06BF0070: "s16", 0x06FF0070: "u16"}[w & 0x0FFF03F0]
                self.assign(rd, ("cast", kind, self.get(rm)))
            elif (w & 0x0F200F00) == 0x0D000A00:
                rn, off = (w >> 16) & 15, (w & 0xFF) * 4 * (1 if (w >> 23) & 1 else -1)
                s = ((w >> 12) & 15) << 1 | ((w >> 22) & 1)
                if s > 3:
                    raise Skip("register")
                if self.cur:
                    raise Skip("conditional")
                if (w >> 20) & 1:
                    self.freg[s] = self.load("f32", rn, off)
                else:
                    self.store("f32", rn, off, self.freg[s])
            else:
                raise Skip(f"instruction: {mnemonic(w)}")
        if self.decisions is not None:
            return                          # the paths together must cover the function (paths())
        for at in range(pc, self.end, 4):   # what follows must be the pool, all of it used
            if at not in self.pool_used:
                raise Skip("tail")

    def writable(self):
        return (0, 1, 2, 3, 12) + ((4, 5, 6, 7, 8) if self.saved else ())

    def arity(self, target):
        """how many integer arguments a function of this program reads (r0 included)."""
        entry = functable.table().get(self.module, {}).get(target)
        if entry is not None and entry[3] == "stub" and self.module != "code.bin":
            try:
                self.imports[target] = imports.resolve(self.image, target)
            except imports.Unsupported as why:
                raise Skip(f"import: {why}")
            return self.imports[target].args
        if entry is None or entry[2] != "arm" or entry[3] == "stub":
            raise Skip("callee")
        found = slotargs.args_of(self.image, target, self.image.translate(entry[0]) if False else entry[0])
        if found is None or found[1]:
            raise Skip("callee arguments")
        return found[0]

    def bl(self, target):
        """a call: its arguments from r0 up, its result in r0 after it."""
        args = [self.get(i) for i in range(self.arity(target))]
        for a in args:
            self.check_fresh(a)
        if any(self.freg[i] != ("farg", i) for i in range(4)):
            raise Skip("float call")
        self.stores.append(("call", target, tuple(args)))
        self.callees.add(target)
        self.reg[0] = ("ret", len(self.stores) - 1)
        for r in (1, 2, 3, 12):
            self.reg[r] = ("junk",)
        self.touched = {0}

    def icall(self, rf):
        """a call through a function pointer (a virtual function read from its vtable): its
        arguments are the registers written since the start or the last call, r0 at least."""
        fn = self.get(rf)
        if fn[0] != "load":
            raise Skip("indirect call")
        written = {r for r in self.touched if r < 4} - {rf}
        n = max(written | {0}) + 1
        if rf < n:
            raise Skip("indirect call")
        args = [self.get(i) for i in range(n)]
        for a in args + [fn]:
            self.check_fresh(a)
        if any(self.freg[i] != ("farg", i) for i in range(4)):
            raise Skip("float call")
        self.stores.append(("icall", fn, tuple(args)))
        self.reg[0] = ("ret", len(self.stores) - 1)
        for r in (1, 2, 3, 12):
            self.reg[r] = ("junk",)
        self.touched = {0}

    def assign(self, rd, e):
        """a register takes a value; under a condition, it keeps the old one otherwise."""
        self.touched.add(rd)
        if self.cur is None:
            self.reg[rd] = e
            return
        old = self.reg.get(rd)
        if old is None or old[0] == "junk":
            raise Skip("conditional")
        flags, code = self.cur
        if old[0] == "sel" and old[1] == (flags, code ^ 1):
            self.reg[rd] = ("sel", old[1], old[2], e)       # moveq then movne: one or the other
        else:
            self.reg[rd] = ("sel", self.cur, e, old)

    def data_op(self, w):
        op, s, rn, rd = (w >> 21) & 15, (w >> 20) & 1, (w >> 16) & 15, (w >> 12) & 15
        if s and op in (8, 10) and rn != 15 and not self.cur:
            if w & 0x02000000:
                right = ("const", ror(w & 0xFF, 2 * ((w >> 8) & 15)))
            elif (w & 0xFF0) == 0 and (w & 15) != 15:
                right = self.get(w & 15)
            else:
                raise Skip(f"instruction: {mnemonic(w)}")
            self.flags = ("tst" if op == 8 else "cmp", self.get(rn), right)
            return
        if (s and self.cur) or rd not in self.writable() or rn == 15 or (s and op not in (0, 2, 4, 12, 13)):
            raise Skip(f"instruction: {mnemonic(w)}")
        if w & 0x02000000:
            b = ("const", ror(w & 0xFF, 2 * ((w >> 8) & 15)))
        else:
            rm, kind, amount = w & 15, (w >> 5) & 3, (w >> 7) & 31
            if rm == 15:
                raise Skip(f"instruction: {mnemonic(w)}")
            b = self.get(rm)
            if amount:
                b = ("shift", ("<<", ">>", "s>>")[kind] if kind < 3 else None, b, amount)
                if b[1] is None:
                    raise Skip(f"instruction: {mnemonic(w)}")
            elif kind:
                raise Skip(f"instruction: {mnemonic(w)}")
        if op == 13:
            self.assign(rd, b)
        elif op == 15 and b[0] == "const":
            self.assign(rd, ("const", ~b[1] & 0xFFFFFFFF))
        elif op in (4, 2) and b[0] == "const" and not s:
            self.assign(rd, ("offset", self.base(self.get(rn)), b[1] if op == 4 else -b[1]))
        elif op in (0, 1, 2, 4, 12):
            left = self.get(rn)
            if s and op == 2:
                self.flags = ("cmp", left, b)               # subs: the flags of a compare with b
            self.assign(rd, ("op", {0: "&", 1: "^", 2: "-", 4: "+", 12: "|"}[op], left, b))
        elif op == 14:
            self.assign(rd, ("op", "& ~", self.get(rn), b))         # bic
        elif op == 3:
            self.assign(rd, ("op", "-", b, self.get(rn)))           # rsb
        else:
            raise Skip(f"instruction: {mnemonic(w)}")
        if s and op != 2:
            self.flags = ("zero", self.reg[rd], ("const", 0))      # movs, ands, adds...: zero or not

    def store(self, kind, rn, off, value):
        if value[0] == "glob" and value[1] in vtable_symbols():
            raise Skip("vtable")                # a constructor: its class must be declared (AGENTS.md)
        if rn == 15:
            raise Skip("pool")
        self.check_fresh(value)
        if self.cur:
            self.check_fresh(self.cur[0][1])
            self.check_fresh(self.cur[0][2])
        self.stores.append((("load", kind, self.base(self.get(rn)), off, len(self.stores)), value, self.cur))

    def check_fresh(self, e):
        """a value read before a store and used after it has no plain source here."""
        if e[0] == "load":
            if e[4] != len(self.stores):
                raise Skip("order")
            self.check_fresh(e[2])
        elif e[0] in ("offset", "shift", "cast"):
            self.check_fresh(e[1] if e[0] == "offset" else e[2])
        elif e[0] == "op":
            self.check_fresh(e[2])
            self.check_fresh(e[3])
        elif e[0] == "sel":
            for x in (e[1][0][1], e[1][0][2], e[2], e[3]):
                self.check_fresh(x)

    def condition(self, cur, negate=False):
        """a comparison as C++."""
        (kind, left, right), code = cur
        if negate:
            code ^= 1
        if kind == "zero":
            if code > 1:
                raise Skip("conditional")
            return f"{self.number(left)} {'==' if code == 0 else '!='} 0"
        if kind == "tst":
            if code > 1:
                raise Skip("conditional")
            return f"({self.number(left)} & {self.number(right)}) {'==' if code == 0 else '!='} 0"
        ops = {0: ("==", 0), 1: ("!=", 0), 2: (">=", 0), 3: ("<", 0), 8: (">", 0), 9: ("<=", 0),
               10: (">=", 1), 11: ("<", 1), 12: (">", 1), 13: ("<=", 1)}
        if code not in ops:
            raise Skip("conditional")
        op, signed = ops[code]
        if right == ("const", 0) and code < 2:
            return f"{self.text(left)[0]} {op} 0"
        a, b = self.number(left), self.number(right)
        if signed:
            a = f"(s32){a}"
            b = b if right[0] == "const" else f"(s32){b}"
        return f"{a} {op} {b}"

    def walk(self):
        todo = [v for s in self.stores if s[0] not in ("call", "icall") for v in s[:2]] \
            + [a for s in self.stores if s[0] in ("call", "icall") for a in s[2]] \
            + [s[1] for s in self.stores if s[0] == "icall"] \
            + list(self.reg.values()) + list(self.freg.values())
        while todo:
            e = todo.pop()
            yield e
            todo += [x for x in e[1:] if isinstance(x, tuple)]

    # writing

    def text(self, e):
        """(C++, type) of an expression."""
        k = e[0]
        if k == "arg":
            self.args.add(e[1])
            return f"a{e[1]}", ("ptr" if e[1] in self.pointers else self.narrow.get(e[1], "u32"))
        if k == "farg":
            self.fargs.add(e[1])
            return f"f{e[1]}", "f32"
        if k == "const":
            return (str(e[1]) if e[1] < 10 else f"0x{e[1]:X}"), "u32"
        if k == "glob":
            return e[1], "ptr"
        if k == "ret":
            self.used_results.add(e[1])
            return f"v{e[1]}", "u32"
        if k == "cast":
            return f"({e[1]}){self.number(e[2])}", e[1]
        if k == "load":
            return f"*({e[1]} *){self.address(e[2], e[3], True)}", e[1]
        if k == "offset":
            return self.address(e[1], e[2], False), "ptr"
        if k == "shift":
            a = self.number(e[2])
            return (f"((s32){a} >> {e[3]})" if e[1] == "s>>" else f"({a} {e[1]} {e[3]})"), "u32"
        if k == "op":
            return f"({self.number(e[2])} {e[1]} {self.number(e[3])})", "u32"
        if k == "sel":
            if (e[2], e[3]) in ((("const", 1), ("const", 0)), (("const", 0), ("const", 1))):
                return f"({self.condition(e[1], e[2] == ('const', 0))})", "bool"
            (x, kx), (y, ky) = self.text(e[2]), self.text(e[3])
            if kx != ky:
                if "f32" in (kx, ky):
                    raise Skip("float bits")
                x, y, kx = self.number(e[2]), self.number(e[3]), "u32"
            return f"({self.condition(e[1])} ? {x} : {y})", kx
        raise Skip("expression")

    def number(self, e):
        t, kind = self.text(e)
        return f"(u32){t}" if kind == "ptr" else t

    def address(self, e, off, wrap):
        t, kind = self.text(e)
        if kind != "ptr":
            t = f"(u8 *){t}"
        if off == 0:
            return t if kind == "ptr" or not wrap else f"({t})"
        return f"({t} {'+' if off > 0 else '-'} {abs(off)})"

    def variants(self, name):
        """[(source text, declarations)]: the sources this function may have had."""
        self.check_final()
        out = self.written(name)
        # an argument stored into a byte or a half word was most likely declared as one
        narrow = {}
        for target, value, _ in self.stores:
            if target in ("call", "icall"):
                continue
            if value[0] == "arg" and target[1] in ("u8", "u16", "s8", "s16") and value[1] not in self.pointers:
                narrow.setdefault(value[1], target[1])
        if narrow:
            self.narrow = narrow
            out = self.written(name) + out
            self.narrow = {}
        return out

    def callee_name(self, target):
        return f"sub_{target:08X}" if self.module == "code.bin" else f"f_{self.module}_{target:08X}"

    def written(self, name, first=True):
        if first:
            # what reads a call's result (text() notes it): a pass that only collects that
            self.used_results = set()
            self.written(name, first=False)
        body, call_decls = self.statements(0, len(self.stores), "    ")
        return self.assemble(name, body, call_decls)

    def statements(self, lo, hi, indent):
        """the lines of the statements lo to hi, and the declarations of what they call."""
        body, call_decls = [], []
        for k, item in list(enumerate(self.stores))[lo:hi]:
            if item[0] == "icall":
                _, fn, args = item
                passed = [self.number(a) if a[0] != "const" else f"(u32){self.number(a)}" for a in args]
                kinds = ", ".join(["u32"] * len(args))
                call = f"((u32 (*)({kinds}))({self.number(fn)}))({', '.join(passed)})"
                body.append(f"{indent}u32 v{k} = {call};" if k in self.used_results else f"{indent}{call};")
                continue
            if item[0] == "call":
                _, target, args = item
                passed = [self.number(a) if a[0] != "const" else f"(u32){self.number(a)}" for a in args]
                if target in self.imports:
                    imp = self.imports[target]
                    if k in self.used_results and imp.void_member:
                        raise Skip("import: its result is used, its header says void")
                    call = imp.call(passed)
                    body.append(f"{indent}u32 v{k} = (u32){call};" if k in self.used_results else f"{indent}{call};")
                    call_decls.extend(imp.declarations())
                    continue
                callee = self.callee_name(target)
                call = f"{callee}({', '.join(passed)})"
                body.append(f"{indent}u32 v{k} = {call};" if k in self.used_results else f"{indent}{call};")
                call_decls.append(f"u32 {callee}({', '.join(['u32'] * len(args))});")
                continue
            target, value, cond = item
            if cond and value[0] == "sel" and value[1] == cond:
                value = value[2]            # stored under the condition it was chosen by
            t, kind = self.text(target)
            v, vkind = self.text(value)
            if kind != vkind and not (kind == "u32" and vkind == "u32"):
                v = f"({kind}){v}" if kind != "f32" and vkind != "f32" else v
                if (kind == "f32") != (vkind == "f32"):
                    raise Skip("float bits")
            if cond:
                body.append(f"{indent}if ({self.condition(cond)}) {{")
                body.append(f"{indent}    {t} = {v};")
                body.append(f"{indent}}}")
            else:
                body.append(f"{indent}{t} = {v};")
        return body, call_decls

    def endings(self):
        """[(return type, its last line or None, a declaration or None)]: how this path may end."""
        returns = []
        if self.call is not None:
            if any(self.freg[i] != ("farg", i) for i in range(4)):
                raise Skip("float call")
            changed = [i for i in range(4) if self.reg[i] != ("arg", i)]
            passed = [self.text(self.reg[i]) for i in range(max(changed) + 1)] if changed else []
            if self.saved or self.callees:
                passed = [self.text(self.reg[i]) for i in range(self.arity(self.call))]
            # a bare constant would fit several overloads of the callee
            passed = [(f"(u32){t}" if self.reg[i][0] == "const" else t, k) for i, (t, k) in enumerate(passed)]
            entry = functable.table().get(self.module, {}).get(self.call)
            if entry is not None and entry[3] == "stub" and self.module != "code.bin":
                try:
                    n = self.arity(self.call)
                    imp = self.imports[self.call]
                    call = imp.call([self.number(self.reg[i]) for i in range(n)])
                    returns.append(("void", f"    {call};", "\n".join(imp.declarations()) or None))
                    return returns
                except (Skip, imports.Unsupported):
                    pass                    # as before: the stub by its address (match.py checks it)
            callee = f"sub_{self.call:08X}" if self.module == "code.bin" else f"f_{self.module}_{self.call:08X}"
            kinds = ", ".join("u8 *" if k == "ptr" else k for _, k in passed)
            # declared returning u32 like the calls of a frame (one callee, one declaration per
            # chunk): a void caller's tail call is the same either way
            returns.append(("void", f"    {callee}({', '.join(t for t, _ in passed)});", f"u32 {callee}({kinds});"))
        else:
            r0, s0 = self.reg[0] != ("arg", 0), self.freg[0] != ("farg", 0)
            if r0 and s0:
                raise Skip("two results")
            if r0 or s0:
                t, kind = self.text(self.reg[0] if r0 else self.freg[0])
                returns.append(("u8 *" if kind == "ptr" else kind, f"    return {t};", None))
                if kind == "bool":
                    returns.append(("u32", f"    return {t};", None))
            if not (r0 or s0) or self.stores:
                returns.append(("void", None, None))
        return returns

    def assemble(self, name, body, call_decls):
        out = []
        returns = self.endings()
        for kind, line, declaration in returns:
            n = max(self.args) + 1 if self.args else 0
            params = [f"{'u8 *' if i in self.pointers else self.narrow.get(i, 'u32') + ' '}a{i}" for i in range(n)]
            params += [f"f32 f{i}" for i in range(max(self.fargs) + 1 if self.fargs else 0)]
            lines = body + ([line] if line else [])
            text = f"{kind}{'' if kind.endswith('*') else ' '}{name}({', '.join(params)})\n{{\n" + "".join(l + "\n" for l in lines) + "}\n"
            decls = [f'extern "C" u8 {g}[];' for g in sorted(self.globals)] + call_decls + ([declaration] if declaration else [])
            out.append((text, decls))
        return out

    def check_final(self):
        if self.call is None and self.reg[0][0] == "load":
            self.check_fresh(self.reg[0])
        if self.callees and any(c == self.start for c in self.callees):
            raise Skip("recursion")
        if self.call is not None:
            for i in range(4):
                self.check_fresh(self.reg[i])
            if self.call < self.image.text or not self.image.in_text(self.call):
                raise Skip("call out of the code")


def paths(image, module, start, end):
    """every path of a function with conditional branches (forward only), as Functions."""
    found, todo = [], [()]
    while todo:
        d = todo.pop()
        try:
            f = Function(image, module, start, end, None, decisions=d)
        except Fork:
            todo += [d + (True,), d + (False,)]
            continue
        found.append(f)
        if len(found) > 6:
            raise Skip("paths")
    seen = set().union(*(f.visited | f.pool_used for f in found))
    if any(at not in seen for at in range(start, end, 4)):
        raise Skip("tail")
    return found


def path_variants(found, name):
    """the sources of a function from its paths: the statements they share, then an if for each
    branch, the way taken first and ending in a return."""
    for f in found:
        f.check_final()
        if any(f.freg[i] != ("farg", i) for i in range(4)) and f.call is None:
            raise Skip("float result")
    pointers = set().union(*(f.pointers for f in found))
    used = set()
    for f in found:
        f.pointers = pointers
        f.used_results = set()
        f.statements(0, len(f.stores), "")
        f.endings()
        for flags, code, _, _ in f.forks:
            f.condition((flags, code))
        if f.call is None and f.reg[0] != ("arg", 0):
            f.text(f.reg[0])
        used |= f.used_results
    for f in found:
        f.used_results = used
    out = []
    for kind in ("u32", "void"):
        decls = []

        def ending(f, indent, last):
            ends = {k: (line, decl) for k, line, decl in f.endings()}
            if f.call is not None:
                line, decl = ends["void"]
                decls.append(decl)
                call = line.strip().rstrip(";")
                if kind == "void":
                    return [indent + call + ";"] + ([] if last else [indent + "return;"])
                if f.call in f.imports and f.imports[f.call].void_member:
                    raise KeyError("a void import's result")    # this variant is not possible
                return [f"{indent}return {call};"]
            if kind == "void":
                return [] if last else [indent + "return;"]
            r0 = f.reg[0]
            if r0 == ("arg", 0):
                f.args.add(0)
            return [f"{indent}return {f.number(r0)};"]

        def tree(group, depth, lo, indent, last):
            if all(len(f.forks) == depth for f in group):
                if len(group) != 1:
                    raise Skip("paths")
                f = group[0]
                lines, cd = f.statements(lo, len(f.stores), indent)
                decls.extend(cd)
                return lines + ending(f, indent, last)
            f0 = next(f for f in group if len(f.forks) > depth)
            flags, code, _, k = f0.forks[depth]
            if any(len(f.forks) <= depth or f.forks[depth][:2] != (flags, code) or f.forks[depth][3] != k for f in group):
                raise Skip("paths")
            lines, cd = f0.statements(lo, k, indent)
            decls.extend(cd)
            taken = [f for f in group if f.forks[depth][2]]
            rest = [f for f in group if not f.forks[depth][2]]
            lines.append(f"{indent}if ({f0.condition((flags, code))}) {{")
            lines += tree(taken, depth + 1, k, indent + "    ", False)
            lines.append(f"{indent}}}")
            return lines + tree(rest, depth + 1, k, indent, last)

        try:
            body = tree(found, 0, 0, "    ", True)
        except KeyError:
            continue
        args = set().union(*(f.args for f in found))
        fargs = set().union(*(f.fargs for f in found))
        n = max(args) + 1 if args else 0
        params = [f"{'u8 *' if i in pointers else 'u32 '}a{i}" for i in range(n)]
        params += [f"f32 f{i}" for i in range(max(fargs) + 1 if fargs else 0)]
        text = f"{kind}{'' if kind.endswith('*') else ' '}{name}({', '.join(params)})\n{{\n" + "".join(l + "\n" for l in body) + "}\n"
        globs = sorted(set().union(*(f.globals for f in found)))
        all_decls = [f'extern "C" u8 {g}[];' for g in globs] + [d for d in dict.fromkeys(decls) if d]
        out.append((text, all_decls))
    if not out:
        raise Skip("paths")
    return out


def written():
    """the functions that already have a source outside src/tiny."""
    done = set()
    for path in (config.ROOT / "src").rglob("*"):
        if path.suffix in (".c", ".cpp") and not (path.parent.name == "generated" and path.name.startswith("tiny_")):
            for where in re.findall(r"^\s*//!\s*(\S+)", path.read_text(encoding="utf-8", errors="replace"), re.M):
                module, _, off = where.rpartition(":")
                done.add((module or "code.bin", int(off, 16)))
    return done


def candidates(modules, limit):
    """[(module, start, name of ours, where, the game's name, variants)], and the skipped by reason."""
    table, out, skipped, done = functable.table(), [], [], written()
    for module in modules:
        image = match.parse_where(f"{module}:0" if module != "code.bin" else "0")[0]
        funcs = table[module]
        for start in sorted(funcs):
            end, body, mode, kind, name = funcs[start]
            if end - start > limit:
                continue
            where = f"0x{start:08X}" if module == "code.bin" else f"{module}:0x{start:08X}"
            if (module, start) in done:
                continue
            if mode != "arm" or kind == "lib":
                skipped.append((where, mode if mode != "arm" else "library"))
                continue
            ours = f"sub_{start:08X}" if module == "code.bin" else f"f_{module}_{start:08X}"
            try:
                f = Function(image, module, start, end, None)
                if f.call is not None and funcs.get(f.call, (0, 0, "arm"))[2] != "arm":
                    raise Skip("thumb call")
                calls = set(f.callees) | ({f.call} if f.call is not None else set())
                out.append((module, start, ours, where, name, f.variants(ours), calls))
            except Skip as why:
                if str(why) != "conditional":
                    skipped.append((where, str(why)))
                    continue
                try:
                    found = paths(image, module, start, end)
                    calls = set().union(*(f.callees | ({f.call} if f.call is not None else set()) for f in found))
                    if any(funcs.get(c, (0, 0, "arm"))[2] != "arm" for c in calls):
                        raise Skip("thumb call")
                    out.append((module, start, ours, where, name, path_variants(found, ours), calls))
                except Skip as why2:
                    skipped.append((where, f"conditional: {why2}"))
                except (struct.error, IndexError):
                    skipped.append((where, "out of the file"))
            except (struct.error, IndexError):
                skipped.append((where, "out of the file"))
    return out, skipped


def chunks(funcs, pick):
    """groups of functions for one file each: a function and what it calls never share a file
    (the compiler would put the callee's code in place of the call). a function that calls
    through an import (declarations of its own) goes to a small file: an error there loses few."""
    out = []
    for f in funcs:
        variant = pick(f)
        if variant is None:
            continue
        start, calls = f[1], f[6]
        small = any(d.startswith(("#include", "namespace")) for d in variant[1])
        for c in out:
            if c["small"] == small and len(c["funcs"]) < (20 if small else CHUNK) \
                    and not (calls & c["starts"]) and start not in c["calls"]:
                break
        else:
            c = dict(funcs=[], starts=set(), calls=set(), small=small)
            out.append(c)
        c["funcs"].append((f, variant))
        c["starts"].add(start)
        c["calls"] |= calls
    return out


def write(path, chunk, note):
    decls, seen = [], set()
    for f, (text, need) in chunk["funcs"]:
        for d in need:
            if d not in seen:
                seen.add(d)
                decls.append(d)
    with open(path, "w", encoding="utf-8", newline="\n") as out:
        out.write(f"// {note}\n\n#include \"types.h\"\n\n")
        out.write("".join(d + "\n" for d in decls) + ("\n" if decls else ""))
        for (module, start, ours, where, name, _, _), (text, _) in chunk["funcs"]:
            if name:
                out.write(f"// {name}\n")
            out.write(f"//! {where} {ours}\n{text}\n")


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--max", type=int, default=64)
    p.add_argument("--module", nargs="*")
    p.add_argument("--dry", action="store_true", help="only count what can be read")
    a = p.parse_args()
    table = functable.table()
    if not table:
        raise SystemExit("no functions.csv: run tools/functable.py")
    modules = a.module or sorted(table)
    found, skipped = candidates(modules, a.max)
    print(f"{len(found)} functions read, {len(skipped)} not", flush=True)
    if a.dry:
        reasons = {}
        for _, why in skipped:
            reasons[why] = reasons.get(why, 0) + 1
        for why, n in sorted(reasons.items(), key=lambda kv: -kv[1]):
            print(f"  {n:6}  {why}")
        return

    work = config.BUILD / "tiny"
    work.mkdir(parents=True, exist_ok=True)
    won = {}   # (module, start) -> variant
    for level in range(max((len(f[5]) for f in found), default=0)):
        left = [f for f in found if (f[0], f[1]) not in won and len(f[5]) > level]
        by_module = {}
        for f in left:
            by_module.setdefault(f[0], []).append(f)
        for module, funcs in by_module.items():
            for i, chunk in enumerate(chunks(funcs, lambda f: f[5][level])):
                path = work / f"{module.replace('.', '_')}_v{level}_{i:03}.cpp"
                write(path, chunk, "candidates of tools/tiny.py")
                items = [(f[3], f[2]) for f, _ in chunk["funcs"]]
                for (f, variant), result in zip(chunk["funcs"], match.check_many(path, items)):
                    if result[0] == "match":
                        won[(f[0], f[1])] = variant
                if match.last_hacks:
                    print(f"{path.name}: {', '.join(match.last_hacks)[:300]}")
        print(f"variant {level + 1}: {len(won)} match", flush=True)

    files = 0
    for module in modules:
        out = config.program_dir(module) / "generated"
        for old in out.glob("tiny_*.cpp"):
            old.unlink()
        funcs = [f for f in found if f[0] == module and (f[0], f[1]) in won]
        for i, chunk in enumerate(chunks(funcs, lambda f: won[(f[0], f[1])])):
            out.mkdir(parents=True, exist_ok=True)
            write(out / f"tiny_{i:03}.cpp", chunk,
                  "written by tools/tiny.py from the instructions; each matches. plain fields until the classes have headers")
            files += 1
    for f in found:
        if (f[0], f[1]) not in won:
            skipped.append((f[3], "does not match"))
    with open(config.BUILD / "tiny_skipped.txt", "w", encoding="utf-8", newline="\n") as f:
        f.writelines(f"{where} {why}\n" for where, why in skipped)
    print(f"{len(won)} functions in {files} files (src/<program>/generated/tiny_*.cpp); {len(skipped)} left "
          f"(build/{config.VERSION}/tiny_skipped.txt)")


if __name__ == "__main__":
    main()
