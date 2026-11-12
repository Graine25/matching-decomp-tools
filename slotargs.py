"""the parameters of a function, from its own code: which argument registers it reads before
it writes them. for the virtual functions whose parameters no name gives (`vf12`):
tools/headers.py takes, for each slot, the most any version of it reads.

    python -I tools/slotargs.py <where> ...     what it finds for these functions

r1 to r3 are the integer arguments after `this` (r0), s0 to s15 the float ones (floats go
in VFP registers here). every path through the function is followed from its entry, each
with the registers already written on it; a register read before it is written on some
path is an argument. a call (bl) ends what can be seen of the arguments: it writes r0 to
r3 and s0 to s15 for the callee, so what is read after it is not one, and what the call
itself passes on is not counted (it may be the callee's, not this function's). a function
that computes its pc (a jump table), reads a d register before writing it, or is not
plain ARM code gives nothing.

a lower bound: an argument no version reads is not seen. the types are not known (a
pointer or an integer, its width): headers.py writes u32 and f32 and says it is a guess.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import config
from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM
from capstone import arm as A

md = Cs(CS_ARCH_ARM, CS_MODE_ARM)
md.detail = True

INTS = {A.ARM_REG_R1: 1, A.ARM_REG_R2: 2, A.ARM_REG_R3: 3}
SREG = {getattr(A, f"ARM_REG_S{i}"): i for i in range(16)}
DREG = {getattr(A, f"ARM_REG_D{i}"): i for i in range(8)}
LIMIT = 4000


def args_of(image, start, end):
    """(integer arguments, r0 included, float arguments), or None: for a function called
    directly, whose first argument may be anything (tools/tiny.py)."""
    return params_of(image, start, end, ints={A.ARM_REG_R0: 1, A.ARM_REG_R1: 2, A.ARM_REG_R2: 3, A.ARM_REG_R3: 4})


def params_of(image, start, end, ints=None):
    """(integer arguments after this, float arguments), or None when it cannot be told."""
    INTS_ = ints or INTS
    if start & 3:
        return None
    code = image.data[start - image.base:end - image.base]
    insns = {i.address: i for i in md.disasm(code, start)}
    ints, floats = 0, 0
    seen = set()
    work = [(start, frozenset())]
    steps = 0
    while work:
        at, written = work.pop()
        while True:
            steps += 1
            if steps > LIMIT:
                return None
            if (at, written) in seen or not start <= at < end:
                break
            seen.add((at, written))
            i = insns.get(at)
            if i is None:
                return None
            if i.id in (A.ARM_INS_BL, A.ARM_INS_BLX):
                break                                    # the arguments end at a call
            try:
                read, wrote = i.regs_access()
            except Exception:
                return None
            read = list(read)
            if i.id == A.ARM_INS_PUSH or (i.id == A.ARM_INS_STMDB and i.operands[0].reg == A.ARM_REG_SP):
                read = []                               # a push saves registers (r3 may be padding)
            elif i.mnemonic.startswith(("vst", "vpush")):
                read += [o.reg for o in i.operands[1 if i.mnemonic.startswith("vstm") else 0:]
                         if o.type == A.ARM_OP_REG]    # capstone leaves the stored registers out
            for r in read:
                if r in INTS_ and ("r", INTS_[r]) not in written:
                    ints = max(ints, INTS_[r])
                elif r in SREG and ("s", SREG[r]) not in written:
                    floats = max(floats, SREG[r] + 1)
                elif r in DREG and ("s", DREG[r] * 2) not in written:
                    return None                         # a double argument: not told here
                elif r == A.ARM_REG_PC and i.id not in (A.ARM_INS_LDR, A.ARM_INS_VLDR, A.ARM_INS_ADR, A.ARM_INS_ADD):
                    pass
            more = set()
            for r in wrote:
                if r in INTS_:
                    more.add(("r", INTS_[r]))
                elif r in SREG:
                    more.add(("s", SREG[r]))
                elif r in DREG:
                    more |= {("s", DREG[r] * 2), ("s", DREG[r] * 2 + 1)}
                elif r == A.ARM_REG_PC and i.id not in (A.ARM_INS_POP, A.ARM_INS_LDM, A.ARM_INS_B, A.ARM_INS_BX):
                    if not (i.id == A.ARM_INS_LDR and i.op_str.startswith("pc, [sp]")):
                        return None                     # add pc, ...: a jump table
            if i.cc == A.ARM_CC_AL:
                written = written | more                # under a condition it may not have written
            word = image.word(at)
            if i.id == A.ARM_INS_B:
                target = i.operands[0].imm
                if start <= target < end:
                    work.append((target, written))
                if i.cc == A.ARM_CC_AL:
                    break
            elif i.id == A.ARM_INS_BX or word == 0xE12FFF1E:
                if i.cc == A.ARM_CC_AL:
                    break
            elif (i.id in (A.ARM_INS_POP, A.ARM_INS_LDM) and A.ARM_REG_PC in wrote) or \
                    (i.id == A.ARM_INS_LDR and A.ARM_REG_PC in wrote):
                if i.cc == A.ARM_CC_AL:
                    break
            at += 4
    return ints, floats


def main():
    import functable
    table = functable.table()
    for where in sys.argv[1:]:
        module, _, off = where.rpartition(":")
        module = module or "code.bin"
        start = int(off, 16)
        entry = table.get(module, {}).get(start)
        if entry is None:
            print(f"{where}: not a function start")
            continue
        print(where, params_of(config.Image(module), start, entry[0]))


if __name__ == "__main__":
    main()
