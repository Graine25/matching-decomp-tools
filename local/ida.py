"""Hex-Rays' C of the game's functions, and IDA's function starts, without IDA's window (idalib).

    py -3.12 tools/local/ida.py c 0x003D6790 Battle:0x4F508 ...   # the C of each function
    py -3.12 tools/local/ida.py c --out build/us-v1.2/ida @list.txt   # one file each, from a list
    py -3.12 tools/local/ida.py starts code.bin [Battle ...]        # build/us-v1.2/ida/<program>.starts.txt
    py -3.12 tools/local/ida.py starts all                          # every database

a local helper (not part of the repository), after decomp-tools' ida/decompile.py. it reads
the databases the Solstice port already has (ports/Solstice/build/ida/<program>.i64: code.bin
and one per module, addressed by file offset as everything here is) and never saves them.

Hex-Rays' C is a reference for what a function does. it is not a draft to repair into a
match, and none of it goes into the repository.

needs IDA 9's idalib for Python 3.12 (the idapro wheel, py-activate-idalib.py).
"""
import sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import config                       # the decomp: project.toml's [paths] ida_databases

ROOT = config.ROOT
DATABASES = config.PATHS["ida_databases"]
OUT = config.ROOT / "build" / config.MAIN / "ida"

import idapro  # first: it loads IDA

import ida_funcs  # noqa: E402
import ida_hexrays  # noqa: E402
import ida_idp  # noqa: E402
import ida_segregs  # noqa: E402
import idautils  # noqa: E402


def database(program):
    name = "code.bin" if program == "code.bin" else f"{program.removesuffix('.cro')}.cro"
    return DATABASES / f"{name}.i64"


def parse(where):
    module, _, addr = where.rpartition(":")
    return module or "code.bin", int(addr, 16)


def opened(program):
    path = database(program)
    if not path.exists():
        print(f"no database for {program} ({path})", file=sys.stderr)
        return False
    if idapro.open_database(str(path), run_auto_analysis=False):
        print(f"cannot open {path} (is it open in IDA's window?)", file=sys.stderr)
        return False
    return True


def c_of(address):
    f = ida_funcs.get_func(address)
    # one IDA merged with the one before (a this-adjusting thunk) is not the function asked for
    if f is None or f.start_ea != address:
        return "(no function there)"
    try:
        return str(ida_hexrays.decompile(f.start_ea, flags=ida_hexrays.DECOMP_NO_CACHE))
    except ida_hexrays.DecompilationFailure as failure:
        return f"(Hex-Rays failed: {failure})"


def command_c(args):
    out = None
    if args[:1] == ["--out"]:
        out, args = Path(args[1]), args[2:]
        out.mkdir(parents=True, exist_ok=True)
    wheres = []
    for a in args:
        wheres += Path(a[1:]).read_text(encoding="utf-8").split() if a.startswith("@") else [a]
    by_program = defaultdict(list)
    for w in wheres:
        program, address = parse(w)
        by_program[program].append(address)
    for program, addresses in by_program.items():
        if not opened(program):
            continue
        try:
            for address in addresses:
                text = c_of(address)
                if out:
                    (out / f"{program.replace('.', '_')}_{address:08X}.c").write_text(text + "\n", encoding="utf-8", newline="\n")
                else:
                    label = f"0x{address:08X}" if program == "code.bin" else f"{program}:0x{address:08X}"
                    print(f"=== {label}")
                    print(text)
        finally:
            idapro.close_database(save=False)


def command_starts(programs):
    OUT.mkdir(parents=True, exist_ok=True)
    if programs == ["all"]:
        programs = sorted(p.name[:-4].removesuffix(".cro") for p in DATABASES.glob("*.i64"))
    for program in programs:
        if not opened(program):
            continue
        try:
            lines = []
            for start in idautils.Functions():
                f = ida_funcs.get_func(start)
                thumb = ida_segregs.get_sreg(start, ida_idp.str2reg("T")) == 1
                lines.append(f"{start:08X} {f.end_ea:08X} {'thumb' if thumb else 'arm'}")
        finally:
            idapro.close_database(save=False)
        path = OUT / f"{program.replace('.', '_')}.starts.txt"
        path.write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")
        print(f"{program}: {len(lines)} functions, {path}")


def main():
    args = sys.argv[1:]
    if args[:1] == ["c"] and len(args) > 1:
        command_c(args[1:])
    elif args[:1] == ["starts"] and len(args) > 1:
        command_starts(args[1:])
    else:
        raise SystemExit(__doc__)


if __name__ == "__main__":
    main()
