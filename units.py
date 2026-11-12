"""finds translation units by their static initializer, and writes the ones it can explain.

  python -I tools/units.py

a file that includes the engine's node headers gets, in its static initializer,
the Inheritance of each node class those headers use (include/gfl2/
renderingengine/scenegraph/NodeTrait.h). the initializer says which classes,
in which order, through the names it imports; so the list of headers the file
includes, in order, can be read back from it.

for every unmatched function that builds such objects this reads the classes,
takes the last class of each run of a derivation chain as an included header
(a derived class's header includes its base's), tries the file with and
without the engine's constant (UnitConstant.h), and keeps what matches as
src/<program>/generated/units/unit_<address>.cpp. an initializer that also sets the
file's own statics does not match and stays open. a class without a written
header (one that has the NodeTrait base) is skipped, and listed.

needs llvm-cxxfilt, and tools/progress.py run before.
"""
import json
import re
import shutil
import subprocess
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import config
import cro as crolib
import functable
import match

GUARD = "_ZGVN4gfl215renderingengine10scenegraph15NodeInheritance"
CONSTANT = "gfl2/renderingengine/scenegraph/UnitConstant.h"


def demangle(names):
    exe = shutil.which("llvm-cxxfilt") or r"C:\Program Files\LLVM\bin\llvm-cxxfilt.exe"
    names = sorted(names)
    r = subprocess.run([exe], input="\n".join(names) + "\n", capture_output=True, text=True)
    return dict(zip(names, r.stdout.split("\n")))


def split_arguments(text):
    depth, start, out = 0, 0, []
    for i, c in enumerate(text):
        depth += c == "<"
        depth -= c == ">"
        if c == "," and depth == 0:
            out.append(text[start:i].strip())
            start = i + 1
    return out + [text[start:].strip()]


def main():
    config.options(__doc__)
    report = config.BUILD / "report.json"
    if not report.exists():
        raise SystemExit("run tools/progress.py first")
    matched = set()
    for r in json.loads(report.read_text(encoding="utf-8")):
        if r["status"] == "match":
            module, _, off = r["where"].rpartition(":")
            matched.add((module or "code.bin", int(off, 16)))
    exports = {addr: name for name, addr in crolib.Cro(config.ORIG / "romfs" / "static.crs").exports().items()
               if name.startswith(GUARD)}

    found = []          # (module, start, [guard names in the order the code reaches them])
    for module, funcs in functable.table().items():
        image = match.parse_where(f"{module}:0" if module != "code.bin" else "0")[0]
        for start, (end, body, mode, kind, name) in funcs.items():
            if (module, start) in matched or kind == "stub" or mode != "arm" or end - start < 100:
                continue
            order = []
            for at in range(start, end, 4):
                w = image.word(at)
                if (w & 0x0F7F0000) != 0x051F0000:           # ldr rX, [pc, #imm]
                    continue
                pool = at + 8 + ((w & 0xFFF) if w & 0x00800000 else -(w & 0xFFF))
                if not start <= pool < end:
                    continue
                if module == "code.bin":
                    symbol = exports.get(image.word(pool))
                else:
                    loaded = image.reloc(pool)
                    symbol = loaded[1][0] if loaded and loaded[0] == "name" and loaded[1][0].startswith(GUARD) else None
                if symbol and symbol not in order:
                    order.append(symbol)
            if order:
                found.append((module, start, order))
    pretty = demangle({s for _, _, order in found for s in order})

    def pair(symbol):
        """(class, its base) of a guard's NodeInheritance<class, base>::s_Inheritance."""
        text = pretty[symbol]
        inner = text[text.index("NodeInheritance<") + 16:text.rindex(">::s_Inheritance")]
        return tuple(split_arguments(inner))

    def header_of(cls):
        path = Path(*cls.split("::")).with_suffix(".h")
        full = config.ROOT / "include" / path
        if full.exists() and "NodeTrait<" in full.read_text(encoding="utf-8", errors="replace"):
            return path.as_posix()
        return None

    work = config.BUILD / "units"
    work.mkdir(parents=True, exist_ok=True)
    wrote, missing, failed = 0, Counter(), 0
    for n, (module, start, order) in enumerate(found):
        pairs = [pair(s) for s in order]
        unknown = [c for c, _ in pairs if header_of(c) is None]
        if unknown:
            for c in unknown:
                missing[c] += 1
            continue
        # the last class of each run of a chain is a header the file includes
        includes = [header_of(c) for i, (c, _) in enumerate(pairs) if i + 1 == len(pairs) or pairs[i + 1][1] != c]
        where = f"0x{start:08X}" if module == "code.bin" else f"{module}:0x{start:08X}"
        done = False
        for constant in (True, False):
            lines = [f"// a file of {module}, known so far only by its static initializer (written by tools/units.py)", ""]
            lines += [f'#include "{h}"' for h in ([CONSTANT] if constant else []) + includes]
            lines += ["", f"//! {where} __sti__", ""]
            path = work / f"{module.replace('.', '_')}_{start:08X}.cpp"
            path.write_text("\n".join(lines), encoding="utf-8", newline="\n")
            if match.check_many(path, [(where, "__sti__")])[0][0] == "match":
                out = config.program_dir(module) / "generated" / "units" / f"unit_{start:08X}.cpp"
                out.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(path, out)
                wrote += 1
                done = True
                break
        failed += not done
        if n % 100 == 99:
            print(f"  {n + 1} of {len(found)}: {wrote} written", flush=True)
    print(f"{len(found)} initializers build node Inheritance objects: {wrote} written, {failed} with more in them "
          f"(left open), {sum(1 for _ in found) - wrote - failed} with a class that has no header yet")
    for cls, count in missing.most_common():
        print(f"  no header: {cls} ({count} files)")


if __name__ == "__main__":
    main()
