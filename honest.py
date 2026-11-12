"""tells an honest match from one forced by a trick.

  python -I tools/honest.py <source or folder ...>

a source can reach the game's bytes with constructs the original never had.
those matches teach nothing and hide what is still not understood, so a
function whose source uses one is 'hack', not 'match', and is not counted.

what is looked for (the list ALBW ended with, plus what armcc itself reports):
  weak        __attribute__((weak)), __weak, #pragma weak   (stops a tail call)
  barrier     __schedule_barrier()
  asm         inline or embedded assembly, asm labels
  volatile    volatile                                       (forces loads and stores)
  mask        & 0xffffffff, a no-op
  permuter    perm_t and other permuter leftovers
  pragma      #pragma that changes code generation for part of a file
  noinline    __declspec(noinline), __attribute__((noinline))
  goto        goto                                           (forces block order)
  do-while-0  do { } while (0) outside a macro
  same-arms   if / else with the same code in both arms
  dummy       a local never used or only set (armcc's #177-D, #550-D)
  ifdef       #if / #ifdef / #elif in a source (not a header) on anything but GAME_VERSION,
              the one switch the game had (include/version.h)
  flags       a compiler or flags of its own, not one of config/<version>/flagsets.txt
  vtable      a vtable's address stored by hand (a data symbol at a vtable's address point,
              config/<version>/vtables.csv, or _ZTV...): the class is declared with its
              virtual functions and the compiler stores it (AGENTS.md)

an entry of config/<version>/honest_allow.txt (<source path> <reason>  # why)
lifts one reason for one file. only the owner adds to it: a real hardware
register is volatile, a system call is an svc. sources never excuse themselves.
"""
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import config

PATTERNS = [
    ("weak", r"__attribute__\s*\(\(\s*[^)]*\bweak\b|\b__weak\b|#\s*pragma\s+weak"),
    ("barrier", r"__schedule_barrier"),
    ("asm", r"\b__asm__\b|\b__asm\b|\basm\s*[({]|\b__svc\b"),
    ("volatile", r"\bvolatile\b"),
    ("mask", r"&\s*0[xX][fF]{8}[uUlL]*\b"),
    ("permuter", r"\bperm_t\b|\bPERM_[A-Z_]+\b"),
    ("pragma", r"#\s*pragma\s+(?:O[0-3]\b|Otime|Ospace|push|pop|arm\b|no_inline|inline|diag_)"),
    ("noinline", r"__declspec\s*\(\s*noinline\s*\)|__attribute__\s*\(\(\s*noinline|\b__noinline\b"),
    ("goto", r"\bgoto\b"),
]


def strip(text):
    """the source without comments and string contents, line breaks kept."""
    def blank(m):
        s = m.group(0)
        if s[0] in "\"'":
            return s[0] + s[-1]
        return re.sub(r"[^\n]", " ", s)
    return re.sub(r'//[^\n]*|/\*.*?\*/|"(?:\\.|[^"\\\n])*"|\'(?:\\.|[^\'\\\n])*\'', blank, text, flags=re.S)


def block(text, start):
    """the end of the braced block that opens at text[start]."""
    depth = 0
    for i in range(start, len(text)):
        if text[i] == "{":
            depth += 1
        elif text[i] == "}":
            depth -= 1
            if depth == 0:
                return i + 1
    return len(text)


def same_arms(text):
    for m in re.finditer(r"\}\s*else\s*\{", text):
        close = m.start()
        depth, i = 0, close
        while i >= 0:
            if text[i] == "}":
                depth += 1
            elif text[i] == "{":
                depth -= 1
                if depth == 0:
                    break
            i -= 1
        first = text[i:close + 1]
        second = text[m.end() - 1:block(text, m.end() - 1)]
        if len(first) > 4 and re.sub(r"\s+", "", first) == re.sub(r"\s+", "", second):
            return True
    return False


_vtables = None


def vtable_symbols():
    """our names for the address points of the game's vtables (data_<address>,
    data_<Module>_<offset>)."""
    global _vtables
    if _vtables is None:
        import csv
        _vtables = set()
        path = config.CONFIG / "vtables.csv"
        if path.exists():
            with open(path, encoding="utf-8", newline="") as f:
                for r in csv.DictReader(f):
                    at = int(r["vtable"], 16)
                    _vtables.add(f"data_{at:08X}" if r["module"] == "code.bin" else f"data_{r['module']}_{at:08X}")
    return _vtables


def vtable_store(text):
    """a vtable's address assigned by hand."""
    for m in re.finditer(r"=\s*(?:\([^()=;]*\)\s*)?&?\s*(data_\w+|_ZTV\w+)", text):
        if m.group(1).startswith("_ZTV") or m.group(1) in vtable_symbols():
            return True
    return False


def conditional(text):
    """a #if, #ifdef, #ifndef or #elif whose condition is not about the version."""
    for m in re.finditer(r"^[ \t]*#[ \t]*(?:if|ifdef|ifndef|elif)\b([^\n]*)", text, re.M):
        if "GAME_VERSION" not in m.group(1):
            return True
    return False


def do_while_0(text):
    for line in text.splitlines():
        if re.search(r"\bwhile\s*\(\s*(?:0|false)\s*\)", line) and not line.rstrip().endswith("\\"):
            return True
    return False


_allow = _flagsets = None


def allowed(source):
    global _allow
    if _allow is None:
        _allow = set()
        path = config.CONFIG / "honest_allow.txt"
        if path.exists():
            for line in path.read_text(encoding="utf-8").splitlines():
                parts = line.split("#")[0].split()
                if len(parts) >= 2:
                    _allow.add((parts[0].replace("\\", "/"), parts[1]))
    try:
        rel = Path(source).resolve().relative_to(config.ROOT).as_posix()
    except ValueError:
        rel = Path(source).as_posix()
    return {reason for path, reason in _allow if path == rel}


def flags_known(cc, flags):
    """a compiler and flags of the project: the defaults or a line of flagsets.txt."""
    global _flagsets
    if _flagsets is None:
        _flagsets = {(config.DEFAULT_CC, " ".join(config.DEFAULT_FLAGS.split()))}
        path = config.CONFIG / "flagsets.txt"
        if path.exists():
            for line in path.read_text(encoding="utf-8").splitlines():
                line = line.split("#")[0].strip()
                if line:
                    c, _, f = line.partition(" ")
                    _flagsets.add((c, " ".join(f.split())))
    return (cc or config.DEFAULT_CC, " ".join((flags or config.DEFAULT_FLAGS).split())) in _flagsets


def reasons(source, log="", cc=None, flags=None):
    """the tricks a source uses, its local headers included."""
    source = Path(source)
    found = set()
    texts = [strip(source.read_text(encoding="utf-8", errors="replace"))]
    for name in re.findall(r'#\s*include\s*"([^"\n]+)"', source.read_text(encoding="utf-8", errors="replace")):
        for folder in (source.parent, config.ROOT / "include"):
            if (folder / name).is_file():
                texts.append(strip((folder / name).read_text(encoding="utf-8", errors="replace")))
                break
    if source.suffix in (".c", ".cpp") and conditional(texts[0]):
        found.add("ifdef")
    if vtable_store(texts[0]):
        found.add("vtable")
    for text in texts:
        for reason, pattern in PATTERNS:
            if re.search(pattern, text):
                found.add(reason)
        if same_arms(text):
            found.add("same-arms")
        if do_while_0(text):
            found.add("do-while-0")
    if re.search(r"#(?:177|550)-D", log):
        found.add("dummy")
    if not flags_known(cc, flags):
        found.add("flags")
    return sorted(found - allowed(source))


def main():
    config.options(__doc__, paths=True)
    files = []
    for arg in sys.argv[1:] or [str(config.ROOT / "src"), str(config.ROOT / "include")]:
        p = Path(arg)
        files += [p] if p.is_file() else sorted(f for f in p.rglob("*") if f.suffix in (".c", ".cpp", ".h", ".hpp"))
    bad = 0
    for f in files:
        why = reasons(f)
        if why:
            bad += 1
            print(f"{f}: {', '.join(why)}")
    print(f"{bad} of {len(files)} files use a trick")
    sys.exit(1 if bad else 0)


if __name__ == "__main__":
    main()
