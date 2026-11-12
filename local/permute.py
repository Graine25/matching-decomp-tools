"""a permuter: changes one function's source at random and keeps what brings it closer to the
game's bytes, by tools/match.py's own count of the words that differ. local, never writes src/.

    python -I tools/local/permute.py <source> <where> --sym NAME [--tries 300] [--seed 1]
    python -I tools/local/permute.py --list build/us-v1.2/permute.txt [--jobs 8] [--tries 300]
        (lines: <source> <where> <sym>)

the changes are the ones that usually move armcc's registers and order (AGENTS.md, "What
usually moves the bytes"): two neighbouring statements swapped, a comparison written the
other way round, if and else swapped under the negated condition, a local's type made
signed or unsigned, a local used once put in its place (and back), `!x` against `x == 0`.
a candidate that tools/honest.py calls a trick, or that does not compile, is dropped. the
best source of each function goes to build/<version>/permute/<where>/best.cpp, with the
words that still differ; a person or an agent reads it before it goes to src/: what the
permuter finds must still be what a programmer would have written.
"""
import argparse
import random
import re
import shutil
import sys
import tempfile
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import config
import honest
import match

SIGN = {"u32": "s32", "s32": "u32", "u16": "s16", "s16": "u16", "u8": "s8", "s8": "u8",
        "int": "unsigned int", "unsigned int": "int"}
MIRROR = {"<": ">", ">": "<", "<=": ">=", ">=": "<=", "==": "==", "!=": "!="}
OPERAND = r"[A-Za-z_][\w.]*(?:->\w+)*(?:\[[^\[\]]+\])?|0x[0-9A-Fa-f]+|\d+"


def body_span(text, where):
    """(start, end) of the braced body of the function under the `//! <where>` line."""
    m = re.search(r"^[ \t]*//![ \t]*" + re.escape(where) + r"\b[^\n]*\n", text, re.M)
    if not m:
        return None
    brace = text.find("{", m.end())
    if brace < 0:
        return None
    return brace, honest.block(text, brace)


def statements(body):
    """the indexes of the simple statement lines of a body (one `...;` a line)."""
    lines = body.split("\n")
    return lines, [i for i, l in enumerate(lines) if l.strip().endswith(";") and not l.strip().startswith(("return", "//"))
                   and l.count(";") == 1 and "{" not in l and "}" not in l]


def mutate(body, rng):
    """one change, or None when the chosen kind has nothing to change."""
    kind = rng.choice(["swap", "swap", "compare", "ifelse", "sign", "inline", "not", "ternary", "temp"])
    lines, simple = statements(body)
    if kind == "swap":
        pairs = [i for i in simple if i + 1 in simple and
                 len(lines[i]) - len(lines[i].lstrip()) == len(lines[i + 1]) - len(lines[i + 1].lstrip())]
        if not pairs:
            return None
        i = rng.choice(pairs)
        lines[i], lines[i + 1] = lines[i + 1], lines[i]
        return "\n".join(lines)
    if kind == "compare":
        found = list(re.finditer(r"(?<![<>=!])(" + OPERAND + r")\s*(<=|>=|==|!=|<|>)\s*(" + OPERAND + r")(?![\w(])", body))
        if not found:
            return None
        m = rng.choice(found)
        return body[:m.start()] + f"{m.group(3)} {MIRROR[m.group(2)]} {m.group(1)}" + body[m.end():]
    if kind == "ifelse":
        for m in rng.sample(list(re.finditer(r"\bif\s*\(", body)), k=len(re.findall(r"\bif\s*\(", body))):
            depth, i = 0, m.end() - 1
            while i < len(body):
                depth += body[i] == "("
                depth -= body[i] == ")"
                if depth == 0:
                    break
                i += 1
            cond = body[m.end():i]
            j = body.find("{", i)
            if j < 0 or body[i + 1:j].strip():
                continue
            k = honest.block(body, j)
            e = re.match(r"\s*else\s*\{", body[k:])
            if not e:
                continue
            l = honest.block(body, k + e.end() - 1)
            first, second = body[j:k], body[k + e.end() - 1:l]
            return body[:m.start()] + f"if (!({cond})) " + second + " else " + first + body[l:]
        return None
    if kind == "ternary":
        m = re.search(r"^([ \t]*)return\s+([^?;]+?)\s*\?\s*([^:;]+?)\s*:\s*([^;]+);", body, re.M)
        if m:
            i = m.group(1)
            return body[:m.start()] + f"{i}if ({m.group(2)}) {{\n{i}    return {m.group(3)};\n{i}}}\n{i}return {m.group(4)};" + body[m.end():]
        m = re.search(r"^([ \t]*)if\s*\((.+)\)\s*\{\s*\n\s*return\s+([^;]+);\s*\n\s*\}\s*\n\s*return\s+([^;]+);", body, re.M)
        if m:
            return body[:m.start()] + f"{m.group(1)}return ({m.group(2)}) ? {m.group(3)} : {m.group(4)};" + body[m.end():]
        return None
    if kind == "temp":
        lines = body.split("\n")
        cands = [(i, m) for i, l in enumerate(lines) if l.strip().endswith(";") and not l.strip().startswith("//")
                 for m in re.finditer(r"\*\((\w+) \*\)\(([^()]*(?:\([^()]*\)[^()]*)*)\)", l)]
        if not cands:
            return None
        i, m = rng.choice(cands)
        indent = lines[i][:len(lines[i]) - len(lines[i].lstrip())]
        name = f"t{rng.randrange(100)}"
        lines[i] = lines[i][:m.start()] + name + lines[i][m.end():]
        lines.insert(i, f"{indent}{m.group(1)} {name} = {m.group(0)};")
        return "\n".join(lines)
    if kind == "sign":
        found = list(re.finditer(r"(?<![\w*])(unsigned int|int|u32|s32|u16|s16|u8|s8)(\s+[A-Za-z_]\w*\s*[=,)])", body))
        found += list(re.finditer(r"\((unsigned int|int|u32|s32|u16|s16|u8|s8)()\)", body))
        if not found:
            return None
        m = rng.choice(found)
        return body[:m.start(1)] + SIGN[m.group(1)] + body[m.end(1):]
    if kind == "inline":
        decls = list(re.finditer(r"^([ \t]*)(?:const\s+)?[\w:]+\s*\*?\s*([A-Za-z_]\w*)\s*=\s*([^;]+);[ \t]*\n", body, re.M))
        rng.shuffle(decls)
        for d in decls:
            rest = body[d.end():]
            uses = re.findall(r"\b" + re.escape(d.group(2)) + r"\b", rest)
            if len(uses) == 1 and not re.search(r"\b" + re.escape(d.group(2)) + r"\s*(?:[+\-*/|&^]?=|\+\+|--)", rest):
                rest = re.sub(r"\b" + re.escape(d.group(2)) + r"\b", "(" + d.group(3).strip() + ")", rest, count=1)
                return body[:d.start()] + rest
        return None
    if kind == "not":
        found = list(re.finditer(r"!\s*(" + OPERAND + r")(?![\w(\[])", body)) + \
            list(re.finditer(r"(" + OPERAND + r")\s*==\s*0(?![\w.])", body))
        if not found:
            return None
        m = rng.choice(found)
        if m.group(0).lstrip().startswith("!"):
            return body[:m.start()] + f"{m.group(1)} == 0" + body[m.end():]
        return body[:m.start()] + f"!{m.group(1)}" + body[m.end():]
    return None


def score(path, where, sym, target):
    """the words that differ, the size counted in words: lower is better; None if it does not
    compile, is a trick, or the function is not there."""
    if honest.reasons(path):
        return None
    result = match.check_many(path, [(where, sym)])[0]
    if result[0] == "error":
        return None
    if result[0] == "match":
        return 0
    return result[1] + result[2] + abs(result[3] - target) // 4


def permute(source, where, sym, tries=300, seed=1):
    rng = random.Random(seed)
    source = Path(source)
    text = source.read_text(encoding="utf-8")
    span = body_span(text, where)
    if span is None:
        return where, None, "no body under the //! line"
    image, addr, main = match.locate(where)
    module = image.name[:-4] if image.name.endswith(".cro") else image.name
    import functable
    entry = functable.table().get(module, {}).get(main)
    target = entry[0] - main if entry else 0
    out = config.BUILD / "permute" / where.replace(":", "_")
    out.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory() as tmp:
        cand = Path(tmp) / source.name
        # the candidate sits where the source does for its own includes: a copy of the folder's headers
        for h in source.parent.glob("*.h"):
            shutil.copy(h, Path(tmp) / h.name)
        # the parameter list goes with the body: their types are guesses as well
        sig = text.rfind("(", 0, text.rfind(")", 0, span[0]) + 1)
        sig = sig if sig > 0 and "\n//!" not in text[sig:span[0]] else span[0]
        head, body, tail = text[:sig], text[sig:span[1]], text[span[1]:]
        cand.write_text(text, encoding="utf-8")
        best = score(cand, where, sym, target)
        if best is None:
            return where, None, "the source does not compile or is a trick"
        start, best_body = best, body
        for _ in range(tries):
            if best == 0:
                break
            new = best_body
            for _ in range(rng.choice((1, 1, 2))):
                changed = mutate(new, rng)
                if changed:
                    new = changed
            if new == best_body:
                continue
            cand.write_text(head + new + tail, encoding="utf-8")
            s = score(cand, where, sym, target)
            # better, or as good and not longer: a source does not grow without a reason
            if s is not None and (s < best or (s == best and len(new) <= len(best_body))):
                best, best_body = s, new
        (out / "best.cpp").write_text(head + best_body + tail, encoding="utf-8")
    return where, best, f"{start} -> {best}" + (" MATCH" if best == 0 else "")


def run(item):
    return permute(*item)


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("source", nargs="?")
    p.add_argument("where", nargs="?")
    p.add_argument("--sym")
    p.add_argument("--list")
    p.add_argument("--jobs", type=int, default=8)
    p.add_argument("--tries", type=int, default=300)
    p.add_argument("--seed", type=int, default=1)
    a = p.parse_args()
    if a.list:
        items = []
        for line in Path(a.list).read_text(encoding="utf-8").splitlines():
            parts = line.split()
            if len(parts) >= 3:
                items.append((parts[0], parts[1], parts[2], a.tries, a.seed))
        with ProcessPoolExecutor(a.jobs) as pool:
            for where, best, note in pool.map(run, items):
                print(f"{where} {note}", flush=True)
    else:
        print(*permute(a.source, a.where, a.sym, a.tries, a.seed)[::2])


if __name__ == "__main__":
    main()
