"""bounds the name of every unnamed function of code.bin by its named neighbours.

  python -I tools/bounds.py            # config/<version>/bounds.csv
  python -I tools/bounds.py --check    # how well the scopes agree with the RTTI's classes

the linker laid the game's functions out in the order of their section names, which are
their mangled names (armcc --split_sections: i.<name>), byte by byte: _ZN3App... before
_ZN3app..., _ZN5Sound12... before _ZN5Sound13.... the names known (the exports of
static.crs) show it: nearly all are in that order by address. the few that are not are
small functions that end in a jump to the function after them, which the linker moves
there (a tail call before its target); they are left out as anchors.

so an unnamed function between two named ones has a mangled name between theirs. what
the two share is certain for it: the columns are

  module, start   the function
  after, before   the nearest named neighbours' mangled names (its name is between them)
  scope           the namespaces and class both neighbours share, read from the common
                  prefix of their names (whole components only): Sound, app::tool::PaneList
  const           yes when both are const member functions (_ZNK), so this one is too

this holds for code that has a section per function, which is the game's own. a
library's object has one section for all its code, and the linker puts it where it likes:
some sit between two of the game's names (the compiler's printf between two functions of
app::tool::InfoWindowBookType). so the scope is what a function is in if it is the game's;
it says nothing about whose code it is, and tools/classify.py does not use it for that.
against the classes the RTTI gives (--check), 97 in 100 agree.

the sorted part starts at the first exported _Z name in order and ends at the last name
in order; before and after it the order is by object file (libraries), and no bounds are
given there. names and addresses only: nothing of the game's code is in the file.
"""
import bisect
import csv
import re
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import config
import cro as crolib
import functable

PATH = config.CONFIG / "bounds.csv"
FIELDS = ["module", "start", "after", "before", "scope", "const"]


def anchors():
    """the exported names that are in order by address: the longest increasing run of them."""
    exports = crolib.Cro(config.ORIG / "romfs" / "static.crs").exports()
    image = config.Image()
    items = sorted((addr & ~1, name) for name, addr in exports.items() if image.text <= addr < image.text + image.text_size)
    # longest strictly increasing subsequence of the names, by patience sorting
    tails, tail_index, back = [], [], [None] * len(items)
    for i, (_, name) in enumerate(items):
        k = bisect.bisect_left(tails, name)
        if k == len(tails):
            tails.append(name)
            tail_index.append(i)
        else:
            tails[k] = name
            tail_index[k] = i
        back[i] = tail_index[k - 1] if k else None
    chain, i = [], tail_index[-1]
    while i is not None:
        chain.append(items[i])
        i = back[i]
    chain.reverse()
    first = next(k for k, (_, name) in enumerate(chain) if name.startswith("_Z"))
    return chain[first:], len(items)


def scope_of(prefix):
    """(the namespaces and class in the whole components of a common prefix, const or not)."""
    found = re.match(r"_ZN(K?)", prefix)
    if not found:
        return "", False
    at, parts = found.end(), []
    while True:
        number = re.match(r"\d+", prefix[at:])
        if not number:
            break
        size = int(number.group())
        begin = at + number.end()
        if begin + size > len(prefix):
            break
        # a component is whole only if something follows it in the prefix or it ends there
        # with the next one started: the neighbours may share Foo of Foo and FooBar
        if begin + size == len(prefix):
            break
        parts.append(prefix[begin:begin + size])
        at = begin + size
    return "::".join(parts), bool(found.group(1))


def build():
    chain, exported = anchors()
    addresses = [a for a, _ in chain]
    rows = []
    for start, (end, body, mode, kind, name) in sorted(functable.table()["code.bin"].items()):
        if kind == "stub" or not addresses[0] < start < addresses[-1]:
            continue
        k = bisect.bisect_left(addresses, start)
        if k < len(addresses) and addresses[k] == start:
            continue                                    # an anchor: it has its name
        after, before = chain[k - 1][1], chain[k][1]
        common = 0
        while common < min(len(after), len(before)) and after[common] == before[common]:
            common += 1
        scope, const = scope_of(after[:common])
        rows.append({"module": "code.bin", "start": f"{start:08X}", "after": after, "before": before,
                     "scope": scope, "const": "yes" if const else ""})
    return rows, chain, exported


def load():
    """{start: row} of bounds.csv ({} without the file)."""
    if not PATH.exists():
        return {}
    with open(PATH, encoding="utf-8", newline="") as f:
        return {int(r["start"], 16): r for r in csv.DictReader(f)}


def check(rows):
    """the scope against what the RTTI says: a function that is in one class's vtable only
    must have that class's name start with... its scope's, when the scope names a class."""
    with open(config.CONFIG / "functions.csv", encoding="utf-8", newline="") as f:
        table = {int(r["start"], 16): r for r in csv.DictReader(f) if r["module"] == "code.bin"}
    agree = differ = 0
    examples = []
    for r in rows:
        t = table.get(int(r["start"], 16))
        if not t or not t["class"] or not r["scope"] or t["method"] == "shared":
            continue
        owner, scope = t["class"], r["scope"]
        # the scope may stop at a namespace of the class, or be the class, or a class nested in it
        if owner == scope or owner.startswith(scope + "::") or scope.startswith(owner + "::"):
            agree += 1
        else:
            differ += 1
            if len(examples) < 12:
                examples.append(f"  {r['start']} scope {scope}, in the vtable of {owner}")
    print(f"against the RTTI: {agree} agree, {differ} differ (a function in a vtable of another class: "
          f"an inherited or shared one, or a tail call moved by the linker)")
    print("\n".join(examples))


def main():
    config.options(__doc__, "--check")
    rows, chain, exported = build()
    print(f"{len(chain)} of {exported} exported names are in order by address, "
          f"{chain[0][0]:08X} to {chain[-1][0]:08X}")
    depth = Counter(r["scope"].count("::") + 1 if r["scope"] else 0 for r in rows)
    print(f"{len(rows)} unnamed functions bounded: {sum(v for k, v in depth.items() if k)} with a scope "
          f"({depth[1]} one name deep, {depth[2]} two, {sum(v for k, v in depth.items() if k > 2)} three or more), "
          f"{depth[0]} without")
    if "--check" in sys.argv:
        check(rows)
        return
    with open(PATH, "w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, FIELDS, lineterminator="\n")
        w.writeheader()
        w.writerows(rows)
    print(f"wrote {PATH}")


if __name__ == "__main__":
    main()
