"""draws the status picture (docs/status.svg) from the last progress run.

  python -I tools/progress.py && python -I tools/status.py

badges, a map of all code by module (area = bytes of code; green squares =
matched, amber = matched by a trick), bars by state and by module, and a line
added to docs/history.csv when the numbers changed. the picture holds module
names and sizes only, nothing of the game's code.
"""
import datetime
import json
import struct
import sys
from pathlib import Path
from xml.sax.saxutils import escape

sys.path.insert(0, str(Path(__file__).resolve().parent))
import config
import functable

BG, PANEL, GREY, GREEN, AMBER, BLUE, TEXT, DIM = "#0d1117", "#161b22", "#3d444d", "#2ea043", "#d29922", "#388bfd", "#e6edf3", "#9198a1"
FONT = 'font-family="Segoe UI,Helvetica,Arial,sans-serif"'


def modules():
    """{name: bytes of code} of the executable and every module."""
    out = {"code.bin": config.Image().text_size}
    for path in sorted((config.ORIG / "romfs").glob("*.cro")):
        head = path.read_bytes()[:0xC0]
        out[path.stem] = struct.unpack_from("<I", head, 0xB4)[0]
    table = functable.table()
    if table:        # what counts is the functions: no import stubs, no padding
        out = {module: sum(end - start for start, (end, _, _, kind, _) in funcs.items() if kind != "stub")
               for module, funcs in table.items()}
    return out


def squarify(items, x, y, w, h):
    """[(name, x, y, w, h)]: a squarified treemap of (name, size), largest first."""
    out = []
    items = [i for i in items if i[1] > 0]
    total = sum(s for _, s in items)
    scale = w * h / total if total else 0
    items = [(n, s * scale) for n, s in items]

    def worst(row, side):
        s = sum(a for _, a in row)
        return max(max(side * side * a / (s * s), s * s / (side * side * a)) for _, a in row)

    while items:
        side = min(w, h)
        row = [items[0]]
        rest = items[1:]
        while rest and worst(row + [rest[0]], side) <= worst(row, side):
            row.append(rest.pop(0))
        s = sum(a for _, a in row)
        thick = s / side
        pos = 0
        for name, a in row:
            length = a / thick
            if w >= h:
                out.append((name, x, y + pos, thick, length))
            else:
                out.append((name, x + pos, y, length, thick))
            pos += length
        if w >= h:
            x, w = x + thick, w - thick
        else:
            y, h = y + thick, h - thick
        items = rest
    return out


def cell(name, x, y, w, h, done, hack, total):
    """a module: a grid of squares, the matched share green from the bottom right."""
    out = [f'<rect x="{x:.1f}" y="{y:.1f}" width="{w:.1f}" height="{h:.1f}" fill="{BG}"/>']
    step = 7
    cols, rows = max(1, int((w - 1) // step)), max(1, int((h - 1) // step))
    n = cols * rows
    green = min(n, int(n * done / total + 0.999)) if done else 0
    amber = min(n - green, int(n * hack / total + 0.999)) if hack else 0
    sw, sh = (w - 1) / cols, (h - 1) / rows
    for i in range(n):
        j = n - 1 - i  # filled from the bottom, clear of the label
        color = GREEN if j < green else AMBER if j < green + amber else GREY
        cx, cy = x + 1 + (i % cols) * sw, y + 1 + (i // cols) * sh
        out.append(f'<rect x="{cx:.1f}" y="{cy:.1f}" width="{sw - 1:.1f}" height="{sh - 1:.1f}" fill="{color}"/>')
    if w > 34 and h > 16:
        label = name if len(name) * 6.2 < w - 6 else name[:max(1, int((w - 6) / 6.2))]
        out.append(f'<rect x="{x + 1:.1f}" y="{y + 1:.1f}" width="{len(label) * 6.2 + 6:.1f}" height="14" fill="{BG}" opacity="0.75"/>')
        out.append(f'<text x="{x + 4:.1f}" y="{y + 12:.1f}" {FONT} font-size="11" fill="{TEXT}">{escape(label)}</text>')
    return out


def badge(x, y, label, value, color):
    lw, vw = len(label) * 6.6 + 16, len(value) * 6.9 + 16
    return x + lw + vw + 6, [
        f'<rect x="{x}" y="{y}" width="{lw:.0f}" height="22" fill="#555d66"/>',
        f'<rect x="{x + lw:.0f}" y="{y}" width="{vw:.0f}" height="22" fill="{color}"/>',
        f'<text x="{x + 8}" y="{y + 15}" {FONT} font-size="12" fill="#fff">{escape(label)}</text>',
        f'<text x="{x + lw + 8:.0f}" y="{y + 15}" {FONT} font-size="12" fill="#fff">{escape(value)}</text>']


def bar(x, y, label, value, total, color, text=None):
    width, share = 170, (value / total if total else 0)
    return [
        f'<text x="{x}" y="{y + 9}" {FONT} font-size="11" fill="{TEXT}">{escape(label)}</text>',
        f'<rect x="{x + 140}" y="{y}" width="{width}" height="10" fill="{GREY}"/>',
        f'<rect x="{x + 140}" y="{y}" width="{max(share * width, 1 if value else 0):.1f}" height="10" fill="{color}"/>',
        f'<text x="{x + 140 + width + 74}" y="{y + 9}" {FONT} font-size="11" fill="{TEXT}" text-anchor="end">{escape(text or f"{value}/{total}")}</text>']


def main():
    config.options(__doc__)
    report = config.BUILD / "report.json"
    if not report.exists():
        raise SystemExit("run tools/progress.py first")
    records = json.loads(report.read_text(encoding="utf-8"))
    sizes = modules()
    done, hack, count = dict.fromkeys(sizes, 0), dict.fromkeys(sizes, 0), {}
    for r in records:
        module = r["where"].split(":")[0] if ":" in r["where"] else "code.bin"
        module = module[:-4] if module.endswith(".cro") else module
        count[r["status"]] = count.get(r["status"], 0) + 1
        if r["status"] == "match":
            done[module] = done.get(module, 0) + r["bytes"]
        elif r["status"] == "hack":
            hack[module] = hack.get(module, 0) + r["bytes"]
    total, matched, hacked = sum(sizes.values()), sum(done.values()), sum(hack.values())
    percent = 100 * matched / total
    known = functable.counted()[0]

    W, H = 872, 470
    svg = [f'<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{H}" viewBox="0 0 {W} {H}">',
           f'<rect width="{W}" height="{H}" fill="{BG}"/>']
    x = 14
    for label, value, color in (("matched", f"{percent:.4f}%" if percent < 1 else f"{percent:.2f}%", GREEN if matched else GREY),
                                ("functions matched", f"{count.get('match', 0):,} / {known:,}" if known else str(count.get("match", 0)),
                                 GREEN if matched else GREY),
                                ("matched by a trick", str(count.get("hack", 0)), AMBER if count.get("hack") else GREY)):
        x, parts = badge(x, 14, label, value, color)
        svg += parts
    svg.append(f'<text x="14" y="62" {FONT} font-size="13" fill="{TEXT}">Game code ({config.VERSION}): {percent:.4f}% '
               f'({matched:,} of {total:,} bytes, {len(sizes)} modules)</text>')
    order = sorted(sizes.items(), key=lambda kv: -kv[1])
    for name, cx, cy, cw, ch in squarify(order, 14, 70, 440, 384):
        svg += cell(name, cx, cy, cw, ch, done.get(name, 0), hack.get(name, 0), sizes[name])

    bx, by = 474, 62
    svg.append(f'<text x="{bx}" y="{by}" {FONT} font-size="13" fill="{TEXT}">Functions in src/ by state ({len(records)})</text>')
    by += 12
    for label, key, color in (("Matched", "match", GREEN), ("Matched by a trick", "hack", AMBER),
                              ("Relocation unchecked", "match?", BLUE), ("Differs", "differ", DIM), ("Does not compile", "error", DIM)):
        svg += bar(bx, by, label, count.get(key, 0), len(records), color)
        by += 18
    by += 22
    svg.append(f'<text x="{bx}" y="{by}" {FONT} font-size="13" fill="{TEXT}">Largest modules (bytes matched)</text>')
    by += 12
    for name, size in order[:12]:
        svg += bar(bx, by, name, done.get(name, 0), size, GREEN, f"{done.get(name, 0):,}/{size // 1024:,}K")
        by += 18
    by += 16
    svg.append(f'<text x="{bx}" y="{by}" {FONT} font-size="11" fill="{DIM}">Counted by tools/progress.py with the game\'s compiler:</text>')
    svg.append(f'<text x="{bx}" y="{by + 15}" {FONT} font-size="11" fill="{DIM}">every byte equal, every call and address checked.</text>')
    svg.append("</svg>")
    out = config.ROOT / "docs" / "status.svg"
    out.write_text("\n".join(svg), encoding="utf-8", newline="\n")

    history = config.ROOT / "docs" / "history.csv"
    line = f"{matched},{count.get('match', 0)},{hacked},{count.get('hack', 0)},{total}"
    old = history.read_text(encoding="utf-8").splitlines() if history.exists() else ["date,version,matched_bytes,matched_functions,hack_bytes,hack_functions,total_bytes"]
    if not old[-1].endswith(line):
        old.append(f"{datetime.date.today().isoformat()},{config.VERSION},{line}")
        history.write_text("\n".join(old) + "\n", encoding="utf-8", newline="\n")
    print(f"{out}: {percent:.4f}% ({matched:,} of {total:,} bytes), {count.get('match', 0)} matched, {count.get('hack', 0)} by a trick")


if __name__ == "__main__":
    main()
