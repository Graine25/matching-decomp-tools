"""reads a CRO module (or static.crs): segments, exports, and what the loader would
write into it.

a module's pointers are not in its file: each word that holds an address is 0
until the loader fills it, from the internal relocations (addresses inside the
module) and the imports (addresses in the executable or another module). this
gives both as tables, addressed by file offset like the rest of the tools.

layout: 3dbrew, "CRO0". nothing here keeps bytes of the game.
"""
import struct
from pathlib import Path

ABSOLUTE = (2, 10)


class Cro:
    def __init__(self, path):
        self.path = Path(path)
        self.data = self.path.read_bytes()
        if self.data[0x80:0x84] != b"CRO0":
            raise ValueError(f"{path}: not a CRO")
        self.name = self.string(self.u32(0x84))
        self.segments = [struct.unpack_from("<III", self.data, self.u32(0xC8) + 12 * i) for i in range(self.u32(0xCC))]

    def u32(self, at):
        return struct.unpack_from("<I", self.data, at)[0]

    def string(self, at):
        return self.data[at:self.data.index(b"\0", at)].decode("ascii", "replace")

    def tag(self, tag):
        """a segment tag (segment in the low 4 bits, offset above) as an address: a file
        offset in a module, an address of the executable in static.crs."""
        segment, offset = tag & 0xF, tag >> 4
        return self.segments[segment][0] + offset if segment < len(self.segments) else None

    def in_code(self, at):
        start, size, _ = self.segments[0]
        return start <= at < start + size

    def table(self, offset_field, count_field, size):
        start, count = self.u32(offset_field), self.u32(count_field)
        return [start + size * i for i in range(count)]

    def exports(self):
        """{name: address} of the named exports."""
        out = {}
        for entry in self.table(0xD0, 0xD4, 8):
            name, tag = struct.unpack_from("<II", self.data, entry)
            at = self.tag(tag)
            if at is not None:
                out.setdefault(self.string(name), at)
        return out

    def batch(self, at):
        """(target, addend) of each absolute word an import's relocation batch fills."""
        while True:
            tag, kind, last = struct.unpack_from("<IBB", self.data, at)
            addend = self.u32(at + 8)
            target = self.tag(tag)
            if kind in ABSOLUTE and target is not None:
                yield target, addend
            if last:
                return
            at += 12

    def internal(self):
        """{file offset: file offset it points to} of the internal relocations."""
        out = {}
        for entry in self.table(0x128, 0x12C, 12):
            tag, kind, segment = struct.unpack_from("<IBB", self.data, entry)
            target = self.tag(tag)
            if kind in ABSOLUTE and target is not None and segment < len(self.segments):
                out[target] = (self.segments[segment][0] + self.u32(entry + 8)) & 0xFFFFFFFF
        return out

    def imports(self):
        """{file offset: (source, symbol, addend)}: source is None and symbol a name for a named
        import, else source is the exporting module's name and symbol a segment tag of it."""
        out = {}
        for entry in self.table(0x100, 0x104, 8):
            name, batch = struct.unpack_from("<II", self.data, entry)
            for target, addend in self.batch(batch):
                out[target] = (None, self.string(name), addend)
        for entry in self.table(0xF0, 0xF4, 0x14):
            module, indexed, indexed_num, anonymous, anonymous_num = struct.unpack_from("<5I", self.data, entry)
            source = self.string(module)
            for i in range(anonymous_num):
                tag, batch = struct.unpack_from("<II", self.data, anonymous + 8 * i)
                for target, addend in self.batch(batch):
                    out[target] = (source, tag, addend)
        return out


def modules(romfs):
    """{name as the module calls itself: Cro} of a romfs folder, static.crs included."""
    out = {}
    for path in sorted(Path(romfs).glob("*.cro")) + sorted(Path(romfs).glob("static.crs")):
        try:
            cro = Cro(path)
        except (ValueError, struct.error, IndexError):
            continue
        out[cro.name] = cro
    return out
