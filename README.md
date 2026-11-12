# matching-decomp-tools

Tools for byte-matching decompilations of ARM games built with armcc (ARM's C/C++ compiler),
first made for Pokémon Ultra Sun and Ultra Moon (3DS). The compiler is the judge: a function is
matched when armcc turns its source into the game's bytes.

The tools hold no game data. They work on a decomp project: the folder with a `project.toml`
(the current folder or one above it, or the one `MATCH_PROJECT` names). Use them as that
project's `tools/` folder (a git submodule), and run them from the project's root:

```sh
python -I tools/match.py check src/main/Foo.cpp 0x003D6790 --sym sub_003D6790
python -I tools/refresh.py            # the whole chain, after new sources
```

## The project they work on

```
project.toml          versions, compiler, flags, libraries (see project.example.toml)
orig/<version>/       the game's files, your own copy: exefs/code.bin, exheader.bin, romfs/*.cro
toolchain/armcc/      the compilers (decomp.me's armcc builds)
config/<version>/     the tables the tools write and read (functions.csv, classes.csv, ...)
src/, include/        the decomp
build/                what the tools write that is not kept
```

## The tools

The judge and the chain:

| Tool | What |
| --- | --- |
| `match.py` | compiles a source and compares a function with the game's: relocations checked by symbol, the linker's own changes modelled (a call to an empty function is a NOP, to a one-instruction one that instruction, a tail call to the next function a NOP), C1/D1 as C2/D2, `_ZTV` vtables and virtual destructors (D0, D1/D2) from the RTTI's vtables, Thumb |
| `honest.py` | finds the tricks a source can reach the bytes with (weak, volatile, asm, goto, a vtable stored by hand...) |
| `progress.py`, `status.py`, `refresh.py` | every `//!` function checked (cached), the progress picture, the chain in order |
| `versions.py` | maps another version of the game onto the main one, function by function |
| `objexport.py` | objects for [objdiff](https://github.com/encounter/objdiff): each source compiled (base), and the game's functions it names as an object of their own (target: the bytes, the base's symbol and section names, the relocations the linker resolved put back); `objdiff.json`, and `--report` runs `objdiff-cli report` |

The function table:

| Tool | What |
| --- | --- |
| `functable.py` | the function table from a Ghidra project (needs `local/ghidra_server.py`) |
| `tailstarts.py` | starts hidden by a tail call the linker made a NOP |
| `unreached.py` | starts hidden after code the function before never reaches |
| `bounds.py` | the scope of unnamed functions from the order of the names (armlink sorts sections) |

The structure, from the game's own code and RTTI:

| Tool | What |
| --- | --- |
| `rtti.py`, `ctors.py`, `classify.py` | classes and vtables from the RTTI, who writes each vtable, each function's class, slot, method and library (a slot pair is the destructor when the second one's last word is the tail call that frees the object) |
| `fields.py` | data members from how functions use `this`; pointers typed by what they are passed to; objects inside |
| `enums.py`, `callers.py`, `slotargs.py` | enums and their sizes from the callers; return types from what callers do; a function's parameters from what it reads |
| `typecontext.py` | a C context of the classes for a decompiler (m2c, IDA, Ghidra): a struct per class with its members, its vtable as a struct of the slots' names, prototypes with `this` typed and as many parameters as the code reads |
| `headers.py` | a header per class: bases, virtual functions by slot, members (offsets checked by the compiler), `X();` when the class has a constructor that reads nothing but `this`; a hand-written header's slots and size followed by the classes built on it |

Writing functions without a person:

| Tool | What |
| --- | --- |
| `tiny.py` | writes small functions from their instructions (paths of conditional branches, calls, calls through import stubs and vtables) and keeps what matches |
| `structors.py` | the virtual destructors and the default constructors from the class's header: `X::~X() {}` / `X::X() {}`, or the body it reads besides what builds or destroys the bases and members (calls on `this`, a member or a global; `delete` of a pointer member; constants stored to members; `if (this->m)` around them); never code that may be an inlined base's; a match also proves the class's bases and members |
| `imports.py` | a call through a module's import stub written as a call to the real function |
| `twins.py`, `copies.py` | a matched source tried at functions with the same code (other constants, other modules) |
| `units.py` | a file per translation unit, from the static initializers |

3DS: `cro.py` (CRO modules: segments, relocations, imports, exports).

`local/`: helpers that need more than the project (`ghidra_server.py`, `ida.py`, `idastarts.py`; both
decompilers take `typecontext.py`'s context: `ida.py c --types DIR`, the server's `typed` command,
applied and never saved; `packets.py` uses IDA's Hex-Rays when its databases are there, else
Ghidra's server), or
that serve agents and people (`packets.py`, `permute.py`, a permuter for C++ sources;
`m2cref.py`, [m2c](https://github.com/matt-kempster/m2c)'s C for a function, a reference only: m2c is
GPL-3.0 and is run as an outside program, nothing of it is in this repository. It gives m2c a C
context made from the project's tables (a struct per class with its members and vtable, prototypes
with `this` typed) and puts the C++ names back in what comes out; its `ctr` target (VFP, floats in
`s` registers) is in a local fork of m2c, `project.toml [paths] m2c`; `ccsweep.py`).

`match.py` keeps every result of a check in `build/<version>/check_cache.sqlite`, by what it
depends on (the source and the headers it includes, the compiler and flags, the functions'
entries, and what the judge reads): a check made again costs no compile. `check_parallel` checks
many sources side by side; the generators (`tiny.py`, `structors.py`, `twins.py`, `units.py`)
use both, and write a candidate's file only when its result is not kept. The file can be
deleted at any time: it changes no result, only saves remaking it.

objdiff shows fewer functions as the same than `match.py` does: it has no model of what the linker
changed (a call the linker made a NOP is a `bl` in the object and a `mov r0, r0` in the game), so
it is a viewer and a report; `match.py` is the judge.

## Needs

Python 3.10 or later, `capstone` 5, the armcc builds of decomp.me in the project's `toolchain/`.
Ghidra 12 with pyghidra for `functable.py`; IDA 9 with idalib for `local/ida.py` (optional).

## Rules the tools keep

No game bytes, assembly or tables in a tool or in what a tool writes to a project's kept folders
(`config/`, `src/`, `include/`): addresses, sizes and names only. Their input is your own copy of
the game and public tools, nothing else.

## License

MIT (`LICENSE`). m2c, which `local/m2cref.py` runs, is GPL-3.0 and is not part of this
repository.
