# matching-decomp-tools: instructions for AI agents

Tools for byte-matching decompilations of armcc-built ARM games (`README.md` lists every tool).
This file is for an agent that helps someone (a) set up a decomp project to use the tools,
(b) work in one, or (c) change the tools. The project's own instructions (its `CLAUDE.md`,
`AGENTS.md` or `CONTRIBUTING.md`) come first for anything about its sources.

## Setting up a project

A decomp project is a folder with a `project.toml` at its root; the tools are its `tools/`
folder (a git submodule, or a link to a checkout of this repository). Run every tool from the
project's root, always as `python -I tools/<tool>.py` (`-I`: no module from the current folder
or the environment is picked up).

1. **Python 3.10 or later** and `pip install capstone` (version 5). The core tools need nothing
   else (the check cache is the standard library's `sqlite3`).
2. **The compiler.** The armcc builds of [decompme/compilers](https://github.com/decompme/compilers):
   unpack `armcc.zip` of its `compilers` release into `toolchain/armcc/`, so that
   `toolchain/armcc/<version>/<build>/bin/armcc.exe` exists for the build `project.toml`'s
   `[compiler] default` names. Windows only for now: the tools run `armcc.exe` directly and do
   not call Wine.
3. **The game.** The person's own copy, decrypted and extracted, in `orig/<version>/` for every
   version in `[versions]`: `exheader.bin`, `exefs/code.bin`, `romfs/*.cro` (and `static.crs`)
   for a 3DS game. Check the SHA-256 the project gives. Never fetch, ask for or accept the
   game's files from anywhere else: if `orig/` is missing, stop and say so.
4. **What the tools derive.** `python -I tools/refresh.py --derive` writes, from that copy,
   what is not kept in git (the generated sources in `src/<program>/generated/`, the reports
   in `build/`) and rewrites the generated headers, then checks every source. The first run
   compiles everything (minutes); later runs reuse `build/<version>/check_cache.sqlite`.
5. **Check it works.** `python -I tools/match.py show <address>` prints the game's code;
   `python -I tools/match.py check <a source> <its address>` on a source the project says is
   matched prints `MATCH`; `python -I tools/progress.py` gives the project's published count.

Optional, none needed to write and check sources:

Their paths are one person's machine: they go in `project.local.toml` beside `project.toml`
(kept out of git; its keys take the place of `project.toml`'s, section by section).

| What | For | Where |
| --- | --- | --- |
| [objdiff](https://github.com/encounter/objdiff) | `objexport.py --report`, a viewer | `toolchain/objdiff/objdiff-cli-windows-x86_64.exe` |
| Ghidra 12 with pyghidra (and the JDK its release asks for) | `functable.py`, rebuilding the function table; `local/ghidra_server.py` | `[paths] ghidra_install`, `ghidra_project`; `[ghidra] name`, `port` |
| IDA 9 with idalib (Python 3.12) | `local/ida.py`, Hex-Rays' C as a reference | `[paths] ida_databases` (default `build/ida`) |
| [m2c](https://github.com/matt-kempster/m2c) | `local/m2cref.py`, a reference | `[paths] m2c`, or `M2C` |

Environment: `MATCH_PROJECT` (the project's folder, when not run from it), `MATCH_VERSION` (check
against another version), `MATCH_CC` (another compiler build, for experiments only),
`MATCH_GHIDRA_PROJECT`, `MATCH_GHIDRA_PORT`.

Common problems:
- `no project.toml here or above`: run from the project's root, or set `MATCH_PROJECT`.
- armcc not found: the build's folder must be `toolchain/armcc/<version>/<build>/bin/`.
- A count lower than the project's: `refresh.py --derive` was not run (the generated sources
  are missing) or `orig/` is another version of the game (check the SHA-256).
- A result that looks stale: deleting `build/<version>/check_cache.sqlite` is always safe; it
  changes no result, it only costs the compiles again.

## Rules for any work

- Matched means `match.py` prints `MATCH`. `HACK`, `MATCH?` and `DIFFER` are not matches, and a
  diff that looks equal is not one either.
- No tricks: nothing written only to get past a check (`honest.py` lists what it finds), no
  special case for one function, no weakening of the judge.
- Nothing of the game in this repository, nor in what a tool writes to a project's kept folders
  (`config/`, `src/`, `include/`): addresses, sizes and names only, never bytes, assembly or
  tables. What a tool derives from the game's code goes to `build/` or
  `src/<program>/generated/`, both outside git. A decompiler's output is a reference, never a
  source.
- The only inputs are the person's copy of the game and public tools.

## Changing the tools

- They know no game: a project's versions, compiler, flags, libraries and paths are in its
  `project.toml` (`project.example.toml`). A tool that needs a new fact of a project reads it
  from there.
- Each tool starts with a docstring that says what it does and how to run it, and stops on an
  argument it does not know (`config.options`). Comments in lowercase, short sentences.
- Edit with an editor tool or a Python script; never a shell heredoc that holds a backslash.
- Checks go through `match.py`'s cache (`check_many`, `check_parallel`); a generator writes a
  file only when it is needed.
- After a change, in a project: `python -I tools/refresh.py --derive`; the number of matched
  functions must not move unless the change is meant to move it, and no function may be lost
  (compare `build/<version>/report.json` before and after).
- A new tool gets a row in `README.md`. Code from elsewhere only under a license compatible with
  MIT and credited in `README.md`, "Credits"; GPL programs (m2c) are run as outside programs,
  never copied in.
