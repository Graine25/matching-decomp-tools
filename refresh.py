"""runs the tools in their order, once, and says how long each took.

  python -I tools/refresh.py            # after new sources: progress, twins, progress, honest, status,
                                        # then progress against each other version
  python -I tools/refresh.py --derive   # after a change to a tool or to config/: classify, fields, enums, callers,
                                        # headers, bounds and the generators first
  python -I tools/refresh.py --table    # after the table changes (needs the Ghidra server, see
                                        # functable.py): functable, rtti, ctors, then --derive

each step is the tool as you would run it by hand; this only spares the typing and the
mistakes of order. a step that fails stops the run. the last lines of each are printed.
"""
import os
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import config

TABLE = [("functable.py",), ("rtti.py",), ("ctors.py",)]
DERIVE = [("classify.py",), ("fields.py",), ("enums.py",), ("callers.py",), ("headers.py",), ("bounds.py",), ("progress.py",), ("tiny.py", "--max", "64")]
ALWAYS = [("progress.py",), ("twins.py", "--apply"), ("copies.py", "--apply"), ("progress.py",), ("honest.py",), ("status.py",)]
# then the other versions: the same sources against each (their reports in build/<version>/)
OTHERS = [(("progress.py",), version) for version in config.GAME_VERSIONS if version != config.MAIN]


def main():
    config.options(__doc__, "--derive", "--table")
    steps = (TABLE if "--table" in sys.argv else []) + (DERIVE if "--table" in sys.argv or "--derive" in sys.argv else []) + ALWAYS
    tools = Path(__file__).resolve().parent
    began = time.time()
    for step, version in [(s, config.MAIN) for s in steps] + OTHERS:
        t = time.time()
        env = dict(os.environ, MATCH_VERSION=version)
        r = subprocess.run([sys.executable, "-I", str(tools / step[0]), *step[1:]], cwd=config.ROOT, capture_output=True,
                           text=True, env=env)
        lines = (r.stdout + r.stderr).strip().splitlines()
        print(f"== {' '.join(step)}{'' if version == config.MAIN else ' (' + version + ')'}  ({time.time() - t:.0f} s)")
        for line in lines[-3:]:
            print("   " + line[:220])
        if r.returncode:
            raise SystemExit(f"{step[0]} failed: stopped")
    print(f"done in {time.time() - began:.0f} s")


if __name__ == "__main__":
    main()
