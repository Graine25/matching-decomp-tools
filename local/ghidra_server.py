"""A Ghidra that stays open, for reading and naming the game's code quickly.

The headless scripts open the project from scratch each time (a minute or
two); this keeps it open in one process and answers over a local socket in
seconds.

    # once, in the background (needs a venv with pyghidra and JDK 25; here: ports/Solstice/build/pyghidra-venv)
    ports/Solstice/build/pyghidra-venv/Scripts/python -I tools/local/ghidra_server.py serve

    # then, from anywhere, with any Python
    python -I tools/local/ghidra_server.py decompile 0x4025CC
    python -I tools/local/ghidra_server.py decompile Battle.cro:0x1A40
    python -I tools/local/ghidra_server.py callers GameManager_BeginFrame
    python -I tools/local/ghidra_server.py find 'G2DUtil::'
    python -I tools/local/ghidra_server.py rename 0x4025CC GameManager_DrawDisplays

Commands:
    decompile <f>          C of a function, with its callers
    disasm <f> [count]     its instructions
    callers <f>            the functions calling it
    functions <program>    every function: offset, size, name | offsets it calls
    table <program>        every function: offset, end, size, arm/thumb, thunk, name
    words <address> [n]    n words there, and where each points
    callees <f>            the functions it calls
    xrefs <address>        what refers to an address, code or data
    find <regex>           functions whose full name matches
    info <f>               name, address, size, prototype
    rename <f> <name>      names it (saved with the project)
    comment <address> <text>  a comment there (saved)
    programs               the programs in the project
    apply <file>           names and relocated words, from cro_names.py (saved)
    types <header> [<program>...]  a header's types into the programs (saved)
    names <file>           our names for functions still f_/FUN_ (saved)
    export <file> [<program>...]  every given name, for IDA (to_ida.py)
    switches [<program>...]  jump tables of the CROs into their functions (saved)
    returns [<program>...]   CRO import stubs taken for no-return, fixed (saved)
    signatures <file>      lines `<program> <offset> <C prototype>`: the
                           function there gets that name and prototype,
                           with the types already in the program (saved)
    stop                   ends the server

<f> is a hex address in the executable, <module>.cro:<hex offset> for one in
a module, or a function's name (or a part of it, when only one matches).
The server is the project's only user while it runs: stop it before
running the headless scripts.
"""

import json
import os
import re
import socket
import sys

# a copy of decomp-tools' ghidra/ghidra_server.py (b610ae7 plus the table command), with
# the paths its paths.py gave written here. the Ghidra project itself is not copied: it is
# a database of the game, in the folder MATCH_GHIDRA_PROJECT names.
_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(_HERE))
import config                       # the decomp: project.toml's [paths] and [ghidra]
_PATHS = config.PATHS
PROJECT_ROOT = os.environ.get("MATCH_GHIDRA_PROJECT", str(_PATHS.get("ghidra_project", config.ROOT)))
WORKSPACE = os.environ.get("MATCH_WORKSPACE", str(_PATHS.get("workspace", config.ROOT)))

HOST = "127.0.0.1"
PORT = int(os.environ.get("MATCH_GHIDRA_PORT", str(config.PROJECT.get("ghidra", {}).get("port", 18970))))
ROOT = str(WORKSPACE)
GHIDRA = os.environ.get("GHIDRA_INSTALL_DIR", str(_PATHS.get("ghidra_install", "")))
PROJECT_DIR = os.path.join(str(PROJECT_ROOT), "build", "ghidra")
PROJECT = config.PROJECT.get("ghidra", {}).get("name", "project")
EXECUTABLE = "code.bin"
DEFAULT_JAVA = r"C:\Program Files\Eclipse Adoptium\jdk-25.0.4.101-hotspot"


# --- the client ---

def query(args):
    """the server's answer to a command, as text"""
    try:
        with socket.create_connection((HOST, PORT), timeout=600) as conn:
            conn.sendall((json.dumps(args) + "\n").encode())
            data = b""
            while chunk := conn.recv(65536):
                data += chunk
    except ConnectionRefusedError:
        sys.exit("no Ghidra server on port %d; start it with: "
                 "ports/Solstice/build/pyghidra-venv/Scripts/python -I tools/local/ghidra_server.py serve" % PORT)
    return data.decode("utf-8", "replace")


def ask(args):
    sys.stdout.write(query(args))


# --- the server ---

class Server:
    def __init__(self):
        import pyghidra
        os.environ.setdefault("JAVA_HOME", DEFAULT_JAVA)
        pyghidra.start(install_dir=GHIDRA)
        from ghidra.app.decompiler import DecompInterface
        from ghidra.util.task import ConsoleTaskMonitor
        self.pyghidra = pyghidra
        self.DecompInterface = DecompInterface
        self.monitor = ConsoleTaskMonitor()
        self.project = pyghidra.open_project(PROJECT_DIR, PROJECT)
        self.paths = {}  # program name -> project path
        self._walk(self.project.getProjectData().getRootFolder())
        self.programs = {}  # name -> (program, consumer, decompiler)

    def _walk(self, folder):
        for f in folder.getFiles():
            self.paths[f.getName()] = f.getPathname()
        for sub in folder.getFolders():
            self._walk(sub)

    def program(self, name):
        if name not in self.programs:
            if name not in self.paths:
                raise ValueError(f"no program {name} in the project")
            program, consumer = self.pyghidra.consume_program(self.project, self.paths[name])
            decompiler = self.DecompInterface()
            decompiler.openProgram(program)
            self.programs[name] = (program, consumer, decompiler)
        return self.programs[name]

    # where <f> points

    def resolve(self, text):
        """the program and the function (or address) a target names"""
        m = re.fullmatch(r"(?:(\w+\.cro):)?(?:0x)?([0-9A-Fa-f]+)", text)
        if m and (m.group(1) or len(m.group(2)) >= 5 or text.startswith("0x")):
            name = m.group(1) or EXECUTABLE
            program = self.program(name)[0]
            address = program.getAddressFactory().getDefaultAddressSpace().getAddress(int(m.group(2), 16))
            return name, program, address
        found = self._by_name(text)
        if len(found) != 1:
            names = "\n".join(f"  {n} {f.getName(True)} {f.getEntryPoint()}" for n, f in found[:40])
            raise ValueError(f"{len(found)} functions match {text!r}" + ("\n" + names if found else ""))
        name, function = found[0]
        return name, self.program(name)[0], function.getEntryPoint()

    def _by_name(self, text, programs=None):
        found = []
        pattern = re.compile(re.escape(text))
        for name in programs or [EXECUTABLE]:
            program = self.program(name)[0]
            for function in program.getFunctionManager().getFunctions(True):
                full = function.getName(True)
                if full == text or function.getName() == text:
                    return [(name, function)]
                if pattern.search(full):
                    found.append((name, function))
        return found

    def function(self, text):
        name, program, address = self.resolve(text)
        function = program.getFunctionManager().getFunctionContaining(address)
        if function is None:
            raise ValueError(f"no function at {address} in {name}")
        return name, program, function

    # commands

    def cmd_programs(self):
        return "\n".join(sorted(self.paths.values())) + "\n"

    def cmd_info(self, target):
        name, program, f = self.function(target)
        return (f"{name} {f.getName(True)} at {f.getEntryPoint()}, {f.getBody().getNumAddresses()} bytes\n"
                f"{f.getPrototypeString(True, False)}\n")

    def cmd_decompile(self, target):
        name, program, f = self.function(target)
        decompiler = self.program(name)[2]
        result = decompiler.decompileFunction(f, 120, self.monitor)
        if not result.decompileCompleted():
            return f"could not decompile: {result.getErrorMessage()}\n"
        callers = sorted({c.getName(True) + "@" + str(c.getEntryPoint()) for c in f.getCallingFunctions(self.monitor)})
        head = (f"/* {name} {f.getName(True)} at {f.getEntryPoint()}, {f.getBody().getNumAddresses()} bytes;"
                f" called from: {', '.join(callers) or 'nothing found (virtual?)'} */\n")
        return head + result.getDecompiledFunction().getC()

    def cmd_disasm(self, target, count="200"):
        name, program, f = self.function(target)
        listing = program.getListing()
        out = []
        for i, ins in enumerate(listing.getInstructions(f.getBody(), True)):
            if i >= int(count):
                break
            out.append(f"{ins.getAddress()}  {ins}")
        return "\n".join(out) + "\n"

    def cmd_words(self, target, count="1"):
        name, program, address = self.resolve(target)
        memory = program.getMemory()
        out = []
        for i in range(int(count)):
            at = address.add(i * 4)
            word = memory.getInt(at) & 0xFFFFFFFF
            block = memory.getBlock(program.getAddressFactory().getDefaultAddressSpace().getAddress(word))
            where = f" {block.getName()}+{word - block.getStart().getOffset():X}" if block else ""
            out.append(f"{at} {word:08X}{where}")
        return "\n".join(out) + "\n"

    def cmd_functions(self, name):
        """every function of a program: offset, size, the offsets it calls, name"""
        program = self.program(name)[0]
        out = []
        for f in program.getFunctionManager().getFunctions(True):
            called = " ".join(f"{c.getEntryPoint().getOffset():X}" for c in f.getCalledFunctions(self.monitor))
            out.append(f"{f.getEntryPoint().getOffset():X} {f.getBody().getNumAddresses()} {f.getName(True)} | {called}")
        return "\n".join(out) + "\n"

    def cmd_table(self, name):
        """every function of a program: offset, end of its body, bytes of its body, arm/thumb, thunk, name"""
        program = self.program(name)[0]
        context = program.getProgramContext()
        tmode = context.getRegister("TMode")
        out = []
        for f in program.getFunctionManager().getFunctions(True):
            entry, body = f.getEntryPoint(), f.getBody()
            value = context.getRegisterValue(tmode, entry) if tmode else None
            thumb = value is not None and value.getUnsignedValueIgnoreMask().intValue() == 1
            out.append(f"{entry.getOffset():X} {body.getMaxAddress().getOffset() + 1:X} {body.getNumAddresses()} "
                       f"{'thumb' if thumb else 'arm'} {'thunk' if f.isThunk() else '-'} {f.getName(True)}")
        return "\n".join(out) + "\n"

    def cmd_callers(self, target):
        name, program, f = self.function(target)
        return "".join(f"{c.getEntryPoint()} {c.getName(True)}\n" for c in f.getCallingFunctions(self.monitor))

    def cmd_callees(self, target):
        name, program, f = self.function(target)
        return "".join(f"{c.getEntryPoint()} {c.getName(True)}\n" for c in f.getCalledFunctions(self.monitor))

    def cmd_xrefs(self, target):
        name, program, address = self.resolve(target)
        out = []
        for ref in program.getReferenceManager().getReferencesTo(address):
            frm = ref.getFromAddress()
            f = program.getFunctionManager().getFunctionContaining(frm)
            out.append(f"{frm} {ref.getReferenceType()} in {f.getName(True) if f else '-'}")
        return "\n".join(out) + "\n"

    def cmd_find(self, regex, *modules):
        pattern = re.compile(regex)
        out = []
        for name in modules or [EXECUTABLE]:
            program = self.program(name)[0]
            for f in program.getFunctionManager().getFunctions(True):
                if pattern.search(f.getName(True)):
                    out.append(f"{name} {f.getEntryPoint()} {f.getName(True)}")
        return "\n".join(out[:500]) + ("\n... more\n" if len(out) > 500 else "\n")

    def cmd_export(self, path, *modules):
        """every function and label a name was given to (not FUN_/f_/LAB_),
        as `<program> <address> <full name>` lines in path, for another tool
        (IDA: tools/ghidra/to_ida.py)"""
        from ghidra.program.model.symbol import SymbolType
        default = re.compile(r"(FUN|f|t|LAB|DAT|PTR|thunk_FUN|switchD|caseD|s|u)_[0-9A-Fa-f_]+$|^(PTR_|DAT_|LAB_|switchD_|caseD_)")
        count = 0
        with open(path, "w", encoding="utf-8") as out:
            for name in modules or [EXECUTABLE]:
                program = self.program(name)[0]
                for symbol in program.getSymbolTable().getAllSymbols(True):
                    if symbol.getSymbolType() not in (SymbolType.FUNCTION, SymbolType.LABEL):
                        continue
                    full = symbol.getName(True)
                    if default.search(symbol.getName()) or not symbol.getAddress().isMemoryAddress():
                        continue
                    out.write(f"{name} {symbol.getAddress()} {full}\n")
                    count += 1
        return f"{count} names -> {path}\n"

    def _save(self, program, why, change):
        transaction = program.startTransaction(why)
        try:
            change()
        finally:
            program.endTransaction(transaction, True)
        program.save(why, self.monitor)

    def cmd_rename(self, target, new_name):
        from ghidra.program.model.symbol import SourceType
        name, program, f = self.function(target)
        old = f.getName(True)
        self._save(program, f"rename {old}", lambda: f.setName(new_name, SourceType.USER_DEFINED))
        return f"{old} -> {f.getName(True)}\n"

    def cmd_comment(self, target, *words):
        from ghidra.program.model.listing import CodeUnit
        name, program, address = self.resolve(target)
        text = " ".join(words)
        self._save(program, "comment", lambda: program.getListing().setComment(address, CodeUnit.PLATE_COMMENT, text))
        return f"comment at {address}\n"

    def cmd_apply(self, path):
        """lines of cro_names.py: `word <program> <offset> <value>` writes a
        relocated word, `name <program> <offset> <symbol>` names (and makes,
        when there is none) the function there, demangled, or labels data"""
        from ghidra.app.util import NamespaceUtils
        from ghidra.program.model.data import PointerDataType
        from ghidra.app.util.demangler import DemanglerOptions, DemanglerUtil
        from ghidra.util.task import TaskMonitor
        from ghidra.program.model.address import AddressSet
        from ghidra.program.model.symbol import SourceType
        by_program = {}
        for line in open(path, encoding="utf-8"):
            parts = line.split()
            if len(parts) == 4 and parts[0] in ("word", "name"):
                by_program.setdefault(parts[1], []).append(parts)
        report = []
        for name, actions in sorted(by_program.items()):
            if name not in self.paths:
                continue
            program = self.program(name)[0]
            space = program.getAddressFactory().getDefaultAddressSpace()
            memory, functions, symbols = program.getMemory(), program.getFunctionManager(), program.getSymbolTable()
            listing = program.getListing()
            done = {"word": 0, "name": 0, "failed": 0}

            def change():
                for kind, _, offset, value in actions:
                    address = space.getAddress(int(offset, 16))
                    try:
                        if kind == "word":
                            memory.setInt(address, int(value, 16))
                            # a pointer, so the decompiler shows what it points at
                            if listing.getInstructionAt(address) is None:
                                listing.clearCodeUnits(address, address.add(3), False)
                                listing.createData(address, PointerDataType())
                        else:
                            function = functions.getFunctionAt(address)
                            if function is None and value.startswith(("_Z", "__aeabi", "nn", "static_", "_")) and not value.startswith("ptr_"):
                                function = functions.createFunction(value, address, AddressSet(address, address.add(7)), SourceType.IMPORTED)
                            demangled = None if value.startswith("ptr_") else DemanglerUtil.demangle(program, value, address)
                            short, namespace = value, program.getGlobalNamespace()
                            if demangled:
                                short = demangled[0].getName()
                                if demangled[0].getNamespace() is not None:
                                    namespace = NamespaceUtils.createNamespaceHierarchy(
                                        demangled[0].getNamespace().getNamespaceString(), None, program, SourceType.USER_DEFINED)
                            if function is not None:
                                # over the f_/FUN_ names the importer gave, not over ours
                                if re.fullmatch(r"(f|t|FUN)_[0-9A-Fa-f]{8}", function.getName()) or function.getName() == short:
                                    function.setParentNamespace(namespace)
                                    function.setName(short, SourceType.USER_DEFINED)
                                if demangled:
                                    try:
                                        demangled[0].applyTo(program, address, DemanglerOptions(), TaskMonitor.DUMMY)
                                    except Exception:
                                        pass
                            else:
                                symbols.createLabel(address, short, namespace, SourceType.USER_DEFINED)
                        done[kind] += 1
                    except Exception as error:
                        done["failed"] += 1
                        done.setdefault("first", f"{kind} {offset}: {error}")
            self._save(program, "cro_names", change)
            report.append(f"{name}: {done['word']} words, {done['name']} names, {done['failed']} failed"
                          + (f" (first: {done['first']})" if "first" in done else ""))
        return "\n".join(report) + "\n"

    def cmd_types(self, header, *programs):
        """the structs, unions, enums and typedefs of a header of ours
        (decomp/include), into each program's types (saved), so Ghidra's C
        uses what the decomp has found"""
        from ghidra.app.util.cparser.C import CParser
        text = open(header, encoding="utf-8").read()
        # what the C parser does not take: include guards and our macros
        kept, directive = [], False
        for line in text.splitlines():
            # a directive, and the lines a backslash carries it on to
            if directive or line.lstrip().startswith("#"):
                directive = line.rstrip().endswith("\\")
                continue
            kept.append(line)
        text = "\n".join(kept)
        out = []
        for name in programs or [EXECUTABLE]:
            program = self.program(name)[0]
            manager = program.getDataTypeManager()
            before = manager.getDataTypeCount(True)
            def change():
                parser = CParser(manager, True, None)
                parser.parse(text)
            self._save(program, "types", change)
            out.append(f"{name}: {manager.getDataTypeCount(True) - before} new types from {header}")
        return "\n".join(out) + "\n"

    def cmd_switches(self, *programs):
        """the jump tables of `cmp rX,#n; ldrcc pc,[pc,rX,lsl #2]`: a CRO's
        are relocated words, written after the analysis (apply), so Ghidra
        made each case a function of its own and cut the function at the
        jump. Each case becomes a target of the jump again, the case
        functions go, and the function takes them back (saved)"""
        from ghidra.app.cmd.function import CreateFunctionCmd
        from ghidra.app.cmd.disassemble import DisassembleCommand
        from ghidra.program.model.data import PointerDataType
        from ghidra.program.model.symbol import RefType, SourceType
        from ghidra.util.task import TaskMonitor
        report = []
        for name in programs or sorted(self.paths):
            program = self.program(name)[0]
            listing, memory = program.getListing(), program.getMemory()
            functions, references = program.getFunctionManager(), program.getReferenceManager()
            done = {"tables": 0, "cases": 0, "merged": 0}

            def change():
                owners = set()
                for instruction in list(listing.getInstructions(True)):
                    text = instruction.toString()
                    if not re.fullmatch(r"ldrcc pc,\[pc,r\d+,lsl #0x2\]", text):
                        continue
                    compare = instruction.getPrevious()
                    m = compare and re.fullmatch(r"cmp r\d+,#(0x[0-9a-f]+|\d+)", compare.toString())
                    if not m:
                        continue
                    count, table = int(m.group(1), 0), instruction.getAddress().add(8)
                    if count > 512:
                        continue
                    targets = [table.getNewAddress(memory.getInt(table.add(4 * i)) & 0xFFFFFFFF) for i in range(count)]
                    if not all(memory.contains(t) for t in targets):
                        continue
                    listing.clearCodeUnits(table, table.add(4 * count - 1), False)
                    for i, target in enumerate(targets):
                        listing.createData(table.add(4 * i), PointerDataType())
                        references.addMemoryReference(instruction.getAddress(), target, RefType.COMPUTED_JUMP,
                                                      SourceType.ANALYSIS, 0)
                        DisassembleCommand(target, None, True).applyTo(program, TaskMonitor.DUMMY)
                        case = functions.getFunctionAt(target)
                        # only the importer's names: a case someone named is left
                        if case is not None and re.fullmatch(r"(f|t|FUN)_[0-9A-Fa-f]{8}", case.getName()):
                            functions.removeFunction(target)
                            done["cases"] += 1
                    done["tables"] += 1
                    owner = functions.getFunctionContaining(instruction.getAddress())
                    if owner is not None:
                        owners.add(owner.getEntryPoint())
                for entry in owners:
                    # an owner that was itself a case is gone, taken by its own owner
                    owner = functions.getFunctionAt(entry)
                    if owner is not None:
                        CreateFunctionCmd.fixupFunctionBody(program, owner, TaskMonitor.DUMMY)
                        done["merged"] += 1
            self._save(program, "switches", change)
            if done["tables"]:
                report.append(f"{name}: {done['tables']} tables, {done['cases']} case functions removed, "
                              f"{done['merged']} functions refitted")
        return "\n".join(report) + "\n"

    def cmd_returns(self, *programs):
        """the import stubs Ghidra took for functions that never return (a
        stub's word was filled in after the analysis): they return, the code
        after each call to them is disassembled, and the callers take it back
        (saved); the game's own aborts keep their mark"""
        from ghidra.app.cmd.disassemble import DisassembleCommand
        from ghidra.app.cmd.function import CreateFunctionCmd
        from ghidra.util.task import TaskMonitor
        from ghidra.program.model.listing import FlowOverride
        keep = re.compile(r"abort|panic|assert|terminate|exit|halt|fatal", re.I)
        report = []
        for name in programs or sorted(n for n in self.paths if n.endswith(".cro")):
            program = self.program(name)[0]
            functions, references = program.getFunctionManager(), program.getReferenceManager()
            listing = program.getListing()
            done = {"stubs": 0, "callers": 0}

            def change():
                callers = set()
                for function in list(functions.getFunctions(True)):
                    if not function.hasNoReturn() or keep.search(function.getName(True)):
                        continue
                    if function.getBody().getNumAddresses() > 8:
                        continue
                    function.setNoReturn(False)
                    done["stubs"] += 1
                # every call that Ghidra cut short (a flow override, or no
                # code after it) to a function that returns
                for instruction in list(listing.getInstructions(True)):
                    if not instruction.getFlowType().isCall():
                        continue
                    targets = [functions.getFunctionAt(a) for a in instruction.getFlows()]
                    if not targets or any(f is None or f.hasNoReturn() for f in targets):
                        continue
                    after = instruction.getAddress().add(4)
                    cut = instruction.getFlowOverride() == FlowOverride.CALL_RETURN
                    if not cut and listing.getInstructionAt(after) is not None:
                        continue
                    if cut:
                        instruction.setFlowOverride(FlowOverride.NONE)
                    DisassembleCommand(after, None, True).applyTo(program, TaskMonitor.DUMMY)
                    caller = functions.getFunctionContaining(instruction.getAddress())
                    if caller is not None:
                        callers.add(caller.getEntryPoint())
                for entry in callers:
                    caller = functions.getFunctionAt(entry)
                    if caller is not None:
                        CreateFunctionCmd.fixupFunctionBody(program, caller, TaskMonitor.DUMMY)
                        done["callers"] += 1
            self._save(program, "returns", change)
            if done["stubs"] or done["callers"]:
                report.append(f"{name}: {done['stubs']} stubs return, {done['callers']} callers refitted")
        return "\n".join(report) + "\n"

    def cmd_signatures(self, path):
        from ghidra.app.cmd.function import ApplyFunctionSignatureCmd, CreateFunctionCmd
        from ghidra.app.util.cparser.C import CParser
        from ghidra.program.model.symbol import SourceType
        from ghidra.util.task import TaskMonitor
        by_program = {}
        for line in open(path, encoding="utf-8"):
            parts = line.split(None, 2)
            if len(parts) == 3 and parts[0] in self.paths:
                by_program.setdefault(parts[0], []).append((int(parts[1], 16), parts[2].strip()))
        report = []
        for name, lines in sorted(by_program.items()):
            program = self.program(name)[0]
            space = program.getAddressFactory().getDefaultAddressSpace()
            functions = program.getFunctionManager()
            done = {"applied": 0, "kept": 0, "failed": 0}

            def change():
                parser = CParser(program.getDataTypeManager())
                for offset, prototype in lines:
                    address = space.getAddress(offset)
                    function = functions.getFunctionAt(address)
                    try:
                        if function is None and functions.getFunctionContaining(address) is None:
                            # code the analysis never reached: a function of its own
                            CreateFunctionCmd(address).applyTo(program, TaskMonitor.DUMMY)
                            function = functions.getFunctionAt(address)
                        if function is None:
                            raise ValueError("no function starts there")
                        definition = parser.parse(prototype)
                        # our own names stay; f_/FUN_ ones and earlier svc names give way
                        if not re.fullmatch(r"(f|t|FUN)_[0-9A-Fa-f]{8}|svc\w*", function.getName()):
                            done["kept"] += 1
                            continue
                        function.setName(definition.getName(), SourceType.USER_DEFINED)
                        ApplyFunctionSignatureCmd(address, definition, SourceType.USER_DEFINED).applyTo(program, TaskMonitor.DUMMY)
                        done["applied"] += 1
                    except Exception as error:
                        done["failed"] += 1
                        done.setdefault("first", f"{offset:08X}: {error}")
            self._save(program, "signatures", change)
            report.append(f"{name}: {done['applied']} applied, {done['kept']} kept, {done['failed']} failed"
                          + (f" (first: {done['first']})" if "first" in done else ""))
        return "\n".join(report) + "\n"

    def cmd_names(self, path):
        """lines `<program> <offset> <name>` (decomp.py writes them from the
        decomp's sources): each function still named f_/FUN_ gets ours"""
        from ghidra.program.model.symbol import SourceType
        done, kept = 0, 0
        for line in open(path, encoding="utf-8"):
            parts = line.split()
            if len(parts) != 3 or parts[0] not in self.paths:
                continue
            program = self.program(parts[0])[0]
            address = program.getAddressFactory().getDefaultAddressSpace().getAddress(int(parts[1], 16))
            function = program.getFunctionManager().getFunctionAt(address)
            if function is None or not re.fullmatch(r"(f|t|FUN)_[0-9A-Fa-f]{8}", function.getName()):
                kept += 1
                continue
            self._save(program, "names", lambda: function.setName(parts[2], SourceType.USER_DEFINED))
            done += 1
        return f"{done} named, {kept} kept their names\n"

    def handle(self, args):
        if not args:
            return __doc__
        command = getattr(self, "cmd_" + args[0], None)
        if command is None:
            return f"no command {args[0]}\n" + __doc__
        try:
            return command(*args[1:])
        except Exception as error:  # the answer, not the server's end
            return f"error: {error}\n"

    def serve(self):
        with socket.create_server((HOST, PORT)) as listener:
            print(f"Ghidra server on {HOST}:{PORT}, {len(self.paths)} programs", flush=True)
            while True:
                conn, _ = listener.accept()
                with conn:
                    line = b""
                    while not line.endswith(b"\n"):
                        chunk = conn.recv(65536)
                        if not chunk:
                            break
                        line += chunk
                    args = json.loads(line or b"[]")
                    if args[:1] == ["stop"]:
                        conn.sendall(b"stopping\n")
                        break
                    conn.sendall(self.handle(args).encode("utf-8", "replace"))
        for program, consumer, decompiler in self.programs.values():
            decompiler.dispose()
            program.release(consumer)
        self.project.close()


if __name__ == "__main__":
    if sys.argv[1:2] == ["serve"]:
        Server().serve()
    else:
        ask(sys.argv[1:])
