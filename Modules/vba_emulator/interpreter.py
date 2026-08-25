"""Tree-walking evaluator for the VBA/VBScript AST.

Entry point strategy (mirrors how real macro sandboxes trigger payloads):
top-level statements run in order (the whole program for a .vbs), then any
recognized auto-exec Sub (AutoOpen, Document_Open, Workbook_Open, ...)
found in global scope is invoked too, since a VBA macro typically has no
top-level executable code at all -- everything lives inside one of those
event handlers.
"""

import re
import sys

import vba_emulator.ast_nodes as A
from vba_emulator.errors import VBRuntimeError
from vba_emulator.parser_engine import parse as parse_source
from vba_emulator.builtins_funcs import BUILTINS, VBA_CONSTANTS
from vba_emulator.runtime_support import Environment, ExitSignal, GotoSignal, NativeFunc, ScriptQuit, VBFunction
from vba_emulator.values import (VBArray, VBEmpty, VBNothing, VBNull, check_string_len,
                     is_numeric, to_bool, to_number, to_str)

_AUTOEXEC_NAMES = [
    "autoopen", "auto_open", "autoexec", "autoclose", "auto_close",
    "document_open", "document_close", "documentopen",
    "workbook_open", "workbook_activate", "workbook_beforeclose",
    "main",
]

# VBA's standard library exposes built-ins both as ambient functions and via
# module-qualified names (`VBA.CreateObject`, `VBA.Environ`,
# `Strings.Replace`, `Interaction.Shell`, ...).  These are namespaces, not
# runtime objects, and should resolve to the same global NativeFunc binding.
_BUILTIN_MODULE_QUALIFIERS = {
    "vba", "strings", "interaction", "conversion", "information",
    "filesystem", "dateandtime", "math",
}

_LIKE_SPECIAL = re.compile(r"[.^$+{}()|\\]")
_USERFORM_REFERENCE = re.compile(r"\b(UserForm\d+)\s*\.", re.IGNORECASE)

# VBA/VBScript's own intrinsic types -- a `Dim x As <name>` whose type
# *isn't* one of these is almost certainly a user-defined `Type ... End
# Type` struct (see st_DimStmt).
_VBA_PRIMITIVE_TYPES = {
    "string", "long", "integer", "double", "boolean", "byte", "currency",
    "date", "variant", "single", "object", "longptr", "longlong", "any",
}


def _like_to_regex(pattern):
    out = []
    i, n = 0, len(pattern)
    while i < n:
        ch = pattern[i]
        if ch == "[":
            # VBA charlist group -- [charlist] or negated [!charlist].
            # Previously passed through untouched char-by-char, which
            # happened to produce an equivalent Python class for a plain
            # [a-z] but silently mistranslated VBA's '!'-negation into a
            # literal '!' member of an *unnegated* Python class (e.g.
            # "[!0-9]" meaning "not a digit" in VBA became "'!' or a
            # digit" in Python) -- the opposite result for any pattern
            # using negation.
            close = pattern.find("]", i + 1)
            if close == -1:
                out.append(r"\[")
                i += 1
                continue
            body = pattern[i + 1:close]
            negate = body.startswith("!")
            if negate:
                body = body[1:]
            body = body.replace("\\", "\\\\")
            out.append("[" + ("^" if negate else "") + body + "]")
            i = close + 1
            continue
        if ch == "*":
            out.append(".*")
        elif ch == "?":
            out.append(".")
        elif ch == "#":
            out.append(r"\d")
        elif _LIKE_SPECIAL.match(ch):
            out.append("\\" + ch)
        else:
            out.append(ch)
        i += 1
    return "^" + "".join(out) + "$"


# ------------------------------------------------------- Class support ---
class VBClassTemplate:
    def __init__(self, name, body):
        self.name = name
        self.body = body


class VBClassInstance:
    """Known limitation: a method body resolves unbound names against the
    class instance's own fields/methods, not true module-level globals
    (the scoping model only supports one fallback hop). Custom classes are
    rare in real-world malicious VBA/VBS, which relies overwhelmingly on
    built-in COM objects, so this trade-off keeps the interpreter simple
    without losing much coverage."""

    def __init__(self, interp, template):
        self.interp = interp
        self.template = template
        self.progid = f"class:{template.name}"
        self.env = Environment(is_proc_scope=False)
        for s in template.body:
            if isinstance(s, A.SubDeclStmt):
                self.env.declare(s.name, VBFunction(s.name, s.params, s.body, False))
            elif isinstance(s, A.FunctionDeclStmt):
                self.env.declare(s.name, VBFunction(s.name, s.params, s.body, True))
        field_stmts = [s for s in template.body if not isinstance(s, (A.SubDeclStmt, A.FunctionDeclStmt))]
        interp.exec_block_in_env(field_stmts, self.env)
        init = self.env.vars.get("class_initialize")
        if isinstance(init, VBFunction):
            interp.call_vbfunc_with_env(init, [], self.env)

    def invoke(self, name, args_values):
        method = self.env.vars.get(name.lower())
        if isinstance(method, VBFunction):
            return self.interp.call_vbfunc_with_env(method, args_values, self.env, pre_evaluated=True)
        self.interp.session.ioc.emit("unknown_com_call", progid=self.progid, member=name, kind="call")
        return VBEmpty

    def get_prop(self, name):
        key = name.lower()
        val = self.env.vars.get(key)
        if isinstance(val, VBFunction):
            if val.is_function:
                return self.interp.call_vbfunc_with_env(val, [], self.env)
            return VBEmpty
        if val is not None:
            return val
        self.interp.session.ioc.emit("unknown_com_call", progid=self.progid, member=name, kind="get")
        return VBEmpty

    def set_prop(self, name, value):
        self.env.vars[name.lower()] = value


class Interpreter:
    def __init__(self, session, max_call_depth=200, activex_controls=None, module_names=None,
                 custom_doc_properties=None, custom_xml_parts=None, extra_entry_points=None):
        self.session = session
        self.ioc = self.session.ioc
        self.global_env = Environment(is_proc_scope=False)
        self.env_stack = []
        self.with_stack = []
        self.error_mode = "NONE"
        self.error_label = None
        self.call_depth = 0
        self.max_call_depth = max_call_depth
        # Each VBA call nests several Python frames (eval_call ->
        # call_vbfunc_with_env -> exec_block -> exec_stmt -> st_* ->
        # eval_expr -> ev_CallExpr -> eval_call, plus more for a call
        # inside a larger expression) before max_call_depth's own check
        # can run again. At Python's default limit (1000) that means a
        # raw, uncatchable RecursionError can fire well before
        # max_call_depth is reached, aborting the script instead of
        # raising the intended (and On-Error-Resume-Next-catchable) "Out
        # of stack space" VBRuntimeError. Give it generous headroom.
        #
        # Deeply nested *expressions* (e.g. `x = ((((...))))`) recurse
        # through parser_engine.Parser.parse_expr() instead, at a higher
        # frames-per-level cost than a VBA call (measured empirically: a
        # limit of 3500 -- max_call_depth's own headroom -- already hits a
        # raw RecursionError around 150 levels of parens, well short of
        # the parser's own MAX_EXPR_DEPTH guard (250) ever getting a
        # chance to raise its catchable error instead). Size the limit for
        # whichever of the two needs more room.
        from vba_emulator.parser_engine import Parser as _Parser
        sys.setrecursionlimit(max(
            sys.getrecursionlimit(),
            max_call_depth * 15 + 500,
            _Parser._MAX_EXPR_DEPTH * 40 + 1000,
        ))
        self.warnings = []
        self._error_counts = {}
        self._error_cap = 20
        # Recovered ActiveX form-control values (see activex_extractor.py),
        # e.g. {"TextBox1": "77,90,..."} -- surfaced through
        # ActiveDocument/ThisDocument below.
        self.activex_controls = activex_controls or {}
        # Recovered docProps/custom.xml values (see
        # doc_properties_extractor.py), surfaced through
        # ActiveDocument/ThisDocument.CustomDocumentProperties(name).Value.
        self.custom_doc_properties = custom_doc_properties or {}
        # Recovered customXml/itemN.xml parts (see
        # custom_xml_extractor.py), surfaced through
        # ActiveDocument/ThisDocument.CustomXMLParts(uri).SelectSingleNode(...).Text.
        self.custom_xml_parts = custom_xml_parts or {}
        # Host callback names recovered from package metadata: Ribbon
        # customUI onLoad/onAction callbacks and Excel drawing-shape macro
        # bindings. The latter represent a simulated click during behavior
        # exploration rather than an automatic document-open event.
        self.extra_entry_points = [n.lower() for n in (extra_entry_points or [])]
        # Names of the VBA modules merged into this run's source (see
        # engine.emulate_vba_source) -- lets `ModuleName.Sub`-style
        # qualified cross-module calls (e.g. a Document_Close handler
        # invoking `Module1.Checker`, a real pattern for stashing a
        # payload Sub in a separate module) resolve to that Sub's binding
        # in the shared global scope instead of crashing with "Object
        # doesn't support this property or method" on an undeclared name.
        self.module_names = {n.strip().lower() for n in (module_names or []) if n}
        self._install_builtins()

    def _install_builtins(self):
        for name, fn in BUILTINS.items():
            self.global_env.declare(name, NativeFunc(name, fn))
        for name, value in VBA_CONSTANTS.items():
            self.global_env.declare(name, value)
        for name, fn in (
            ("createobject", lambda interp, args: interp.create_com_object(to_str(args[0]))),
            ("getobject", self._bi_getobject),
            ("execute", lambda interp, args: interp.dynamic_execute(to_str(args[0]), in_global=False)),
            ("executeglobal", lambda interp, args: interp.dynamic_execute(to_str(args[0]), in_global=True)),
            ("eval", lambda interp, args: interp.dynamic_eval(to_str(args[0]))),
            # Excel exposes Range/Cells through its ambient _Global object,
            # so macros call them without an explicit Application/worksheet.
            # Missing these globals used to abort Workbook_Open on benign UI
            # bookkeeping before a later downloader/dropper chain ran.
            ("range", self._bi_excel_range),
            ("cells", self._bi_excel_cells),
        ):
            self.global_env.declare(name, NativeFunc(name, fn))
        from vba_emulator.com_objects import WScriptGlobal, ErrObject, DebugObject, ComObject
        from vba_emulator.excel import ExcelSheetsCollection
        self.global_env.declare("wscript", WScriptGlobal(self.session, self))
        self.global_env.declare("err", ErrObject(self.session, self))
        self.global_env.declare("debug", DebugObject(self.session, self))
        sheets = ExcelSheetsCollection(self.session, self)
        self.global_env.declare("sheets", sheets)
        self.global_env.declare("worksheets", sheets)
        # Word/Excel VBA macros reach the host application's object model
        # through ambient globals (no CreateObject involved) -- e.g.
        # `ActiveDocument.InlineShapes(1)...` or `ThisWorkbook.Sheets(1)`.
        # We don't model the Word/Excel object model itself (far larger
        # than the Win32 COM surface covered elsewhere) -- plain
        # ComObject instances so any member access degrades gracefully
        # (logged as unknown_com_call, returns Empty) instead of raising
        # "Object doesn't support this property or method" on the very
        # first touch: real macros overwhelmingly reference these names
        # in their AutoOpen/Document_Open handlers.
        for name, progid in (
            ("activedocument", "Word.Document"), ("thisdocument", "Word.Document"),
            ("application", "Application"),
            ("activeworkbook", "Excel.Workbook"), ("thisworkbook", "Excel.Workbook"),
            ("activesheet", "Excel.Worksheet"), ("selection", "Selection"),
        ):
            if progid == "Word.Document":
                from vba_emulator.word import WordDocumentObject
                obj = WordDocumentObject(self.session, self, controls=self.activex_controls,
                                          custom_properties=self.custom_doc_properties,
                                          custom_xml_parts=self.custom_xml_parts)
            elif progid == "Application":
                from vba_emulator.word import ApplicationObject
                obj = ApplicationObject(self.session, self)
            elif progid == "Excel.Workbook":
                from vba_emulator.excel import ExcelWorkbookObject
                obj = ExcelWorkbookObject(self.session, self)
            elif progid == "Excel.Worksheet":
                from vba_emulator.excel import ExcelWorksheetObject
                obj = ExcelWorksheetObject(self.session, self,
                                           self.session.excel_active_sheet)
            else:
                obj = ComObject(self.session, self)
            obj.progid = progid
            if name == "application":
                obj.props["username"] = self.session.env_vars.get("USERNAME", "User")
                obj.props["version"] = "16.0"
            self.global_env.declare(name, obj)

    def _bi_excel_range(self, interp, args):
        from vba_emulator.excel import ambient_range
        return ambient_range(self, args)

    def _bi_excel_cells(self, interp, args):
        from vba_emulator.excel import ambient_cells
        return ambient_cells(self, args)

    def _bi_getobject(self, interp, args):
        moniker = to_str(args[0]) if args else ""
        self.ioc.emit("com_getobject", api="GetObject", moniker=moniker)
        if len(args) > 1:
            return self.create_com_object(to_str(args[1]))
        # Single-argument GetObject(moniker) is a common shortcut for
        # connecting to a running/well-known object. "winmgmts:..."
        # specifically is the standard way malware queries/creates WMI
        # objects (process creation via Win32_Process, fingerprinting via
        # Win32_ComputerSystem, ...) -- without recognizing it, the whole
        # WMI interaction silently returned Nothing and broke on first use.
        if moniker.lower().startswith("winmgmts:"):
            from vba_emulator.com_objects import SWbemObjectClass, SWbemServices
            # A moniker can bind straight to a class (`winmgmts:
            # Win32_Process`, or with a namespace path/impersonation
            # prefix before a final ":ClassName") instead of the bare
            # `winmgmts:` + a later `.Get("Win32_Process")` call -- a
            # real sample used this shortcut specifically to call
            # `.Create(...)` directly on the GetObject() result. Without
            # recognizing it, that call silently fell through to the
            # generic "not modeled" fallback and the process-creation
            # step never got recorded.
            rest = moniker[len("winmgmts:"):]
            if ":" in rest:
                classname = rest.rsplit(":", 1)[-1]
            elif rest and "/" not in rest and "\\" not in rest:
                classname = rest
            else:
                classname = ""
            classname = classname.strip("{}!")
            if re.match(r"^[A-Za-z_]\w*$", classname):
                return SWbemObjectClass(self.session, self, classname)
            return SWbemServices(self.session, self)
        self.ioc.emit("unsupported", detail=f"GetObject(\"{moniker}\"): moniker not modeled")
        return VBNothing

    def run(self, source, filename="sample"):
        # A VBA UserForm class has a predeclared default instance, so code
        # commonly reaches it directly as `UserForm1.TextBox1.Text`.  It is
        # not introduced by a Dim/Set statement and therefore must be
        # installed from source references before normal name resolution.
        from vba_emulator.word import UserFormObject
        for form_name in _USERFORM_REFERENCE.findall(source):
            if self.lookup_maybe(form_name) is None:
                self.global_env.declare(
                    form_name,
                    UserFormObject(self.session, self, form_name,
                                   controls=self.activex_controls),
                )
        try:
            program, parse_warnings = parse_source(source)
        except Exception as e:
            self.ioc.emit("parse_error", error=str(e), filename=filename)
            return
        self.warnings.extend(parse_warnings)
        self._hoist(program.body, self.global_env)
        try:
            self.exec_block_in_env(program.body, self.global_env)
        except ScriptQuit:
            pass
        except TimeoutError as e:
            self.ioc.emit("emulation_timeout", error=str(e))
            return
        except Exception as e:
            self.ioc.emit("emulation_error", error=str(e), phase="top-level")

        for name in _AUTOEXEC_NAMES + self.extra_entry_points:
            fn = self.global_env.vars.get(name)
            if isinstance(fn, VBFunction):
                self.ioc.emit("entry_point_invoked", name=name)
                try:
                    self.call_vbfunc(fn, [])
                except ScriptQuit:
                    break
                except TimeoutError as e:
                    self.ioc.emit("emulation_timeout", error=str(e))
                    break
                except Exception as e:
                    self.ioc.emit("emulation_error", error=str(e), phase=name)

    def _hoist(self, stmts, env):
        for s in stmts:
            if isinstance(s, A.SubDeclStmt):
                env.declare(s.name, VBFunction(s.name, s.params, s.body, False))
            elif isinstance(s, A.FunctionDeclStmt):
                env.declare(s.name, VBFunction(s.name, s.params, s.body, True))
            elif isinstance(s, A.ClassStmt):
                env.declare(s.name, VBClassTemplate(s.name, s.body))
            elif isinstance(s, A.DeclareStmt):
                from vba_emulator.win32_api import make_declare_handler
                env.declare(s.name, NativeFunc(s.name, make_declare_handler(s)))
            elif isinstance(s, A.IfStmt):
                # `#If VBA7 Then ... #Else ... #End If` conditional
                # compilation -- the lexer only recognizes `#` as a date-
                # literal marker, so `#If`/`#Else`/`#End If` fall through
                # as plain "skip this one unknown character" (see
                # lexer.py), leaving "If VBA7 Then ... Else ... End If" to
                # parse as an ordinary runtime IfStmt. Real macros
                # overwhelmingly use exactly this construct to declare
                # both a VBA7 (PtrSafe/LongPtr) and legacy VBA6 form of
                # the same Declare -- without recursing into its branches,
                # neither ever gets hoisted, and every Win32 API call
                # through it silently raises "Sub or Function not
                # defined" instead of surfacing as a modeled call.
                for _, body in s.branches:
                    self._hoist(body, env)
                if s.else_body:
                    self._hoist(s.else_body, env)

    def current_env(self):
        return self.env_stack[-1] if self.env_stack else self.global_env

    def lookup_maybe(self, name):
        try:
            return self.current_env().get(name)
        except KeyError:
            return None

    def create_com_object(self, progid):
        from vba_emulator.com_objects import create_com_object
        return create_com_object(self.session, self, progid)

    def dynamic_execute(self, code, in_global):
        self.ioc.emit("dynamic_execute", api="Execute", code_preview=code[:300], length=len(code))
        try:
            program, warnings = parse_source(code)
        except Exception as e:
            self.ioc.emit("parse_error", error=str(e), context="Execute")
            return VBEmpty
        target_env = self.global_env if in_global else self.current_env()
        self._hoist(program.body, self.global_env)
        self.exec_block_in_env(program.body, target_env)
        return VBEmpty

    def dynamic_eval(self, expr_src):
        self.ioc.emit("dynamic_execute", api="Eval", code_preview=expr_src[:300], length=len(expr_src))
        try:
            from vba_emulator.lexer import tokenize
            from vba_emulator.parser_engine import Parser
            tokens = tokenize(expr_src)
            p = Parser(tokens)
            expr = p.parse_expr()
        except Exception as e:
            self.ioc.emit("parse_error", error=str(e), context="Eval")
            return VBEmpty
        return self.eval_expr(expr)

    def exec_block_in_env(self, stmts, env):
        self.env_stack.append(env)
        try:
            self.exec_block(stmts)
        finally:
            self.env_stack.pop()

    def exec_block(self, stmts):
        labels = {s.name.lower(): i for i, s in enumerate(stmts) if isinstance(s, A.LabelStmt)}
        i = 0
        n = len(stmts)
        while i < n:
            self.session.tick()
            stmt = stmts[i]
            try:
                self.exec_stmt(stmt)
            except GotoSignal as g:
                key = g.label.lower()
                if key in labels:
                    i = labels[key]
                    continue
                raise
            except (ExitSignal, ScriptQuit, TimeoutError, RecursionError):
                raise
            except Exception as e:
                handled = self._handle_runtime_error(e)
                if not handled:
                    raise
                if self.error_mode == "GOTO_LABEL" and self.error_label:
                    key = self.error_label.lower()
                    if key in labels:
                        i = labels[key]
                        continue
                    raise
            i += 1

    def _handle_runtime_error(self, e):
        number = getattr(e, "number", 5)
        msg = str(e)
        self.session.err_number = number
        self.session.err_description = msg
        # A loop under On Error Resume Next that fails the same *kind* of
        # way every iteration (e.g. a per-byte decode loop hitting a
        # conversion bug) can emit tens of thousands of near-identical
        # "script_error" events -- floods the IOC stream for zero
        # additional signal. Rate-limit by error *number* rather than the
        # full message: real loops embed the differing per-iteration value
        # right in the message (e.g. "Type mismatch: '&H24'", then
        # '&H72', ...), so messages are rarely identical even though it's
        # the same failure.
        count = self._error_counts.get(number, 0) + 1
        self._error_counts[number] = count
        if count <= self._error_cap:
            self.ioc.emit("script_error", error=msg, number=number)
        elif count == self._error_cap + 1:
            self.ioc.emit("script_error_suppressed", error=msg, number=number,
                           note=f"further occurrences of error #{number} are suppressed")
        return self.error_mode in ("RESUME_NEXT", "GOTO_LABEL")

    def exec_stmt(self, stmt):
        method = getattr(self, "st_" + type(stmt).__name__, None)
        if method is None:
            return
        method(stmt)

    def _eval_dim_bounds(self, dims):
        # Each dim is (lower_bound_expr_or_None, upper_bound_expr) -- see
        # Parser._parse_dim_bound(). A bare `Dim arr(10)` has no explicit
        # lower bound (defaults to 0); `Dim arr(1 To 10)` does.
        bounds = []
        for lo_expr, hi_expr in dims:
            hi = int(to_number(self.eval_expr(hi_expr)))
            lo = int(to_number(self.eval_expr(lo_expr))) if lo_expr is not None else 0
            bounds.append((lo, hi))
        return bounds

    def st_DimStmt(self, stmt):
        env = self.current_env()
        for name, dims, type_name, is_new in stmt.names:
            if dims is None:
                if not env.has_local(name):
                    if is_new:
                        # `Dim x As New Foo[.Bar]` -- auto-instantiate
                        # immediately (real VBA defers this to first use,
                        # but eagerly here is observationally equivalent
                        # for anything this emulator models and much
                        # simpler than tracking a "not yet instantiated"
                        # state).
                        env.declare(name, self._instantiate_new(type_name))
                    # `Dim x As SomeUDT` where SomeUDT isn't a recognized
                    # VBA primitive/intrinsic type is almost always a
                    # user-defined `Type ... End Type` struct (this
                    # emulator doesn't parse Type blocks -- their field
                    # list is never needed since ComObject's property bag
                    # already accepts any field name on first access/set).
                    # Pre-seed it as one instead of leaving it Empty, so
                    # `x.SomeField = value` / `= x.SomeField` (the whole
                    # point of a struct -- e.g. reading back the process
                    # handle a Declare'd CreateProcess call wrote into a
                    # PROCESS_INFORMATION passed by reference) doesn't
                    # crash on "Object doesn't support this property or
                    # method" the way member access on real Empty does.
                    # Harmless for actual primitives too: idiomatic code
                    # always assigns a real value before first use, which
                    # replaces this placeholder outright via env.set().
                    elif type_name is not None and type_name.lower() not in _VBA_PRIMITIVE_TYPES:
                        from vba_emulator.com_objects import ComObject
                        placeholder = ComObject(self.session, self)
                        placeholder.progid = f"UDT:{type_name}"
                        env.declare(name, placeholder)
                    else:
                        env.declare(name)
            else:
                env.declare(name, VBArray(self._eval_dim_bounds(dims)))

    def st_ReDimStmt(self, stmt):
        env = self.current_env()
        for name, dims in stmt.targets:
            bounds = self._eval_dim_bounds(dims)
            existing = env.vars.get(name.lower()) if env.has_local(name) else None
            if stmt.preserve and isinstance(existing, VBArray):
                existing.redim_preserve(bounds)
            else:
                env.set(name, VBArray(bounds))

    def st_ConstStmt(self, stmt):
        env = self.current_env()
        for name, expr in stmt.names:
            env.declare(name, self.eval_expr(expr))

    def st_AssignStmt(self, stmt):
        value = self.eval_expr(stmt.value)
        self.assign_to(stmt.target, value)

    def st_ExprStmt(self, stmt):
        self.eval_expr(stmt.expr)

    def st_IfStmt(self, stmt):
        for cond, body in stmt.branches:
            if to_bool(self.eval_expr(cond)):
                self.exec_block(body)
                return
        if stmt.else_body is not None:
            self.exec_block(stmt.else_body)

    def st_ForStmt(self, stmt):
        env = self.current_env()
        start = to_number(self.eval_expr(stmt.start))
        stop = to_number(self.eval_expr(stmt.stop))
        step = to_number(self.eval_expr(stmt.step)) if stmt.step is not None else 1
        env.set(stmt.var, start)
        try:
            i = start
            while (step >= 0 and i <= stop) or (step < 0 and i >= stop):
                # exec_block() ticks per statement, but ticks zero times for
                # an empty body -- an explicit tick here keeps the
                # step/wall-clock budget enforced even for `For i = 1 To
                # huge: Next` with nothing inside it (same reasoning as
                # ForEachStmt below). tick() is also the *sole* iteration
                # cap now (session.py's max_steps, deliberately raised to
                # 500,000,000 for real heavy-loop samples -- see its own
                # comment) -- a separate, lower hardcoded guard here would
                # just re-impose the truncation that raise was meant to fix.
                self.session.tick()
                try:
                    self.exec_block(stmt.body)
                except ExitSignal as sig:
                    if sig.kind == "FOR":
                        break
                    raise
                i = to_number(env.get(stmt.var)) + step
                env.set(stmt.var, i)
        except ExitSignal as sig:
            if sig.kind != "FOR":
                raise

    def st_ForEachStmt(self, stmt):
        env = self.current_env()
        iterable = self.eval_expr(stmt.iterable)
        items = iterable.to_list() if isinstance(iterable, VBArray) else []
        if hasattr(iterable, "m_items"):
            try:
                items = iterable.m_items([]).to_list()
            except Exception:
                items = []
        for item in items:
            # exec_block() only ticks per *statement* -- zero times for an
            # empty body -- so `For Each x In huge: Next` would otherwise
            # never hit the step/wall-clock budget check at all, no matter
            # how large `items` is. See st_ForStmt above.
            self.session.tick()
            env.set(stmt.var, item)
            try:
                self.exec_block(stmt.body)
            except ExitSignal as sig:
                if sig.kind == "FOR":
                    break
                raise

    def st_DoLoopStmt(self, stmt):
        def cond_ok(cond, is_while):
            if cond is None:
                return True
            v = to_bool(self.eval_expr(cond))
            return v if is_while else not v

        try:
            while cond_ok(stmt.pre_cond, stmt.pre_is_while):
                # See st_ForStmt above -- tick() is the sole iteration cap.
                self.session.tick()
                try:
                    self.exec_block(stmt.body)
                except ExitSignal as sig:
                    if sig.kind == "DO":
                        break
                    raise
                if not cond_ok(stmt.post_cond, stmt.post_is_while):
                    break
        except ExitSignal as sig:
            if sig.kind != "DO":
                raise

    def st_WhileWendStmt(self, stmt):
        while to_bool(self.eval_expr(stmt.cond)):
            self.session.tick()
            self.exec_block(stmt.body)

    def st_SelectCaseStmt(self, stmt):
        subject = self.eval_expr(stmt.expr)
        for values, body in stmt.cases:
            if values is None:
                self.exec_block(body)
                return
            for kind, *rest in values:
                if kind == "value":
                    if self._values_equal(subject, self.eval_expr(rest[0])):
                        self.exec_block(body)
                        return
                elif kind == "range":
                    lo, hi = self.eval_expr(rest[0]), self.eval_expr(rest[1])
                    if self._compare(subject, lo) >= 0 and self._compare(subject, hi) <= 0:
                        self.exec_block(body)
                        return
                elif kind == "is":
                    op, expr = rest
                    other = self.eval_expr(expr)
                    if self._apply_compare(op, subject, other):
                        self.exec_block(body)
                        return

    def _values_equal(self, a, b):
        try:
            return self._compare(a, b) == 0
        except Exception:
            return False

    def st_SubDeclStmt(self, stmt):
        pass

    def st_FunctionDeclStmt(self, stmt):
        pass

    def st_ClassStmt(self, stmt):
        pass

    def st_ExitStmt(self, stmt):
        raise ExitSignal(stmt.kind)

    def st_OnErrorStmt(self, stmt):
        if stmt.mode == "RESUME_NEXT":
            self.error_mode = "RESUME_NEXT"
            self.error_label = None
        elif stmt.mode == "GOTO_ZERO":
            self.error_mode = "NONE"
            self.error_label = None
        elif stmt.mode == "GOTO_LABEL":
            self.error_mode = "GOTO_LABEL"
            self.error_label = stmt.label

    def st_ResumeStmt(self, stmt):
        return

    def st_WithStmt(self, stmt):
        obj = self.eval_expr(stmt.expr)
        self.with_stack.append(obj)
        try:
            self.exec_block(stmt.body)
        finally:
            self.with_stack.pop()

    def st_LabelStmt(self, stmt):
        pass

    def st_GotoStmt(self, stmt):
        raise GotoSignal(stmt.label)

    def st_OptionStmt(self, stmt):
        pass

    # -- legacy Open/Put/Get/Close binary file I/O ---------------------------------
    def st_OpenStmt(self, stmt):
        path = to_str(self.eval_expr(stmt.path))
        filenum = int(to_number(self.eval_expr(stmt.filenum)))
        existing = b""
        if stmt.mode in ("BINARY", "RANDOM", "APPEND"):
            content = self.session.vfs_read(path)
            if isinstance(content, (bytes, bytearray)):
                existing = bytes(content)
            elif isinstance(content, str):
                existing = content.encode("latin-1", "replace")
        position = len(existing) if stmt.mode == "APPEND" else 0
        self.session.file_handles[filenum] = {
            "path": path, "mode": stmt.mode, "buffer": bytearray(existing), "position": position,
        }
        self.ioc.emit("filesystem_access", api="Open", path=path, mode=stmt.mode.lower())

    def st_NameStmt(self, stmt):
        old_path = to_str(self.eval_expr(stmt.old_path))
        new_path = to_str(self.eval_expr(stmt.new_path))
        content = self.session.vfs_read(old_path)
        if content is not None:
            self.session.vfs_write(new_path, content)
            self.session.vfs_delete(old_path)
        from vba_emulator.com_objects import _SUSPICIOUS_EXT, _ext
        self.ioc.emit("filesystem_move", api="Name", src=old_path, dst=new_path,
                       suspicious_ext=_ext(new_path) in _SUSPICIOUS_EXT)

    def st_CloseStmt(self, stmt):
        if stmt.filenums:
            nums = [int(to_number(self.eval_expr(e))) for e in stmt.filenums]
        else:
            nums = list(self.session.file_handles.keys())
        for n in nums:
            self._close_file_handle(n)

    def _close_file_handle(self, filenum):
        handle = self.session.file_handles.pop(filenum, None)
        if handle is None:
            return
        content = bytes(handle["buffer"])
        self.session.vfs_write(handle["path"], content, is_binary=True)
        from vba_emulator.com_objects import _SUSPICIOUS_EXT, _ext, executable_magic
        magic = executable_magic(content)
        self.ioc.emit("filesystem_write", api="Close", path=handle["path"], size=len(content),
                       is_binary=True, suspicious_ext=_ext(handle["path"]) in _SUSPICIOUS_EXT,
                       executable_content=bool(magic), magic=magic)

    def _value_to_put_bytes(self, value):
        if isinstance(value, (bytes, bytearray)):
            return bytes(value)
        if isinstance(value, VBArray):
            out = bytearray()
            for el in value.to_list():
                try:
                    out.append(int(to_number(el)) & 0xFF)
                except Exception:
                    s = to_str(el)
                    out.append((ord(s[0]) & 0xFF) if s else 0)
            return bytes(out)
        if isinstance(value, str):
            return value.encode("latin-1", "replace")
        if is_numeric(value):
            return bytes([int(value) & 0xFF])
        return b""

    def st_PutStmt(self, stmt):
        filenum = int(to_number(self.eval_expr(stmt.filenum)))
        handle = self.session.file_handles.get(filenum)
        if handle is None:
            raise VBRuntimeError("Bad file name or number", 52)
        data = self._value_to_put_bytes(self.eval_expr(stmt.data))
        if stmt.recnum is not None:
            offset = int(to_number(self.eval_expr(stmt.recnum))) - 1
            if offset < 0:
                offset = 0
        else:
            offset = handle["position"]
        buf = handle["buffer"]
        if len(buf) < offset:
            buf.extend(b"\0" * (offset - len(buf)))
        buf[offset:offset + len(data)] = data
        handle["position"] = offset + len(data)

    def st_GetStmt(self, stmt):
        filenum = int(to_number(self.eval_expr(stmt.filenum)))
        handle = self.session.file_handles.get(filenum)
        if handle is None:
            raise VBRuntimeError("Bad file name or number", 52)
        if stmt.recnum is not None:
            offset = int(to_number(self.eval_expr(stmt.recnum))) - 1
            if offset < 0:
                offset = 0
        else:
            offset = handle["position"]
        chunk = bytes(handle["buffer"][offset:])
        handle["position"] = offset + len(chunk)
        self.assign_to(stmt.target, chunk)

    def st_PrintStmt(self, stmt):
        filenum = int(to_number(self.eval_expr(stmt.filenum)))
        handle = self.session.file_handles.get(filenum)
        if handle is None:
            raise VBRuntimeError("Bad file name or number", 52)
        text = "".join(to_str(self.eval_expr(p)) for p in stmt.parts) + "\r\n"
        data = text.encode("latin-1", "replace")
        handle["buffer"].extend(data)
        handle["position"] = len(handle["buffer"])

    def call_vbfunc(self, func, raw_arg_nodes):
        return self.call_vbfunc_with_env(func, raw_arg_nodes, self.global_env)

    def call_vbfunc_with_env(self, func, args, owner_env, pre_evaluated=False):
        self.call_depth += 1
        if self.call_depth > self.max_call_depth:
            self.call_depth -= 1
            raise VBRuntimeError("Out of stack space", 28)
        old_error_mode, old_error_label = self.error_mode, self.error_label
        self.error_mode, self.error_label = "NONE", None
        try:
            local = Environment(is_proc_scope=True, global_env=owner_env)
            for i, p in enumerate(func.params):
                if i < len(args):
                    v = args[i] if pre_evaluated else self.eval_expr(args[i])
                elif p.optional:
                    v = self.eval_expr(p.default) if p.default is not None else VBEmpty
                else:
                    v = VBEmpty
                local.declare(p.name, v)
            if func.is_function:
                local.declare(func.name, VBEmpty)
            self.env_stack.append(local)
            try:
                self.exec_block(func.body)
            except ExitSignal as sig:
                if sig.kind not in ("SUB", "FUNCTION"):
                    pass
            finally:
                self.env_stack.pop()
            if not pre_evaluated:
                for i, p in enumerate(func.params):
                    if p.byref and i < len(args) and self._is_assignable(args[i]):
                        try:
                            self.assign_to(args[i], local.vars.get(p.name.lower(), VBEmpty))
                        except Exception:
                            pass
            if func.is_function:
                return local.vars.get(func.name.lower(), VBEmpty)
            return VBEmpty
        finally:
            self.call_depth -= 1
            self.error_mode, self.error_label = old_error_mode, old_error_label

    def _is_assignable(self, node):
        return isinstance(node, (A.NameExpr, A.MemberExpr, A.CallExpr))

    def _is_module_qualifier(self, obj_node):
        """True for the `X` in `X.Member` when X isn't a real variable/
        object but names one of this run's merged VBA modules -- see
        module_names above."""
        return (isinstance(obj_node, A.NameExpr)
                and obj_node.name.lower() in (self.module_names | _BUILTIN_MODULE_QUALIFIERS)
                and self.lookup_maybe(obj_node.name) is None)

    def eval_call(self, node):
        callee = node.callee
        if isinstance(callee, A.MemberExpr):
            if self._is_module_qualifier(callee.obj):
                return self.eval_call(A.CallExpr(callee=A.NameExpr(name=callee.name), args=node.args))
            obj_val = self.eval_expr(callee.obj)
            if obj_val is VBNothing or obj_val is None:
                raise VBRuntimeError("Object variable not set", 91)
            args_vals = [self.eval_expr(a) for a in node.args]
            if hasattr(obj_val, "invoke"):
                return obj_val.invoke(callee.name, args_vals)
            raise VBRuntimeError(f"Object doesn't support this property or method: '{callee.name}'", 438)

        if isinstance(callee, A.NameExpr):
            name = callee.name
            val = self.lookup_maybe(name)
            if isinstance(val, VBArray):
                idxs = tuple(int(to_number(self.eval_expr(a))) for a in node.args)
                return val.get(idxs)
            if isinstance(val, VBFunction):
                return self.call_vbfunc(val, node.args)
            if isinstance(val, NativeFunc):
                args_vals = [self.eval_expr(a) for a in node.args]
                return val.fn(self, args_vals)
            if isinstance(val, VBClassTemplate):
                raise VBRuntimeError(f"'{name}' is a class; use New {name}", 424)
            if val is not None and hasattr(val, "default_index"):
                args_vals = [self.eval_expr(a) for a in node.args]
                return val.default_index(args_vals)
            raise VBRuntimeError(f"Sub or Function not defined: {name}", 424)

        callee_val = self.eval_expr(callee)
        args_vals = [self.eval_expr(a) for a in node.args]
        # VBScript permits immediate indexing into a Variant array returned
        # by another expression: `Array("x")(0)`, `Split(s, ",")(1)`, or
        # `Filter(items, needle)(0)`. The parser correctly represents this
        # as a CallExpr whose callee is itself a CallExpr; treat the outer
        # parentheses as array subscripts rather than trying to invoke the
        # VBArray as a function.
        if isinstance(callee_val, VBArray):
            idxs = tuple(int(to_number(value)) for value in args_vals)
            return callee_val.get(idxs)
        if hasattr(callee_val, "default_index"):
            return callee_val.default_index(args_vals)
        raise VBRuntimeError("Cannot call this expression", 424)

    def assign_to(self, target, value):
        if isinstance(target, A.NameExpr):
            if target.name.lower() == "__with__":
                raise VBRuntimeError("Cannot assign to With-block reference", 424)
            self.current_env().set(target.name, value)
            return
        if isinstance(target, A.MemberExpr):
            if self._is_module_qualifier(target.obj):
                self.current_env().set(target.name, value)
                return
            obj_val = self._assignment_container(target.obj)
            if obj_val is VBNothing or obj_val is None:
                raise VBRuntimeError("Object variable not set", 91)
            if hasattr(obj_val, "set_prop"):
                obj_val.set_prop(target.name, value)
                return
            raise VBRuntimeError(f"Cannot set property '{target.name}'", 438)
        if isinstance(target, A.CallExpr):
            args_vals = [self.eval_expr(a) for a in target.args]
            if isinstance(target.callee, A.NameExpr):
                base = self.lookup_maybe(target.callee.name)
                if isinstance(base, VBArray):
                    idxs = tuple(int(to_number(v)) for v in args_vals)
                    base.set(idxs, value)
                    return
                if base is not None and hasattr(base, "set_index"):
                    base.set_index(args_vals, value)
                    return
            elif isinstance(target.callee, A.MemberExpr):
                obj_val = self.eval_expr(target.callee.obj)
                member_val = obj_val.get_prop(target.callee.name) if hasattr(obj_val, "get_prop") else None
                if isinstance(member_val, VBArray):
                    idxs = tuple(int(to_number(v)) for v in args_vals)
                    member_val.set(idxs, value)
                    return
                if member_val is not None and hasattr(member_val, "set_index"):
                    member_val.set_index(args_vals, value)
                    return
            raise VBRuntimeError("Cannot assign to this expression", 424)
        raise VBRuntimeError("Invalid assignment target", 424)

    def _assignment_container(self, node):
        """Resolve the object that owns a property assignment.

        Parsed VBA ``Type`` blocks are represented by lightweight property
        bags because native layout is irrelevant to sandboxed behavior.  A
        UDT may itself contain another UDT (`startupEx.STARTUPINFO.cb = ...`).
        Materialize that intermediate bag only when it is demonstrably being
        used as an assignment container. A normal read of an unknown scalar
        field still returns Empty, and non-UDT COM behavior is unchanged.
        """
        if not isinstance(node, A.MemberExpr):
            return self.eval_expr(node)

        owner = self._assignment_container(node.obj)
        if owner is VBNothing or owner is None:
            raise VBRuntimeError("Object variable not set", 91)
        key = node.name.lower()
        if hasattr(owner, "props") and key in owner.props:
            return owner.props[key]
        if getattr(owner, "progid", "").lower().startswith("udt:"):
            from vba_emulator.com_objects import ComObject
            nested = ComObject(self.session, self)
            nested.progid = f"UDT:{node.name}"
            owner.props[key] = nested
            return nested
        if hasattr(owner, "get_prop"):
            return owner.get_prop(node.name)
        raise VBRuntimeError(
            f"Object doesn't support this property or method: '{node.name}'", 438)

    def eval_expr(self, node):
        method = getattr(self, "ev_" + type(node).__name__)
        return method(node)

    def ev_LiteralExpr(self, node):
        return node.value

    def ev_KeywordLiteralExpr(self, node):
        if node.kind == "TRUE":
            return True
        if node.kind == "FALSE":
            return False
        if node.kind == "NULL":
            return VBNull
        if node.kind == "NOTHING":
            return VBNothing
        if node.kind == "EMPTY":
            return VBEmpty
        if node.kind == "ME":
            return self.with_stack[-1] if self.with_stack else VBNothing
        return VBEmpty

    def ev_NameExpr(self, node):
        if node.name == "__with__":
            if not self.with_stack:
                raise VBRuntimeError("'.' used outside a With block", 424)
            return self.with_stack[-1]
        val = self.lookup_maybe(node.name)
        if val is None:
            return VBEmpty
        if isinstance(val, VBFunction):
            return self.call_vbfunc(val, [])
        if isinstance(val, NativeFunc):
            return val.fn(self, [])
        return val

    def ev_UnaryExpr(self, node):
        v = self.eval_expr(node.operand)
        if node.op == "NOT":
            if is_numeric(v) and not isinstance(v, bool):
                return ~int(v)
            return not to_bool(v)
        if v is VBNull:
            return VBNull
        n = to_number(v)
        return -n if node.op == "-" else +n

    def ev_MemberExpr(self, node):
        if self._is_module_qualifier(node.obj):
            return self.ev_NameExpr(A.NameExpr(name=node.name))
        obj = self.eval_expr(node.obj)
        if obj is VBNothing or obj is None:
            raise VBRuntimeError(f"Object variable not set (accessing '{node.name}')", 91)
        if hasattr(obj, "get_prop"):
            return obj.get_prop(node.name)
        raise VBRuntimeError(f"Object doesn't support this property or method: '{node.name}'", 438)

    def ev_CallExpr(self, node):
        return self.eval_call(node)

    def ev_NewExpr(self, node):
        return self._instantiate_new(node.class_name)

    def _instantiate_new(self, class_name):
        tmpl = self.lookup_maybe(class_name)
        if isinstance(tmpl, VBClassTemplate):
            return VBClassInstance(self, tmpl)
        # Not a class defined in this project -- almost always a COM
        # progid (`New Shell32.Shell`, `New Scripting.Dictionary`, ...).
        # create_com_object() already degrades any unrecognized progid to
        # a generic, gracefully-fallback-everything ComObject rather than
        # raising, so routing every non-template name through it (instead
        # of returning VBNothing) avoids "Object variable not set" on the
        # very next property/method use.
        return self.create_com_object(class_name)

    def ev_BinaryExpr(self, node):
        op = node.op
        left = self.eval_expr(node.left)
        right = self.eval_expr(node.right)

        if op == "&":
            l = "" if left is VBNull else to_str(left)
            r = "" if right is VBNull else to_str(right)
            check_string_len(len(l) + len(r))
            return l + r

        if op in ("=", "<>", "<", ">", "<=", ">="):
            if left is VBNull or right is VBNull:
                return VBNull
            return self._apply_compare(op, left, right)

        if op == "IS":
            if left is VBNothing and right is VBNothing:
                return True
            return left is right

        if op == "LIKE":
            pattern = _like_to_regex(to_str(right))
            return re.match(pattern, to_str(left), re.IGNORECASE) is not None

        if op in ("AND", "OR", "XOR", "EQV", "IMP"):
            return self._logic_op(op, left, right)

        if left is VBNull or right is VBNull:
            return VBNull

        if op == "+":
            if isinstance(left, str) and isinstance(right, str):
                check_string_len(len(left) + len(right))
                return left + right
            if isinstance(left, str) and right is VBEmpty:
                return left
            if isinstance(right, str) and left is VBEmpty:
                return right
            return to_number(left) + to_number(right)
        if op == "-":
            return to_number(left) - to_number(right)
        if op == "*":
            return to_number(left) * to_number(right)
        if op == "/":
            r = to_number(right)
            if r == 0:
                raise VBRuntimeError("Division by zero", 11)
            return to_number(left) / r
        if op == "\\":
            li, ri = int(to_number(left)), int(to_number(right))
            if ri == 0:
                raise VBRuntimeError("Division by zero", 11)
            import math as _m
            return _m.trunc(li / ri)
        if op == "MOD":
            li, ri = int(to_number(left)), int(to_number(right))
            if ri == 0:
                raise VBRuntimeError("Division by zero", 11)
            import math as _m
            return li - ri * _m.trunc(li / ri)
        if op == "^":
            # Real VBA's `^` always yields a Double, unlike Python's `**`
            # which stays in arbitrary-precision int for two int operands
            # -- e.g. `99999999 ^ 99999999` would otherwise materialize an
            # ~800-million-digit integer in one expression, between two
            # session.tick() checks, with no loop/step count to interrupt
            # it. Casting to float both matches VBA semantics and caps the
            # result to a fixed-size float (or a catchable "Overflow"
            # error, matching real VBA's error 6, instead of an
            # unbounded allocation).
            try:
                return float(to_number(left)) ** float(to_number(right))
            except OverflowError:
                raise VBRuntimeError("Overflow", 6)

        raise VBRuntimeError(f"Unsupported operator {op}", 5)

    def _compare(self, a, b):
        try:
            na, nb = to_number(a), to_number(b)
            return (na > nb) - (na < nb)
        except VBRuntimeError:
            sa, sb = to_str(a), to_str(b)
            return (sa > sb) - (sa < sb)

    def _apply_compare(self, op, a, b):
        c = self._compare(a, b)
        return {"=": c == 0, "<>": c != 0, "<": c < 0, ">": c > 0,
                "<=": c <= 0, ">=": c >= 0}[op]

    def _logic_op(self, op, l, r):
        # AND/OR/XOR/EQV/IMP coerce numeric *strings* to numbers too, same
        # as VBA's arithmetic operators -- `"110" Xor 11"` is a common
        # shape straight out of a `Split(numberList, ",")` decode loop
        # (a real, common obfuscation technique). The old is_numeric()
        # check required the operand to already be a Python int/float, so
        # a string operand silently fell through to the *boolean* fallback
        # below instead (`to_bool("110") != to_bool(11)` -> False/0),
        # corrupting every byte of the decode instead of raising or
        # computing the right bitwise result.
        li = ri = None
        if not isinstance(l, bool) and not isinstance(r, bool):
            try:
                li, ri = int(to_number(l)), int(to_number(r))
            except VBRuntimeError:
                li = ri = None
        if li is not None:
            if op == "AND":
                return li & ri
            if op == "OR":
                return li | ri
            if op == "XOR":
                return li ^ ri
            if op == "EQV":
                return ~(li ^ ri)
            if op == "IMP":
                return (~li) | ri
        lb, rb = to_bool(l), to_bool(r)
        if op == "AND":
            return lb and rb
        if op == "OR":
            return lb or rb
        if op == "XOR":
            return lb != rb
        if op == "EQV":
            return lb == rb
        if op == "IMP":
            return (not lb) or rb
