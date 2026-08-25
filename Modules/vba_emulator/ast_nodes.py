"""AST node definitions for the VBA/VBScript subset we emulate.

VBA/VBScript use the same ``name(args)`` syntax for both array indexing and
function/sub calls -- no syntactic distinction, only semantic (resolved at
runtime). We mirror that: the parser always produces a single ``CallExpr``
for ``postfix (...)``, and the interpreter decides whether that means
"index into this array" or "invoke this function/method" based on the
runtime value of the callee.
"""

from dataclasses import dataclass, field


class Node:
    pass


class Expr(Node):
    pass


class Stmt(Node):
    pass


@dataclass
class NameExpr(Expr):
    name: str


@dataclass
class LiteralExpr(Expr):
    value: object


@dataclass
class KeywordLiteralExpr(Expr):
    kind: str  # 'TRUE' | 'FALSE' | 'NULL' | 'NOTHING' | 'EMPTY' | 'ME'


@dataclass
class UnaryExpr(Expr):
    op: str
    operand: Expr


@dataclass
class BinaryExpr(Expr):
    op: str
    left: Expr
    right: Expr


@dataclass
class MemberExpr(Expr):
    obj: Expr
    name: str


@dataclass
class CallExpr(Expr):
    callee: Expr
    args: list = field(default_factory=list)


@dataclass
class NewExpr(Expr):
    class_name: str


@dataclass
class DimStmt(Stmt):
    names: list  # list of (name, dims, type_name_or_None) -- dims: list[(Expr|None, Expr)] | None, each entry (lower_bound_or_None, upper_bound)


@dataclass
class ReDimStmt(Stmt):
    preserve: bool
    targets: list  # list of (name, dims: list[(Expr|None, Expr)])


@dataclass
class ConstStmt(Stmt):
    names: list  # list of (name, Expr)


@dataclass
class AssignStmt(Stmt):
    target: Expr
    value: Expr
    is_set: bool = False


@dataclass
class ExprStmt(Stmt):
    expr: Expr


@dataclass
class IfStmt(Stmt):
    branches: list  # list of (cond, body)
    else_body: list


@dataclass
class ForStmt(Stmt):
    var: str
    start: Expr
    stop: Expr
    step: Expr
    body: list


@dataclass
class ForEachStmt(Stmt):
    var: str
    iterable: Expr
    body: list


@dataclass
class DoLoopStmt(Stmt):
    pre_cond: Expr
    pre_is_while: bool
    body: list
    post_cond: Expr
    post_is_while: bool


@dataclass
class WhileWendStmt(Stmt):
    cond: Expr
    body: list


@dataclass
class SelectCaseStmt(Stmt):
    expr: Expr
    cases: list  # list of (values | None, body)


@dataclass
class Param:
    name: str
    byref: bool = False
    optional: bool = False
    default: Expr = None


@dataclass
class SubDeclStmt(Stmt):
    name: str
    params: list
    body: list


@dataclass
class FunctionDeclStmt(Stmt):
    name: str
    params: list
    body: list


@dataclass
class ClassStmt(Stmt):
    name: str
    body: list


@dataclass
class DeclareStmt(Stmt):
    """`Declare [PtrSafe] Function/Sub Name Lib "lib" [Alias "alias"] (params) [As type]`
    -- a direct call into a native DLL (overwhelmingly kernel32.dll Win32
    APIs in real malicious macros: VirtualAllocEx/WriteProcessMemory/
    CreateRemoteThread-style shellcode injection). See win32_api.py for
    where `alias` (the real exported function name; defaults to `name`
    when there's no explicit Alias clause) is matched against modeled
    stand-ins."""
    name: str
    lib: str
    alias: str
    is_function: bool
    params: list


@dataclass
class ExitStmt(Stmt):
    kind: str  # 'SUB' | 'FUNCTION' | 'FOR' | 'DO' | 'PROPERTY'


@dataclass
class OnErrorStmt(Stmt):
    mode: str  # 'RESUME_NEXT' | 'GOTO_ZERO' | 'GOTO_LABEL'
    label: str = None


@dataclass
class ResumeStmt(Stmt):
    mode: str
    label: str = None


@dataclass
class WithStmt(Stmt):
    expr: Expr
    body: list


@dataclass
class LabelStmt(Stmt):
    name: str


@dataclass
class GotoStmt(Stmt):
    label: str


@dataclass
class OpenStmt(Stmt):
    path: Expr
    mode: str
    access: str
    filenum: Expr
    reclen: Expr = None


@dataclass
class CloseStmt(Stmt):
    filenums: list


@dataclass
class PutStmt(Stmt):
    filenum: Expr
    recnum: Expr
    data: Expr


@dataclass
class GetStmt(Stmt):
    filenum: Expr
    recnum: Expr
    target: Expr


@dataclass
class PrintStmt(Stmt):
    """`Print #filenum, outputlist` -- the legacy text-mode file-write
    statement paired with `Open ... For Output`. Comma/semicolon-driven
    column spacing between outputlist items isn't modeled -- each item is
    just concatenated -- since analysis only needs the written content,
    not its on-screen column alignment."""
    filenum: Expr
    parts: list


@dataclass
class OptionStmt(Stmt):
    name: str


@dataclass
class NameStmt(Stmt):
    old_path: Expr
    new_path: Expr


@dataclass
class Program(Node):
    body: list
