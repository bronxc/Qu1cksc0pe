"""Scoping, non-local control-flow signals, and callable-value wrappers.

Scoping model: VBA/VBScript have exactly two levels of scope that matter
here -- module/global scope, and one flat scope per procedure call (If/
For/Do/etc. bodies do NOT introduce new scopes). A procedure's local scope
falls back to the global scope for lookups (to reach other Subs/Functions/
Consts/global Dims) but never sees a caller's locals.
"""

from vba_emulator.values import VBEmpty


class Environment:
    def __init__(self, is_proc_scope=False, global_env=None):
        self.vars = {}
        self.is_proc_scope = is_proc_scope
        self.global_env = global_env  # None for the global env itself

    def declare(self, name, value=None):
        self.vars[name.lower()] = VBEmpty if value is None else value

    def has_local(self, name):
        return name.lower() in self.vars

    def get(self, name):
        key = name.lower()
        if key in self.vars:
            return self.vars[key]
        if self.is_proc_scope and self.global_env is not None and key in self.global_env.vars:
            return self.global_env.vars[key]
        raise KeyError(name)

    def set(self, name, value):
        key = name.lower()
        if key in self.vars:
            self.vars[key] = value
            return
        if self.is_proc_scope and self.global_env is not None and key in self.global_env.vars:
            self.global_env.vars[key] = value
            return
        self.vars[key] = value


class ExitSignal(Exception):
    def __init__(self, kind):
        self.kind = kind  # 'SUB' | 'FUNCTION' | 'FOR' | 'DO' | 'PROPERTY'


class GotoSignal(Exception):
    def __init__(self, label):
        self.label = label


class ScriptQuit(Exception):
    def __init__(self, code=0):
        self.code = code


class VBFunction:
    """A user-defined Sub or Function."""
    __slots__ = ("name", "params", "body", "is_function")

    def __init__(self, name, params, body, is_function):
        self.name = name
        self.params = params
        self.body = body
        self.is_function = is_function


class NativeFunc:
    """Wraps a Python callable(interp, args) -> value as a callable VBA value."""
    __slots__ = ("name", "fn")

    def __init__(self, name, fn):
        self.name = name
        self.fn = fn
