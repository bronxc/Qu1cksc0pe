"""Exception types used by the VBA/VBScript emulator."""


class VBSyntaxError(Exception):
    def __init__(self, message, line=0, col=0):
        self.line = line
        self.col = col
        super().__init__(f"{message} (line {line}, col {col})")


class VBRuntimeError(Exception):
    """An emulated VBA/VBScript runtime error (Err.Raise, type mismatch,
    division by zero, ...). Caught internally to support
    On Error Resume Next."""

    def __init__(self, message, number=5):
        self.number = number
        self.message = message
        super().__init__(message)
