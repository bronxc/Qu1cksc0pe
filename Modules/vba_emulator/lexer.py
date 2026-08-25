"""Hand-written tokenizer for the VBA/VBScript dialect.

VBA and VBScript share one practical dialect for malware-analysis purposes:
control flow, Dim/Set, Sub/Function, and common string/conversion built-ins
are effectively identical. We lex both with the same token set.

Dialect quirks handled here:
  - ``'`` starts a comment that runs to end of line.
  - A line ending in `` _`` (whitespace + underscore) is a continuation.
  - Strings are double-quoted with ``""`` as an escaped quote.
  - ``:`` separates statements on one line.
  - Hex (``&H..``) and octal (``&O..``) integer literals.
"""

from enum import Enum, auto

from vba_emulator.errors import VBSyntaxError


class TokenType(Enum):
    IDENT = auto()
    INT = auto()
    FLOAT = auto()
    STRING = auto()
    DATE = auto()

    LPAREN = auto()
    RPAREN = auto()
    COMMA = auto()
    DOT = auto()
    COLON = auto()
    NEWLINE = auto()

    PLUS = auto()
    MINUS = auto()
    STAR = auto()
    SLASH = auto()
    BACKSLASH = auto()
    CARET = auto()
    AMP = auto()

    EQ = auto()
    NEQ = auto()
    LT = auto()
    GT = auto()
    LE = auto()
    GE = auto()

    EOF = auto()
    KEYWORD = auto()


KEYWORDS = {
    "DIM", "SET", "LET", "CONST", "PUBLIC", "PRIVATE", "GLOBAL",
    "IF", "THEN", "ELSE", "ELSEIF", "END",
    "FOR", "TO", "STEP", "NEXT", "EACH", "IN",
    "DO", "WHILE", "WEND", "LOOP", "UNTIL",
    "SELECT", "CASE", "IS",
    "SUB", "FUNCTION", "CALL", "EXIT",
    "DECLARE", "AS", "BYVAL", "BYREF", "OPTIONAL", "PARAMARRAY",
    "TRUE", "FALSE", "NULL", "NOTHING", "EMPTY",
    "AND", "OR", "NOT", "XOR", "EQV", "IMP", "MOD",
    "NEW", "WITH", "REDIM", "PRESERVE",
    "ON", "ERROR", "RESUME", "GOTO",
    "OPTION", "EXPLICIT", "BASE",
    "CLASS", "PROPERTY", "GET",
    "ME", "TYPE", "LIKE", "ATTRIBUTE",
    "OPEN", "CLOSE", "PUT", "NAME", "PRINT",
}


class Token:
    __slots__ = ("type", "value", "line", "col")

    def __init__(self, type_, value, line, col):
        self.type = type_
        self.value = value
        self.line = line
        self.col = col

    def __repr__(self):
        return f"Token({self.type.name}, {self.value!r}, L{self.line}:{self.col})"

    def is_kw(self, *names):
        return self.type is TokenType.KEYWORD and self.value in names


_SINGLE_CHAR = {
    "(": TokenType.LPAREN, ")": TokenType.RPAREN, ",": TokenType.COMMA,
    ".": TokenType.DOT, ":": TokenType.COLON, "+": TokenType.PLUS,
    "-": TokenType.MINUS, "*": TokenType.STAR, "/": TokenType.SLASH,
    "\\": TokenType.BACKSLASH, "^": TokenType.CARET, "&": TokenType.AMP,
    "=": TokenType.EQ,
}


class Lexer:
    def __init__(self, source):
        self.src = source.replace("\r\n", "\n").replace("\r", "\n")
        self.n = len(self.src)
        self.pos = 0
        self.line = 1
        self.col = 1
        self.tokens = []
        self.warnings = []

    def _peek(self, off=0):
        # NUL sentinel for past-end-of-input: unlike "", it never satisfies
        # `x in "some non-empty string"` membership checks below.
        i = self.pos + off
        return self.src[i] if i < self.n else "\0"

    def _advance(self):
        c = self.src[self.pos]
        self.pos += 1
        if c == "\n":
            self.line += 1
            self.col = 1
        else:
            self.col += 1
        return c

    def _emit(self, type_, value, line, col):
        self.tokens.append(Token(type_, value, line, col))

    def tokenize(self):
        while self.pos < self.n:
            c = self._peek()

            if c in " \t":
                self._advance()
                continue

            if c == "\n":
                start_line, start_col = self.line, self.col
                self._advance()
                if not (self.tokens and self.tokens[-1].type is TokenType.NEWLINE):
                    self._emit(TokenType.NEWLINE, "\n", start_line, start_col)
                continue

            if c == "_" and self._is_line_continuation():
                self._consume_line_continuation()
                continue

            if c == "'":
                self._skip_line_comment()
                continue

            if c == '"':
                self._read_string()
                continue

            if c == "#" and self._looks_like_date_literal():
                self._read_date_literal()
                continue

            if c.isdecimal() or (c == "." and self._peek(1).isdecimal()):
                self._read_number()
                continue

            if c == "&" and self._peek(1) in ("h", "H", "o", "O"):
                self._read_radix_number()
                continue

            if c.isalpha() or c == "_":
                if self._looks_like_rem_comment():
                    self._skip_line_comment()
                    continue
                self._read_ident_or_keyword()
                continue

            two = c + self._peek(1)
            if two == "<>":
                self._emit(TokenType.NEQ, "<>", self.line, self.col)
                self._advance(); self._advance()
                continue
            if two == "<=":
                self._emit(TokenType.LE, "<=", self.line, self.col)
                self._advance(); self._advance()
                continue
            if two == ">=":
                self._emit(TokenType.GE, ">=", self.line, self.col)
                self._advance(); self._advance()
                continue

            if c == "<":
                self._emit(TokenType.LT, "<", self.line, self.col)
                self._advance()
                continue
            if c == ">":
                self._emit(TokenType.GT, ">", self.line, self.col)
                self._advance()
                continue

            if c in _SINGLE_CHAR:
                self._emit(_SINGLE_CHAR[c], c, self.line, self.col)
                self._advance()
                continue

            # Unknown character: skip it rather than aborting the whole
            # analysis (malware source is often mangled/obfuscated).
            self._advance()

        self._emit(TokenType.EOF, None, self.line, self.col)
        return self.tokens

    def _looks_like_rem_comment(self):
        # `Rem` is VBA's keyword-form line comment, an alternative to `'`
        # -- but only when it stands as its own statement (first thing
        # after a newline/':', or at the very start of the file), not as
        # a prefix of a longer identifier (Remove, RemoteThing, ...) or a
        # member name (obj.Rem). Without this, a `Rem ...` line was
        # tokenized as ordinary code instead of skipped, corrupting the
        # AST for that logical line.
        j = self.pos
        while j < self.n and (self.src[j].isalnum() or self.src[j] == "_"):
            j += 1
        if self.src[self.pos:j].upper() != "REM":
            return False
        if not self.tokens:
            return True
        return self.tokens[-1].type in (TokenType.NEWLINE, TokenType.COLON)

    def _is_line_continuation(self):
        i = self.pos + 1
        while i < self.n and self.src[i] in " \t":
            i += 1
        return i >= self.n or self.src[i] == "\n"

    def _consume_line_continuation(self):
        self._advance()
        while self._peek() in " \t":
            self._advance()
        if self._peek() == "\n":
            self._advance()

    def _skip_line_comment(self):
        while self.pos < self.n and self._peek() != "\n":
            self._advance()

    def _read_string(self):
        start_line, start_col = self.line, self.col
        self._advance()
        out = []
        while True:
            if self.pos >= self.n:
                # Malware-analysis inputs are sometimes damaged exports of
                # otherwise obvious VBA (for example, a command assignment
                # missing only its final quote).  Aborting tokenization here
                # loses every payload statement after that line.  VBA cannot
                # legally continue a quoted literal across a physical line
                # without closing it first, so EOF is an unambiguous recovery
                # boundary: retain the text collected so far and report that
                # the AST is an approximation.
                self._emit(TokenType.STRING, "".join(out), start_line, start_col)
                self.warnings.append(str(VBSyntaxError(
                    "Recovered unterminated string literal at end of file",
                    start_line, start_col,
                )))
                return
            c = self._peek()
            if c == '"':
                if self._peek(1) == '"':
                    out.append('"')
                    self._advance(); self._advance()
                    continue
                self._advance()
                break
            if c == "\n":
                # Do not consume the newline: the main loop must still emit a
                # statement boundary so the following VBA line can be parsed
                # and emulated normally.
                self._emit(TokenType.STRING, "".join(out), start_line, start_col)
                self.warnings.append(str(VBSyntaxError(
                    "Recovered unterminated string literal at end of line",
                    start_line, start_col,
                )))
                return
            out.append(c)
            self._advance()
        self._emit(TokenType.STRING, "".join(out), start_line, start_col)

    def _looks_like_date_literal(self):
        i = self.pos + 1
        buf = []
        while i < self.n and self.src[i] != "\n" and self.src[i] != "#":
            buf.append(self.src[i])
            i += 1
        if i < self.n and self.src[i] == "#":
            body = "".join(buf)
            return all(ch.isalnum() or ch in " /:-" for ch in body) and body.strip() != ""
        return False

    def _read_date_literal(self):
        start_line, start_col = self.line, self.col
        self._advance()
        out = []
        while self.pos < self.n and self._peek() != "#":
            out.append(self._advance())
        self._advance()
        self._emit(TokenType.DATE, "".join(out).strip(), start_line, start_col)

    def _read_number(self):
        # str.isdigit() is True for Unicode digit-*like* characters (e.g.
        # superscript '²') that int()/float() then reject with a raw,
        # uncaught ValueError -- aborting parsing of the entire file (and
        # with it, any real payload elsewhere in the source) over one
        # stray character. isdecimal() matches exactly the characters
        # int()/float() actually accept.
        start_line, start_col = self.line, self.col
        out = []
        is_float = False
        while self._peek().isdecimal():
            out.append(self._advance())
        if self._peek() == "." and self._peek(1).isdecimal():
            is_float = True
            out.append(self._advance())
            while self._peek().isdecimal():
                out.append(self._advance())
        if self._peek() in ("e", "E") and (self._peek(1).isdecimal() or (self._peek(1) in "+-" and self._peek(2).isdecimal())):
            is_float = True
            out.append(self._advance())
            if self._peek() in "+-":
                out.append(self._advance())
            while self._peek().isdecimal():
                out.append(self._advance())
        if self._peek() in "%&#!":
            self._advance()
        text = "".join(out)
        if is_float:
            self._emit(TokenType.FLOAT, float(text), start_line, start_col)
        else:
            self._emit(TokenType.INT, int(text), start_line, start_col)

    def _read_radix_number(self):
        start_line, start_col = self.line, self.col
        self._advance()
        radix_char = self._advance().lower()
        base = 16 if radix_char == "h" else 8
        digits = []
        valid = "0123456789abcdefABCDEF" if base == 16 else "01234567"
        while self._peek() in valid:
            digits.append(self._advance())
        if self._peek() == "&":
            self._advance()
        text = "".join(digits) or "0"
        self._emit(TokenType.INT, int(text, base), start_line, start_col)

    def _read_ident_or_keyword(self):
        start_line, start_col = self.line, self.col
        out = []
        while self._peek().isalnum() or self._peek() == "_":
            out.append(self._advance())
        text = "".join(out)
        upper = text.upper()
        if upper in KEYWORDS:
            self._emit(TokenType.KEYWORD, upper, start_line, start_col)
        else:
            self._emit(TokenType.IDENT, text, start_line, start_col)


def tokenize(source):
    return Lexer(source).tokenize()
