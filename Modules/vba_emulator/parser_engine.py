"""Recursive-descent parser for the VBA/VBScript subset.

Deliberately permissive: real-world malicious macros/scripts are often
slightly non-standard or obfuscated, so a statement-level parse error skips
to the next statement boundary rather than aborting the whole analysis.
"""

import vba_emulator.ast_nodes as A
from vba_emulator.errors import VBSyntaxError
from vba_emulator.lexer import Lexer, Token, TokenType


class Parser:
    # Guards parse_expr()'s recursion (re-entered on every nested `(` via
    # parse_primary) with a catchable VBSyntaxError instead of a raw
    # RecursionError. Interpreter.run() wraps the whole parse_source()
    # call in a plain `except Exception`, so an uncaught RecursionError
    # from a few hundred bytes of `x = ((((...1...))))` aborted parsing of
    # the *entire* file -- including any real payload elsewhere in the
    # same source -- instead of just failing that one statement the way
    # parse_statement_list()'s normal per-statement error recovery does.
    _MAX_EXPR_DEPTH = 250

    def __init__(self, tokens):
        self.toks = tokens
        self.pos = 0
        self.warnings = []
        self._expr_depth = 0

    def _cur(self):
        return self.toks[self.pos]

    def _peek(self, off=0):
        i = self.pos + off
        return self.toks[i] if i < len(self.toks) else self.toks[-1]

    def _advance(self):
        t = self.toks[self.pos]
        if t.type is not TokenType.EOF:
            self.pos += 1
        return t

    def _check_kw(self, *names):
        return self._cur().is_kw(*names)

    def _match_kw(self, *names):
        if self._check_kw(*names):
            self._advance()
            return True
        return False

    def _expect_kw(self, name):
        if not self._check_kw(name):
            raise VBSyntaxError(f"Expected keyword {name}, got {self._cur()}", self._cur().line, self._cur().col)
        return self._advance()

    def _check(self, type_):
        return self._cur().type is type_

    def _match(self, type_):
        if self._check(type_):
            self._advance()
            return True
        return False

    def _expect(self, type_):
        if not self._check(type_):
            raise VBSyntaxError(f"Expected {type_.name}, got {self._cur()}", self._cur().line, self._cur().col)
        return self._advance()

    def _skip_newlines_and_colons(self):
        while self._check(TokenType.NEWLINE) or self._check(TokenType.COLON):
            self._advance()

    def _at_stmt_end(self):
        return self._check(TokenType.NEWLINE) or self._check(TokenType.COLON) or self._check(TokenType.EOF)

    def parse_program(self):
        body = self.parse_statement_list(enders=set())
        return A.Program(body=body)

    def parse_statement_list(self, enders):
        stmts = []
        self._skip_newlines_and_colons()
        while not self._check(TokenType.EOF):
            if self._cur().type is TokenType.KEYWORD and self._cur().value in enders:
                break
            start_pos = self.pos
            try:
                stmt = self.parse_statement()
                if stmt is not None:
                    stmts.append(stmt)
            except VBSyntaxError as e:
                self.warnings.append(str(e))
                if self.pos == start_pos:
                    self._advance()
                while not (self._at_stmt_end() or (self._cur().type is TokenType.KEYWORD and self._cur().value in enders)):
                    self._advance()
            self._skip_newlines_and_colons()
        return stmts

    def parse_statement(self):
        t = self._cur()

        if t.type is TokenType.KEYWORD:
            kw = t.value
            if kw in ("PUBLIC", "PRIVATE", "GLOBAL"):
                self._advance()
                if self._check_kw("CONST"):
                    return self.parse_const()
                if self._check_kw("SUB"):
                    return self.parse_sub()
                if self._check_kw("FUNCTION"):
                    return self.parse_function()
                if self._check_kw("DIM"):
                    return self.parse_dim()
                if self._check_kw("DECLARE"):
                    return self.parse_declare()
                return self.parse_dim(implicit=True)
            if kw == "DIM":
                return self.parse_dim()
            if kw == "DECLARE":
                return self.parse_declare()
            if kw == "REDIM":
                return self.parse_redim()
            if kw == "CONST":
                return self.parse_const()
            if kw in ("SET", "LET"):
                return self.parse_assign(is_set=(kw == "SET"))
            if kw == "IF":
                return self.parse_if()
            if kw == "FOR":
                return self.parse_for()
            if kw == "DO":
                return self.parse_do_loop()
            if kw == "WHILE":
                return self.parse_while_wend()
            if kw == "SELECT":
                return self.parse_select_case()
            if kw == "SUB":
                return self.parse_sub()
            if kw == "FUNCTION":
                return self.parse_function()
            if kw == "CLASS":
                return self.parse_class()
            if kw == "PROPERTY":
                return self.parse_property_as_sub_or_func()
            if kw == "CALL":
                self._advance()
                expr = self.parse_postfix()
                return A.ExprStmt(expr=expr)
            if kw == "EXIT":
                self._advance()
                kind_tok = self._advance()
                kind = kind_tok.value if kind_tok.type is TokenType.KEYWORD else "SUB"
                return A.ExitStmt(kind=kind)
            if kw == "ON":
                return self.parse_on_error()
            if kw == "RESUME":
                return self.parse_resume()
            if kw == "WITH":
                return self.parse_with()
            if kw == "OPTION":
                self._advance()
                name_parts = []
                while not self._at_stmt_end():
                    name_parts.append(str(self._advance().value))
                return A.OptionStmt(name=" ".join(name_parts))
            if kw == "ATTRIBUTE":
                # `Attribute VB_Name = "ModuleName"` -- VBA module/
                # procedure metadata that every module extracted via
                # oletools' extract_all_macros() starts with (normally
                # hidden by the VBA IDE, present in the raw stored
                # source). Discard entirely rather than parsing the value
                # as an expression, since its syntax doesn't have to
                # follow normal expression grammar.
                self._advance()
                while not self._at_stmt_end():
                    self._advance()
                return None
            if kw == "GOTO":
                self._advance()
                label = self._advance().value
                return A.GotoStmt(label=str(label))
            if kw == "NAME":
                return self.parse_name_stmt()
            if kw == "OPEN":
                return self.parse_open()
            if kw == "CLOSE":
                return self.parse_close()
            if kw == "PUT":
                return self.parse_put()
            if kw == "GET":
                return self.parse_get_stmt()
            if kw == "PRINT":
                return self.parse_print()
            if kw in ("TRUE", "FALSE", "NULL", "NOTHING", "EMPTY", "NEW", "NOT", "ME"):
                expr = self.parse_expr()
                return self._finish_expr_statement(expr)
            # Unknown/unsupported leading keyword (e.g. TYPE, DECLARE): skip
            # the rest of the logical line rather than failing hard.
            self._advance()
            while not self._at_stmt_end():
                self._advance()
            return None

        if t.type is TokenType.IDENT and self._peek(1).type is TokenType.COLON and \
                self._peek(2).type in (TokenType.NEWLINE, TokenType.EOF):
            self._advance()
            self._advance()
            return A.LabelStmt(name=str(t.value))

        if t.type in (TokenType.NEWLINE, TokenType.COLON):
            return None

        expr = self.parse_postfix()
        return self._finish_expr_statement(expr)

    def _finish_expr_statement(self, expr):
        if self._check(TokenType.EQ):
            self._advance()
            value = self.parse_expr()
            return A.AssignStmt(target=expr, value=value, is_set=False)
        if self._starts_expr() and isinstance(expr, (A.NameExpr, A.MemberExpr, A.CallExpr)):
            args = self.parse_unparenthesized_args()
            if args:
                if isinstance(expr, A.CallExpr):
                    expr.args.extend(args)
                else:
                    expr = A.CallExpr(callee=expr, args=args)
        return A.ExprStmt(expr=expr)

    def _starts_expr(self):
        t = self._cur()
        if t.type in (TokenType.STRING, TokenType.INT, TokenType.FLOAT, TokenType.DATE,
                      TokenType.IDENT, TokenType.MINUS, TokenType.PLUS, TokenType.LPAREN, TokenType.DOT):
            return True
        if t.type is TokenType.KEYWORD and t.value in ("TRUE", "FALSE", "NULL", "NOTHING", "EMPTY", "NOT", "NEW", "ME"):
            return True
        return False

    def parse_unparenthesized_args(self):
        args = [self.parse_expr()]
        while self._match(TokenType.COMMA):
            if self._check(TokenType.COMMA) or self._at_stmt_end():
                args.append(A.KeywordLiteralExpr(kind="EMPTY"))
            else:
                args.append(self.parse_expr())
        return args

    def _parse_dim_bound(self):
        # A dimension is either a bare upper bound (`10`, implicit lower
        # bound 0 -- by far the common case) or an explicit `lower To
        # upper` (e.g. `1 To 100`, `0 To n - 1`). Without recognizing
        # `To` here, `parse_expr()` alone stops right after the lower
        # bound (`To` isn't part of any expression grammar), leaving the
        # `To upper)` tail to fail `_expect(RPAREN)` -- silently dropping
        # the whole Dim/ReDim statement via the usual per-statement
        # recovery, and leaving the array unresized for whatever code
        # runs after it (observed: a following `LBound(arr)` call then
        # raw-crashes on an empty `.bounds` list instead of the array
        # ever getting its real size).
        first = self.parse_expr()
        if self._match_kw("TO"):
            return (first, self.parse_expr())
        return (None, first)

    def parse_dim(self, implicit=False):
        if not implicit:
            self._expect_kw("DIM")
        names = []
        while True:
            name = str(self._expect(TokenType.IDENT).value)
            dims = None
            if self._match(TokenType.LPAREN):
                dims = []
                if not self._check(TokenType.RPAREN):
                    dims.append(self._parse_dim_bound())
                    while self._match(TokenType.COMMA):
                        dims.append(self._parse_dim_bound())
                self._expect(TokenType.RPAREN)
            type_name = None
            is_new = False
            if self._match_kw("AS"):
                is_new = self._match_kw("NEW")
                # `As New Foo.Bar` (auto-instantiate, a qualified COM
                # progid like Shell32.Shell being especially common in
                # real malware) -- unlike a plain `As TypeName`, this is a
                # dotted chain, not one token; the previous "always
                # consume exactly one token after AS" simplification left
                # ".Bar" trailing as its own bogus statement, which then
                # crashed on member access off an undeclared name.
                parts = [str(self._expect(TokenType.IDENT).value)]
                while self._match(TokenType.DOT):
                    parts.append(str(self._expect(TokenType.IDENT).value))
                type_name = ".".join(parts)
            names.append((name, dims, type_name, is_new))
            if not self._match(TokenType.COMMA):
                break
        return A.DimStmt(names=names)

    def parse_redim(self):
        self._expect_kw("REDIM")
        preserve = self._match_kw("PRESERVE")
        targets = []
        while True:
            name = str(self._expect(TokenType.IDENT).value)
            dims = []
            if self._match(TokenType.LPAREN):
                if not self._check(TokenType.RPAREN):
                    dims.append(self._parse_dim_bound())
                    while self._match(TokenType.COMMA):
                        dims.append(self._parse_dim_bound())
                self._expect(TokenType.RPAREN)
            targets.append((name, dims))
            if not self._match(TokenType.COMMA):
                break
        return A.ReDimStmt(preserve=preserve, targets=targets)

    def parse_const(self):
        self._expect_kw("CONST")
        names = []
        while True:
            name = str(self._expect(TokenType.IDENT).value)
            if self._match_kw("AS"):
                self._advance()
            self._expect(TokenType.EQ)
            value = self.parse_expr()
            names.append((name, value))
            if not self._match(TokenType.COMMA):
                break
        return A.ConstStmt(names=names)

    def parse_assign(self, is_set):
        self._advance()
        target = self.parse_postfix()
        self._expect(TokenType.EQ)
        value = self.parse_expr()
        return A.AssignStmt(target=target, value=value, is_set=is_set)

    def parse_if(self):
        self._expect_kw("IF")
        cond = self.parse_expr()
        self._expect_kw("THEN")
        branches = [(cond, None)]
        else_body = None

        if self._check(TokenType.NEWLINE) or self._check(TokenType.EOF):
            body = self.parse_statement_list(enders={"ELSE", "ELSEIF", "END"})
            branches[0] = (cond, body)
            while self._check_kw("ELSEIF"):
                self._advance()
                c = self.parse_expr()
                self._expect_kw("THEN")
                b = self.parse_statement_list(enders={"ELSE", "ELSEIF", "END"})
                branches.append((c, b))
            if self._check_kw("ELSE"):
                self._advance()
                else_body = self.parse_statement_list(enders={"END"})
            self._expect_kw("END")
            self._expect_kw("IF")
        else:
            # Single-line form: `If cond Then s1 : s2 [Else s3 : s4]`. Unlike
            # the block form, there is no closing keyword -- end-of-line is
            # the only terminator -- so this must NOT reuse
            # parse_statement_list, which treats NEWLINE as just another
            # statement separator and would otherwise swallow every
            # following line up to the next literal "Else"/EOF in the whole
            # file as this if's body. (Found via a real ~326KB malware
            # sample chaining several bare `If cond Then stmt` lines back
            # to back -- without this fix the first one silently absorbed
            # the entire rest of the file.)
            body = self.parse_single_line_body(enders={"ELSE"})
            branches[0] = (cond, body)
            if self._check_kw("ELSE"):
                self._advance()
                else_body = self.parse_single_line_body(enders=set())
        return A.IfStmt(branches=branches, else_body=else_body)

    def parse_single_line_body(self, enders):
        stmts = []
        while True:
            if self._at_stmt_end():
                break
            if self._cur().type is TokenType.KEYWORD and self._cur().value in enders:
                break
            stmt = self.parse_statement()
            if stmt is not None:
                stmts.append(stmt)
            if self._check(TokenType.COLON):
                self._advance()
                continue
            break
        return stmts

    def parse_for(self):
        self._expect_kw("FOR")
        if self._match_kw("EACH"):
            var = str(self._expect(TokenType.IDENT).value)
            self._expect_kw("IN")
            iterable = self.parse_expr()
            body = self.parse_statement_list(enders={"NEXT"})
            self._expect_kw("NEXT")
            if self._check(TokenType.IDENT):
                self._advance()
            return A.ForEachStmt(var=var, iterable=iterable, body=body)
        var = str(self._expect(TokenType.IDENT).value)
        self._expect(TokenType.EQ)
        start = self.parse_expr()
        self._expect_kw("TO")
        stop = self.parse_expr()
        step = None
        if self._match_kw("STEP"):
            step = self.parse_expr()
        body = self.parse_statement_list(enders={"NEXT"})
        self._expect_kw("NEXT")
        if self._check(TokenType.IDENT):
            self._advance()
        return A.ForStmt(var=var, start=start, stop=stop, step=step, body=body)

    def parse_do_loop(self):
        self._expect_kw("DO")
        pre_cond = None
        pre_is_while = True
        if self._check_kw("WHILE", "UNTIL"):
            pre_is_while = self._advance().value == "WHILE"
            pre_cond = self.parse_expr()
        body = self.parse_statement_list(enders={"LOOP"})
        self._expect_kw("LOOP")
        post_cond = None
        post_is_while = True
        if self._check_kw("WHILE", "UNTIL"):
            post_is_while = self._advance().value == "WHILE"
            post_cond = self.parse_expr()
        return A.DoLoopStmt(pre_cond=pre_cond, pre_is_while=pre_is_while, body=body,
                             post_cond=post_cond, post_is_while=post_is_while)

    def parse_while_wend(self):
        self._expect_kw("WHILE")
        cond = self.parse_expr()
        body = self.parse_statement_list(enders={"WEND"})
        self._expect_kw("WEND")
        return A.WhileWendStmt(cond=cond, body=body)

    def parse_select_case(self):
        self._expect_kw("SELECT")
        self._expect_kw("CASE")
        expr = self.parse_expr()
        self._skip_newlines_and_colons()
        cases = []
        while self._check_kw("CASE"):
            self._advance()
            if self._match_kw("ELSE"):
                self._skip_newlines_and_colons()
                body = self.parse_statement_list(enders={"END"})
                cases.append((None, body))
                break
            values = [self.parse_case_value()]
            while self._match(TokenType.COMMA):
                values.append(self.parse_case_value())
            self._skip_newlines_and_colons()
            body = self.parse_statement_list(enders={"CASE", "END"})
            cases.append((values, body))
        self._expect_kw("END")
        self._expect_kw("SELECT")
        return A.SelectCaseStmt(expr=expr, cases=cases)

    def parse_case_value(self):
        if self._match_kw("IS"):
            op_tok = self._advance()
            op = op_tok.value
            expr = self.parse_expr()
            return ("is", op, expr)
        first = self.parse_expr()
        if self._match_kw("TO"):
            second = self.parse_expr()
            return ("range", first, second)
        return ("value", first)

    def parse_params(self):
        params = []
        self._expect(TokenType.LPAREN)
        if not self._check(TokenType.RPAREN):
            while True:
                optional = self._match_kw("OPTIONAL")
                byref = True
                if self._match_kw("BYVAL"):
                    byref = False
                elif self._match_kw("BYREF"):
                    byref = True
                name = str(self._expect(TokenType.IDENT).value)
                if self._match(TokenType.LPAREN):
                    self._expect(TokenType.RPAREN)
                if self._match_kw("AS"):
                    self._advance()
                default = None
                if self._match(TokenType.EQ):
                    default = self.parse_expr()
                params.append(A.Param(name=name, byref=byref, optional=optional, default=default))
                if not self._match(TokenType.COMMA):
                    break
        self._expect(TokenType.RPAREN)
        return params

    def parse_sub(self):
        self._expect_kw("SUB")
        name = str(self._expect(TokenType.IDENT).value)
        params = self.parse_params() if self._check(TokenType.LPAREN) else []
        body = self.parse_statement_list(enders={"END"})
        self._expect_kw("END")
        self._expect_kw("SUB")
        return A.SubDeclStmt(name=name, params=params, body=body)

    def parse_function(self):
        self._expect_kw("FUNCTION")
        name = str(self._expect(TokenType.IDENT).value)
        params = self.parse_params() if self._check(TokenType.LPAREN) else []
        if self._match_kw("AS"):
            self._advance()
            # Array-valued functions use a suffix on the return type, e.g.
            # `Function Decode(...) As Byte()`.  The type itself is not
            # semantically enforced by this emulator, but both parentheses
            # must still be consumed or they become a bogus statement and
            # generate a parser warning before the function body.
            if self._match(TokenType.LPAREN):
                self._expect(TokenType.RPAREN)
        body = self.parse_statement_list(enders={"END"})
        self._expect_kw("END")
        self._expect_kw("FUNCTION")
        return A.FunctionDeclStmt(name=name, params=params, body=body)

    def parse_declare(self):
        # `Declare [PtrSafe] Function/Sub Name Lib "lib" [Alias "alias"]
        # (params) [As type]` -- a direct call into a native DLL. Real
        # malicious macros overwhelmingly use this for Win32 shellcode-
        # injection primitives (VirtualAllocEx/WriteProcessMemory/
        # CreateRemoteThread) via kernel32.dll -- previously fell into the
        # generic "unknown leading keyword: skip the whole line" path, so
        # every subsequent call to the declared name raised "Sub or
        # Function not defined" and the entire injection chain was
        # invisible (risk_score 0) instead of surfacing as the single
        # clearest process-injection signature this emulator can model.
        self._expect_kw("DECLARE")
        if self._check(TokenType.IDENT) and str(self._cur().value).upper() == "PTRSAFE":
            self._advance()
        is_function = self._match_kw("FUNCTION")
        if not is_function:
            self._expect_kw("SUB")
        name = str(self._expect(TokenType.IDENT).value)
        lib = ""
        if self._check(TokenType.IDENT) and str(self._cur().value).upper() == "LIB":
            self._advance()
            lib = str(self._expect(TokenType.STRING).value)
        alias = name
        if self._check(TokenType.IDENT) and str(self._cur().value).upper() == "ALIAS":
            self._advance()
            alias = str(self._expect(TokenType.STRING).value)
        params = self.parse_params() if self._check(TokenType.LPAREN) else []
        if self._match_kw("AS"):
            self._advance()
        return A.DeclareStmt(name=name, lib=lib, alias=alias, is_function=is_function, params=params)

    def parse_property_as_sub_or_func(self):
        self._expect_kw("PROPERTY")
        kind = self._advance().value
        name = str(self._expect(TokenType.IDENT).value)
        params = self.parse_params() if self._check(TokenType.LPAREN) else []
        if self._match_kw("AS"):
            self._advance()
        body = self.parse_statement_list(enders={"END"})
        self._expect_kw("END")
        self._expect_kw("PROPERTY")
        if kind == "GET":
            return A.FunctionDeclStmt(name=name, params=params, body=body)
        return A.SubDeclStmt(name=name, params=params, body=body)

    def parse_class(self):
        self._expect_kw("CLASS")
        name = str(self._expect(TokenType.IDENT).value)
        body = self.parse_statement_list(enders={"END"})
        self._expect_kw("END")
        self._expect_kw("CLASS")
        return A.ClassStmt(name=name, body=body)

    def parse_on_error(self):
        self._expect_kw("ON")
        self._expect_kw("ERROR")
        if self._match_kw("RESUME"):
            self._match_kw("NEXT")
            return A.OnErrorStmt(mode="RESUME_NEXT")
        if self._match_kw("GOTO"):
            if self._check(TokenType.INT) and self._cur().value == 0:
                self._advance()
                return A.OnErrorStmt(mode="GOTO_ZERO")
            if self._check(TokenType.MINUS) and self._peek(1).type is TokenType.INT:
                self._advance(); self._advance()
                return A.OnErrorStmt(mode="GOTO_ZERO")
            label = str(self._advance().value)
            return A.OnErrorStmt(mode="GOTO_LABEL", label=label)
        while not self._at_stmt_end():
            self._advance()
        return A.OnErrorStmt(mode="RESUME_NEXT")

    def parse_resume(self):
        self._expect_kw("RESUME")
        if self._match_kw("NEXT"):
            return A.ResumeStmt(mode="NEXT")
        if self._at_stmt_end():
            return A.ResumeStmt(mode="BARE")
        label = str(self._advance().value)
        return A.ResumeStmt(mode="LABEL", label=label)

    def parse_name_stmt(self):
        # `Name oldpath As newpath` -- VBA's file-rename statement. Its `As`
        # separator (not a comma) doesn't fit the generic unparenthesized-
        # call-statement grammar used for e.g. MkDir/Kill, so it needs its
        # own rule -- otherwise the parser silently drops everything from
        # `As` onward and `Name` is left looking like a call to an
        # undefined function, aborting emulation on the very common
        # drop-and-rename-payload idiom this statement is used for.
        self._expect_kw("NAME")
        old_path = self.parse_expr()
        self._expect_kw("AS")
        new_path = self.parse_expr()
        return A.NameStmt(old_path=old_path, new_path=new_path)

    def parse_open(self):
        self._expect_kw("OPEN")
        path = self.parse_expr()
        mode = "RANDOM"
        access = ""
        reclen = None

        if self._match_kw("FOR") and self._check(TokenType.IDENT):
            mode = str(self._advance().value).upper()

        if self._check(TokenType.IDENT) and str(self._cur().value).upper() == "ACCESS":
            self._advance()
            if self._check(TokenType.IDENT):
                w = str(self._advance().value).upper()
                access = w
                if w == "READ" and self._check(TokenType.IDENT) and str(self._cur().value).upper() == "WRITE":
                    self._advance()
                    access = "READWRITE"

        while not self._check_kw("AS") and not self._at_stmt_end():
            self._advance()

        self._expect_kw("AS")
        filenum = self.parse_expr()

        if self._check(TokenType.IDENT) and str(self._cur().value).upper() == "LEN":
            self._advance()
            self._expect(TokenType.EQ)
            reclen = self.parse_expr()

        return A.OpenStmt(path=path, mode=mode, access=access, filenum=filenum, reclen=reclen)

    def parse_close(self):
        self._expect_kw("CLOSE")
        filenums = []
        if not self._at_stmt_end():
            filenums.append(self.parse_expr())
            while self._match(TokenType.COMMA):
                filenums.append(self.parse_expr())
        return A.CloseStmt(filenums=filenums)

    def parse_put(self):
        self._expect_kw("PUT")
        filenum = self.parse_expr()
        self._expect(TokenType.COMMA)
        recnum = None
        if not self._check(TokenType.COMMA):
            recnum = self.parse_expr()
        self._expect(TokenType.COMMA)
        data = self.parse_expr()
        return A.PutStmt(filenum=filenum, recnum=recnum, data=data)

    def parse_get_stmt(self):
        self._expect_kw("GET")
        filenum = self.parse_expr()
        self._expect(TokenType.COMMA)
        recnum = None
        if not self._check(TokenType.COMMA):
            recnum = self.parse_expr()
        self._expect(TokenType.COMMA)
        target = self.parse_postfix()
        return A.GetStmt(filenum=filenum, recnum=recnum, target=target)

    def parse_print(self):
        # `Print #filenum, outputlist` -- the "#" before filenum was
        # already silently dropped by the lexer (same as for Open/Close/
        # Put/Get's `#filenum`; it isn't a distinct token here at all).
        self._expect_kw("PRINT")
        filenum = self.parse_expr()
        self._match(TokenType.COMMA)
        parts = []
        if not self._at_stmt_end():
            parts.append(self.parse_expr())
            while self._match(TokenType.COMMA) and not self._at_stmt_end():
                parts.append(self.parse_expr())
        return A.PrintStmt(filenum=filenum, parts=parts)

    def parse_with(self):
        self._expect_kw("WITH")
        expr = self.parse_expr()
        body = self.parse_statement_list(enders={"END"})
        self._expect_kw("END")
        self._expect_kw("WITH")
        return A.WithStmt(expr=expr, body=body)

    def parse_expr(self):
        self._expr_depth += 1
        if self._expr_depth > self._MAX_EXPR_DEPTH:
            self._expr_depth -= 1
            raise VBSyntaxError("Expression nested too deeply", self._cur().line, self._cur().col)
        try:
            return self.parse_imp()
        finally:
            self._expr_depth -= 1

    def _bin_level(self, next_fn, ops_kw=(), ops_tok=()):
        left = next_fn()
        while True:
            if ops_kw and self._cur().type is TokenType.KEYWORD and self._cur().value in ops_kw:
                op = self._advance().value
                right = next_fn()
                left = A.BinaryExpr(op=op, left=left, right=right)
                continue
            if ops_tok and self._cur().type in ops_tok:
                op = self._advance()
                right = next_fn()
                left = A.BinaryExpr(op=op.value, left=left, right=right)
                continue
            break
        return left

    def parse_imp(self):
        return self._bin_level(self.parse_eqv, ops_kw=("IMP",))

    def parse_eqv(self):
        return self._bin_level(self.parse_xor, ops_kw=("EQV",))

    def parse_xor(self):
        return self._bin_level(self.parse_or, ops_kw=("XOR",))

    def parse_or(self):
        return self._bin_level(self.parse_and, ops_kw=("OR",))

    def parse_and(self):
        return self._bin_level(self.parse_not, ops_kw=("AND",))

    def parse_not(self):
        if self._match_kw("NOT"):
            operand = self.parse_not()
            return A.UnaryExpr(op="NOT", operand=operand)
        return self.parse_compare()

    def parse_compare(self):
        left = self.parse_concat()
        while True:
            if self._cur().type in (TokenType.EQ, TokenType.NEQ, TokenType.LT, TokenType.GT,
                                     TokenType.LE, TokenType.GE):
                op = self._advance().value
                right = self.parse_concat()
                left = A.BinaryExpr(op=op, left=left, right=right)
                continue
            if self._check_kw("IS"):
                self._advance()
                right = self.parse_concat()
                left = A.BinaryExpr(op="IS", left=left, right=right)
                continue
            if self._check_kw("LIKE"):
                self._advance()
                right = self.parse_concat()
                left = A.BinaryExpr(op="LIKE", left=left, right=right)
                continue
            break
        return left

    def parse_concat(self):
        return self._bin_level(self.parse_additive, ops_tok=(TokenType.AMP,))

    def parse_additive(self):
        return self._bin_level(self.parse_mult, ops_tok=(TokenType.PLUS, TokenType.MINUS))

    def parse_mult(self):
        return self._bin_level(self.parse_intdiv, ops_tok=(TokenType.STAR, TokenType.SLASH))

    def parse_intdiv(self):
        return self._bin_level(self.parse_mod, ops_tok=(TokenType.BACKSLASH,))

    def parse_mod(self):
        return self._bin_level(self.parse_unary, ops_kw=("MOD",))

    def parse_unary(self):
        if self._cur().type in (TokenType.MINUS, TokenType.PLUS):
            op = self._advance().value
            operand = self.parse_unary()
            return A.UnaryExpr(op=op, operand=operand)
        return self.parse_exponent()

    def parse_exponent(self):
        left = self.parse_postfix()
        if self._check(TokenType.CARET):
            self._advance()
            right = self.parse_unary()
            return A.BinaryExpr(op="^", left=left, right=right)
        return left

    def parse_postfix(self):
        expr = self.parse_primary()
        while True:
            if self._check(TokenType.DOT):
                self._advance()
                name = str(self._advance().value)
                expr = A.MemberExpr(obj=expr, name=name)
                continue
            if self._check(TokenType.LPAREN):
                self._advance()
                args = []
                if not self._check(TokenType.RPAREN):
                    if self._check(TokenType.COMMA):
                        args.append(A.KeywordLiteralExpr(kind="EMPTY"))
                    else:
                        args.append(self.parse_expr())
                    while self._match(TokenType.COMMA):
                        if self._check(TokenType.COMMA) or self._check(TokenType.RPAREN):
                            args.append(A.KeywordLiteralExpr(kind="EMPTY"))
                        else:
                            args.append(self.parse_expr())
                self._expect(TokenType.RPAREN)
                expr = A.CallExpr(callee=expr, args=args)
                continue
            break
        return expr

    def parse_primary(self):
        t = self._cur()

        if t.type is TokenType.INT or t.type is TokenType.FLOAT:
            self._advance()
            return A.LiteralExpr(value=t.value)
        if t.type is TokenType.STRING:
            self._advance()
            return A.LiteralExpr(value=t.value)
        if t.type is TokenType.DATE:
            self._advance()
            return A.LiteralExpr(value=t.value)
        if t.type is TokenType.LPAREN:
            self._advance()
            inner = self.parse_expr()
            self._expect(TokenType.RPAREN)
            return inner
        if t.type is TokenType.DOT:
            # implicit With-block member reference: `.Foo`
            return A.NameExpr(name="__with__")
        if t.type is TokenType.KEYWORD:
            if t.value in ("TRUE", "FALSE", "NULL", "NOTHING", "EMPTY", "ME"):
                self._advance()
                return A.KeywordLiteralExpr(kind=t.value)
            if t.value == "NEW":
                # `New Foo.Bar` (a qualified COM progid, e.g. New
                # Shell32.Shell) is a dotted chain, not one token --
                # consuming only the first left ".Bar" trailing as its
                # own bogus statement, crashing on member access off an
                # undeclared name (same issue as Dim's `As New` -- see
                # parse_dim).
                self._advance()
                parts = [str(self._expect(TokenType.IDENT).value)]
                while self._match(TokenType.DOT):
                    parts.append(str(self._expect(TokenType.IDENT).value))
                return A.NewExpr(class_name=".".join(parts))
            if t.value == "NOT":
                return self.parse_not()
            if t.value in ("BYVAL", "BYREF"):
                # An inline `ByVal`/`ByRef` modifier on a single call
                # argument (e.g. `RunStuff(..., ByVal 0&, ...)`) -- legal
                # VBA syntax to override a callee's declared parameter
                # passing convention for just that one argument, common in
                # Declare/Win32-API calls specifically. The passing
                # convention itself isn't modeled either way (every
                # argument is just evaluated), so this is transparent:
                # `ByVal <expr>` parses as `<expr>`. Previously unhandled
                # here, so any call using it raised "Unexpected token
                # BYVAL", silently dropping the *entire* call statement
                # via the usual per-statement recovery -- e.g. the
                # CreateProcessA/WriteProcessMemory calls in a shellcode-
                # injection chain, which conventionally pass several
                # pointer-sized args `ByVal 0&`.
                self._advance()
                return self.parse_expr()
            if t.value == "TYPE":
                self._advance()
                return A.NameExpr(name="Type")
        if t.type is TokenType.IDENT:
            self._advance()
            return A.NameExpr(name=str(t.value))

        raise VBSyntaxError(f"Unexpected token {t}", t.line, t.col)


def parse(source):
    """Parse VBA/VBScript source. Returns (Program, warnings)."""
    lexer = Lexer(source)
    tokens = lexer.tokenize()
    p = Parser(tokens)
    program = p.parse_program()
    return program, lexer.warnings + p.warnings
