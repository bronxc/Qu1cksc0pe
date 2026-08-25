"""Small, side-effect-free Excel host-object model.

This is deliberately not an attempt to emulate Excel itself.  VBA macros
often perform harmless workbook/UI bookkeeping (for example
``Range("A1").Value = "Please wait"``) before their interesting network or
process behavior.  Treating the ambient ``Range`` global as an undefined VBA
function aborts the whole entry point at that cosmetic statement and creates
a severe false negative.  The objects below model just enough of Range/Cells
to let analysis continue and to make simple write/read pairs deterministic.
"""

import re

from vba_emulator.com_objects import ComObject, safe_str
from vba_emulator.values import VBEmpty, to_number


_A1_RE = re.compile(r"^\$?([A-Za-z]+)\$?(\d+)$")


def _column_name(number):
    """Convert a 1-based Excel column number to its A1 column name."""
    try:
        n = int(number)
    except (TypeError, ValueError):
        return safe_str(number)
    if n < 1:
        return str(n)
    chars = []
    while n:
        n, rem = divmod(n - 1, 26)
        chars.append(chr(65 + rem))
    return "".join(reversed(chars))


def _column_number(name):
    value = 0
    for char in str(name).upper():
        if not ("A" <= char <= "Z"):
            return 0
        value = value * 26 + (ord(char) - 64)
    return value


def _normalize_address(value):
    text = safe_str(value).strip()
    match = _A1_RE.match(text)
    if match:
        return f"{match.group(1).upper()}{match.group(2)}"
    return text.upper().replace("$", "")


def _range_address(args):
    if not args:
        return ""
    first = _normalize_address(args[0])
    if len(args) == 1:
        return first
    second = _normalize_address(args[1])
    return f"{first}:{second}"


def _cells_address(args):
    if len(args) < 2:
        return _range_address(args)
    try:
        row = int(to_number(args[0]))
        column = int(to_number(args[1]))
    except Exception:
        return f"R{safe_str(args[0])}C{safe_str(args[1])}"
    return f"{_column_name(column)}{row}"


def _offset_address(address, row_delta, column_delta):
    """Apply Excel's Range.Offset arithmetic to a single A1 cell/range."""
    parts = str(address).split(":", 1)
    shifted = []
    for part in parts:
        match = _A1_RE.match(part)
        if not match:
            return ""
        column = _column_number(match.group(1)) + column_delta
        row = int(match.group(2)) + row_delta
        if column < 1 or row < 1:
            return ""
        shifted.append(f"{_column_name(column)}{row}")
    return ":".join(shifted)


class ExcelRangeObject(ComObject):
    """A fake Excel.Range with persistent in-memory Value/Value2 state."""

    progid = "Excel.Range"

    def __init__(self, session, interp, address="", sheet="ActiveSheet"):
        super().__init__(session, interp)
        self.address = _normalize_address(address)
        self.sheet = safe_str(sheet) or "ActiveSheet"
        self._font = ExcelFontObject(session, interp)

    @property
    def _key(self):
        return f"{self.sheet.lower()}!{self.address.lower()}"

    def p_address(self):
        return self.address

    def p_value(self):
        return self.session.excel_cells.get(self._key, VBEmpty)

    def s_value(self, value):
        self.session.excel_cells[self._key] = value

    def p_value2(self):
        return self.p_value()

    def s_value2(self, value):
        self.s_value(value)

    def p_text(self):
        value = self.p_value()
        return "" if value is VBEmpty else safe_str(value)

    def p_font(self):
        return self._font

    def m_clear(self, args):
        self.session.excel_cells.pop(self._key, None)
        return VBEmpty

    def m_clearcontents(self, args):
        return self.m_clear(args)

    def m_select(self, args):
        if self.interp is not None:
            self.interp.global_env.set("selection", self)
        return VBEmpty

    def m_activate(self, args):
        return self.m_select(args)

    def m_offset(self, args):
        try:
            row_delta = int(to_number(args[0])) if args else 0
            column_delta = int(to_number(args[1])) if len(args) > 1 else 0
        except Exception:
            row_delta = column_delta = 0
        shifted = _offset_address(self.address, row_delta, column_delta)
        if shifted:
            return ExcelRangeObject(self.session, self.interp, shifted, self.sheet)
        suffix = ",".join(safe_str(a) for a in args)
        return ExcelRangeObject(self.session, self.interp,
                                f"{self.address}.OFFSET({suffix})", self.sheet)

    def m_resize(self, args):
        suffix = ",".join(safe_str(a) for a in args)
        return ExcelRangeObject(self.session, self.interp,
                                f"{self.address}.RESIZE({suffix})", self.sheet)

    def m_cells(self, args):
        return ExcelRangeObject(self.session, self.interp,
                                _cells_address(args), self.sheet)

    def default_index(self, args):
        return self.m_cells(args) if args else self


class ExcelFontObject(ComObject):
    """Settable Range.Font facade (Bold/Italic/Underline/etc.)."""

    progid = "Excel.Font"


class ExcelWorksheetObject(ComObject):
    """Minimal worksheet facade for ActiveSheet.Range/Cells calls."""

    progid = "Excel.Worksheet"

    def __init__(self, session, interp, name="ActiveSheet"):
        super().__init__(session, interp)
        self.name = name

    def p_name(self):
        return self.name

    def m_range(self, args):
        return ExcelRangeObject(self.session, self.interp,
                                _range_address(args), self.name)

    def m_cells(self, args):
        return ExcelRangeObject(self.session, self.interp,
                                _cells_address(args), self.name)

    def p_cells(self):
        return ExcelRangeObject(self.session, self.interp, "", self.name)


class ExcelSheetsCollection(ComObject):
    """Workbook Sheets/Worksheets collection with name/index lookup."""

    progid = "Excel.Sheets"

    def _sheet_name(self, value):
        names = self.session.excel_sheet_names
        try:
            index = int(to_number(value))
        except Exception:
            index = 0
        if index and 1 <= index <= len(names):
            return names[index - 1]
        requested = safe_str(value)
        for name in names:
            if name.lower() == requested.lower():
                return name
        return requested or self.session.excel_active_sheet

    def default_index(self, args):
        value = args[0] if args else self.session.excel_active_sheet
        return ExcelWorksheetObject(self.session, self.interp,
                                    self._sheet_name(value))

    def m_item(self, args):
        return self.default_index(args)

    def p_count(self):
        return len(self.session.excel_sheet_names) or 1


class ExcelWorkbookObject(ComObject):
    """Minimal ActiveWorkbook/ThisWorkbook Sheets facade."""

    progid = "Excel.Workbook"

    def __init__(self, session, interp):
        super().__init__(session, interp)
        self._sheets = ExcelSheetsCollection(session, interp)

    def p_sheets(self):
        return self._sheets

    def p_worksheets(self):
        return self._sheets

    def m_sheets(self, args):
        return self._sheets.default_index(args)

    def m_worksheets(self, args):
        return self._sheets.default_index(args)


def ambient_range(interp, args):
    """Implementation shared by bare Range()/Cells()-style globals."""
    sheet = interp.global_env.vars.get("activesheet")
    if isinstance(sheet, ExcelWorksheetObject):
        return sheet.m_range(args)
    return ExcelRangeObject(interp.session, interp, _range_address(args))


def ambient_cells(interp, args):
    sheet = interp.global_env.vars.get("activesheet")
    if isinstance(sheet, ExcelWorksheetObject):
        return sheet.m_cells(args)
    return ExcelRangeObject(interp.session, interp, _cells_address(args))
