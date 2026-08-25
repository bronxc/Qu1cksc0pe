"""Built-in VBA/VBScript language functions (string, math, conversion,
array, and type-testing functions). Pure language features, as opposed to
the fake COM objects in com_objects.py, which model external Windows APIs.

Each entry is ``name -> callable(interp, args) -> value``.
"""

import calendar
import datetime
import math
import random
import time

from vba_emulator.errors import VBRuntimeError
from vba_emulator.values import (VBArray, VBEmpty, VBNothing, VBNull, check_string_len,
                     is_numeric, to_bool, to_number, to_str, vb_type_name)


def _s(v):
    return to_str(v)


def _n(v):
    return to_number(v)


def _i(v):
    return int(to_number(v))


def bi_chr(interp, args):
    return chr(_i(args[0]))


def bi_asc(interp, args):
    s = _s(args[0])
    if not s:
        raise VBRuntimeError("Invalid procedure call or argument", 5)
    return ord(s[0])


def bi_len(interp, args):
    v = args[0]
    if isinstance(v, VBArray):
        return len(v)
    if isinstance(v, (bytes, bytearray)):
        return len(v)
    return len(_s(v))


def _bytes(v):
    """Byte-level view of a value, for the *B-suffixed VBA/VBScript
    functions (LenB/MidB/...). VBA strings are UTF-16LE internally (BSTR),
    so a plain string's byte length is 2x its character length -- matters
    for scripts that manually walk a base64-decoded byte blob as UTF-16LE
    text."""
    if isinstance(v, (bytes, bytearray)):
        return bytes(v)
    return _s(v).encode("utf-16-le")


def bi_lenb(interp, args):
    return len(_bytes(args[0]))


def bi_ascb(interp, args):
    b = _bytes(args[0])
    if not b:
        raise VBRuntimeError("Invalid procedure call or argument", 5)
    return b[0]


def bi_chrb(interp, args):
    return bytes([_i(args[0]) & 0xFF])


def bi_midb(interp, args):
    b = _bytes(args[0])
    start = max(_i(args[1]) - 1, 0)
    if len(args) >= 3:
        length = max(_i(args[2]), 0)
        return b[start:start + length]
    return b[start:]


def bi_leftb(interp, args):
    b = _bytes(args[0])
    n = max(_i(args[1]), 0)
    return b[:n]


def bi_rightb(interp, args):
    b = _bytes(args[0])
    n = max(_i(args[1]), 0)
    return b[-n:] if n else b""


def bi_strconv(interp, args):
    v, conv = args[0], _i(args[1])
    if conv & 64:  # vbUnicode: byte blob -> String (UTF-16LE decode)
        if isinstance(v, (bytes, bytearray)):
            return bytes(v).decode("utf-16-le", errors="replace")
        return _s(v)
    if conv & 128:  # vbFromUnicode: String -> raw UTF-16LE bytes
        return _s(v).encode("utf-16-le")
    if conv & 1:  # vbUpperCase
        return _s(v).upper()
    if conv & 2:  # vbLowerCase
        return _s(v).lower()
    return v if isinstance(v, (bytes, bytearray)) else _s(v)


def bi_mid(interp, args):
    s = _s(args[0])
    start = max(_i(args[1]) - 1, 0)
    if len(args) >= 3:
        length = _i(args[2])
        return s[start:start + max(length, 0)]
    return s[start:]


def bi_left(interp, args):
    s = _s(args[0])
    n = max(_i(args[1]), 0)
    return s[:n]


def bi_right(interp, args):
    s = _s(args[0])
    n = max(_i(args[1]), 0)
    return s[-n:] if n else ""


def bi_instr(interp, args):
    if len(args) >= 3 and is_numeric(args[0]):
        start = _i(args[0]) - 1
        hay, needle = _s(args[1]), _s(args[2])
    else:
        start = 0
        hay, needle = _s(args[0]), _s(args[1])
    idx = hay.find(needle, max(start, 0))
    return idx + 1


def bi_instrrev(interp, args):
    # InStrRev(string1, string2, [start], [compare]) -- the optional
    # 1-based `start` bounds the backward search to string1's first
    # `start` characters (VBA's -1 sentinel, the default, means "search
    # the whole string"). Previously ignored entirely, so a bounded
    # backward search silently searched past its intended window.
    hay, needle = _s(args[0]), _s(args[1])
    if len(args) >= 3 and _i(args[2]) != -1:
        hay = hay[:_i(args[2])]
    return hay.rfind(needle) + 1


def bi_replace(interp, args):
    s, find, repl = _s(args[0]), _s(args[1]), _s(args[2])
    if find == "":
        return s
    # Unlike concatenation/String()/Space() (checked at every call site --
    # see check_string_len), a single str.replace() with a short `find` and
    # a long `repl` can blow the output size up by orders of magnitude
    # (e.g. replacing every "a" in a 25M-char string with another 25M-char
    # string) in one call, allocating far past the intended per-value cap
    # before any step/wall-clock budget check gets a chance to fire.
    # Precompute the resulting length and cap it *before* building the
    # string, not after.
    occurrences = s.count(find)
    check_string_len(len(s) + occurrences * (len(repl) - len(find)))
    return s.replace(find, repl)


def bi_split(interp, args):
    s = _s(args[0])
    delim = _s(args[1]) if len(args) > 1 else " "
    parts = s.split(delim) if delim else list(s)
    arr = VBArray(bounds=[(0, max(len(parts) - 1, -1))])
    for i, p in enumerate(parts):
        arr.set((i,), p)
    return arr


def bi_join(interp, args):
    arr = args[0]
    delim = _s(args[1]) if len(args) > 1 else " "
    items = [_s(x) for x in (arr.to_list() if isinstance(arr, VBArray) else list(arr))]
    check_string_len(sum(len(x) for x in items) + len(delim) * max(len(items) - 1, 0))
    return delim.join(items)


def bi_filter(interp, args):
    """VBScript/VBA ``Filter`` over a one-dimensional string array."""
    source = args[0]
    if not isinstance(source, VBArray):
        raise VBRuntimeError("Type mismatch: Filter requires an array", 13)
    match = _s(args[1])
    include = to_bool(args[2]) if len(args) > 2 else True
    compare = _i(args[3]) if len(args) > 3 else 0
    needle = match.lower() if compare == 1 else match
    selected = []
    for value in source.to_list():
        text = _s(value)
        haystack = text.lower() if compare == 1 else text
        if (needle in haystack) == include:
            selected.append(text)
    result = VBArray(bounds=[(0, len(selected) - 1)] if selected else [(0, -1)])
    for index, value in enumerate(selected):
        result.set((index,), value)
    return result


def bi_strreverse(interp, args):
    return _s(args[0])[::-1]


def bi_lcase(interp, args):
    return _s(args[0]).lower()


def bi_ucase(interp, args):
    return _s(args[0]).upper()


def bi_trim(interp, args):
    return _s(args[0]).strip()


def bi_ltrim(interp, args):
    return _s(args[0]).lstrip()


def bi_rtrim(interp, args):
    return _s(args[0]).rstrip()


def bi_space(interp, args):
    n = max(_i(args[0]), 0)
    check_string_len(n)
    return " " * n


def bi_string_(interp, args):
    n = max(_i(args[0]), 0)
    check_string_len(n)
    ch = args[1]
    ch = _s(ch)[0] if isinstance(ch, str) and ch else chr(_i(ch))
    return ch * n


def bi_strcomp(interp, args):
    a, b = _s(args[0]), _s(args[1])
    return 0 if a == b else (-1 if a < b else 1)


def bi_cstr(interp, args):
    return _s(args[0])


def bi_formatcurrency(interp, args):
    """Deterministic, en-US model of VBScript's ``FormatCurrency``.

    The real function takes its currency symbol and defaults from the host's
    regional settings.  The sandbox deliberately has a fixed Windows-like
    profile, so using stable en-US defaults keeps obfuscation output
    repeatable while still honoring all optional formatting switches.
    """
    value = float(_n(args[0]))

    digits = 2
    if len(args) > 1 and args[1] is not VBEmpty:
        requested = _i(args[1])
        if requested >= 0:  # -1 means use the regional default.
            digits = requested
    if digits > 99:
        raise VBRuntimeError("Invalid procedure call or argument", 5)

    def option(index, default):
        if len(args) <= index or args[index] is VBEmpty:
            return default
        raw = _i(args[index])
        return default if raw == -2 else raw != 0  # vbUseDefault / Boolean

    leading_zero = option(2, True)
    parentheses = option(3, False)
    group_digits = option(4, True)

    negative = value < 0
    number = format(abs(value), f",.{digits}f" if group_digits else f".{digits}f")
    if not leading_zero and abs(value) < 1:
        number = number[1:]  # 0.50 -> .50
    rendered = "$" + number
    if negative:
        rendered = f"({rendered})" if parentheses else "-" + rendered
    return rendered


def bi_cint(interp, args):
    return int(round(_n(args[0])))


def bi_cbyte(interp, args):
    return int(round(_n(args[0]))) & 0xFF


def bi_cdbl(interp, args):
    return float(_n(args[0]))


def bi_cbool(interp, args):
    return to_bool(args[0])


def bi_val(interp, args):
    s = _s(args[0]).strip()
    # Val() recognizes a leading "&H"/"&O" the same way to_number() does
    # for plain numeric-string coercion elsewhere (see values.py) -- a
    # hex-byte-pair decode loop (`Val("&H" & Mid$(s, i, 2))`, a very
    # common real obfuscation idiom) previously always fell straight
    # through to the plain-decimal-digit scan below, which treats the
    # leading "&" as "not a digit" and returns 0 for every single byte
    # -- silently decoding the whole payload as null bytes instead of
    # raising or decoding correctly.
    low = s.lower()
    if low.startswith("&h"):
        try:
            return int(s[2:] or "0", 16)
        except ValueError:
            pass
    elif low.startswith("&o"):
        try:
            return int(s[2:] or "0", 8)
        except ValueError:
            pass
    out = []
    seen_dot = seen_digit = False
    for i, ch in enumerate(s):
        if ch.isdigit():
            seen_digit = True
            out.append(ch)
        elif ch == "." and not seen_dot:
            seen_dot = True
            out.append(ch)
        elif ch in "+-" and i == 0:
            out.append(ch)
        else:
            break
    if not seen_digit:
        return 0
    text = "".join(out)
    return float(text) if seen_dot else int(text)


def bi_hex(interp, args):
    n = _i(args[0])
    return format(n & 0xFFFFFFFF if n < 0 else n, "X")


def bi_oct(interp, args):
    return format(_i(args[0]), "o")


def bi_abs(interp, args):
    return abs(_n(args[0]))


def bi_int(interp, args):
    return math.floor(_n(args[0]))


def bi_fix(interp, args):
    return math.trunc(_n(args[0]))


def bi_sgn(interp, args):
    n = _n(args[0])
    return (n > 0) - (n < 0)


def bi_sqr(interp, args):
    return math.sqrt(_n(args[0]))


def bi_rnd(interp, args):
    return random.random()


def bi_randomize(interp, args):
    random.seed()
    return VBEmpty


def bi_doevents(interp, args):
    # No-op: yields to the OS message loop in real VBA, often used
    # (alongside a busy-wait For loop, as here) purely to stall for a
    # while as a crude sandbox-timeout evasion instead of a Sleep() call
    # more heuristics watch for.
    return 0


def bi_now(interp, args):
    return time.strftime("%m/%d/%Y %I:%M:%S %p")


def bi_date(interp, args):
    return time.strftime("%m/%d/%Y")


def bi_time(interp, args):
    return time.strftime("%I:%M:%S %p")


def bi_timer(interp, args):
    return time.time() % 86400


# Formats produced by bi_now/bi_date/bi_time above -- the only shapes a
# date/time value can currently take in this emulator (dates aren't a
# distinct value type, just plain strings). Hour/Minute/Second/etc. need to
# parse a value back out of one of these to extract a component.
_DATETIME_FORMATS = (
    "%m/%d/%Y %I:%M:%S %p",
    "%m/%d/%Y",
    "%I:%M:%S %p",
)

_VB_DATE_EPOCH = datetime.datetime(1899, 12, 30)


def _to_datetime(v):
    if is_numeric(v):
        # VBA represents dates internally as a Double: the integer part is
        # days since 1899-12-30, the fractional part is time of day.
        return _VB_DATE_EPOCH + datetime.timedelta(days=_n(v))
    s = _s(v).strip()
    for fmt in _DATETIME_FORMATS:
        try:
            return datetime.datetime.strptime(s, fmt)
        except ValueError:
            continue
    raise VBRuntimeError(f"Type mismatch: '{s}' is not a valid date", 13)


def bi_hour(interp, args):
    return _to_datetime(args[0]).hour


def bi_minute(interp, args):
    return _to_datetime(args[0]).minute


def bi_second(interp, args):
    return _to_datetime(args[0]).second


def bi_day(interp, args):
    return _to_datetime(args[0]).day


def bi_month(interp, args):
    return _to_datetime(args[0]).month


def bi_year(interp, args):
    return _to_datetime(args[0]).year


def bi_weekday(interp, args):
    # Python's Monday=0..Sunday=6 vs. VBA's default Sunday=1..Saturday=7
    # (vbSunday firstdayofweek default -- the optional 2nd arg to change
    # the start-of-week isn't modeled, same as elsewhere in this file).
    dt = _to_datetime(args[0])
    return (dt.weekday() + 1) % 7 + 1


def bi_timeserial(interp, args):
    hour, minute, second = _i(args[0]), _i(args[1]), _i(args[2])
    dt = datetime.datetime.combine(datetime.date.today(), datetime.time()) + \
        datetime.timedelta(hours=hour, minutes=minute, seconds=second)
    return dt.strftime("%I:%M:%S %p")


def bi_timevalue(interp, args):
    value = args[0]
    if is_numeric(value):
        dt = _to_datetime(value)
        return dt.strftime("%I:%M:%S %p")
    raw = _s(value).strip()
    for fmt in ("%H:%M:%S", "%H:%M", "%I:%M:%S %p", "%I:%M %p"):
        try:
            return datetime.datetime.strptime(raw, fmt).strftime("%I:%M:%S %p")
        except ValueError:
            continue
    # Also accept the date/time strings emitted by Now/Date/Time.
    try:
        return _to_datetime(raw).strftime("%I:%M:%S %p")
    except VBRuntimeError:
        raise VBRuntimeError(f"Type mismatch: '{raw}' is not a valid time", 13)


def bi_dateserial(interp, args):
    # Let month/day overflow naturally the way VBA's DateSerial does
    # (DateSerial(2024, 13, 1) == Jan 1 2025) -- build via timedelta
    # arithmetic from a normalized first-of-month rather than
    # datetime.date(y, m, d) directly, which rejects an out-of-range
    # month/day outright instead of rolling over.
    year, month, day = _i(args[0]), _i(args[1]), _i(args[2])
    total_months = month - 1
    y, m = year + total_months // 12, total_months % 12 + 1
    dt = datetime.datetime(y, m, 1) + datetime.timedelta(days=day - 1)
    return dt.strftime("%m/%d/%Y")


def _add_months(dt, months):
    total = dt.year * 12 + (dt.month - 1) + months
    year, month = total // 12, total % 12 + 1
    day = min(dt.day, calendar.monthrange(year, month)[1])
    return dt.replace(year=year, month=month, day=day)


def bi_dateadd(interp, args):
    # DateAdd(interval, number, date) -- also a common busy-wait/delay-
    # loop building block (`For i = 0 To N: Call DateAdd("s", i, Now):
    # Next`, discarding the result -- just CPU-bound stalling to dodge
    # sandbox timeouts that only fault on a real Sleep()/WScript.Sleep
    # call), so it needs to exist and return *something* plausible even
    # though the result is often never used.
    interval = _s(args[0]).lower()
    number = int(_n(args[1]))
    dt = _to_datetime(args[2])
    if interval == "yyyy":
        dt = _add_months(dt, number * 12)
    elif interval == "q":
        dt = _add_months(dt, number * 3)
    elif interval == "m":
        dt = _add_months(dt, number)
    elif interval in ("d", "y", "w"):
        dt = dt + datetime.timedelta(days=number)
    elif interval == "ww":
        dt = dt + datetime.timedelta(weeks=number)
    elif interval == "h":
        dt = dt + datetime.timedelta(hours=number)
    elif interval == "n":
        dt = dt + datetime.timedelta(minutes=number)
    elif interval == "s":
        dt = dt + datetime.timedelta(seconds=number)
    else:
        raise VBRuntimeError("Invalid procedure call or argument", 5)
    return dt.strftime("%m/%d/%Y %I:%M:%S %p")


def bi_callbyname(interp, args):
    # CallByName(object, procname, calltype, args...) -- dynamically
    # invokes a method or gets/sets a property by string name, a common
    # real obfuscation technique specifically because it evades static
    # detection looking for literal `.MethodName(` call sites. calltype:
    # vbMethod=1 (call), vbGet=2 (property get), vbLet=4/vbSet=8
    # (property assignment, not distinguished here).
    obj = args[0]
    proc_name = _s(args[1])
    call_type = _i(args[2]) if len(args) > 2 else 1
    call_args = list(args[3:])
    if obj is None or obj is VBNothing:
        raise VBRuntimeError("Object variable not set", 91)
    if call_type == 2:
        # A parameterized property get (e.g. Dictionary/Collection's
        # indexed `.Item(key)`) needs its argument passed through like a
        # call, not dropped -- get_prop() only supports the bare,
        # zero-arg property-get shape.
        if call_args and hasattr(obj, "invoke"):
            return obj.invoke(proc_name, call_args)
        if hasattr(obj, "get_prop"):
            return obj.get_prop(proc_name)
        raise VBRuntimeError(f"Object doesn't support this property or method: '{proc_name}'", 438)
    if call_type in (4, 8):
        if hasattr(obj, "set_prop"):
            obj.set_prop(proc_name, call_args[0] if call_args else VBEmpty)
            return VBEmpty
        raise VBRuntimeError(f"Cannot set property '{proc_name}'", 438)
    if hasattr(obj, "invoke"):
        return obj.invoke(proc_name, call_args)
    raise VBRuntimeError(f"Object doesn't support this property or method: '{proc_name}'", 438)


def bi_varptr(interp, args):
    """Return a safe, symbolic address for VBA's hidden pointer helpers.

    ``VarPtr``/``StrPtr``/``ObjPtr`` are chiefly useful to malware as
    arguments to Declare'd memory APIs.  Python values have no VBA address
    that would be meaningful to the fake Win32 layer, and exposing a real
    host address would be both incorrect and unnecessary.  A stable nonzero
    sentinel preserves the branch/call semantics while all native calls stay
    inside the sandbox model.
    """
    return 0x00500000


def bi_isnumeric(interp, args):
    try:
        to_number(args[0])
        return True
    except VBRuntimeError:
        return False


def bi_isarray(interp, args):
    return isinstance(args[0], VBArray)


def bi_isobject(interp, args):
    from vba_emulator.com_objects import ComObject
    return isinstance(args[0], ComObject) or args[0] is VBNothing


def bi_isnull(interp, args):
    return args[0] is VBNull


def bi_isempty(interp, args):
    return args[0] is VBEmpty


def bi_typename(interp, args):
    return vb_type_name(args[0])


def bi_array(interp, args):
    arr = VBArray(bounds=[(0, len(args) - 1)] if args else [(0, -1)])
    for i, v in enumerate(args):
        arr.set((i,), v)
    return arr


def bi_ubound(interp, args):
    arr = args[0]
    if not isinstance(arr, VBArray):
        raise VBRuntimeError("Subscript out of range", 9)
    dim = _i(args[1]) if len(args) > 1 else 1
    if dim < 1 or dim > len(arr.bounds):
        raise VBRuntimeError("Subscript out of range", 9)
    return arr.bounds[dim - 1][1]


def bi_lbound(interp, args):
    arr = args[0]
    if not isinstance(arr, VBArray):
        raise VBRuntimeError("Subscript out of range", 9)
    dim = _i(args[1]) if len(args) > 1 else 1
    if dim < 1 or dim > len(arr.bounds):
        raise VBRuntimeError("Subscript out of range", 9)
    return arr.bounds[dim - 1][0]


def bi_escape(interp, args):
    import urllib.parse
    result = urllib.parse.quote(_s(args[0]))
    check_string_len(len(result))
    return result


def bi_unescape(interp, args):
    import urllib.parse
    result = urllib.parse.unquote(_s(args[0]))
    check_string_len(len(result))
    return result


def bi_environ(interp, args):
    # VBA's built-in Environ()/Environ$() -- previously always returned ""
    # regardless of session.env_vars (already populated with TEMP/APPDATA/
    # USERPROFILE/... and kept in sync with WshEnvironment writes), unlike
    # every other environment-read path in the package. A common idiom
    # like `Environ("TEMP") & "\payload.exe"` resolved to just
    # "\payload.exe", corrupting the reported drop location.
    name = _s(args[0])
    interp.ioc.emit("environment_access", name=name)
    return interp.session.env_vars.get(name.upper(), interp.session.env_vars.get(name, ""))


def bi_msgbox(interp, args):
    text = _s(args[0]) if args else ""
    interp.ioc.emit("ui_prompt", api="MsgBox", text=text)
    return 1


def bi_inputbox(interp, args):
    interp.ioc.emit("ui_prompt", api="InputBox", text=_s(args[0]) if args else "")
    return ""


def bi_shell(interp, args):
    # VBA's own built-in Shell() function -- part of the VBA runtime
    # itself, no CreateObject involved. Runs a program and returns its
    # (fake) process ID. At least as common in real macro malware as the
    # CreateObject("WScript.Shell").Run route; found missing via a real
    # sample where it was the macro's actual payload-launch call
    # (`Shell "explorer " & path, vbNormalFocus`), silently aborting the
    # whole AutoOpen with "Sub or Function not defined" past that point.
    cmd = _s(args[0]) if args else ""
    interp.session.process_log.append(cmd)
    interp.ioc.emit("process_create", api="Shell", command=cmd)
    return 1337


def bi_dir(interp, args):
    # VBA's built-in Dir([pathname], [attributes]) -- returns the first
    # matching filename, "" if not found; called again with no arguments,
    # returns the *next* match from the same wildcard listing. Extremely
    # common for existence checks before a drop (`If Dir(path) = "" Then
    # ... write the payload ...`, seen in a real sample) and for
    # enumerating files to exfiltrate/tamper with.
    #
    # We only resolve concrete, non-wildcard paths against files the
    # script itself already wrote into the virtual filesystem. A wildcard
    # query (or the no-argument continuation call) always returns "" --
    # deliberately, rather than fabricating a listing of files that don't
    # exist on this (nonexistent) virtual host, or omitting real ones.
    # This still lets the extremely common existence-check idiom above
    # observe the "file doesn't exist yet" branch (the interesting one)
    # correctly on a first run.
    if not args:
        return ""
    pathname = _s(args[0])
    if not pathname or "*" in pathname or "?" in pathname:
        return ""
    if not interp.session.vfs_exists(pathname):
        return ""
    return pathname.replace("\\", "/").rsplit("/", 1)[-1]


def bi_freefile(interp, args):
    n = interp.session._next_freefile
    interp.session._next_freefile += 1
    return n


def bi_mkdir(interp, args):
    # VBA's built-in MkDir statement (called as a function here, same as
    # Shell/Dir above -- VBA statement-vs-function call syntax collapses to
    # the same "identifier(args)"/"identifier args" shape this parser
    # already handles). Registered into the virtual FS so a later
    # `Dir(path, vbDirectory)` existence check sees the directory as
    # created -- a common `If Dir(p, vbDirectory) = "" Then MkDir p`
    # staging-folder idiom seen in real drop-and-run macros.
    path = _s(args[0])
    interp.session.vfs_write(path, "", is_binary=False)
    interp.ioc.emit("filesystem_create", api="MkDir", path=path)
    return VBEmpty


def bi_rmdir(interp, args):
    path = _s(args[0])
    interp.session.vfs_delete(path)
    interp.ioc.emit("filesystem_delete", api="RmDir", path=path)
    return VBEmpty


def bi_kill(interp, args):
    path = _s(args[0])
    interp.session.vfs_delete(path)
    interp.ioc.emit("filesystem_delete", api="Kill", path=path)
    return VBEmpty


def bi_chdir(interp, args):
    return VBEmpty


BUILTINS = {
    "chr": bi_chr, "chrw": bi_chr, "chr$": bi_chr,
    "asc": bi_asc, "ascw": bi_asc,
    "len": bi_len,
    "lenb": bi_lenb, "ascb": bi_ascb, "chrb": bi_chrb,
    "midb": bi_midb, "midb$": bi_midb,
    "leftb": bi_leftb, "leftb$": bi_leftb,
    "rightb": bi_rightb, "rightb$": bi_rightb,
    "strconv": bi_strconv,
    "mid": bi_mid, "mid$": bi_mid,
    "left": bi_left, "left$": bi_left,
    "right": bi_right, "right$": bi_right,
    "instr": bi_instr, "instrrev": bi_instrrev,
    "replace": bi_replace,
    "split": bi_split,
    "join": bi_join,
    "filter": bi_filter,
    "strreverse": bi_strreverse,
    "lcase": bi_lcase, "lcase$": bi_lcase,
    "ucase": bi_ucase, "ucase$": bi_ucase,
    "trim": bi_trim, "trim$": bi_trim,
    "ltrim": bi_ltrim, "rtrim": bi_rtrim,
    "space": bi_space, "space$": bi_space,
    "string": bi_string_,
    "strcomp": bi_strcomp,
    "cstr": bi_cstr, "cint": bi_cint, "clng": bi_cint, "cbyte": bi_cbyte,
    "formatcurrency": bi_formatcurrency,
    "cdbl": bi_cdbl, "csng": bi_cdbl, "cbool": bi_cbool, "val": bi_val,
    "hex": bi_hex, "oct": bi_oct,
    "abs": bi_abs, "int": bi_int, "fix": bi_fix, "sgn": bi_sgn, "sqr": bi_sqr,
    "rnd": bi_rnd, "randomize": bi_randomize, "doevents": bi_doevents,
    "now": bi_now, "date": bi_date, "time": bi_time, "timer": bi_timer,
    "hour": bi_hour, "minute": bi_minute, "second": bi_second,
    "day": bi_day, "month": bi_month, "year": bi_year, "weekday": bi_weekday,
    "timeserial": bi_timeserial, "timevalue": bi_timevalue,
    "dateserial": bi_dateserial, "dateadd": bi_dateadd,
    "callbyname": bi_callbyname,
    "varptr": bi_varptr, "strptr": bi_varptr, "objptr": bi_varptr,
    "isnumeric": bi_isnumeric, "isarray": bi_isarray, "isobject": bi_isobject,
    "isnull": bi_isnull, "isempty": bi_isempty,
    "typename": bi_typename,
    "array": bi_array, "ubound": bi_ubound, "lbound": bi_lbound,
    "escape": bi_escape, "unescape": bi_unescape,
    "environ": bi_environ, "environ$": bi_environ,
    "msgbox": bi_msgbox, "inputbox": bi_inputbox, "inputbox$": bi_inputbox,
    "shell": bi_shell,
    "dir": bi_dir, "dir$": bi_dir,
    "freefile": bi_freefile,
    "mkdir": bi_mkdir, "rmdir": bi_rmdir, "kill": bi_kill, "chdir": bi_chdir,
}


# VBA/VBScript intrinsic constants (vbCrLf, vbNormalFocus, ...) -- plain
# identifiers, not language keywords, so they're declared as ordinary
# global values rather than handled in the parser. Left unmodeled they
# silently evaluate to Empty (0 / "") instead of their real value --
# doesn't crash, but silently wrong (e.g. string concatenation missing
# its line breaks, a window-style argument being 0 instead of intended).
VBA_CONSTANTS = {
    "vbcr": "\r", "vblf": "\n", "vbcrlf": "\r\n", "vbnewline": "\r\n",
    "vbtab": "\t", "vbback": "\b", "vbformfeed": "\f", "vbverticaltab": "\v",
    "vbnullchar": "\0", "vbnullstring": "",
    "vbobjecterror": -2147221504,
    "vbokonly": 0, "vbokcancel": 1, "vbabortretryignore": 2, "vbyesnocancel": 3,
    "vbyesno": 4, "vbretrycancel": 5,
    "vbcritical": 16, "vbquestion": 32, "vbexclamation": 48, "vbinformation": 64,
    "vbdefaultbutton1": 0, "vbdefaultbutton2": 256, "vbdefaultbutton3": 512,
    "vbapplicationmodal": 0, "vbsystemmodal": 4096,
    "vbok": 1, "vbcancel": 2, "vbabort": 3, "vbretry": 4, "vbignore": 5,
    "vbyes": 6, "vbno": 7,
    "vbhide": 0, "vbnormalfocus": 1, "vbminimizedfocus": 2, "vbmaximizedfocus": 3,
    "vbnormalnofocus": 4, "vbminimizednofocus": 6,
    "vbempty": 0, "vbnull": 1, "vbinteger": 2, "vblong": 3, "vbsingle": 4,
    "vbdouble": 5, "vbcurrency": 6, "vbdate": 7, "vbstring": 8, "vbobject": 9,
    "vberror": 10, "vbboolean": 11, "vbvariant": 12, "vbdataobject": 13,
    "vbdecimal": 14, "vbbyte": 17, "vbarray": 8192,
    "vbuppercase": 1, "vblowercase": 2, "vbpropercase": 3,
    "vbwide": 4, "vbnarrow": 8, "vbkatakana": 16, "vbhiragana": 32,
    "vbunicode": 64, "vbfromunicode": 128,
    "vbbinarycompare": 0, "vbtextcompare": 1, "vbdatabasecompare": 2,
    "forreading": 1, "forwriting": 2, "forappending": 8,
    "tristatetrue": -1, "tristatefalse": 0, "tristateusedefault": -2,
    "vbtrue": -1, "vbfalse": 0, "vbusedefault": -2,
    "vbmethod": 1, "vbget": 2, "vblet": 4, "vbset": 8,
    # Excel's broad Constants enumeration. Malware occasionally borrows an
    # unrelated built-in constant purely as an obfuscated numeric literal;
    # `Step xlClassic2` means `Step 2`. Leaving it Empty coerces to zero and
    # turns an otherwise finite string decoder into an infinite loop.
    "xlclassic1": 1, "xlclassic2": 2, "xlclassic3": 3,
}
