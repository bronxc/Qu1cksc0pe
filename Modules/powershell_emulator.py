"""Side-effect-free PowerShell behavior emulation for suspicious scripts.

This module deliberately never hands attacker-controlled source to a real
PowerShell/pwsh interpreter, ``subprocess``, ``os.system``, Python ``eval``/
``exec``, or a host native-code loader. It performs bounded abstract
interpretation of common malicious PowerShell idioms (download cradles,
Base64/XOR/char-array obfuscation, process/registry/file operations,
``Invoke-Expression`` chains, .NET reflection loaders) and records the
effects against fake, in-memory cmdlet/.NET models.

Known native byte buffers may additionally be explored by a bounded Unicorn
guest CPU with synthetic memory and Windows imports. Guest API calls are
never forwarded to the host, and network responses are never fetched.

The goal is behavioral IOC recovery, not standards-compliant PowerShell
execution. Unsupported expressions remain symbolic (``_Unknown``) and never
become real host operations. Mirrors the architecture of ``js_emulator.py``
in this same package -- same bounded-interpreter philosophy, same
subprocess+RLIMIT worker isolation, same JSON result shape family.
"""

from __future__ import annotations

import base64
import binascii
import functools
import fnmatch
import hashlib
import json
import math
import ntpath
import os
import pickle
import re
import struct
import subprocess
import sys
import time
import urllib.parse
import xml.etree.ElementTree as _ElementTree
import zlib
from collections import ChainMap, OrderedDict, deque, namedtuple
from contextlib import contextmanager, nullcontext


class _CommandName(str):
    """A modeled CommandInfo name, distinct from an ordinary string."""


class _GuidValue(str):
    """A GUID value retaining its type for .ToString(format)."""


class _CharValue(str):
    """One UTF-16 code unit; numeric casts must retain its ordinal."""


class _ValueUnresolved(Exception):
    """Internal control transfer for an unavailable pure model value."""


class _PipelineOutput(list):
    """Bounded success-stream collection for structured script bodies."""
    value_chars = 0


def _char_units(text):
    raw = str(text).encode('utf-16-le', errors='surrogatepass')
    return [_CharValue(chr(raw[i] | raw[i + 1] << 8)) for i in range(0, len(raw), 2)]


_HASH_TYPES = {
    'security.cryptography.'+name+suffix: name
    for name in ('md5','sha1','sha256','sha384','sha512')
    for suffix in ('','managed','cryptoserviceprovider','cng')
    if not (name == 'md5' and suffix == 'managed')
}


class _VariableScopes(ChainMap):
    """Variable scopes for the single synthetic script session.

    Reads search parents; unqualified writes stay local. Script/global
    qualifiers target the current synthetic script/root scopes.
    Environment entries also belong to this synthetic root.
    """

    def __init__(self, *maps, script_map=None, type_maps=None):
        super().__init__(*maps)
        self._script_map = self.maps[-1] if script_map is None else script_map
        self._type_maps = [{} for _ in self.maps] if type_maps is None else type_maps

    def new_child(self, m=None, **kwargs):
        child = {} if m is None else m
        child.update(kwargs)
        return type(self)(child, *self.maps, script_map=self._script_map, type_maps=[{}, *self._type_maps])

    def copy(self):
        first = self.maps[0].copy()
        script = first if self._script_map is self.maps[0] else self._script_map
        return type(self)(first, *self.maps[1:], script_map=script,
                          type_maps=[self._type_maps[0].copy(), *self._type_maps[1:]])

    def type_slot(self, key):
        mappings, name = self._target(key)
        target = mappings[0]
        if key.startswith('private:') or 'private:' + name in target:
            name = 'private:' + name
        for index, mapping in enumerate(self.maps):
            if target is mapping:
                return self._type_maps[index], name
        raise KeyError(key)

    def _target(self, key):
        prefix, separator, name = key.partition(':')
        if separator and prefix == 'script':
            return [self._script_map], name
        if separator and prefix == 'global':
            return [self.maps[-1]], name
        if separator and prefix in ('local', 'private'):
            return [self.maps[0]], name
        if prefix == 'env' and separator:
            return [self.maps[-1]], key
        return self.maps, key

    def __getitem__(self, key):
        mappings, name = self._target(key)
        for mapping in mappings:
            if mapping is self.maps[0] and 'private:' + name in mapping:
                return mapping['private:' + name]
            if name in mapping:
                return mapping[name]
        raise KeyError(key)

    def __contains__(self, key):
        try:
            self[key]
            return True
        except KeyError:
            return False

    def __setitem__(self, key, value):
        mappings, name = self._target(key)
        target = mappings[0]
        if key.startswith('private:') or 'private:' + name in target:
            name = 'private:' + name
        target[name] = value


# Entire pure radix-52 function shape. Equality includes every operator,
# bound and branch; variable renaming and whitespace are immaterial.
_DECIMAL_XOR_FUNCTION_SHAPE = '''
param (
    [string]$decimalData,
    [byte]$xorKey = 47
)
$decimalArray = $decimalData -split ',' | ForEach-Object { [int]$_ }
$byteArray = [byte[]]::new($decimalArray.Count)
for ($i = 0; $i -lt $decimalArray.Count; $i++) {
    $byteArray[$i] = [byte]($decimalArray[$i] -bxor $xorKey)
}
return $byteArray
'''

_MEMORY_XOR_IL = (
    ('ldarg_2', None), ('ldlen', None), ('conv_i4', None), ('stloc', 1),
    ('ldc_i4_0', None), ('stloc', 0), ('br_s', 1), ('label', 0),
    ('ldarg_0', None), ('ldloc', 0), ('conv_i', None), ('add', None),
    ('dup', None), ('ldind_u1', None), ('ldarg_2', None), ('ldloc', 0),
    ('ldloc', 1), ('rem', None), ('ldelem_u1', None), ('xor', None),
    ('conv_u1', None), ('stind_i1', None), ('ldloc', 0), ('ldc_i4_1', None),
    ('add', None), ('stloc', 0), ('label', 1), ('ldloc', 0),
    ('ldarg_1', None), ('blt_s', 0), ('ret', None),
)

_BASE28_FUNCTION_SHAPE = '''
param ([string]$b28)
$alpha = 'ABCDEFGHIJKLMNOPQRSTUVWXYZab'
$lut = @{}; for ($k = 0; $k -lt 28; $k++) { $lut[$alpha[$k]] = [long]$k }
$out = [System.Collections.Generic.List[byte]]::new()
$i = 0; $n = $b28.Length
while ($i -lt $n) {
    $r = $n - $i
    if ($r -ge 5) {
        $v = [long]0
        for ($j = 0; $j -lt 5; $j++) { $v = $v * 28 + $lut[$b28[$i + $j]] }
        $out.Add([byte](($v -shr 16) -band 0xFF))
        $out.Add([byte](($v -shr  8) -band 0xFF))
        $out.Add([byte]($v -band 0xFF))
        $i += 5
    } elseif ($r -eq 4) {
        $v = [long]0
        for ($j = 0; $j -lt 4; $j++) { $v = $v * 28 + $lut[$b28[$i + $j]] }
        $out.Add([byte](($v -shr 8) -band 0xFF))
        $out.Add([byte]($v -band 0xFF))
        $i += 4
    } elseif ($r -eq 2) {
        $v = [long]0
        for ($j = 0; $j -lt 2; $j++) { $v = $v * 28 + $lut[$b28[$i + $j]] }
        $out.Add([byte]($v -band 0xFF))
        $i += 2
    } else { break }
}
return ,$out.ToArray()
'''

_BASE52_FUNCTION_SHAPE = '''
param ([string]$s)
$lut=[int[]]::new(0x80);$ai=0
foreach($c in @(0x41..0x5A)+@(0x61..0x7A)){$lut[$c]=$ai;$ai++}
$n=$s.Length
$maxBytes=[int](($n/0xA)*0x7+0x8)
$o=[byte[]]::new($maxBytes);$oi=0;$sc=$s.ToCharArray();$i=0
while($i -lt $n){
 $r=$n-$i
 if($r -ge 0xA){
  $v=[long]$lut[[int]$sc[$i]]
  for($q=1;$q -lt 0xA;$q++){$v=$v*0x34+[long]$lut[[int]$sc[$i+$q]]}
  for($q=6;$q -ge 0;$q--){$o[$oi+$q]=[byte]($v -band 0xFF);$v=$v -shr 8}
  $oi+=7;$i+=0xA
 }else{
  $nb=0
  if($r -eq 9){$nb=6}elseif($r -eq 8){$nb=5}
  elseif($r -eq 6){$nb=4}elseif($r -eq 5){$nb=3}
  elseif($r -eq 3){$nb=2}elseif($r -eq 2){$nb=1}else{break}
  $v=[long]$lut[[int]$sc[$i]]
  for($q=1;$q -lt $r;$q++){$v=$v*0x34+[long]$lut[[int]$sc[$i+$q]]}
  for($q=$nb-1;$q -ge 0;$q--){$o[$oi+$q]=[byte]($v -band 0xFF);$v=$v -shr 8}
  $oi+=$nb;$i+=$r
 }
}
$out=[byte[]]::new($oi)
[System.Buffer]::BlockCopy($o,0,$out,0,$oi)
return ,$out
'''

# Expression evaluation genuinely nests (parens, ``$(...)``, a
# statement-processing round-trip for each nested subexpression --
# roughly 5-6 real Python frames per logical nesting level, confirmed by
# testing a deliberately pathological ``$($($($(...))))`` chain) deeper
# than Python's conservative default 1000-frame limit accommodates for
# some real, heavily-obfuscated samples' legitimate nesting depth.
# Raised once, globally, at import time -- comfortably within a normal
# thread's default 8MB stack for CPython's actual per-frame overhead --
# and paired with ``MAX_EXPR_DEPTH``'s own, tighter, in-process counter
# below (which is what actually decides "too deep," returning a bounded
# ``_Unknown`` instead of ever reaching this raised ceiling) so the two
# together leave real headroom on both sides rather than one bare number
# hoping for the best.
if sys.getrecursionlimit() < 5000:
    sys.setrecursionlimit(5000)

try:
    from Crypto.Cipher import AES as _PyCryptoAES
except ImportError:  # pragma: no cover - pycryptodome is a declared
    # project dependency (requirements.txt); guarded anyway so a
    # stripped-down environment degrades to leaving AES output
    # symbolic instead of crashing the whole emulator.
    _PyCryptoAES = None


# Hex wrappers require roughly twice their decoded text size. Keep the
# source, intermediate text and binary budgets consistent; the worker's
# independent time and memory limits remain in force.
MAX_SOURCE_CHARS = 32_000_000
MAX_VALUE_CHARS = 32_000_000
# A real multi-layer decode chain (hex string -> cleaned hex -> decoded
# bytes -> XOR-decrypted bytes -> final script text, each held in its
# own variable at once) commonly duplicates the *same* ~2MB embedded
# payload across five or more variables simultaneously -- easily
# 15-20MB of legitimate cumulative storage for one ordinary sample,
# confirmed the hard way when a real RemcosRAT sample's chain measured
# ~22.8M chars just before its final decrypted-script assignment, which
# tripped the previous, much tighter budget and silently replaced that
# assignment with ``_Unknown``, breaking the rest of the chain. Kept
# well below unbounded (a genuine runaway/pathological accumulation
# still trips this) but generous enough for several full duplicate
# copies of the largest payload this emulator will resolve at all.
MAX_TOTAL_VALUE_CHARS = 120_000_000
MAX_VARIABLES = 8_000
MAX_EVENTS = 4_000
MAX_STATEMENTS = 1_000_000
# A single real RC4 KSA+PRGA decrypt loop (the near-universal shape for
# a multi-stage loader's own decrypt routine, no fast-path recognizer
# for it the way there is for hex/XOR decode) costs on the order of
# 150-200K real per-statement ticks for just a few KB of payload --
# genuinely bounded work, not a runaway, but a real 2-3-stage loader
# chaining several of these back to back (confirmed against a real
# sample: decrypting its *first* stage alone consumed the entire old
# 200K budget, leaving the second stage's own decrypt -- which is what
# actually reveals the next URL/payload -- truncated) blew straight
# through the old ceiling while using well under 10% of the wall-clock
# budget (the real, final backstop against a genuine infinite loop) to
# get there. Raised 5x on that headroom rather than on the wall clock.
MAX_DECODED_LAYERS = 8
MAX_DYNAMIC_SOURCES = 128
# Large literal AES droppers need ~25 MB of Base64 for a ~19 MB PE.
# Keep finite, coordinated source/data/export bounds; the worker retains
# its independent 768 MiB memory and wall-clock limits.
MAX_EMBEDDED_PAYLOAD_BYTES = 24_000_000
MAX_EXPORTED_PAYLOAD_BYTES = 24_000_000
MAX_PARENTHESES_UNWRAP = 128
MAX_WORKER_MEMORY_BYTES = 768 * 1024 * 1024
WORKER_STARTUP_GRACE_SECONDS = 0.75
DEFAULT_TIMEOUT_SECONDS = 15
MAX_TIMEOUT_SECONDS = 60
MAX_LOOP_ITERATIONS = 300_000
MAX_CALL_DEPTH = 50
MAX_CHILD_PROCESSES = 64
MAX_CHILD_PROCESS_DEPTH = 8
# A blanket circuit-breaker on ``_eval_expr``'s own real recursion depth
# (genuine nesting -- parens, ``$(...)``, a paren-suffix chain each
# recursing into their inner expression -- as opposed to a long *chain*
# of the same operator/pipe stage/method call, which every one of those
# constructs already evaluates iteratively, not recursively, specifically
# so it can't hit this at all). Real source only nests a handful of
# levels deep even in heavily obfuscated samples; this exists purely so
# that *whichever* recursive pattern this bounded interpreter doesn't yet
# handle iteratively -- the one already found and fixed, or a different
# one no sample here happens to exercise -- degrades to a symbolic
# ``_Unknown`` for just that one sub-expression instead of an unhandled
# ``RecursionError`` aborting the entire analysis. One logical nesting
# level here costs several *real* Python frames, not one (a nested
# ``$(...)`` round-trips through statement processing to get back to
# ``_eval_expr`` -- confirmed empirically at ~5-6 real frames per level,
# not assumed), so this is checked against the raised recursion limit
# above with real headroom on both sides: 300 levels x ~6 frames/level
# stays well under half of the raised 5000-frame ceiling, leaving ample
# margin for every other frame already on the stack (statement/loop/
# function-call machinery) by the time any single expression gets this
# deep.
MAX_EXPR_DEPTH = 300
MAX_INTEGER_BITS = 4096
MAX_PARSE_CACHE_BYTES = 64 * 1024 * 1024


class _Unknown:
    """Placeholder for a value this bounded interpreter could not resolve.

    Never treated as a real string/number: propagating it (instead of
    guessing) keeps every downstream finding honest about what was actually
    observed versus merely suspected.
    """

    __slots__ = ("hint",)

    def __init__(self, hint=""):
        self.hint = str(hint)[:512]

    def __str__(self):
        return f"<unknown:{self.hint}>" if self.hint else "<unknown>"

    def __repr__(self):
        return f"_Unknown({self.hint!r})"


def _is_unknown(value):
    return isinstance(value, _Unknown)


def _cap(value, limit=MAX_VALUE_CHARS):
    text = value if isinstance(value, str) else str(value)
    if len(text) > limit:
        return text[:limit] + "...<truncated>"
    return text


_DOTNET_CODECS = {
    "unicode": "utf-16-le",
    "utf-16": "utf-16-le",
    "utf16": "utf-16-le",
    "bigendianunicode": "utf-16-be",
    "utf32": "utf-32-le",
    "ascii": "ascii",
    "utf8": "utf-8",
    "utf-8": "utf-8",
    "default": "utf-8",
}


def _dotnet_codec(name):
    """Map a .NET ``System.Text.Encoding`` name (as captured from
    ``::Unicode``/``::UTF8``/``GetEncoding("...")``) to the Python codec
    that actually decodes/encodes it. ``Encoding.Unicode`` specifically
    means UTF-16LE, not UTF-8 -- silently assuming UTF-8 for it (this
    emulator's original, unconditional behavior) turns real UTF-16
    payload text into null-byte-interleaved noise, which is exactly the
    shape a reflection-based ``[Convert].GetMethod('FromBase64String',
    ...)`` + ``[Text.Encoding]::GetEncoding('Unicode').GetString(...)``
    decode chain produces.
    """
    return _DOTNET_CODECS.get(str(name or "").lower(), "utf-8")


def _value_size(value):
    """Cheap element/char-count proxy for ``_store_variable``'s resource
    budget. A hex-decode/XOR-decrypt loop's output is commonly a list of
    a few million ints; ``len(str(value))`` would have to materialize
    that entire list as a comma-joined string just to measure it (both
    very slow and a wildly inflated ~5x overcount of the real per-byte
    weight), so list/str/bytes-like values are measured by element count
    directly instead.
    """
    if value is None:
        return 0
    if isinstance(value, (str, list, bytes, bytearray)):
        return len(value)
    if isinstance(value, _BinaryValue):
        return len(value.data)
    return len(str(value))


def _safe_text(value, limit=4096):
    if value is None:
        return ""
    return _cap(str(value), limit)


def _regex_replace(pattern, replacement, text):
    """Bounded replacement with common .NET substitution tokens.

    Python's replacement syntax uses backslashes; PowerShell uses $1,
    ${name}, $&, $$, $`, $' and $_. Never interpret replacement as code.
    """
    tokens = re.split(r"(\$(?:\d+|\{\w+\}|[&$`'_+]))", replacement)
    fragments = []
    size = 0

    def append(part):
        nonlocal size
        size += len(part)
        if size > MAX_VALUE_CHARS:
            raise ValueError("replacement-output-limit")
        fragments.append(part)

    end = 0
    for match in re.finditer(pattern, text, re.IGNORECASE):
        append(text[end:match.start()])
        for token in tokens:
            if token == "$$":
                part = "$"
            elif token == "$&":
                part = match.group(0)
            elif token == "$`":
                part = text[:match.start()]
            elif token == "$'":
                part = text[match.end():]
            elif token == "$_":
                part = text
            elif token == "$+":
                part = next((g for g in reversed(match.groups()) if g is not None), "")
            elif re.fullmatch(r"\$(?:\d+|\{\w+\})", token):
                key = token[2:-1] if token.startswith("${") else token[1:]
                try:
                    part = match.group(int(key) if key.isdigit() else key) or ""
                except (IndexError, KeyError):
                    part = token
            else:
                part = token
            append(part)
        end = match.end()
    append(text[end:])
    return "".join(fragments)


def _safe_event_value(value, depth=0):
    if depth > 3:
        return "<depth-limit>"
    if isinstance(value, (_Unknown, _BinaryValue, str)):
        return _safe_text(value)
    if value is None or isinstance(value, (bool, int, float)):
        return value
    if isinstance(value, (list, tuple)):
        bounded = [_safe_event_value(item, depth + 1) for item in value[:32]]
        if len(value) > 32:
            bounded.append(f"<{len(value) - 32} more items>")
        return bounded
    if isinstance(value, dict):
        bounded = {}
        for index, (key, item) in enumerate(value.items()):
            if index >= 32:
                bounded["<more>"] = f"{len(value) - 32} more entries"
                break
            bounded[_safe_text(key, 128)] = _safe_event_value(item, depth + 1)
        return bounded
    return _safe_text(value)


class _ObjectRef:
    """A fake, in-memory stand-in for a .NET/COM object instance
    (``New-Object Net.WebClient``, ``[Text.Encoding]::UTF8``, a
    ``[scriptblock]``, ...). ``kind`` drives which behavior model
    ``_apply_method``/``_apply_property`` dispatch to; ``state`` holds
    whatever small bit of symbolic data that model needs (e.g. an
    ``ADODB.Stream``'s buffered bytes).  Never a real object -- every method
    call on one of these only ever manipulates this plain Python state and
    optionally emits an IOC event.
    """

    __slots__ = ("kind", "state")

    def __init__(self, kind, state=None):
        self.kind = kind
        self.state = state if state is not None else {}

    def __str__(self):
        return f"<object:{self.kind}>"


class _BinaryValue:
    """Opaque in-memory bytes recovered from a modeled data flow."""

    __slots__ = ("data", "sha256", "complete")

    def __init__(self, data, *, complete=True):
        self.data = bytes(data[:MAX_EMBEDDED_PAYLOAD_BYTES])
        self.sha256 = hashlib.sha256(self.data).hexdigest()
        self.complete = bool(complete) and len(data) <= MAX_EMBEDDED_PAYLOAD_BYTES

    def __len__(self):
        return len(self.data)

    def __str__(self):
        state = "complete" if self.complete else "partial"
        return f"<binary:{len(self.data)} bytes sha256={self.sha256} {state}>"


class _ByteArray(list):
    """Mutable managed byte[] retaining its element type for API models."""


class _IntegerArray(list):
    """One-dimensional integer array with a known CLR element type."""

    def __init__(self, values, element_type):
        super().__init__(values)
        self.element_type = element_type


class _FloatingArray(list):
    def __init__(self, values, element_type):
        super().__init__(values)
        self.element_type = element_type


class _ObjectArray(list):
    """Object[] retains known boxing provenance, never guesses integer widths."""
    def __init__(self, values, boxed_types=None):
        super().__init__(values)
        self.boxed_types = list(boxed_types) if boxed_types is not None else [None] * len(self)

    def __setitem__(self, index, value):
        super().__setitem__(index, value)
        self.boxed_types[index] = [None] * len(value) if isinstance(index, slice) else None


_INTEGER_CAST_TYPES = {
    alias: (name, minimum, maximum)
    for names, name, minimum, maximum in (
        (('sbyte',), 'SByte', -128, 127),
        (('short', 'int16'), 'Int16', -(1 << 15), (1 << 15) - 1),
        (('ushort', 'uint16'), 'UInt16', 0, (1 << 16) - 1),
        (('int', 'int32'), 'Int32', -(1 << 31), (1 << 31) - 1),
        (('uint', 'uint32'), 'UInt32', 0, (1 << 32) - 1),
        (('long', 'int64'), 'Int64', -(1 << 63), (1 << 63) - 1),
        (('ulong', 'uint64'), 'UInt64', 0, (1 << 64) - 1),
    ) for alias in names
}


# ---------------------------------------------------------------------------
# Lexical helpers: PowerShell quoting is meaningfully different from C-style
# languages -- single quotes are fully literal (only ``''`` escapes),
# double quotes interpolate ``$var``/``$(expr)`` and use a backtick escape,
# and here-strings (``@"..."@`` / ``@'...'@``) span multiple lines and are
# closed only by ``"@``/``'@`` at the start of a line. Every scanner below
# needs to agree on these rules or one text span gets misclassified and
# corrupts everything after it -- the exact failure mode already hardened
# against at length in js_emulator.py's own quote-tracking history.
# ---------------------------------------------------------------------------

_IDENT = r"[A-Za-z_][A-Za-z0-9_]*"
# Same as ``_IDENT`` but tolerating an embedded no-op backtick
# (``I`E`X``) anywhere in the token, for matching a *command name*
# directly against un-stripped source -- see ``_eval_expr``'s call-match
# for why the whole expression can't be backtick-stripped up front.
_IDENT_BACKTICK = r"[A-Za-z_`][A-Za-z0-9_`]*"
# Function/variable *names* (unlike a real .NET member name, which the
# CLS forbids from starting with a digit -- ``_IDENT`` stays correct for
# ``.Member`` matching) are far more permissive in real PowerShell: a
# generated obfuscated helper is routinely named like
# ``9R0V9OweVKT3GXyqYK1vtLIXCx`` specifically because a leading digit
# defeats naive "identifiers start with a letter" signature/regex
# matching -- the same class of evasion this pattern exists to not fall
# for. Confirmed against a real sample: ``function 9R0V9Owe...{ }``
# never even registered as a callable function with the stricter
# ``_IDENT``, and ``(Get-Command 9R0V9Owe...).ScriptBlock`` -- real
# PowerShell's own workaround for a callee name a plain bareword/``&``
# site can't spell -- silently failed to re-dispatch to it for the same
# reason, leaving an entire RC4+GZip decrypt-and-invoke stage inert. The
# ``(?=...[A-Za-z])`` lookahead still excludes a bare number (``& 123``
# is never a real command) without excluding anything that mixes in even
# one letter.
_COMMAND_IDENT = r"(?=[A-Za-z0-9_]*[A-Za-z])[A-Za-z0-9_]+"
_COMMAND_IDENT_BACKTICK = r"(?=[A-Za-z0-9_`]*[A-Za-z])[A-Za-z0-9_`]+"
# A PowerShell variable name: ``$name``, ``${name with spaces}``, or one of
# the automatic variables. Backticks inside an unbraced name are a no-op
# escape obfuscators use to dodge literal string matching (``$e`nv``) --
# stripped by ``_strip_backtick_noop`` before this ever has to match it.
_VAR_REF = r"\$(?:\{[^}]+\}|[A-Za-z0-9_]+(?::[A-Za-z_][A-Za-z0-9_]*)?|\$|\?|_)"


def _strip_backtick_noop(text):
    """Remove a backtick immediately before an identifier character outside
    any quoted span -- ``I`E`X`` is exactly ``IEX`` to the real parser, a
    trivial static-signature evasion with no other effect. Backticks that
    are genuine string escapes (inside quotes) are left untouched; this is
    only ever called on short, already-extracted identifier-like tokens
    (cmdlet/member names), never on a whole statement.
    """
    return text.replace("`", "")


def _numeric_coerce(value):
    if isinstance(value, _CharValue):
        return ord(value)
    if value is None:
        return 0
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, (int, float)):
        return value
    number = _numeric_literal(str(value))
    if number is not None:
        return number
    raise ValueError(f"not numeric: {value!r}")


def _bounded_text_cache(function):
    # Bound both entries and estimated retained bytes. Large scripts recur
    # across parser helpers too: excluding all long keys forces repeated
    # full-source scans, while an entry-only LRU can retain GB of prefixes.
    cache = OrderedDict()
    retained = hits = misses = 0
    info = namedtuple("CacheInfo", "hits misses maxsize currsize retained_bytes")

    @functools.wraps(function)
    def bounded(text):
        nonlocal retained, hits, misses
        # Integer keys avoid a second full string comparison in move_to_end.
        # Keep the most recently supplied equal string so repeated calls with
        # that object also skip comparison against an older multi-MB copy.
        # A hash collision is a cache miss, never evidence of equal source.
        key = (hash(text), len(text))
        item = cache.get(key)
        if item is not None and (text is item[2] or text == item[2]):
            hits += 1
            if text is not item[2]:
                replacement_weight = item[1] + sys.getsizeof(text) - sys.getsizeof(item[2])
                if replacement_weight <= item[1]:
                    retained += replacement_weight - item[1]
                    cache[key] = (item[0], replacement_weight, text)
            cache.move_to_end(key)
            return item[0]
        misses += 1
        value = function(text)
        # Include the string's actual Unicode storage, not a fixed multiplier
        # that needlessly evicts repeated ASCII/Base64 layers. Scanner spans
        # include tuples, indices and list slots.
        weight = sys.getsizeof(text) + (len(value.mask) if isinstance(value, _PositionMask) else len(value) * 192) + 256
        if weight <= MAX_PARSE_CACHE_BYTES:
            previous = cache.pop(key, None)
            if previous is not None:
                retained -= previous[1]
            while cache and (len(cache) >= 256 or retained + weight > MAX_PARSE_CACHE_BYTES):
                _, (_, old_weight, _) = cache.popitem(last=False)
                retained -= old_weight
            cache[key] = (value, weight, text)
            retained += weight
        return value

    def clear():
        nonlocal retained, hits, misses
        cache.clear()
        retained = hits = misses = 0

    bounded.cache_clear = clear
    bounded.cache_info = lambda: info(hits, misses, 256, len(cache), retained)
    return bounded


class _PositionMask:
    """Constant-time position membership with one byte per source character."""
    __slots__ = ("mask",)

    def __init__(self, mask):
        self.mask = bytes(mask)

    def __contains__(self, position):
        return 0 <= position < len(self.mask) and bool(self.mask[position])


@_bounded_text_cache
def _top_level_positions(expr):
    """The character indices in ``expr`` that are top-level code:
    depth 0, outside any quoted/comment span. Bracket-opening/closing
    characters themselves are excluded (only relevant as depth deltas, an
    operator match never starts on one of these).

    Cached: a bounded ``for``/``foreach`` loop's body is the *same*
    statement text re-evaluated once per iteration (up to
    ``MAX_LOOP_ITERATIONS`` times), and this scan -- plus
    ``_scan_ps_text``'s, cached alongside it -- was, by a wide margin, the
    dominant cost of running one, confirmed via profiling a real hex/XOR
    decode sample that otherwise couldn't get through a fraction of its
    payload before exhausting its statement budget. Every caller only ever
    reads the returned set (membership tests), never mutates it, so
    sharing the cached object across calls is safe.
    """
    top_level = bytearray(len(expr))
    depth = 0
    for start, end, kind in _scan_ps_text(expr):
        if kind != "code":
            continue
        for offset, ch in enumerate(expr[start:end]):
            if ch in "([{":
                depth += 1
            elif ch in ")]}":
                depth = max(0, depth - 1)
            elif depth == 0:
                top_level[start + offset] = 1
    return _PositionMask(top_level)


def _top_level_matches(expr, pattern):
    """Yield ``pattern`` matches that start outside any quoted/comment span
    *and* at bracket depth 0 -- the shared building block every binary-
    operator tier below uses so ``Foo($a + $b) -bxor $c`` never mistakes
    the ``+`` inside the call for a top-level operator.

    Matches the *whole* ``expr`` in one ``finditer`` pass (not one pass per
    quote-delimited sub-segment): a lookaround-based pattern anchored right
    after a closing quote -- ``"x" -f $y``, the space before ``-f`` needs
    ``(?<=\\S)`` to see the quote that ends the *previous* span -- would
    otherwise search an isolated fragment with no character before it,
    silently failing every such lookaround.
    """
    top_level = _top_level_positions(expr)
    for match in pattern.finditer(expr):
        if match.start() in top_level:
            yield match


def _last_top_level_match(expr, pattern, top_level):
    """Like ``_top_level_matches``, but takes an already-computed
    ``_top_level_positions(expr)`` set (so a caller checking many patterns
    against the same ``expr`` -- every ``_OPERATOR_TIERS`` entry, in
    particular -- computes that O(len(expr)) scan once, not once per
    pattern) and returns only the last match (what every operator tier
    actually needs, for left-associative splitting).
    """
    last = None
    for match in pattern.finditer(expr):
        if match.start() in top_level:
            last = match
    return last


_WORD_OP_PATTERNS = set()


def _word_op_pattern(*names):
    escaped = sorted((re.escape(name) for name in names), key=len, reverse=True)
    # Unlike ``_PLUS_MINUS_RE``, the left side only needs to reject a
    # *letter*/underscore immediately before the operator that isn't
    # itself the tail of a ``$variable`` name (still blocking a real
    # hyphenated bareword like ``Do-Match``) -- a digit, quote, or
    # closing bracket right before it (``83-bxor $k``, no space) is
    # completely unambiguous, since no real PowerShell identifier ends
    # in a bare digit immediately followed by one of these exact
    # keyword operators. Requiring whitespace there too (the original,
    # more conservative rule) silently dropped every such unpadded
    # numeric/bracket-adjacent use straight to ``_Unknown`` -- and,
    # separately, so did rejecting *every* letter-before case: a real
    # minified/obfuscated decode loop routinely has zero whitespace
    # anywhere (``$k_Cp4VuhBLpefMV-lt$Fh7U7rpF3n.Length``), and most
    # PowerShell variable names end in a letter, not a digit. A fixed-
    # width lookbehind can't tell "tail of a bareword" from "tail of a
    # $variable name" (both are just "preceded by a letter") since a
    # variable name has no bounded length, so that distinction is made
    # afterward in Python by ``_word_op_last_match`` (walking back over
    # the whole identifier run to check whether it started with ``$``)
    # instead of in the regex itself; this pattern only excludes the
    # unambiguous case of *no* letter/underscore at all before it. Every
    # pattern built here is tracked in ``_WORD_OP_PATTERNS`` so
    # ``_split_binary_operator`` knows which tiers need that extra check.
    # The right side has the same asymmetry fixed on the left: a real
    # ``Verb-Noun`` cmdlet name never has a variable sigil, quote,
    # opening bracket, or digit immediately after one of these keyword
    # operators either, so ``$a-bxor$b``/``$a[0]-bxor$c[0]``/``$_-bxor0``
    # (no space on either side -- a common minified decode-loop shape)
    # is just as unambiguous as the already-allowed left-side adjacency.
    pattern = re.compile(
        r"(" + "|".join(escaped) + r")(?:(?!\S)|(?=[$'\"(\[0-9]))",
        re.IGNORECASE,
    )
    _WORD_OP_PATTERNS.add(pattern)
    return pattern


def _word_op_last_match(expr, pattern, top_level):
    """Like ``_last_top_level_match``, but for a ``_word_op_pattern``
    tier: a match immediately preceded by a letter/digit/underscore is
    only accepted if that whole contiguous identifier run traces back to
    a ``$`` (a real variable name's tail, e.g. ``$Fh7U7rpF3n-lt...``) --
    otherwise it's a hyphenated bareword's own token (``Do-Match``) and
    must be rejected, exactly as the old, stricter regex-only left
    lookbehind did for that case. See ``_word_op_pattern``'s docstring.
    """
    last = None
    for match in pattern.finditer(expr):
        pos = match.start()
        if pos not in top_level:
            continue
        if pos > 0 and (expr[pos - 1].isalnum() or expr[pos - 1] == "_"):
            numeric_left = re.search(
                r'(?:^|[^\w.]|-(?:eq|ne|gt|lt|ge|le|bxor|band|bor|shl|shr))'
                r'(?:0x[0-9a-f]+|\d+(?:\.\d+)?)$', expr[:pos], re.I)
            if numeric_left:
                last = match
                continue
            j = pos
            while j > 0 and (expr[j - 1].isalnum() or expr[j - 1] == "_"):
                j -= 1
            if j == 0 or expr[j - 1] != "$":
                continue
        last = match
    return last


# Mandatory whitespace on *both* sides, unlike a typical "operator" regex --
# specifically to never mistake a bare ``Verb-Noun`` cmdlet name (``Start-
# Process``, hyphen with zero surrounding whitespace, both sides plain
# letters) for a binary minus. Real PowerShell arithmetic is essentially
# always written with padding (``$a + $b``, ``$x - 1``); the rare unpadded
# form (``$a+$b``) falls through to ``_Unknown`` instead, which is the
# correct trade to make -- confirmed the hard way: an earlier unpadded
# version of this pattern silently misparsed every single cmdlet call
# containing a hyphen.
#
# Two unpadded shapes that are still completely unambiguous:
#  - a quote character directly against the operator (``'http://'+
#    '1.2.3.4'``, a very common way to build a C2 URL specifically to
#    keep the literal string out of one obvious static-scan token).
#  - a digit immediately on the *right* of the operator (``$x.Length-
#    1``, the near-universal "last valid index" idiom), checked via a
#    lookahead so it applies regardless of what's on the left -- no
#    real ``Verb-Noun`` cmdlet/function noun starts with a bare digit,
#    so this can't collide with the ``Start-Process`` case either.
# No real ``Verb-Noun`` name can have a quote touching its hyphen or a
# digit right after it, so allowing either of these to skip the padding
# requirement can't reintroduce the cmdlet ambiguity this whole
# tradeoff exists to avoid.
_PLUS_MINUS_RE = re.compile(
    r"(?:(?<=\S)[ \t]+|(?<=['\")\]])|(?=[+\-]\d))([+\-])(?:[ \t]+(?=\S)|(?=['\"$0-9(\[]))"
)
_VARIABLE_ADD_SUB_RE = re.compile(r"([+\-])(?=[$('\"\[])")
# ``)``/``]`` added to the left-side unpadded set alongside quotes: a
# closing paren/bracket immediately before ``+``/``-`` (the tail end of a
# ``.Insert(...)+$(...)`` chained-method-call concatenation, extremely
# common in deeply nested string-building obfuscation -- no space ever
# separates the method call's own closing paren from the next ``+``) is
# exactly as unambiguous as a quote there: no real ``Verb-Noun`` cmdlet
# name can have one of these immediately before its hyphen either.
# Confirmed missing the hard way -- ``_split_binary_operator`` silently
# refused to split an entire multi-``+`` concatenation chain built purely
# from ``)+$(...)`` joins, collapsing the whole thing to one opaque
# unparsed ``_Unknown`` even though every individual joined piece
# resolved fine on its own.
# A fully unrestricted version of this (confirmed the hard way) turns a
# bareword *route/path* argument like ``Invoke-Request /script`` into
# "Invoke-Request" divided by "script" -- ``/`` and ``%`` start plenty
# of real unquoted command-argument tokens even though neither can
# appear *inside* a cmdlet/identifier name. Same fix shape as
# ``_PLUS_MINUS_RE``: padded is always safe, and unpadded is safe only
# when the right side is a digit specifically (no real argument token
# starts with a bare digit right after the operator), which is exactly
# what the common unpadded ``.Length/2``/``.Length%8`` idiom needs.
# Also accept an adjacent variable operand (``$i%$key.Length``).
# Requiring a non-whitespace left operand keeps ``Command /$route``
# from being split as arithmetic.
# Start with the operator character so regex search can skip large
# strings without testing multiple lookarounds at every character.
_MUL_DIV_RE = re.compile(
    r"([*/%])(?:(?=\d)|(?<=[\w)\]][*/%])(?=\$)|(?<=[ \t][*/%])(?=[ \t]+\S))"
)

_OPERATOR_TIERS = [
    _word_op_pattern("-f"),
    _word_op_pattern("-or"),
    _word_op_pattern("-and"),
    _word_op_pattern("-bor"),
    _word_op_pattern("-bxor"),
    _word_op_pattern("-band"),
    _word_op_pattern(
        "-eq", "-ne", "-gt", "-lt", "-ge", "-le", "-like", "-notlike",
        "-match", "-notmatch", "-contains", "-notcontains", "-in", "-notin",
        "-shl", "-shr", "-replace", "-as", "-is", "-isnot",
    ),
    _PLUS_MINUS_RE,
    _MUL_DIV_RE,
    _word_op_pattern("-join", "-split"),
    # Range operator (``0..255``, an RC4/S-box KSA loop's near-universal
    # way to seed a 0..N array) -- binds tighter than every operator
    # above in real PowerShell precedence too, so it belongs last (this
    # list is checked loosest-first, see ``_split_binary_operator``).
    re.compile(r"(\.\.)"),
]


def _fully_wrapped(text, opener, closer):
    """True when ``text`` is exactly one balanced ``opener``...``closer``
    group spanning the whole string (``(...)``, ``@(...)``) -- i.e. the
    outermost bracket's own matching close is the very last character, not
    some inner one.

    Delegates to ``_extract_balanced`` rather than hand-rolling a depth
    counter: an ``opener`` longer than one character (``@(``) has an inner
    bracket *character* (``(``) that recurs on its own throughout the
    body (``@(('a'+'b'))`` has a plain, ``@``-less ``(`` right after the
    ``@(``) -- a counter that only treated ``@(`` itself as depth+1 (not
    every bare ``(``) undercounted nested groups and misjudged them as
    "closed early", which made every array subexpression containing a
    single parenthesized item fail to evaluate at all.
    """
    if not (text.startswith(opener) and text.endswith(closer)):
        return False
    open_index = len(opener) - 1
    inner, end_index = _extract_balanced(text, open_index, opener[-1], closer)
    return inner is not None and end_index == len(text) - 1


def _strip_backtick_noop_outside_strings(text):
    spans = _scan_ps_text(text)
    out = []
    for start, end, kind in spans:
        segment = text[start:end]
        if kind == "code":
            out.append(segment.replace("`", ""))
        else:
            out.append(segment)
    return "".join(out)


def _truthy(value):
    if _is_unknown(value):
        return False
    if isinstance(value, str):
        return value != ""
    if isinstance(value, (list, tuple)):
        return _truthy(value[0]) if len(value) == 1 else len(value) > 1
    if value is None:
        return False
    return bool(value)


def _is_unknown_looking_bareword(name):
    return name.lower() in ("true", "false", "null")


def _normalize_var_name(raw):
    """PowerShell variable names are case-insensitive and may be written
    ``${braced with spaces}``; normalize both to one lowercase, unbraced
    lookup key so ``$Env:Path`` and ``$env:PATH`` (real PowerShell
    behavior) hit the same dict entry.
    """
    name = _strip_backtick_noop(str(raw or "")).strip()
    if name.startswith("$"):
        name = name[1:]
    if name.startswith("{") and name.endswith("}"):
        return name[1:-1].lower()
    return name.strip().lower()


def _parse_native_memory_declarations(source):
    """Recognize a complete declaration-only C# class, never compile C#."""
    if not isinstance(source, str) or len(source) > 65536:
        return None
    outer = re.fullmatch(r'\s*public\s+(?:static\s+)?class\s+([A-Za-z_]\w*)\s*\{(.*)\}\s*', source, re.S)
    if not outer:
        return None
    body, constants, methods = outer[2].strip(), {}, {}
    literal = r'(?:"[A-Za-z0-9_.]*"|[A-Za-z_]\w*)'
    expression = literal + r'(?:\s*\+\s*' + literal + r')*'
    def string_value(text):
        if re.fullmatch(expression, text.strip()) is None:
            return None
        values = [p.strip() for p in text.split('+')]
        values = [p[1:-1] if p.startswith('"') else constants.get(p) for p in values]
        if any(v is None for v in values):
            return None
        return ''.join(values)
    expected = {
        'VirtualAlloc': ('intptr', ('intptr', 'uint', 'uint', 'uint')),
        'VirtualProtect': ('bool', ('intptr', 'uint', 'uint', 'out uint')),
        'VirtualFree': ('bool', ('intptr', 'uint', 'uint')),
    }
    def type_name(text):
        return {'System.IntPtr': 'intptr', 'System.UInt32': 'uint', 'System.Boolean': 'bool'}.get(text, text)
    while body:
        if len(constants) + len(methods) >= 128:
            return None
        const = re.match(r'(?:private|public|internal)\s+const\s+string\s+([A-Za-z_]\w*)\s*=\s*([^;]+);', body)
        if const:
            value = string_value(const[2])
            if value is None or const[1] in constants or const[1].lower() in methods or len(value) > 256:
                return None
            constants[const[1]] = value
            body = body[const.end():].strip()
            continue
        method = re.match(
            r'\[System\.Runtime\.InteropServices\.DllImport\(([^()]+)\)\]\s*'
            r'public\s+static\s+extern\s+([\w.]+)\s+([A-Za-z_]\w*)\s*\(([^()]*)\)\s*;', body)
        if not method:
            return None
        attributes = [p.strip() for p in method[1].split(',')]
        module = string_value(attributes[0])
        entry = method[3]
        seen = set()
        for part in attributes[1:]:
            attr = re.fullmatch(r'(\w+)\s*=\s*(.+)', part)
            if not attr or attr[1] in seen:
                return None
            seen.add(attr[1])
            if attr[1] == 'EntryPoint':
                entry = string_value(attr[2])
            elif attr[1] == 'CharSet':
                if attr[2] not in ('System.Runtime.InteropServices.CharSet.Auto',
                                   'System.Runtime.InteropServices.CharSet.Ansi',
                                   'System.Runtime.InteropServices.CharSet.Unicode'):
                    return None
            elif attr[1] in ('SetLastError', 'ExactSpelling'):
                if attr[2] not in ('true', 'false'):
                    return None
            else:
                return None
        params, param_names = [], set()
        for param in method[4].split(','):
            parsed = re.fullmatch(r'\s*(out\s+)?([\w.]+)\s+([A-Za-z_]\w*)\s*', param)
            if not parsed or parsed[3] in param_names:
                return None
            param_names.add(parsed[3])
            params.append(('out ' if parsed[1] else '') + type_name(parsed[2]))
        if (module not in ('kernel32.dll', 'kernelbase.dll') or entry not in expected
                or (type_name(method[2]), tuple(params)) != expected[entry]
                or method[3].lower() in methods or method[3] in constants):
            return None
        methods[method[3].lower()] = {'module': module, 'name': entry}
        body = body[method.end():].strip()
    return (outer[1].lower(), methods) if methods else None


def _pure_decoder_shape(source):
    if len(source) > 8192:
        return ''
    source = _strip_comments(source)
    if any(kind != 'code' for _, _, kind in _scan_ps_text(source)):
        return ''
    names = {}
    def rename(match):
        key = _normalize_var_name(match[0])
        return '$v' + str(names.setdefault(key, len(names)))
    source = re.sub(_VAR_REF, rename, source.lower())
    source = re.sub(r'\r?\n', ';', source)
    source = re.sub(r'\s+', '', source)
    source = re.sub(r';+', ';', source).strip(';')
    return source.replace('{;', '{').replace(';}', '}').replace('};', '}')


@_bounded_text_cache
def _scan_ps_text(text):
    """Return (start, end, kind) spans classifying every char run in
    ``text`` as one of: ``code``, ``squote``, ``dquote``, ``here_d``,
    ``here_s``, ``comment_line``, ``comment_block``. Single linear pass,
    reused by every higher-level splitter below so they can never disagree
    about where a string/comment starts or ends.

    Cached for the same reason as ``_top_level_positions`` (see its
    docstring): every caller here only reads the returned list, never
    mutates it, so sharing the cached list across calls is safe.
    """
    spans = []
    index = 0
    length = len(text)
    code_start = 0

    def flush_code(end):
        if end > code_start:
            spans.append((code_start, end, "code"))

    while index < length:
        ch = text[index]
        if ch == "'":
            flush_code(index)
            start = index
            index += 1
            while index < length:
                if text[index] == "'":
                    if index + 1 < length and text[index + 1] == "'":
                        index += 2
                        continue
                    index += 1
                    break
                index += 1
            spans.append((start, index, "squote"))
            code_start = index
            continue
        if ch == '"':
            flush_code(index)
            start = index
            index += 1
            while index < length:
                current = text[index]
                if current == "`" and index + 1 < length:
                    index += 2
                    continue
                if current == '"':
                    index += 1
                    break
                index += 1
            spans.append((start, index, "dquote"))
            code_start = index
            continue
        if ch == "@" and index + 1 < length and text[index + 1] in ("'", '"') and (
            index == 0 or text[index - 1] in "\r\n \t(="
        ):
            quote = text[index + 1]
            # A here-string opener must be followed by a newline (optional
            # trailing whitespace) to be real; ``@"literal"`` on one line is
            # just an array-subexpression-looking string, not a here-string.
            probe = index + 2
            while probe < length and text[probe] in " \t":
                probe += 1
            if probe < length and text[probe] in "\r\n":
                flush_code(index)
                start = index
                closer = quote + "@"
                search_from = probe
                found = text.find("\n" + closer, search_from)
                if found == -1:
                    # Also accept the literal start-of-string case (no
                    # leading newline byte to match against).
                    found = length if not text.startswith(closer) else -2
                end = found + 1 + len(closer) if found >= 0 else length
                spans.append((start, min(end, length), "here_d" if quote == '"' else "here_s"))
                code_start = min(end, length)
                index = code_start
                continue
        if ch == "#":
            flush_code(index)
            start = index
            newline = text.find("\n", index)
            end = newline if newline != -1 else length
            spans.append((start, end, "comment_line"))
            code_start = end
            index = end
            continue
        if ch == "<" and index + 1 < length and text[index + 1] == "#":
            flush_code(index)
            start = index
            end_marker = text.find("#>", index + 2)
            end = end_marker + 2 if end_marker != -1 else length
            spans.append((start, end, "comment_block"))
            code_start = end
            index = end
            continue
        index += 1
    flush_code(length)
    spans.sort(key=lambda item: item[0])
    return spans


def _strip_comments(source):
    spans = _scan_ps_text(source)
    out = []
    for start, end, kind in spans:
        if kind in ("comment_line", "comment_block"):
            out.append("\n" if "\n" in source[start:end] else "")
            continue
        out.append(source[start:end])
    return "".join(out)


def _decode_ps_string(token):
    """Decode a single-quoted or double-quoted literal token (quotes
    included) into its literal text. ``$var``/``$(...)`` interpolation in
    double-quoted strings is left as literal text here -- the caller
    resolves it separately via ``_interpolate`` once variable state is
    available, mirroring how a real double-quoted string is a template,
    not a constant.
    """
    if len(token) < 2:
        return token
    quote = token[0]
    body = token[1:-1] if token[-1] == quote else token[1:]
    if quote == "'":
        return body.replace("''", "'")
    out = []
    index = 0
    length = len(body)
    escapes = {
        "n": "\n", "t": "\t", "r": "\r", "0": "\0", "a": "\a", "b": "\b",
        "f": "\f", "v": "\v", "`": "`", "'": "'", '"': '"', "#": "#", "$": "$",
    }
    while index < length:
        ch = body[index]
        if ch == "`" and index + 1 < length:
            nxt = body[index + 1]
            out.append(escapes.get(nxt, nxt))
            index += 2
            continue
        out.append(ch)
        index += 1
    return "".join(out)


def _decode_here_string(token):
    if len(token) < 4:
        return ""
    quote = token[1]
    body = token[2:]
    closer_index = body.rfind(quote + "@")
    if closer_index != -1:
        body = body[:closer_index]
    if body.startswith("\r\n"):
        body = body[2:]
    elif body.startswith("\n"):
        body = body[1:]
    if body.endswith("\n"):
        body = body[:-1]
        if body.endswith("\r"):
            body = body[:-1]
    if quote == "'":
        return body
    return body


def _string_literal_end(text):
    """Find a closing quote without per-character regex backtracking state."""
    quote = text[0]
    index = 1
    while index < len(text):
        ch = text[index]
        if quote == '"' and ch == "`":
            index += 2
        elif ch == quote:
            if index + 1 < len(text) and text[index + 1] == quote:
                index += 2
            else:
                return index + 1
        else:
            index += 1
    return None


def _extract_balanced(text, open_index, opener="(", closer=")"):
    """Find the matching close bracket for ``text[open_index]``, skipping
    quoted/comment spans via the same scanner every other splitter uses.
    """
    # Reuse the full source's lexical spans. Scanning text[open_index:]
    # rescans a multi-MB tail for every bracket and thrashes the cache.
    spans = _scan_ps_text(text)
    depth = 0
    for start, end, kind in spans:
        if kind != "code" or end <= open_index:
            continue
        offset = max(start, open_index)
        while True:
            op = text.find(opener, offset, end)
            cl = text.find(closer, offset, end)
            if op == -1 and cl == -1:
                break
            if cl != -1 and (op == -1 or cl < op):
                depth -= 1
                if depth == 0:
                    return text[open_index + 1:cl], cl
                offset = cl + 1
                continue
            depth += 1
            offset = op + 1
    return None, None


@functools.lru_cache(maxsize=256)
def _is_literal_member_expression(text):
    """Conservative proof for short, variable-free string computations.

    Callers restrict keys to 4096 characters. Commands, interpolation,
    arbitrary types/methods and assignment are intentionally excluded.
    """
    pieces = []
    for start, end, kind in _scan_ps_text(text):
        token = text[start:end]
        if kind == "code":
            pieces.append(token)
        elif kind in ("squote", "dquote"):
            if kind == "dquote" and "$" in token:
                return False
            pieces.append("0")
        else:
            return False
    syntax = "".join(pieces)
    syntax = re.sub(r"\[(?:system\.)?(?:string|char|int|byte)(?:\[\])?\]", "", syntax, flags=re.I)
    syntax = re.sub(r"::(?:concat|join)\b", "", syntax, flags=re.I)
    syntax = re.sub(r"\.(?:insert|remove|replace|substring|tolower|toupper|tochararray|trim|length|count)\b", "", syntax, flags=re.I)
    syntax = re.sub(r"-(?:join|f)\b", "", syntax, flags=re.I).replace("$(", "(")
    return bool(re.fullmatch(r"[\s0-9(),\[\]@+*/%\-]+", syntax))


def _numeric_rpn(expression):
    """Parse a restricted arithmetic expression into data tokens, not Python
    code. No compile/eval/exec, commands, calls, indexing or attributes.
    """
    if len(expression) > 4096:
        return None
    return _numeric_rpn_cached(expression)


@functools.lru_cache(maxsize=512)
def _numeric_rpn_cached(expression):
    if '++' in expression or '--' in expression:
        return None
    # Tokenize before discarding whitespace: "1 2" and "$a b" must
    # never become the different expressions "12" and "$ab".
    tokens = re.findall(r"\$\w+|[0-9]+|[()+*/%\-]|[^\s]", expression)
    if not tokens:
        return None
    output, operators = [], []
    expect_value = True
    precedence = {'+':1, '-':1, '*':2, '/':2, '%':2, 'u+':3, 'u-':3}
    for token in tokens:
        if re.fullmatch(r'\$\w+|[0-9]+', token):
            if not expect_value:
                return None
            if token.startswith('$'):
                output.append(('variable',token[1:].lower()))
            else:
                number = int(token)
                if number.bit_length() > MAX_INTEGER_BITS:
                    return None
                output.append(('number',number))
            expect_value = False
        elif token == '(':
            if not expect_value:
                return None
            operators.append(token)
        elif token == ')':
            if expect_value:
                return None
            while operators and operators[-1] != '(':
                output.append(operators.pop())
            if not operators:
                return None
            operators.pop()
            expect_value = False
        elif token in ('+', '-', '*', '/', '%'):
            if expect_value:
                if token not in ('+','-'):
                    return None
                token = 'u'+token
            while operators and operators[-1] != '(' and (precedence[operators[-1]] > precedence[token] or (precedence[operators[-1]] == precedence[token] and not token.startswith('u'))):
                output.append(operators.pop())
            operators.append(token)
            expect_value = True
        else:
            return None
    if expect_value or '(' in operators:
        return None
    return output + list(reversed(operators))


def _split_top_level(text, delimiter=","):
    spans = _scan_ps_text(text)
    parts = []
    current = []
    depth = 0
    for start, end, kind in spans:
        segment = text[start:end]
        if kind != "code":
            current.append(segment)
            continue
        cursor = 0
        for index, ch in enumerate(segment):
            if ch in "([{":
                depth += 1
            elif ch in ")]}":
                depth = max(0, depth - 1)
            elif ch == delimiter and depth == 0:
                current.append(segment[cursor:index])
                parts.append("".join(current))
                current = []
                cursor = index + 1
        current.append(segment[cursor:])
    parts.append("".join(current))
    return [part.strip() for part in parts if part.strip()] if len(parts) > 1 else (
        [text.strip()] if text.strip() else []
    )


def _aes_transform(data, key, iv, mode, encrypt):
    """Perform a real AES encrypt/decrypt on bytes already present in the
    sample's own source text (an embedded static key/IV -- never a
    real host operation, the same category of pure data transform the
    RC4/hex/XOR fast-path decoders already do). Returns ``None`` on any
    failure (unsupported mode, wrong key length, bad padding, missing
    ``pycryptodome``) so the caller can leave the result symbolic
    instead of fabricating plaintext.
    """
    if _PyCryptoAES is None or not isinstance(key, (bytes, bytearray)) or len(key) not in (16, 24, 32):
        return None
    mode_key = (mode or "cbc").lower()
    try:
        if mode_key == "ecb":
            cipher = _PyCryptoAES.new(bytes(key), _PyCryptoAES.MODE_ECB)
        elif mode_key in ("cbc", "", None):
            if not isinstance(iv, (bytes, bytearray)) or len(iv) != 16:
                return None
            cipher = _PyCryptoAES.new(bytes(key), _PyCryptoAES.MODE_CBC, bytes(iv))
        else:
            return None  # CFB/OFB/CTR/GCM not modeled
        if encrypt:
            pad_len = 16 - (len(data) % 16)
            padded = bytes(data) + bytes([pad_len]) * pad_len
            return cipher.encrypt(padded)
        raw = cipher.decrypt(bytes(data))
    except (ValueError, TypeError):
        return None
    if not raw:
        return raw
    pad_len = raw[-1]
    if 1 <= pad_len <= 16 and raw[-pad_len:] == bytes([pad_len]) * pad_len:
        return raw[:-pad_len]
    return raw  # padding didn't validate -- return unpadded rather than guess


def _convert_integer_value(value, minimum, maximum):
    """Known scalar conversion only; never wrap overflow into another value."""
    converted = None
    if isinstance(value, _CharValue):
        converted = ord(value)
    elif value is None:
        converted = 0
    elif type(value) in (bool, int):
        converted = int(value)
    elif type(value) is float and math.isfinite(value):
        converted = round(value)
    elif isinstance(value, str) and not _is_unknown(value):
        text = value.strip()
        if not text:
            converted = 0
        elif len(text) <= 128 and re.fullmatch(r'[+-]?\d+', text):
            converted = int(text)
        elif len(text) <= 128 and re.fullmatch(r'[+-]?0[xX][0-9a-fA-F]+', text):
            converted = int(text, 16)
    return converted if converted is not None and minimum <= converted <= maximum else None


def _as_bytes(value):
    if isinstance(value,(bytes,bytearray)):
        return bytes(value) if len(value)<=MAX_EMBEDDED_PAYLOAD_BYTES else None
    if isinstance(value, _BinaryValue):
        return value.data if value.complete else None
    if isinstance(value, list):
        if len(value) > MAX_EMBEDDED_PAYLOAD_BYTES:
            return None
        try:
            return bytes(_convert_integer_value(item, 0, 255) for item in value)
        except (TypeError, ValueError):
            return None
    if isinstance(value, str):
        return value.encode("utf-8", errors="replace")
    return None


# Named parameters this emulator knows are real single-token
# enum/switch values, not free-text -- see ``_parse_command_syntax``.
_SINGLE_TOKEN_PARAMS = frozenset((
    "windowstyle", "verb", "method", "erroraction", "warningaction",
    "informationaction", "mode",
))
_PARAM_TOKEN_RE = re.compile(r"(?<!\S)-([A-Za-z][A-Za-z0-9]*)\b")
# Windows PowerShell web-cmdlet formal parameters. Its binder prefers a
# unique formal-parameter prefix over common parameters (e.g. -o/OutFile).
# Keep this catalog command-local so -useba cannot change function binding.
_WEB_PARAMETER_NAMES = frozenset("""usebasicparsing uri websession sessionvariable
credential usedefaultcredentials certificate certificatethumbprint useragent
disablekeepalive timeoutsec headers maximumredirection method proxy
proxycredential proxyusedefaultcredentials body contenttype transferencoding
infile outfile passthru""".split())
_WEB_SWITCH_PARAMS = frozenset(("usebasicparsing", "usedefaultcredentials",
    "disablekeepalive", "proxyusedefaultcredentials", "passthru", "verbose", "debug"))
_ADD_TYPE_PARAMETER_NAMES = frozenset("""codedomprovider compilerparameters
typedefinition language referencedassemblies outputassembly outputtype passthru
ignorewarnings name memberdefinition namespace usingnamespace path literalpath
assemblyname""".split())
_NEW_OBJECT_RE = re.compile(r"^new-object\b(.*)$", re.IGNORECASE | re.DOTALL)
_PARAM_BLOCK_RE = re.compile(r"^\s*param\s*\(", re.IGNORECASE)
_INCREMENT_RE = re.compile(rf"^(?:({_VAR_REF})(\+\+|--)|(\+\+|--)({_VAR_REF}))\s*\Z")
_FOR_START_RE = re.compile(r"^for\s*\(", re.IGNORECASE)
_FOREACH_START_RE = re.compile(r"^foreach\s*\(", re.IGNORECASE)

# -- fast-path recognizers for the two byte-array transform loop shapes
# that dominate real-world PowerShell hex-decode/XOR-decrypt obfuscation.
# A real malware sample's embedded payload can be megabytes of hex text,
# needing far more loop iterations than any per-statement tick budget can
# afford; these let ``_try_fast_for_loop`` compute the whole loop natively
# in Python when the body is EXACTLY one of these two shapes, falling
# through to the real (slow but always-correct) simulation otherwise.
_HEX_LOOP_BODY_RE = re.compile(
    r"^\$(?P<target>[A-Za-z_]\w*)\s*\[\s*\$(?P<idx1>[A-Za-z_]\w*)\s*/\s*2\s*\]"
    r"\s*=\s*\[convert\]::tobyte\s*\(\s*"
    r"\$(?P<source>[A-Za-z_]\w*)\.substring\s*\(\s*\$(?P<idx2>[A-Za-z_]\w*)\s*,\s*2\s*\)"
    r"\s*,\s*16\s*\)\s*$",
    re.IGNORECASE,
)
# The same hex-decode transform, parameterized the other natural way:
# loop over the *output* byte index directly (0..N-1, exactly what
# ``0..($target.Length-1)`` produces) with the source substring offset
# scaled up by the loop variable instead of the target index scaled
# down -- ``$target[$_] = [Convert]::ToByte($src.Substring($_*2,2),16)``.
_HEX_LOOP_BODY_SCALED_RE = re.compile(
    r"^\$(?P<target>[A-Za-z_]\w*)\s*\[\s*\$(?P<idx1>[A-Za-z_]\w*)\s*\]"
    r"\s*=\s*\[convert\]::tobyte\s*\(\s*"
    r"\$(?P<source>[A-Za-z_]\w*)\.substring\s*\(\s*\$(?P<idx2>[A-Za-z_]\w*)\s*\*\s*2\s*,\s*2\s*\)"
    r"\s*,\s*16\s*\)\s*$",
    re.IGNORECASE,
)
_IF_GUARD_ONLY_RE = re.compile(r"^if\s*\(.*\)\s*$", re.IGNORECASE | re.DOTALL)
# ``$byteList = New-Object System.Collections.Generic.List[byte]`` +
# ``$byteList.Add(...)`` in the loop body -- a hex-decode-into-a-.NET-
# List shape that shows up just as often as the plain ``$bytes[$i/2] =
# ...`` array-index form these two cover (some samples wrap the ``.Add``
# in a bounds-check ``if ($i + 1 -lt $x.Length) { ... }``, which
# ``_try_fast_for_loop`` tolerates by ignoring any pure-condition
# statement left over from that block's flattening).
_HEX_ADD_TEMP_RE = re.compile(
    r"^\$(?P<temp>[A-Za-z_]\w*)\s*=\s*\$(?P<source>[A-Za-z_]\w*)\.substring\s*\(\s*\$(?P<idx>[A-Za-z_]\w*)\s*,\s*2\s*\)\s*$",
    re.IGNORECASE,
)
_HEX_ADD_RE = re.compile(
    r"^\$(?P<target>[A-Za-z_]\w*)\.add\s*\(\s*\[convert\]::tobyte\s*\(\s*\$(?P<temp>[A-Za-z_]\w*)\s*,\s*16\s*\)\s*\)\s*$",
    re.IGNORECASE,
)
# The same "substring into a temp var, then decode" shape, but writing
# through ``$target[$i/2] = ...`` index assignment instead of ``.Add``.
_HEX_INDEX_TEMP_RE = re.compile(
    r"^\$(?P<target>[A-Za-z_]\w*)\s*\[\s*\$(?P<idx1>[A-Za-z_]\w*)\s*/\s*2\s*\]"
    r"\s*=\s*\[convert\]::tobyte\s*\(\s*\$(?P<temp>[A-Za-z_]\w*)\s*,\s*16\s*\)\s*$",
    re.IGNORECASE,
)
# A custom-alphabet bit-unpacking decoder (base32/base58/base62/any
# N-bits-per-character variant, built from a runtime lookup table
# rather than a library call specifically to dodge a
# ``FromBase64String``/``[Convert]::`` signature) -- the near-universal
# shape: skip characters missing from the table, accumulate N bits per
# known character into a buffer, and flush a byte out every time 8 bits
# have piled up.
#
# Matched on the loop body *after* it already went through
# ``_normalize_block_syntax`` once as part of normalizing its enclosing
# function/script (that single pass runs over the whole source before
# any statement gets split out, including a ``foreach``'s own body --
# unlike ``foreach`` itself, the ``if``s *inside* it are recognized
# block keywords and get their braces blanked to ``;`` right along with
# every other one in the file). So the two nested ``if``s here have
# already lost their own braces by the time this ever sees them,
# leaving no delimiter at all for where the second ``if``'s "body"
# should stop -- which is exactly why this shape needs a real fast path
# and not just a bigger statement budget: run through the generic
# per-statement simulator, ``continue`` (never implemented -- there's
# no real one to implement once the guard's brace is gone) and the
# conditional emit both silently become unconditional, corrupting every
# single byte instead of just running out of budget on a large payload.
_ALPHABET_DECODE_FOREACH_RE = re.compile(
    r"^if\s*\(\s*-not\s+\$(?P<table>[A-Za-z_]\w*)\.ContainsKey\(\s*\$(?P<loopvar>[A-Za-z_]\w*)\s*\)\s*\)"
    r"\s*;\s*continue\s*;\s*"
    r"\$(?P<buf>[A-Za-z_]\w*)\s*=\s*\(\s*\$(?P=buf)\s*-shl\s*(?P<shift>\d+)\s*\)\s*-bor\s*"
    r"\$(?P=table)\[\s*\$(?P=loopvar)\s*\]\s*;?\s*"
    r"\$(?P<bits>[A-Za-z_]\w*)\s*\+=\s*(?P=shift)\s*;?\s*"
    r"if\s*\(\s*\$(?P=bits)\s*-ge\s*(?P<threshold>\d+)\s*\)\s*;\s*"
    r"\$(?P=bits)\s*-=\s*(?P=threshold)\s*;?\s*"
    r"\$(?P<bytevar>[A-Za-z_]\w*)\s*=\s*\(\s*\$(?P=buf)\s*-shr\s*\$(?P=bits)\s*\)\s*-band\s*0x[fF]{2}\s*;?\s*"
    r"\$(?P<outvar>[A-Za-z_]\w*)\.Add\(\s*\[byte\]\s*\$(?P=bytevar)\s*\)\s*;?\s*$",
    re.IGNORECASE | re.DOTALL,
)
# ``$keyByte = $xorKey[$i % $xorKey.Length]`` then
# ``$plainBytes[$i] = $cipherBytes[$i] -bxor $keyByte`` -- the same XOR
# transform as ``_XOR_LOOP_BODY_RE`` but with the key-byte lookup
# pre-computed into its own temp variable the line before, instead of
# inlined into the ``-bxor`` expression directly.
_XOR_KEYBYTE_TEMP_RE = re.compile(
    r"^\$(?P<temp>[A-Za-z_]\w*)\s*=\s*\$(?P<key>[A-Za-z_]\w*)\s*\[\s*\$(?P<idx1>[A-Za-z_]\w*)\s*%\s*"
    r"(?:\$(?P<keylen>[A-Za-z_]\w*)\.length|\$(?P<keylenvar>[A-Za-z_]\w*))\s*\]\s*$",
    re.IGNORECASE,
)
_XOR_KEYBYTE_WRITE_RE = re.compile(
    r"^\$(?P<target>[A-Za-z_]\w*)\s*\[\s*\$(?P<idx2>[A-Za-z_]\w*)\s*\]"
    r"\s*=\s*\$(?P<source>[A-Za-z_]\w*)\s*\[\s*\$(?P<idx3>[A-Za-z_]\w*)\s*\]"
    r"\s*-bxor\s*\$(?P<temp>[A-Za-z_]\w*)\s*$",
    re.IGNORECASE,
)

_XOR_LOOP_BODY_RE = re.compile(
    r"^\$(?P<target>[A-Za-z_]\w*)\s*\[\s*\$(?P<idx1>[A-Za-z_]\w*)\s*\]"
    r"\s*=\s*\$(?P<source>[A-Za-z_]\w*)\s*\[\s*\$(?P<idx2>[A-Za-z_]\w*)\s*\]"
    r"\s*-bxor\s*\$(?P<key>[A-Za-z_]\w*)\s*\[\s*\$(?P<idx3>[A-Za-z_]\w*)\s*%\s*"
    # The key-length divisor is either ``$Key.Length`` inline, or a
    # separate precomputed variable (``$keyCount = $keyData.Length``
    # earlier, then ``... % $keyCount]`` in the loop -- a shape the same
    # decode-helper template uses interchangeably across samples).
    # ``_try_fast_for_loop`` only trusts the variable form once it has
    # verified, at runtime, that it actually equals the real key length.
    r"(?:\$(?P<keylen>[A-Za-z_]\w*)\.length|\$(?P<keylenvar>[A-Za-z_]\w*))\s*\]\s*$",
    re.IGNORECASE,
)

# Exact RC4 PRGA body, after ordinary KSA statements have produced the
# concrete S-box. No source code is compiled or executed by this shortcut.
_RC4_PRGA_RE = re.compile(
    r"\$(?P<x>\w+)=\(\$(?P=x)\+1\)%256;"
    r"\$(?P<y>\w+)=\(\$(?P=y)\+\$(?P<s>\w+)\[\$(?P=x)\]\)%256;"
    r"\$(?P<t>\w+)=\$(?P=s)\[\$(?P=x)\];"
    r"\$(?P=s)\[\$(?P=x)\]=\$(?P=s)\[\$(?P=y)\];"
    r"\$(?P=s)\[\$(?P=y)\]=\$(?P=t);"
    r"\$(?P<k>\w+)=\$(?P=s)\[\(\$(?P=s)\[\$(?P=x)\]\+\$(?P=s)\[\$(?P=y)\]\)%256\];"
    r"\$(?P<out>\w+)\[\$(?P<i>\w+)\]=\$(?P<data>\w+)\[\$(?P=i)\]-bxor\$(?P=k)"
)

_XOR_INDEX_MOD_RE = re.compile(
    r"\$(?P<out>\w+)\[\$(?P<i>\w+)\]="
    r"\$(?P<data>\w+)\[\$(?P=i)\]-bxor(?P<key>\d+)-bxor\(\$(?P=i)%(?P<mod>\d+)\)"
)


def _extract_incr_step(loop_var, incr_text):
    """Return the integer step of a ``for`` loop's increment clause when
    it is one of the handful of textual shapes a fast-path loop can
    trust (``$i++``, ``$i += N``, ``$i = $i + N``), else ``None``."""
    if not incr_text:
        return None
    stripped = incr_text.strip()
    incr_match = _INCREMENT_RE.match(stripped)
    if incr_match:
        name = incr_match.group(1) or incr_match.group(4)
        if _normalize_var_name(name) == loop_var:
            return 1 if (incr_match.group(2) or incr_match.group(3)) == "++" else -1
    escaped = re.escape(loop_var)
    plus_match = re.match(rf"^\$(?:{escaped})\s*\+=\s*(\d+)\s*$", stripped, re.IGNORECASE)
    if plus_match:
        return int(plus_match.group(1))
    assign_match = re.match(
        rf"^\$(?:{escaped})\s*=\s*\$(?:{escaped})\s*\+\s*(\d+)\s*$", stripped, re.IGNORECASE
    )
    if assign_match:
        return int(assign_match.group(1))
    return None


def _cond_matches_length(loop_var, source_key, cond_text, allow_count=False):
    """True when a loop condition is exactly ``$loop_var -lt $source.Length``
    -- the shape both fast-path loops require before trusting that the
    loop's real (pre-truncation) extent is ``len(source)``."""
    if not cond_text:
        return False
    member = "(?:length|count)" if allow_count else "length"
    pattern = re.compile(
        rf"^\$(?:{re.escape(loop_var)})\s*-lt\s*\$(?:{re.escape(source_key)})\.{member}\s*$",
        re.IGNORECASE,
    )
    return bool(pattern.match(cond_text.strip()))


def _try_parse_for_header(statement):
    """``for (INIT; COND; INCR) { BODY }`` as one intact statement (see
    ``_BLOCK_KEYWORD_RE``'s exclusion of ``for``) -- returns ``None`` (never
    a guess) for anything that doesn't cleanly match this exact shape, most
    commonly because it isn't a ``for`` loop at all.
    """
    match = _FOR_START_RE.match(statement)
    if not match:
        return None
    header, header_end = _extract_balanced(statement, match.end() - 1, "(", ")")
    if header is None:
        return None
    cursor = header_end + 1
    while cursor < len(statement) and statement[cursor] in " \t\r\n":
        cursor += 1
    if cursor >= len(statement) or statement[cursor] != "{":
        return None
    body, _ = _extract_balanced(statement, cursor, "{", "}")
    if body is None:
        return None
    parts = header.split(";")
    if len(parts) != 3:
        return None
    return parts[0].strip(), parts[1].strip(), parts[2].strip(), body


def _try_parse_foreach_header(statement):
    match = _FOREACH_START_RE.match(statement)
    if not match:
        return None
    header, header_end = _extract_balanced(statement, match.end() - 1, "(", ")")
    if header is None:
        return None
    cursor = header_end + 1
    while cursor < len(statement) and statement[cursor] in " \t\r\n":
        cursor += 1
    if cursor >= len(statement) or statement[cursor] != "{":
        return None
    body, _ = _extract_balanced(statement, cursor, "{", "}")
    if body is None:
        return None
    header_match = re.match(rf"^\s*({_VAR_REF})\s+in\s+(.+)$", header, re.IGNORECASE | re.DOTALL)
    if not header_match:
        return None
    return header_match.group(1), header_match.group(2).strip(), body


_STATE_MACHINE_WHILE_RE = re.compile(
    r"while\s*\(\s*(\$[A-Za-z_]\w*)\s*-ne\s*-1\s*\)\s*\{", re.IGNORECASE
)


def _parse_switch_cases(body):
    """Split a switch statement's brace-delimited body into a list of
    ``(label_text, case_body_text)`` pairs -- each top-level ``LABEL {
    BLOCK }`` group in source order (used both by
    ``_normalize_block_syntax``'s general case-flattening and by the
    state-machine dispatcher below, which additionally needs each
    label's *own* text to match against the live dispatch value).
    """
    cases = []
    cursor = 0
    body_len = len(body)
    while cursor < body_len:
        brace_rel = body.find("{", cursor)
        if brace_rel == -1:
            break
        # A ``;`` between cases (``CASE1 { ... }; CASE2 { ... }``, legal
        # and fairly common) is a statement separator, not part of the
        # next label's value expression.
        label = body[cursor:brace_rel].strip().strip(";").strip()
        case_body, end_rel = _extract_balanced(body, brace_rel, "{", "}")
        if case_body is None:
            break
        cases.append((label, case_body))
        cursor = end_rel + 1
    return cases


def _scan_state_machine(text, start):
    """``$state = N; while ($state -ne -1) { switch ($state) { CASE1 {
    BODY1; $state = NEXT1 } CASE2 {...} } }`` -- a real, common
    obfuscator-generated control-flow-flattening shape (numeric
    opcode/state dispatch). Structurally incompatible with this
    emulator's usual "flatten every branch, run them all
    unconditionally" treatment of ``if``/``switch``: unlike an ordinary
    switch (every case independent, safe to run all of them for
    IOC-surfacing value even though the real condition can't be
    trusted), each case here explicitly picks the *next* state --
    running every case on every pass executes the whole decoded program
    in the wrong order and can't converge. Detected here as one
    self-contained unit (kept out of the general flattening entirely,
    see its use in ``_normalize_block_syntax``'s ``protected_ranges``)
    so ``PowerShellEmulator._handle_state_machine`` can dispatch it for
    real: one case per pass, exactly like the real ``while`` would.

    Returns ``(state_var, cases, end_index)`` -- ``end_index`` is the
    index of the outer ``while`` block's closing ``}`` in ``text`` --
    or ``(None, None, None)`` if ``text[start]`` isn't the start of
    this exact shape.
    """
    match = _STATE_MACHINE_WHILE_RE.match(text, start)
    if not match or match.start() != start:
        return None, None, None
    body, end = _extract_balanced(text, match.end() - 1, "{", "}")
    if body is None:
        return None, None, None
    state_var = match.group(1)
    stripped_body = body.strip()
    switch_match = re.match(
        rf"^switch\s*\(\s*{re.escape(state_var)}\s*\)\s*\{{", stripped_body, re.IGNORECASE
    )
    if not switch_match:
        return None, None, None
    switch_body, switch_end = _extract_balanced(stripped_body, switch_match.end() - 1, "{", "}")
    if switch_body is None or stripped_body[switch_end + 1:].strip():
        # Something besides the one switch statement in the while body
        # (extra statements before/after it) -- not this exact shape.
        return None, None, None
    cases = _parse_switch_cases(switch_body)
    if not cases:
        return None, None, None
    return state_var, cases, end


def _try_parse_state_machine(statement):
    """``_scan_state_machine`` applied to a single, already-isolated
    statement (see ``_normalize_block_syntax``'s protection of this
    shape -- by the time ``_process_statement`` sees it, it survives as
    one intact ``while (...) { switch (...) { ... } }`` blob with real,
    depth-tracked braces, same as a scriptblock literal would).
    """
    state_var, cases, end = _scan_state_machine(statement, 0)
    if state_var is None or end != len(statement) - 1:
        return None
    return state_var, cases


def _try_parse_range_foreach(statement):
    """``0..($b.Length-1) | % { $b[$_] = ... }`` -- the range-operator +
    pipe + ``ForEach-Object`` spelling of a bounded fill loop, using
    PowerShell's automatic ``$_`` in place of a named counter. Common
    enough as an alternative to a real ``for`` statement that
    ``_try_fast_range_foreach`` needs a shot at it too (see there for
    why plain per-item ``ForEach-Object`` simulation alone can't get a
    large hex-decode/XOR-decrypt loop through the statement budget).
    Returns ``(range_end_text, body_text)`` or ``None``.
    """
    stages = _split_top_level(statement, "|")
    if len(stages) != 2:
        return None
    range_match = re.match(r"^0\s*\.\.\s*(.+)$", stages[0].strip(), re.DOTALL)
    if not range_match:
        return None
    # ``\b`` after ``%`` wouldn't fire here -- a word boundary needs one
    # side to be a word character, and both ``%`` and the whitespace
    # after it are non-word, so a lookahead for whitespace-or-end is
    # used instead.
    verb_match = re.match(r"^(%|foreach-object|foreach)(?=\s|\{|$)\s*(.*)$", stages[1].strip(), re.IGNORECASE | re.DOTALL)
    if not verb_match:
        return None
    body_text = verb_match.group(2).strip()
    if body_text[:1] != "{" or body_text[-1:] != "}":
        return None
    return range_match.group(1).strip(), body_text[1:-1]


def _scan_if_expression_chain(text, start=0):
    """Core scanner shared by ``_try_parse_if_expression`` (needs the
    parsed branches, requires nothing trailing) and
    ``_normalize_block_syntax`` (needs only the chain's end index,
    scanning within much larger, not-yet-statement-split source text
    where there's always real content after it). ``text[start:]`` must
    already look like ``if\\s*\\(``. Returns ``(branches, end_index)``,
    or ``(None, None)`` if malformed. ``branches`` pairs a condition
    text with its body text (``None`` condition for a trailing
    ``else``); never a partial/guessed parse.
    """
    branches = []
    cursor = start
    while True:
        paren_start = text.index("(", cursor)
        cond_text, paren_end = _extract_balanced(text, paren_start, "(", ")")
        if cond_text is None:
            return None, None
        brace_start = paren_end + 1
        while brace_start < len(text) and text[brace_start] in " \t\r\n":
            brace_start += 1
        if brace_start >= len(text) or text[brace_start] != "{":
            return None, None
        body_text, brace_end = _extract_balanced(text, brace_start, "{", "}")
        if body_text is None:
            return None, None
        branches.append((cond_text, body_text))
        cursor = brace_end + 1
        probe = cursor
        while probe < len(text) and text[probe] in " \t\r\n":
            probe += 1
        elseif_match = re.match(r"^elseif\s*\(", text[probe:], re.IGNORECASE)
        if elseif_match:
            cursor = probe + elseif_match.end() - 1
            continue
        else_match = re.match(r"^else\s*\{", text[probe:], re.IGNORECASE)
        if else_match:
            else_brace_start = probe + else_match.end() - 1
            else_body, else_brace_end = _extract_balanced(text, else_brace_start, "{", "}")
            if else_body is None:
                return None, None
            branches.append((None, else_body))
            cursor = else_brace_end + 1
        break
    return branches, cursor


def _try_parse_if_expression(expr):
    """``if (COND) { A } elseif (COND2) { B } else { C }`` used as an
    *expression* (a real PowerShell feature: the executed branch's last
    statement becomes the whole construct's value -- ``$x = if (...)
    {...} else {...}``). Returns a list of ``(cond_text, body_text)``
    pairs in source order (``cond_text`` is ``None`` for a trailing
    ``else``), or ``None`` if ``expr`` isn't cleanly this shape (no
    trailing text after the last branch, no missing/unbalanced pieces)
    -- never a partial/guessed parse.
    """
    if not re.match(r"^if\s*\(", expr, re.IGNORECASE):
        return None
    branches, end = _scan_if_expression_chain(expr, 0)
    if branches is None or expr[end:].strip():
        return None
    return branches


def _value_expression_supported(text):
    """Small data-only expression vocabulary for structured char decoders.

    Validate before evaluating any branch. No dynamic calls, pipelines,
    arbitrary object members, scope writes, or interpolated subexpressions.
    The general heuristic interpreter handles helpers outside this subset.
    """
    pieces = []
    for start, end, kind in _scan_ps_text(text):
        part = text[start:end]
        if kind == 'code':
            pieces.append(part)
        elif part.startswith(("'", '"')) and '$' not in part and '`' not in part:
            pieces.append('0')
        else:
            return False
    code = ''.join(pieces)
    if any(':' in match[0] or '{' in match[0] for match in re.finditer(_VAR_REF, code)):
        return False
    code = re.sub(_VAR_REF, '0', code)
    code = re.sub(r'\[(?:System\.)?(?:Convert|Text\.Encoding|byte|char|int|int32|bool|string)(?:\[\])?\]', '0', code, flags=re.I)
    code = re.sub(r'(?:\.|::)(?:FromBase64String|GetString|ToCharArray|UTF8|Length|Count)\b', '', code, flags=re.I)
    code = re.sub(r'\bNew-Object\s+byte\[\]', '', code, flags=re.I)
    code = re.sub(r'-(?:and|or|not|eq|ne|ge|le|gt|lt|is|isnot|bxor|band|bor|join|replace)\b', '', code, flags=re.I)
    code = re.sub(r'\b0x[0-9a-f]+\b', '0', code, flags=re.I)
    return bool(text.strip()) and re.fullmatch(r'[\d\s@(),\[\]+*/%!.\-]*', code) is not None


def _parse_value_program(source, depth=0):
    """Preserve if/loop/return scopes in a fully validated value helper."""
    if depth > 12:
        return None
    nodes = []
    rest = source.strip(' \t\r\n;')
    while rest:
        if re.match(r'if\s*\(', rest, re.I):
            branches, end = _scan_if_expression_chain(rest)
            if branches is None:
                return None
            compiled = []
            for condition, body in branches:
                child = _parse_value_program(body, depth + 1)
                if child is None or (condition is not None and not _value_expression_supported(condition)):
                    return None
                compiled.append((condition, child))
            nodes.append(('if', compiled))
        elif (match := re.match(r'(foreach|for)\s*\(', rest, re.I)):
            header, close = _extract_balanced(rest, match.end() - 1)
            if header is None:
                return None
            start = close + 1
            while start < len(rest) and rest[start].isspace():
                start += 1
            if start >= len(rest) or rest[start] != '{':
                return None
            body, close = _extract_balanced(rest, start, '{', '}')
            child = _parse_value_program(body, depth + 1) if body is not None else None
            if child is None:
                return None
            if match[1].lower() == 'foreach':
                binding = re.fullmatch(r'(\$\w+)\s+in\s+(.+)', header.strip(), re.I | re.S)
                if not binding or not _value_expression_supported(binding[2]):
                    return None
                nodes.append(('foreach', binding[1], binding[2], child))
            else:
                parts = _split_top_level(header, ';')
                if len(parts) != 3 or not _value_expression_supported(parts[1]):
                    return None
                init = _parse_value_program(parts[0], depth + 1)
                increment = _parse_value_program(parts[2], depth + 1)
                if (not init or not increment or any(n[0] != 'statement' for n in init + increment)):
                    return None
                nodes.append(('for', init, parts[1], increment, child))
            end = close + 1
        elif re.match(r'try\s*\{', rest, re.I):
            body, close = _extract_balanced(rest, rest.index('{'), '{', '}')
            catch = re.match(r'\s*catch\s*\{', rest[close + 1:], re.I) if close is not None else None
            if not catch:
                return None
            catch_body, catch_close = _extract_balanced(rest, close + catch.end(), '{', '}')
            child = _parse_value_program(body, depth + 1)
            failure = _parse_value_program(catch_body, depth + 1) if catch_body is not None else None
            if child is None or failure is None:
                return None
            # Unknown model inputs are not evidence that a real exception
            # occurred. Never select the catch block to invent a value.
            nodes.append(('try', child))
            end = catch_close + 1
        else:
            statements = _split_statements(rest)
            if not statements or not rest.startswith(statements[0]):
                return None
            statement = statements[0]
            returned = re.fullmatch(r'return\b\s*(.*)', statement, re.I | re.S)
            assigned = re.fullmatch(r'(\$\w+(?:\[[^\]\r\n]+\])?)\s*(\+=|-=|=)\s*(.+)', statement, re.S)
            increment = re.fullmatch(r'\$\w+(?:\+\+|--)', statement)
            if returned and (not returned[1] or _value_expression_supported(returned[1])):
                nodes.append(('return', returned[1]))
            elif assigned and _value_expression_supported(assigned[1]) and _value_expression_supported(assigned[3]):
                nodes.append(('statement', statement))
            elif increment:
                nodes.append(('statement', statement))
            else:
                return None
            end = len(statement)
        rest = rest[end:].strip(' \t\r\n;')
    return nodes


def _parse_script_method_program(source, depth=0):
    """Structured subset for script-defined methods; never compile host code."""
    if depth > 12 or len(source) > 131072:
        return None
    nodes = []
    rest = _strip_comments(source).strip(' \t\r\n;')
    while rest:
        if re.match(r'if\s*\(', rest, re.I):
            branches, end = _scan_if_expression_chain(rest)
            if branches is None:
                return None
            children = [(condition, _parse_script_method_program(body, depth + 1)) for condition, body in branches]
            if any(child is None for _, child in children):
                return None
            nodes.append(('if', children))
        elif (match := re.match(r'(switch|while)\s*\(', rest, re.I)):
            condition, end = _extract_balanced(rest, match.end() - 1)
            if end is None:
                return None
            start = end + 1
            while start < len(rest) and rest[start].isspace():
                start += 1
            if start >= len(rest) or rest[start] != '{':
                return None
            body, close = _extract_balanced(rest, start, '{', '}')
            if close is None:
                return None
            end = close + 1
            if match[1].lower() == 'while':
                child = _parse_script_method_program(body, depth + 1)
                if child is None:
                    return None
                nodes.append(('while', condition, child))
            else:
                cases = []
                tail = body.strip()
                while tail:
                    if tail.startswith('('):
                        label, label_end = _extract_balanced(tail, 0)
                        if label_end is None:
                            return None
                        cursor = label_end + 1
                    else:
                        label_match = re.match(r'(?:default|-?\d+|\w+)\b', tail, re.I)
                        if not label_match:
                            return None
                        label = label_match[0]
                        cursor = label_match.end()
                        if label.lower() != 'default' and not re.fullmatch(r'-?\d+', label):
                            label = "'" + label + "'"
                    while cursor < len(tail) and tail[cursor].isspace():
                        cursor += 1
                    if cursor >= len(tail) or tail[cursor] != '{':
                        return None
                    case_body, case_end = _extract_balanced(tail, cursor, '{', '}')
                    child = _parse_script_method_program(case_body, depth + 1) if case_body is not None else None
                    if child is None:
                        return None
                    cases.append((None if label.lower() == 'default' else label, child))
                    tail = tail[case_end + 1:].strip(' \t\r\n;')
                nodes.append(('switch', condition, cases))
        else:
            statements = _split_statements(rest)
            if not statements or not rest.startswith(statements[0]):
                return None
            statement = statements[0]
            returned = re.fullmatch(r'return\b\s*(.*)', statement, re.I | re.S)
            if returned:
                nodes.append(('return', returned[1]))
            elif re.match(r'(?:break|continue|throw|try|catch|finally|for|foreach|do|function|class|enum|begin|process|end|clean|param|trap|elseif|else)\b|:\w+\s', statement, re.I):
                return None
            else:
                nodes.append(('statement', statement))
            end = len(statement)
        rest = rest[end:].strip(' \t\r\n;')
    return nodes


def _parse_script_type_definition(source):
    """Parse complete declarations, rejecting unsupported member syntax."""
    match = re.match(r'^(class|enum)\s+(\w+)\s*(?::\s*([\w.]+)\s*)?\{', source, re.I)
    if not match or len(source) > 131072:
        return None
    body, end = _extract_balanced(source, match.end() - 1, '{', '}')
    if body is None or source[end + 1:].strip():
        return None
    kind, name, base = match.groups()
    if kind.lower() == 'enum':
        if base is not None:
            return None
        members, value = {}, 0
        statements = _split_statements(body)
        if len(statements) > 1024:
            return None
        for statement in statements:
            member = re.fullmatch(r'([A-Za-z_]\w*)\s*(?:=\s*(-?\d+))?', statement.strip())
            if not member or member[1].lower() in members:
                return None
            value = int(member[2]) if member[2] is not None else value
            if not -(2 ** 31) <= value < 2 ** 31:
                return None
            members[member[1].lower()] = value
            value += 1
        return name.lower(), {'kind': 'enum', 'members': members}
    if base is not None and base.lower() != 'system.collections.ienumerator':
        return None
    properties, methods = {}, {}
    statements = _split_statements(body)
    joined, index = [], 0
    while index < len(statements):
        statement = statements[index]
        if (index + 1 < len(statements) and statements[index + 1].lstrip().startswith('{')
                and re.fullmatch(r'(?:\[[\w.]+(?:\[\])?\]\s*)?\w+\s*\([^{}]*\)', statement.strip(), re.S)):
            statement += '\n' + statements[index + 1]
            index += 1
        joined.append(statement)
        index += 1
    statements = joined
    if len(statements) > 256:
        return None
    for statement in statements:
        rest = statement.strip()
        type_name = 'void'
        if rest.startswith('['):
            type_name, close = _extract_balanced(rest, 0, '[', ']')
            if close is None or not re.fullmatch(r'[\w.]+(?:\[\])?', type_name):
                return None
            rest = rest[close + 1:].lstrip()
        prop = re.fullmatch(r'\$(\w+)\s*(?:=\s*(.+))?', rest, re.S)
        if prop:
            if type_name == 'void' or prop[1].lower() in properties:
                return None
            properties[prop[1].lower()] = (type_name.lower(), prop[2])
            continue
        method = re.match(r'(\w+)\s*\(', rest)
        if not method:
            return None
        params, close = _extract_balanced(rest, method.end() - 1)
        if close is None:
            return None
        tail = rest[close + 1:].strip()
        if not tail.startswith('{'):
            return None
        method_body, end = _extract_balanced(tail, 0, '{', '}')
        if end is None or tail[end + 1:].strip():
            return None
        names, types = [], []
        for param in _split_top_level(params, ',') if params.strip() else []:
            binding = re.fullmatch(r'\s*\[([\w.]+(?:\[\])?)\]\s*\$(\w+)\s*', param)
            if not binding or binding[2].lower() in names:
                return None
            types.append(binding[1].lower())
            names.append(binding[2].lower())
        program = _parse_script_method_program(method_body)
        # Constructor returns and values returned from void methods are
        # invalid source, even when their branch would not be reached.
        def invalid_return(nodes):
            for node in nodes or []:
                if node[0] == 'return' and (method[1].lower() == name.lower() or (type_name.lower() == 'void' and node[1])):
                    return True
                children = ([child for _, child in node[1]] if node[0] == 'if' else
                            [child for _, child in node[2]] if node[0] == 'switch' else
                            [node[2]] if node[0] == 'while' else [])
                if any(invalid_return(child) for child in children):
                    return True
            return False
        if invalid_return(program):
            program = None
        methods.setdefault(method[1].lower(), []).append({'params': names, 'types': types,
                                                         'return_type': type_name.lower(), 'program': program})
    return name.lower(), {'kind': 'class', 'properties': properties, 'methods': methods}


def _simple_assignment_branches(branches):
    """Recognize side-effect-free value selection, preserving its branch scopes."""
    def scalar(text):
        text = text.strip()
        if re.fullmatch(_VAR_REF, text) or re.fullmatch(r'-?\d+(?:\.\d+)?', text):
            return True
        if text[:1] in ('"', "'") and _string_literal_end(text) == len(text):
            return text.startswith("'") or '$(' not in text
        return False

    def predicate(text, depth=0):
        text = text.strip()
        if depth > 12 or len(text) > 4096:
            return None
        if text.startswith('('):
            inner, end = _extract_balanced(text, 0)
            if inner is not None and end == len(text) - 1:
                return predicate(inner, depth + 1)
        logical = _last_top_level_match(text, re.compile(r'\s+(-and|-or)\s+', re.I), _top_level_positions(text))
        if logical:
            left = predicate(text[:logical.start()], depth + 1)
            right = predicate(text[logical.end():], depth + 1)
            return (logical[1].lower(), left, right) if left is not None and right is not None else None
        negate = re.fullmatch(r'(?:-not\s+|!\s*)(.+)', text, re.I | re.S)
        if negate:
            operand = negate[1].strip()
            # Restrict unary operands so a comparison cannot accidentally
            # become part of the negation through a guessed precedence rule.
            if re.fullmatch(_VAR_REF, operand) or operand.startswith('('):
                child = predicate(operand, depth + 1)
                return ('-not', child) if child is not None else None
            return None
        comparison = re.fullmatch(rf'({_VAR_REF})\s+-(?:eq|ne)\s+(.+)', text, re.I | re.S)
        null_check = re.fullmatch(rf'\[(?:System\.)?string\]::IsNullOrEmpty\(\s*({_VAR_REF})\s*\)', text, re.I)
        if null_check:
            return ('null-or-empty', null_check[1])
        if re.fullmatch(_VAR_REF, text) or (comparison and scalar(comparison[2])):
            return ('atom', text)
        return None

    prepared = []
    for condition, body in branches:
        if condition is not None:
            condition = predicate(condition)
            if condition is None:
                return None
        assignments = []
        for statement in _split_statements(body):
            match = _ASSIGN_RE.fullmatch(statement.strip())
            if not match or match[2] != '=' or not scalar(match[3]):
                return None
            assignments.append((match[1], match[3]))
        prepared.append((condition, assignments))
    return prepared


def _try_parse_for_expression(expr):
    """``$x = for (INIT; COND; INCR) { BODY }`` -- PowerShell's for-as-
    expression form: the loop's own naked/unassigned pipeline output,
    collected across every iteration, becomes the whole construct's value
    (real semantics, same family as ``_try_parse_if_expression``). A
    favorite obfuscation idiom for a per-byte transform decode --
    ``for(...){ $data[$i] -bxor $key[...] }`` looks like a bare statement
    but is actually building the decoded byte array one element per
    iteration. ``for``/``foreach`` braces are never flattened by
    ``_normalize_block_syntax`` (real bounded-loop execution needs them
    intact), so they're still real here regardless of statement vs.
    expression position. Returns ``(init_text, cond_text, incr_text,
    body_text)`` or ``None`` if ``expr`` isn't cleanly this shape.
    """
    match = _FOR_START_RE.match(expr)
    if not match:
        return None
    header, header_end = _extract_balanced(expr, match.end() - 1, "(", ")")
    if header is None:
        return None
    cursor = header_end + 1
    while cursor < len(expr) and expr[cursor] in " \t\r\n":
        cursor += 1
    if cursor >= len(expr) or expr[cursor] != "{":
        return None
    body, body_end = _extract_balanced(expr, cursor, "{", "}")
    if body is None or expr[body_end + 1:].strip():
        return None
    parts = header.split(";")
    if len(parts) != 3:
        return None
    return parts[0].strip(), parts[1].strip(), parts[2].strip(), body


def _scan_do_loop(source, offset=0):
    match = re.match(r'do\s*\{', source[offset:], re.I)
    if not match:
        return None
    body, end = _extract_balanced(source, offset + match.end() - 1, '{', '}')
    if body is None:
        return None
    condition_start = re.match(r'\s*(while|until)\s*\(', source[end + 1:], re.I)
    if not condition_start:
        return None
    condition, condition_end = _extract_balanced(source, end + condition_start.end(), '(', ')')
    if condition is None:
        return None
    return body, condition, condition_start[1].lower(), condition_end + 1


def _scan_bigint_byte_loop(source, offset=0):
    match = re.match(r'while\s*\(', source[offset:], re.I)
    if not match:
        return None
    condition, end = _extract_balanced(source, offset + match.end()-1)
    if condition is None:
        return None
    bound = re.fullmatch(r'\s*\$(\w+)\s*-gt\s*0\s*', condition, re.I)
    cursor = end+1
    while cursor < len(source) and source[cursor].isspace():
        cursor += 1
    if not bound or source[cursor:cursor+1] != '{':
        return None
    body, body_end = _extract_balanced(source, cursor, '{', '}')
    compact = re.sub(r'\s+', '', body or '').lower().strip(';')
    parsed = re.fullmatch(
        r'\$(?P<out>\w+)\+=\[char\]\[int\]\(\[bigint\]::remainder\(\$(?P<n>\w+),256\)\);'
        r'\$(?P=n)=\[bigint\]::divide\(\$(?P=n),256\)', compact)
    if parsed and parsed['n'] == bound[1].lower() and parsed['out'] != parsed['n']:
        return parsed['n'], parsed['out'], body_end+1
    return None


def _try_parse_index_assign(statement):
    """``$var[index] = value`` -- the write side of the byte-array fill
    loops these decode routines are built from. Uses ``_extract_balanced``
    for the index expression rather than a regex so a nested-bracket index
    (``$out[$i % $n]``, rare but real) still parses correctly.
    """
    var_match = re.match(rf"^({_VAR_REF})\s*\[", statement)
    if not var_match:
        return None
    bracket_start = statement.index("[", var_match.end() - 1)
    index_text, bracket_end = _extract_balanced(statement, bracket_start, "[", "]")
    if index_text is None:
        return None
    rest = statement[bracket_end + 1:].lstrip()
    eq_match = re.match(r"^=(?!=)\s*(.+)$", rest, re.DOTALL)
    if not eq_match:
        return None
    return var_match.group(1), index_text, eq_match.group(1)


def _try_parse_generic_index_assign(statement):
    """``(EXPR)[index] = value`` -- index assignment through an
    arbitrary parenthesized expression rather than a bare ``$var[index]``
    target. Most common shape: ``(gv('name'))[$i] = ...``, the array-
    mutation counterpart of ``Get-Variable``-based dynamic naming (real
    PowerShell array reference semantics mean this genuinely mutates the
    same array the variable holds, exactly like Python list mutation
    here does). Returns ``(target_text, index_text, expr_text)`` or None.
    """
    stripped = statement.strip()
    if not stripped.startswith("("):
        return None
    inner, end = _extract_balanced(stripped, 0, "(", ")")
    if inner is None:
        return None
    cursor = end + 1
    if cursor >= len(stripped) or stripped[cursor] != "[":
        return None
    index_text, bracket_end = _extract_balanced(stripped, cursor, "[", "]")
    if index_text is None:
        return None
    rest = stripped[bracket_end + 1:].lstrip()
    eq_match = re.match(r"^=(?!=)\s*(.+)$", rest, re.DOTALL)
    if not eq_match:
        return None
    return stripped[:end + 1], index_text, eq_match.group(1)


def _find_top_level_assign(text):
    """Position of a bare top-level ``=`` (not ``==``/``+=``/``!=``/``<=``/
    ``>=``, and outside any bracket depth or quoted span) -- the one
    thing ``_try_parse_multi_assign`` needs that ``_ASSIGN_RE`` can't
    give it, since that regex anchors its match at a single ``$var``
    right before the operator and never matches a multi-target LHS like
    ``$a[$i], $a[$j] = ...`` at all. Returns ``None`` if there is none.
    """
    spans = _scan_ps_text(text)
    depth = 0
    for start, end, kind in spans:
        if kind != "code":
            continue
        segment = text[start:end]
        for index, ch in enumerate(segment):
            if ch in "([{":
                depth += 1
            elif ch in ")]}":
                depth = max(0, depth - 1)
            elif depth == 0 and ch == "=":
                abs_index = start + index
                prev_ch = text[abs_index - 1] if abs_index > 0 else ""
                next_ch = text[abs_index + 1] if abs_index + 1 < len(text) else ""
                if prev_ch not in "=+-*/!<>" and next_ch != "=":
                    return abs_index
    return None


def _try_parse_multi_assign(statement):
    """``$a[$i], $a[$j] = $a[$j], $a[$i]`` -- PowerShell's tuple/multi-
    assignment syntax, the near-universal way an RC4 (or any other
    Fisher-Yates-shuffle-shaped) key-scheduling loop swaps two array
    elements in place. Returns ``(lhs_parts, rhs_parts)`` (equal-length
    lists of raw expression text, length > 1) or ``None``.
    """
    eq_pos = _find_top_level_assign(statement)
    if eq_pos is None or "," not in statement[:eq_pos]:
        return None
    lhs_parts = [part.strip() for part in _split_top_level(statement[:eq_pos], ",")]
    rhs_parts = [part.strip() for part in _split_top_level(statement[eq_pos + 1:], ",")]
    if len(lhs_parts) < 2 or len(lhs_parts) != len(rhs_parts):
        return None
    if not all(lhs_parts) or not all(rhs_parts):
        return None
    return lhs_parts, rhs_parts


def _try_parse_chained_assign(statement):
    """``$a = $b = 0`` -- chained simple assignment. Every target but
    the last is a plain ``$var`` immediately followed by ``=``; the
    final segment is the real expression, and every target gets that
    *same* evaluated value (real PowerShell right-to-left
    chained-assignment semantics). Without this, ``_ASSIGN_RE`` alone
    greedily swallows ``$b = 0`` as the RHS *text* for ``$a`` -- an
    inert, never-evaluated-as-assignment string -- silently leaving
    ``$b`` unset (an RC4 KSA/PRGA loop resetting both its ``i``/``j``
    counters this way between phases is the shape that surfaced this).
    Returns ``(targets, final_expr_text)`` (``len(targets) >= 2``) or
    ``None``.
    """
    match = re.match(rf"^({_VAR_REF})\s*=(?!=)\s*(.+)$", statement, re.DOTALL)
    if not match:
        return None
    targets = [match.group(1)]
    rest = match.group(2)
    while True:
        next_match = re.match(rf"^({_VAR_REF})\s*=(?!=)\s*(.+)$", rest, re.DOTALL)
        if not next_match:
            break
        targets.append(next_match.group(1))
        rest = next_match.group(2)
    if len(targets) < 2:
        return None
    return targets, rest


def _extract_scriptblock_params(source):
    match = _PARAM_BLOCK_RE.match(source)
    if not match:
        return []
    params_text, _ = _extract_balanced(source, match.end() - 1)
    if params_text is None:
        return []
    names = []
    for part in _split_top_level(params_text, ","):
        var_match = re.search(rf"({_VAR_REF})\s*(?:=.*)?$", part.strip(), re.DOTALL)
        if var_match:
            names.append(_normalize_var_name(var_match.group(1)))
    return names


_ASSIGN_RE = re.compile(rf"^({_VAR_REF})\s*(\+=|-=|\*=|/=|=)\s*(.+)$", re.DOTALL)
_PROPERTY_ASSIGN_RE = re.compile(rf"^({_VAR_REF}(?:\.[A-Za-z_]\w*)+)\s*=\s*(.+)$", re.DOTALL)
_FUNCTION_DEF_RE = re.compile(r"^function\s+(?:(?:global|script|local|private):)?([A-Za-z0-9_]+(?:-[A-Za-z0-9_]+)*)\b", re.IGNORECASE)
# ``function Name`` (optionally ``(params)``) with nothing else on the
# line -- an Allman-style definition puts its ``{`` on the *next* line.
# Used by ``_split_statements`` to keep the signature from being cut off
# as its own (bodyless, silently ignored) statement before that brace is
# ever reached.
_FUNCTION_SIGNATURE_PENDING_RE = re.compile(
    r"^function\s+\S+(?:\s*\([^)]*\))?\s*$", re.IGNORECASE,
)


def _try_parse_function_def(statement):
    """``function Verb-Noun [(params)] { BODY }`` (PowerShell allows the
    param list either in this parenthesized form or as a ``param(...)``
    statement at the top of ``BODY`` -- ``_invoke_function`` checks both).
    ``function`` is deliberately *not* in ``_BLOCK_KEYWORD_RE``: unlike a
    control-flow block, this needs its ``{...}`` body kept intact (so
    ``_split_statements``'s normal brace depth-tracking protects it, same
    as a scriptblock literal) rather than flattened, since a named
    function's ``param()`` values must come from its *caller*'s real
    arguments -- flattening the body in at definition time (as this
    interpreter first tried) left every parameter permanently unbound.
    """
    match = _FUNCTION_DEF_RE.match(statement)
    if not match:
        return None
    cursor = match.end()
    while cursor < len(statement) and statement[cursor] in " \t\r\n":
        cursor += 1
    params_text = ""
    if cursor < len(statement) and statement[cursor] == "(":
        body, end = _extract_balanced(statement, cursor, "(", ")")
        if body is None:
            return None
        params_text = body
        cursor = end + 1
        while cursor < len(statement) and statement[cursor] in " \t\r\n":
            cursor += 1
    if cursor >= len(statement) or statement[cursor] != "{":
        return None
    body, _ = _extract_balanced(statement, cursor, "{", "}")
    if body is None:
        return None
    return match.group(1), params_text, body


def _split_top_level_ws(text):
    """Split PowerShell "command syntax" positional arguments on top-level
    whitespace (bracket/quote-aware) -- distinct from ``_split_top_level``,
    which splits *expression*-syntax argument lists on commas instead.
    """
    spans = _scan_ps_text(text)
    parts = []
    current = []
    depth = 0
    for start, end, kind in spans:
        segment = text[start:end]
        if kind != "code":
            current.append(segment)
            continue
        cursor = 0
        index = 0
        seg_len = len(segment)
        while index < seg_len:
            ch = segment[index]
            if ch in "([{":
                depth += 1
                index += 1
                continue
            if ch in ")]}":
                depth = max(0, depth - 1)
                index += 1
                continue
            if ch.isspace() and depth == 0:
                current.append(segment[cursor:index])
                piece = "".join(current).strip()
                if piece:
                    parts.append(piece)
                current = []
                while index < seg_len and segment[index].isspace():
                    index += 1
                cursor = index
                continue
            index += 1
        current.append(segment[cursor:])
    tail = "".join(current).strip()
    if tail:
        parts.append(tail)
    return parts


_STATEMENT_SEP_RE = re.compile(r"[;\r\n]+")


_BLOCK_KEYWORD_RE = re.compile(
    # ``for``/``foreach``/``function`` are deliberately excluded here, each
    # for its own reason -- but all three need their ``{...}`` body kept
    # intact as one block rather than flattened apart:
    #  - ``for``/``foreach`` get *real* bounded loop execution (see
    #    ``_handle_for_loop``/``_handle_foreach_loop``), which depends on
    #    running the *whole* body once per index/item, not once total --
    #    the byte-array/XOR decode loop shape
    #    (``for ($i=0;$i -lt $x.Length;$i++) { $out[$i] = $x[$i] -bxor $k }``)
    #    this exists for is extremely common.
    #  - ``function`` gets real call-time invocation (see
    #    ``_try_parse_function_def``/``_invoke_function``): a named
    #    function's ``param()`` values must come from its *caller*'s real
    #    arguments at the point it's actually called, not from whatever
    #    happened to be in scope when it was merely *defined* -- flattening
    #    the body in at definition time (this interpreter's first attempt)
    #    left every parameter permanently unbound.
    #  - ``begin``/``process``/``end`` (PowerShell "advanced function"
    #    pipeline blocks -- ``function F { param(...) process { ... } }``)
    #    are *not* excluded: they always run in real semantics (once, or
    #    once per pipeline item for ``process``), so flattening them the
    #    same as ``try`` is the correct match, not an approximation --
    #    and leaving them unflattened left the block's entire body as one
    #    unrecognized opaque statement, silently skipping everything
    #    inside a function written this way (a shape a modeled ``[Convert]``
    #    decode helper reached for in real samples).
    r"\b(if|elseif|while|switch|catch|try|finally|else|do|begin|process|end)\b",
    re.IGNORECASE,
)


def _normalize_block_syntax(source):
    """Replace the ``{``/``}`` pair of every recognized control-flow block
    (``if (...) { ... }``, ``try { ... } catch { ... }``, ``foreach (...)
    { ... }``, ...) with ``;``.

    Real malware -- especially generated/minified droppers -- routinely
    writes an entire ``try { (New-Object ...).DownloadFile(...) } catch
    {}`` on one physical line with no ``;``/newline anywhere inside it.
    ``_split_statements`` only splits at top-level ``;``/newline *outside*
    any bracket depth (by design: it never executes real control flow,
    just visits every statement once in order), and depth-tracks ``{``/
    ``}`` same as parens/brackets -- needed so a scriptblock literal
    (``$x = { param($a) ... }``) survives as one atomic value instead of
    truncating at its first internal newline. Those two needs conflict for
    a control-flow block's braces specifically, so this step resolves it
    by *removing* just those braces (turning them into statement
    separators) before ``_split_statements`` ever runs, while every other
    brace -- scriptblock literals, hashtables, array subexpressions, a
    block's *own* nested control-flow blocks -- is left completely alone
    for that later depth-tracking to protect correctly. This does not
    change *what* gets executed, only where the text is allowed to break.
    """
    quoted_ranges = [(start, end) for start, end, kind in _scan_ps_text(source) if kind != "code"]

    def in_quotes(pos):
        return any(start <= pos < end for start, end in quoted_ranges)

    # Protect an ``if``/``elseif``/``else`` chain used as an assignment
    # RHS (``$x = if (...) {...} else {...}``, PowerShell's
    # if-as-expression feature -- see ``_try_parse_if_expression``) from
    # the flattening below: unlike statement-position ``if`` (both
    # branches deliberately run, for IOC-surfacing value even when the
    # condition can't be trusted), an expression-position ``if`` needs
    # its braces to stay real so the whole construct survives as one
    # atomic RHS for ``_split_statements``/``_ASSIGN_RE`` to hand to
    # ``_try_parse_if_expression``, which evaluates the condition for
    # real and returns only the chosen branch's value.
    protected_ranges = []
    for type_match in re.finditer(r'\b(?:class|enum)\s+\w+\s*(?::\s*[\w.]+\s*)?\{', source, re.I):
        if not in_quotes(type_match.start()):
            _, end = _extract_balanced(source, type_match.end() - 1, '{', '}')
            if end is not None:
                protected_ranges.append((type_match.start(), end + 1))
    for loop_match in re.finditer(r'\bwhile\s*\(\s*\$\w+\.\w+\(\)\s*\)\s*\{', source, re.I):
        if not in_quotes(loop_match.start()):
            _, end = _extract_balanced(source, loop_match.end() - 1, '{', '}')
            if end is not None:
                protected_ranges.append((loop_match.start(), end + 1))
    # Pipeline scriptblocks are parsed when invoked, so preserve their
    # branch boundaries until then (including pure character decoders).
    for pipeline_match in re.finditer(r'\|\s*(?:%|foreach-object)\s*\{', source, re.I):
        if not in_quotes(pipeline_match.start()):
            _, end = _extract_balanced(source, pipeline_match.end()-1, '{', '}')
            if end is not None:
                protected_ranges.append((pipeline_match.end()-1, end+1))
    for while_match in re.finditer(r'\bwhile\s*\(', source, re.I):
        if not in_quotes(while_match.start()):
            radix_loop = _scan_bigint_byte_loop(source, while_match.start())
            if radix_loop:
                protected_ranges.append((while_match.start(),radix_loop[2]))
    # Store function source intact. Its local parser (or an exact pure
    # decoder recognizer) needs the original control-flow boundaries.
    for function_match in re.finditer(r'\bfunction\s+[\w-]+', source, re.I):
        if in_quotes(function_match.start()):
            continue
        cursor = function_match.end()
        while cursor < len(source) and source[cursor].isspace():
            cursor += 1
        if cursor < len(source) and source[cursor] == '(':
            _, end = _extract_balanced(source, cursor)
            if end is None:
                continue
            cursor = end + 1
            while cursor < len(source) and source[cursor].isspace():
                cursor += 1
        if cursor < len(source) and source[cursor] == '{':
            _, end = _extract_balanced(source, cursor, '{', '}')
            if end is not None:
                protected_ranges.append((cursor, end + 1))
    # The postcondition and body must survive until the bounded loop model.
    for do_match in re.finditer(r'\bdo\s*\{', source, re.I):
        if not in_quotes(do_match.start()):
            loop = _scan_do_loop(source, do_match.start())
            if loop:
                protected_ranges.append((do_match.start(), loop[3]))
    # Keep nested control-flow scopes inside for bodies until the loop
    # handler can distinguish a loop-level break from a switch/if break.
    for loop_match in re.finditer(r"\bfor\s*\(", source, re.IGNORECASE):
        if in_quotes(loop_match.start()):
            continue
        _, header_end = _extract_balanced(source, loop_match.end()-1)
        if header_end is None:
            continue
        cursor = header_end+1
        while cursor < len(source) and source[cursor].isspace():
            cursor += 1
        if cursor < len(source) and source[cursor] == '{':
            _, body_end = _extract_balanced(source,cursor,'{','}')
            if body_end is not None:
                protected_ranges.append((loop_match.start(),body_end+1))
    for if_match in re.finditer(r"\bif\s*\(", source, re.IGNORECASE):
        if in_quotes(if_match.start()):
            continue
        prefix = source[:if_match.start()].rstrip()
        branches, chain_end = _scan_if_expression_chain(source, if_match.start())
        if branches is None:
            continue
        expression_position = prefix and prefix[-1] == '=' and not (len(prefix)>1 and prefix[-2] in '=!<>+-*/')
        if expression_position or _simple_assignment_branches(branches) is not None:
            protected_ranges.append((if_match.start(), chain_end))

    # Protect a ``while ($state -ne -1) { switch ($state) { ... } }``
    # numeric state-machine block (see ``_scan_state_machine``'s
    # docstring) from the flattening below entirely -- both the
    # ``while``'s and the inner ``switch``'s braces need to stay real so
    # the whole thing survives as one atomic statement for
    # ``_try_parse_state_machine`` to hand to
    # ``PowerShellEmulator._handle_state_machine``, which dispatches it
    # for real (one case per pass) instead of the flatten-everything
    # treatment a state machine can't produce a coherent result from.
    for sm_match in _STATE_MACHINE_WHILE_RE.finditer(source):
        if in_quotes(sm_match.start()):
            continue
        _, _, sm_end = _scan_state_machine(source, sm_match.start())
        if sm_end is not None:
            protected_ranges.append((sm_match.start(), sm_end + 1))

    def in_protected(pos):
        return any(start <= pos < end for start, end in protected_ranges)

    brace_positions = []
    blank_spans = []
    for match in _BLOCK_KEYWORD_RE.finditer(source):
        if in_quotes(match.start()) or in_protected(match.start()):
            continue
        cursor = match.end()
        valid = True
        while True:
            while cursor < len(source) and source[cursor] in " \t\r\n":
                cursor += 1
            if cursor < len(source) and source[cursor] == "(":
                body, end = _extract_balanced(source, cursor, "(", ")")
                if body is None:
                    valid = False
                    break
                cursor = end + 1
                continue
            if cursor < len(source) and source[cursor] == "[":
                body, end = _extract_balanced(source, cursor, "[", "]")
                if body is None:
                    valid = False
                    break
                cursor = end + 1
                continue
            break
        if not valid:
            continue
        while cursor < len(source) and source[cursor] in " \t\r\n":
            cursor += 1
        if cursor >= len(source) or source[cursor] != "{":
            continue
        body, end = _extract_balanced(source, cursor, "{", "}")
        if body is None:
            continue
        if match.group(1).lower() == "catch":
            # This emulator never models a real exception being thrown,
            # so a ``try`` block is always treated as though it ran to
            # completion successfully -- meaning ``catch`` can never
            # actually run either, in real PowerShell semantics. Unlike
            # every other flattened control-flow block (kept for
            # IOC-surfacing value even though its condition can't be
            # reliably evaluated), including catch's statements
            # unconditionally would let its fallback ``return``/error
            # handling clobber the try block's real result -- exactly
            # backwards from what a try/catch/return decode helper
            # needs (and the near-universal shape of one).
            blank_spans.append((match.start(), end))
            continue
        brace_positions.append(cursor)
        brace_positions.append(end)
        if match.group(1).lower() == "switch":
            # ``switch (EXPR) { 4 { BODY1 } 8 { BODY2 } default { BODY3 } }``
            # -- blanking only the switch's own outer braces (as done for
            # every other keyword above) leaves each ``CASE { BODY }``
            # sub-block as one opaque, un-flattened statement (a case
            # label is never a recognized block keyword, so it never
            # matches ``_BLOCK_KEYWORD_RE`` on its own), silently skipping
            # every case body's contents entirely. Blanking each case's
            # *own* brace pair too -- scanned as a flat top-level
            # sequence of ``{...}`` groups inside the switch body, which
            # is exactly the shape a case list always has -- lets every
            # case run unconditionally, same "flatten and run every
            # branch" treatment as ``if``/``elseif``/``else`` already get.
            case_cursor = 0
            body_len = len(body)
            while case_cursor < body_len:
                brace_rel = body.find("{", case_cursor)
                if brace_rel == -1:
                    break
                case_body, case_end_rel = _extract_balanced(body, brace_rel, "{", "}")
                if case_body is None:
                    break
                brace_positions.append(cursor + 1 + brace_rel)
                brace_positions.append(cursor + 1 + case_end_rel)
                case_cursor = case_end_rel + 1
    chars = list(source)
    for pos in brace_positions:
        chars[pos] = ";"
    for start, end in blank_spans:
        for pos in range(start, end + 1):
            if chars[pos] not in ("\n", "\r"):
                chars[pos] = " "

    # A single-line, minified ``function F { param([string]$z) $p1 =
    # ... }`` (the near-universal shape a generated/obfuscated helper
    # comes in) sometimes has no ``;``/newline between the ``param(...)``
    # block's closing paren and the first real statement that follows
    # it. ``_split_statements`` would then glue that statement onto the
    # ``param(...)`` text as one blob, and ``_run_scriptblock_body``'s
    # ``param``-skip check (a simple ``^param\s*\(`` prefix match) would
    # discard the whole thing -- silently dropping real code, not just
    # the parameter declaration. Insert a synthetic ``;`` right after
    # the closing paren whenever one isn't already there.
    param_positions = []
    for match in re.finditer(r"\bparam\s*\(", source, re.IGNORECASE):
        if in_quotes(match.start()):
            continue
        body, end = _extract_balanced(source, match.end() - 1, "(", ")")
        if body is None:
            continue
        cursor = end + 1
        if cursor < len(source) and source[cursor] not in ";\r\n":
            param_positions.append(cursor)
    for pos in sorted(param_positions, reverse=True):
        chars.insert(pos, ";")

    return "".join(chars)


# Real .ps1 "droppers" are frequently just a one-line CLI invocation
# (spawned from a scheduled task, a macro, a registry Run key, ...) rather
# than a real PowerShell *script* -- the payload lives entirely inside a
# ``-Command``/``-EncodedCommand`` argument. ``powershell -c "..."`` is not
# itself valid PowerShell script syntax, so without unwrapping it first the
# interpreter never sees the actual behavior at all.
_POWERSHELL_ENC_WRAPPER_RE = re.compile(
    r"powershell(?:\.exe)?\b(?:\s+-[\w:]+(?:\s+[^\s]+)?)*?\s+-(?:e|en|enc|encodedcommand)\b\s+([A-Za-z0-9+/=]{16,})",
    re.IGNORECASE,
)
_POWERSHELL_CMD_WRAPPER_RE = re.compile(
    r"powershell(?:\.exe)?\b(?:\s+-[\w:]+(?:\s+(?:\"[^\"]*\"|'[^']*'|[^\s\"']+))?)*?\s+-(?:c|command)\s+(\"(?:[^\"]|\"\")*\"|'(?:[^']|'')*')",
    re.IGNORECASE | re.DOTALL,
)


def _split_windows_arguments(text):
    """Parse modeled Windows process arguments as data, without a shell."""
    if not isinstance(text, str) or len(text) > MAX_SOURCE_CHARS or '\0' in text:
        return None
    args, index = [], 0
    while index < len(text):
        while index < len(text) and text[index] in ' \t':
            index += 1
        if index == len(text):
            break
        if len(args) >= MAX_VARIABLES:
            return None
        value, quoted = [], False
        while index < len(text):
            if text[index] in ' \t' and not quoted:
                break
            slashes = 0
            while index < len(text) and text[index] == '\\':
                slashes += 1
                index += 1
            if index < len(text) and text[index] == '"':
                value.append('\\' * (slashes // 2))
                if slashes % 2:
                    value.append('"')
                elif quoted and index + 1 < len(text) and text[index + 1] == '"':
                    value.append('"')
                    index += 1
                else:
                    quoted = not quoted
                index += 1
            else:
                value.append('\\' * slashes)
                if index < len(text):
                    if text[index] in ' \t' and not quoted:
                        break
                    value.append(text[index])
                    index += 1
        args.append(''.join(value))
    return args


def _unwrap_powershell_cli_wrapper(source):
    # Only a complete top-level invocation is a wrapper. Searching inside
    # assignments, comments or later statements discards the real program.
    stripped = _strip_comments(source).strip()
    # A captured Windows PowerShell command line may contain an absolute
    # quoted executable path and the positional (implicit -Command) string.
    # Require the entire artifact to consist of these two literal arguments.
    # pwsh uses different positional defaults and is deliberately excluded.
    plausible_wrapper = re.match(r'''(?:["']?[A-Za-z]:[\\/]|powershell(?:\.exe)?\s)''', stripped, re.I)
    tokens = _split_top_level_ws(stripped) if plausible_wrapper else []
    if len(tokens) >= 2:
        executable = tokens[0].strip('"\x27')
        if re.fullmatch(r'(?:[A-Za-z]:[\\/][^"\x27\r\n]*[\\/])?powershell(?:\.exe)?', executable, re.I):
            index = 1
            switches = {'-noprofile','-nop','-noninteractive','-noni','-nologo','-nol','-noexit','-noe','-sta','-mta'}
            options = {'-executionpolicy','-ep','-ex','-windowstyle','-w','-wi','-win','-window','-version','-v','-inputformat','-outputformat'}
            while index < len(tokens)-1:
                option = tokens[index].lower()
                if option in switches:
                    index += 1
                elif option in options and index+2 < len(tokens):
                    index += 2
                elif option in ('-command','-c') and index == len(tokens)-2:
                    index += 1
                else:
                    break
            if index == len(tokens)-1 and re.fullmatch(r'"(?:[^"`]|`.)*"|\x27(?:[^\x27]|\x27\x27)*\x27', tokens[index], re.S):
                return _decode_ps_string(tokens[index])
    enc_match = _POWERSHELL_ENC_WRAPPER_RE.fullmatch(stripped)
    if enc_match:
        token = enc_match.group(1)
        try:
            raw = base64.b64decode(token + "=" * (-len(token) % 4), validate=False)
            return raw.decode("utf-16-le", errors="ignore")
        except Exception:
            pass
    cmd_match = _POWERSHELL_CMD_WRAPPER_RE.fullmatch(stripped)
    if cmd_match:
        token = cmd_match.group(1)
        return _decode_ps_string(token)
    return None


def _split_statements(source):
    """Split into individual statements at top-level ``;``/newline
    boundaries.

    Deliberately coarse (same philosophy as
    ``js_emulator._split_statements``): a pipeline (``a | b | c``) stays one
    statement. Braces *are* depth-tracked here, same as parens/brackets --
    unlike a control-flow block, a scriptblock literal (``$x = { param($a)
    ... }``, commonly assigned to a variable and invoked later) must stay
    one atomic statement, or the assignment truncates at the literal's
    first internal newline and the scriptblock's body is lost entirely.
    ``if``/``foreach``/``try``/etc.'s own block bodies get split into
    individual statements a different way: ``_normalize_block_syntax``
    rewrites *those* braces into semicolons before this ever runs, so this
    function only ever sees "real" (scriptblock/hashtable/array-literal)
    braces once its input has already been normalized -- see that
    function's own docstring for why plain depth-tracking alone can't
    satisfy both needs at once.
    """
    spans = _scan_ps_text(source)
    statements = []
    current = []
    depth = 0
    pending_continuation = False

    def flush():
        text = "".join(current).strip()
        if text:
            statements.append(text)
        current.clear()

    for start, end, kind in spans:
        segment = source[start:end]
        if kind != "code":
            current.append(segment)
            pending_continuation = False
            continue
        cursor = 0
        index = 0
        seg_len = len(segment)
        while index < seg_len:
            ch = segment[index]
            if ch in "([{":
                depth += 1
                index += 1
                continue
            if ch in ")]}":
                depth = max(0, depth - 1)
                if ch == '}' and depth == 0:
                    candidate = ''.join(current) + segment[cursor:index + 1]
                    if (_FUNCTION_DEF_RE.match(candidate.lstrip())
                            or re.match(r'\s*(?:for|foreach)\s*\(', candidate, re.I)):
                        current.append(segment[cursor:index + 1])
                        flush()
                        cursor = index + 1
                index += 1
                continue
            if ch == "`" and index + 1 < seg_len and segment[index + 1] in "\r\n":
                current.append(segment[cursor:index])
                # Consume the *whole* line ending, not just its first
                # character -- on a CRLF file (the common case for a
                # Windows-authored dropper) leaving the ``\n`` of a
                # ``\r\n`` pair behind meant it immediately hit the
                # newline-is-a-statement-separator check below and split
                # the "continued" line off anyway, silently truncating
                # every backtick-continued multi-line command (a
                # `` `` -TypeIdentifier ... `` `` -MethodIdentifier ...``
                # parameter chain, for example) into several nonsense
                # fragment statements.
                skip = 3 if segment[index + 1:index + 3] == "\r\n" else 2
                cursor = index + skip
                index += skip
                continue
            if depth == 0 and (ch == ";" or ch in "\r\n"):
                current.append(segment[cursor:index])
                stripped_tail = "".join(current).rstrip()
                # A trailing pipe/binary-operator/open-continuation means
                # the statement is not actually finished yet.
                if ch in "\r\n" and (
                    stripped_tail.endswith(("|", "+", "-", "*", "/", ",", "-and", "-or", "-band", "-bor", "-f", "="))
                    or re.search(r'''(?:\$[\w:]+(?:\.[\w]+)*|[)'"\]])\.$''', stripped_tail)
                    or not stripped_tail
                    or _FUNCTION_SIGNATURE_PENDING_RE.match(stripped_tail.lstrip())
                    or (re.fullmatch(r'\s*(?:class|enum)\s+\w+\s*(?::\s*[\w.]+)?\s*', stripped_tail, re.I)
                        and source[start + index + 1:].lstrip().startswith('{'))
                    or (re.match(r'\s*do\b', stripped_tail, re.I) and _scan_do_loop(stripped_tail.lstrip()) is None)
                ):
                    current.append(' ')
                    cursor = index + 1
                    index += 1
                    continue
                flush()
                cursor = index + 1
            index += 1
        current.append(segment[cursor:])
    flush()
    return statements


# A small set of cmdlet/alias names this interpreter recognizes as pure
# no-ops for behavior-tracking purposes -- present in virtually every real
# script, never themselves an IOC. Modeling them as "known, does nothing"
# avoids spending an _Unknown result (and the noise that comes with it) on
# something this common.
_NOOP_CMDLETS = frozenset((
    "write-host", "write-output", "write-verbose", "write-debug",
    "write-warning", "write-error", "write-information", "out-null",
    "out-host", "start-sleep", "sleep", "clear-host", "cls",
    "set-strictmode", "set-executionpolicy", "select-object", "select",
    "sort-object", "sort", "where-object", "where", "foreach-object",
    "%", "?", "measure-object", "group-object", "tee-object",
    "format-list", "format-table", "fl", "ft",
))

# Default aliases for command forms modeled here (Windows PowerShell profile).
# Keep these in mutable model state: removing/redefining an alias changes which
# function/cmdlet a later invocation resolves to.
_DEFAULT_COMMAND_ALIASES = {
    'iex': 'invoke-expression', 'irm': 'invoke-restmethod', 'iwr': 'invoke-webrequest',
    'curl': 'invoke-webrequest', 'wget': 'invoke-webrequest',
    'saps': 'start-process', 'start': 'start-process', 'ii': 'invoke-item', 'icm': 'invoke-command',
    'ri': 'remove-item', 'del': 'remove-item', 'rm': 'remove-item', 'erase': 'remove-item',
    'gwmi': 'get-wmiobject', 'gci': 'get-childitem', 'ls': 'get-childitem', 'dir': 'get-childitem',
    'gi': 'get-item', 'gcm': 'get-command', 'gv': 'get-variable', 'sv': 'set-variable',
    'nv': 'new-variable', 'gc': 'get-content', 'cat': 'get-content', 'type': 'get-content',
    'cd': 'set-location', 'chdir': 'set-location', 'sl': 'set-location',
    'kill': 'stop-process', 'spps': 'stop-process', 'sal': 'set-alias', 'nal': 'new-alias',
    'sleep': 'start-sleep', 'cls': 'clear-host',
}

# Legitimate, Microsoft-signed .NET binaries with a long history of being
# passed as the target of a process-hollowing/AppDomain-injection loader
# specifically because they're signed (bypasses naive AppLocker/allowlist
# rules) -- seeing one show up as a reflective assembly invoke's argument
# is a strong, well-known technique fingerprint on its own.
_LOLBIN_INJECTION_TARGET_RE = re.compile(
    r"\b(aspnet_compiler|caspol|installutil|regasm|regsvcs|msbuild|vbc|jsc|ilasm|cvtres|csc|msdt|mshta)\.exe\b",
    re.IGNORECASE,
)

_SIZE_SUFFIX_RE = re.compile(r"^(-?\d+(?:\.\d+)?)(kb|mb|gb|tb|pb)$", re.IGNORECASE)
_SIZE_MULTIPLIERS = {"kb": 1024, "mb": 1024 ** 2, "gb": 1024 ** 3, "tb": 1024 ** 4, "pb": 1024 ** 5}


def _numeric_literal(token):
    text = token.strip()
    if not text:
        return None
    lowered = text.lower()
    size_match = _SIZE_SUFFIX_RE.match(lowered)
    if size_match:
        base, suffix = size_match.groups()
        try:
            return float(base) * _SIZE_MULTIPLIERS[suffix]
        except ValueError:
            return None
    try:
        if lowered.startswith(("0x", "-0x")):
            return int(text, 16)
        if re.fullmatch(r"-?\d+", text):
            return int(text)
        if re.fullmatch(r"-?\d+\.\d+", text):
            return float(text)
    except ValueError:
        return None
    return None


def _has_bounded_pe_layout(data):
    """Validate PE header/section bounds for speculative data recovery."""
    if not isinstance(data, bytes) or len(data) < 64 or data[:2] != b'MZ':
        return False
    offset = struct.unpack_from('<I', data, 60)[0]
    if offset < 64 or offset + 24 > len(data) or data[offset:offset + 4] != b'PE\0\0':
        return False
    sections = struct.unpack_from('<H', data, offset + 6)[0]
    optional_size = struct.unpack_from('<H', data, offset + 20)[0]
    table = offset + 24 + optional_size
    if not 1 <= sections <= 96 or optional_size < 96 or table + sections * 40 > len(data):
        return False
    if struct.unpack_from('<H', data, offset + 24)[0] not in (0x10b, 0x20b):
        return False
    for index in range(sections):
        size, position = struct.unpack_from('<II', data, table + index * 40 + 16)
        if size and (position < table + sections * 40 or position + size > len(data)):
            return False
    return True


def _recover_x64_wininet_config(data):
    """Read one known x64 WinINet stager layout as bytes, never CPU code.

    Require the resolver prologue, API hashes, argument setup and relative
    CALL targets around each inline string. Arbitrary strings/IPs alone
    are insufficient evidence for a URL. Other layouts remain unresolved.
    """
    if not isinstance(data, bytes) or not data.startswith(bytes.fromhex("fc4883e4f0e8")) or len(data) < 10:
        return None
    body = 10 + struct.unpack_from('<i', data, 6)[0]
    # This resolver starts at seed 0xa2e1c749, hashes the uppercase
    # UTF-16LE module name (no NUL), then the function name including NUL
    # into the same ROR13 accumulator. Validate its complete implementation
    # so changed resolver semantics cannot turn API constants into false IOCs.
    if (not 64 <= body <= min(4096, len(data)) or hashlib.sha256(data[10:body]).hexdigest()
            != 'cbc6f3b045f5ca146db5316737397bcf7499795780292e41e6fcd6a371159fbd'):
        return None

    def consume(offset, signature):
        code = bytes.fromhex(signature)
        return offset + len(code) if data.startswith(code, offset) else None

    def inline_string(offset, limit):
        if offset is None or offset + 5 > len(data) or data[offset] != 0xe8:
            return None
        start = offset + 5
        end = start + struct.unpack_from('<i', data, offset + 1)[0]
        if not start < end <= min(len(data), start + limit + 1):
            return None
        raw = data[start:end]
        if raw[-1:] != b'\0' or any(c < 32 or c > 126 for c in raw[:-1]):
            return None
        return raw[:-1].decode('ascii'), end, start

    at = consume(body, '5d4831db5349be77696e696e65740041564889e141ba75699d73ffd55353')
    agent = inline_string(at, 512)
    if agent is None:
        return None
    at = consume(agent[1], '59535a4d31c04d31c9535341baf8c8a8a0ffd5')
    host = inline_string(at, 253)
    if host is None or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9.-]*', host[0]):
        return None
    at = consume(host[1], '5a4889c149c7c0')
    if at is None or at + 4 > len(data):
        return None
    port_offset = at
    port = struct.unpack_from('<I', data, at)[0]
    at = consume(at + 4, '4d31c953536a035341ba72ae6fadffd5')
    path = inline_string(at, 2048)
    if not 1 <= port <= 65535 or path is None or not path[0].startswith('/') or ' ' in path[0]:
        return None
    at = consume(path[1], '4889c1535a41584d31c95348b8')
    if at is None or at + 8 > len(data):
        return None
    flags_offset = at
    flags = struct.unpack_from('<Q', data, at)[0]
    at = consume(at + 8, '50535341ba077bfe21ffd5')
    if at is None or flags > 0xffffffff:
        return None
    # Seeded ROR13 module/function hashes, followed by CALL RBP. These establish
    # the send/read APIs in this layout; they do not prove reachability.
    send = data.find(bytes.fromhex('41ba492be861ffd5'), at, at + 512)
    read = data.find(bytes.fromhex('41ba2dbb59c9ffd5'), max(at, send), at + 512)
    if send < 0 or read < send:
        return None
    scheme = 'https' if flags & 0x00800000 else 'http'
    return {'architecture': 'x64', 'family': 'wininet-stager', 'host': host[0], 'port': port,
            'method': 'GET', 'path': path[0], 'user_agent': agent[0], 'request_flags': hex(flags),
            'url': f'{scheme}://{host[0]}:{port}{path[0]}',
            'evidence_offsets': {'host': host[2], 'port': port_offset, 'path': path[2], 'flags': flags_offset}}


# Exact pure Base85 decoder syntax, stored only as matching data.
_BASE85_FUNCTION_SHAPE = r"""
    param([string]$encoded)
    $alpha = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz!#$%&()*+-;<=>?@^_`{|}~'
    $enc = $encoded -replace '[\r\n\t ]',''
    $fullChunks = [Math]::Floor($enc.Length / 5)
    $rem = $enc.Length % 5
    $outLen = $fullChunks * 4 + [Math]::Max($rem - 1, 0)
    $out = [byte[]]::new($outLen)
    $pos = 0
    for ($i = 0; $i -lt $fullChunks; $i++) {
        [uint64]$v = 0
        for ($j = 0; $j -lt 5; $j++) {
            $charIdx = $i*5+$j
            $char = [string]$enc[$charIdx]
            $idx = $alpha.IndexOf($char)
            if ($idx -lt 0) {
                
                throw "Invalid Base85 character at position $charIdx"
            }
            $v = $v * 85 + $idx
        }
        $out[$pos++] = [byte](($v -shr 24) -band 0xFF)
        $out[$pos++] = [byte](($v -shr 16) -band 0xFF)
        $out[$pos++] = [byte](($v -shr  8) -band 0xFF)
        $out[$pos++] = [byte]($v -band 0xFF)
    }
    if ($rem -gt 0) {
        [uint64]$v = 0
        for ($j = 0; $j -lt 5; $j++) {
            if ($j -lt $rem) {
                $charIdx = $fullChunks*5+$j
                $char = [string]$enc[$charIdx]
                $idx = $alpha.IndexOf($char)
                if ($idx -lt 0) {
                    
                    throw "Invalid Base85 character at position $charIdx"
                }
                $v = $v * 85 + $idx
            } else {
                $v = $v * 85 + 84
            }
        }
        $last = [byte[]]::new(4)
        $last[0] = [byte](($v -shr 24) -band 0xFF)
        $last[1] = [byte](($v -shr 16) -band 0xFF)
        $last[2] = [byte](($v -shr  8) -band 0xFF)
        $last[3] = [byte]($v -band 0xFF)
        [Array]::Copy($last, 0, $out, $pos, $rem - 1)
    }
    return ,$out"""

# The same decoder also occurs with its two error guards on one line.
# Accept this exact second layout; do not erase whitespace or quoted
# literals generally (doing so can change PowerShell token semantics).
_BASE85_FUNCTION_SHAPES = frozenset((
    _BASE85_FUNCTION_SHAPE.strip(),
    re.sub(r'\{\s+throw ("Invalid Base85 character at position \$charIdx")\s+\}',
           r'{ throw \1 }',_BASE85_FUNCTION_SHAPE).strip(),
))


class _NativeProfileStop(Exception):
    pass


class _NativeCPUProfile:
    """Unicorn guest CPU with synthetic Windows imports; no host API forwarding."""

    EXPORTS = {
        'kernel32.dll': {'LoadLibraryA':1,'LoadLibraryW':1,'GetProcAddress':2,'GetModuleHandleA':1,
                         'GetModuleHandleW':1,'VirtualAlloc':4,'VirtualProtect':4,'VirtualFree':3,
                         'Sleep':1,'ExitThread':1,'ExitProcess':1,'GetLastError':0},
        'ntdll.dll': {'RtlExitUserThread':1,'RtlExitUserProcess':1},
        'kernelbase.dll': {'LoadLibraryA':1,'GetProcAddress':2,'VirtualAlloc':4,'VirtualProtect':4},
        'wininet.dll': {'InternetOpenA':5,'InternetOpenW':5,'InternetConnectA':8,'InternetConnectW':8,
                        'HttpOpenRequestA':8,'HttpOpenRequestW':8,'HttpSendRequestA':5,'HttpSendRequestW':5,
                        'InternetReadFile':4,'InternetSetOptionA':4,'InternetSetOptionW':4,
                        'InternetCloseHandle':1,'HttpQueryInfoA':5,'InternetOpenUrlA':6},
        'ws2_32.dll': {'WSAStartup':2,'WSASocketA':6,'socket':3,'connect':3,'send':4,'recv':4,'closesocket':1},
    }
    CODE, STACK, ENV, HEAP = 0x1000000, 0x2000000, 0x3000000, 0x5000000
    MAX_INSTRUCTIONS, MAX_MEMORY = 100000, 32 * 1024 * 1024

    def __init__(self, owner, raw, bits, args):
        import unicorn as uc
        from unicorn import x86_const as reg
        self.owner, self.raw, self.bits, self.args = owner, raw, bits, args
        self.ucmod, self.reg = uc, reg
        self.cpu = uc.Uc(uc.UC_ARCH_X86, uc.UC_MODE_64 if bits == 64 else uc.UC_MODE_32)
        self.cpu.ctl_set_tcg_buffer_size(8 * 1024 * 1024)
        self.ptr = bits // 8
        self.sp = reg.UC_X86_REG_RSP if bits == 64 else reg.UC_X86_REG_ESP
        self.ip = reg.UC_X86_REG_RIP if bits == 64 else reg.UC_X86_REG_EIP
        self.ax = reg.UC_X86_REG_RAX if bits == 64 else reg.UC_X86_REG_EAX
        self.steps, self.allocated, self.heap_next = 0, 0, self.HEAP
        self.reason, self.result, self.imports, self.modules, self.handles = 'not-started', None, {}, {}, {}
        self.buffers = []
        self.deadline = min(owner.deadline, time.monotonic() + 2.0)

    def emit(self, category, **fields):
        self.owner._emit(category, analysis_context='emulated-native-profile',
                         architecture='x64' if self.bits == 64 else 'x86', **fields)

    def stop(self, reason):
        self.reason = reason
        self.cpu.emu_stop()
        raise _NativeProfileStop()

    def map(self, address, size, permissions=None):
        size = (size + 4095) & ~4095
        if size <= 0 or self.allocated + size > self.MAX_MEMORY:
            self.stop('native-memory-budget')
        self.cpu.mem_map(address, size, self.ucmod.UC_PROT_ALL if permissions is None else permissions)
        self.allocated += size
        return size

    def putptr(self, address, value):
        self.cpu.mem_write(address, int(value).to_bytes(self.ptr, 'little', signed=False))

    def readptr(self, address):
        return int.from_bytes(self.cpu.mem_read(address, self.ptr), 'little')

    def text(self, address, wide=False):
        if not address:
            return ''
        data = bytearray(); width = 2 if wide else 1
        for i in range(2048):
            part = bytes(self.cpu.mem_read(address + i * width, width))
            if part == bytes(width):
                return data.decode('utf-16-le' if wide else 'latin-1', errors='strict')
            data.extend(part)
        self.stop('native-string-budget')

    def allocate(self, size):
        if not 0 < size <= MAX_EMBEDDED_PAYLOAD_BYTES:
            self.stop('native-allocation-unresolved')
        address = self.heap_next; mapped = self.map(address, size); self.heap_next += mapped
        self.buffers.append((address, size))
        return address

    def handle(self, state):
        address = self.ENV + 0x18000 + len(self.handles) * 16
        if len(self.handles) >= 128:
            self.stop('native-handle-budget')
        self.handles[address] = state
        return address

    def module(self, name):
        return self.modules.get(ntpath.basename(name).lower().removesuffix('.dll') + '.dll', 0)

    def setup(self):
        if not self.raw or len(self.raw) > 2 * 1024 * 1024:
            self.stop('native-code-size-limit')
        self.map(self.CODE, len(self.raw)); self.cpu.mem_write(self.CODE, self.raw)
        self.map(self.STACK, 0x100000, self.ucmod.UC_PROT_READ | self.ucmod.UC_PROT_WRITE)
        self.map(self.ENV, 0x20000)
        peb, ldr = self.ENV + 0x1000, self.ENV + 0x2000
        list_offset, node_offset = (0x20, 0x10) if self.bits == 64 else (0x14, 8)
        self.putptr(self.ENV + (0x60 if self.bits == 64 else 0x30), peb)
        self.putptr(peb + (0x18 if self.bits == 64 else 0x0c), ldr)
        nodes = []
        for i, (name, exports) in enumerate(self.EXPORTS.items()):
            base = 0x4000000 + i * 0x20000
            self.map(base, 0x10000, self.ucmod.UC_PROT_READ | self.ucmod.UC_PROT_EXEC)
            self.modules[name] = base
            image = bytearray(0x10000); image[:2] = b'MZ'
            struct.pack_into('<I', image, 0x3c, 0x80); image[0x80:0x84] = b'PE\0\0'
            struct.pack_into('<H', image, 0x84, 0x8664 if self.bits == 64 else 0x14c)
            struct.pack_into('<H', image, 0x98, 0x20b if self.bits == 64 else 0x10b)
            struct.pack_into('<I', image, 0x80 + (0x88 if self.bits == 64 else 0x78), 0x1000)
            struct.pack_into('<IIIII', image, 0x1014, len(exports), len(exports), 0x1200, 0x1400, 0x1600)
            cursor = 0x2000
            for j, (api, count) in enumerate(exports.items()):
                stub = 0x4000 + j * 16
                struct.pack_into('<I', image, 0x1200 + j * 4, stub)
                struct.pack_into('<I', image, 0x1400 + j * 4, cursor)
                struct.pack_into('<H', image, 0x1600 + j * 2, j)
                encoded = api.encode('ascii') + b'\0'; image[cursor:cursor + len(encoded)] = encoded; cursor += len(encoded)
                image[stub] = 0xcc
                self.imports[base + stub] = (name, api, count)
            self.cpu.mem_write(base, bytes(image))
            entry = self.ENV + 0x3000 + i * 0x200
            node = entry + node_offset; nodes.append(node)
            name_address = entry + 0x100; encoded = name.encode('utf-16-le')
            self.cpu.mem_write(name_address, encoded + b'\0\0')
            self.putptr(node + (0x20 if self.bits == 64 else 0x10), base)
            name_offset = 0x48 if self.bits == 64 else 0x24
            self.cpu.mem_write(node + name_offset, struct.pack('<HH', len(encoded), len(encoded) + 2))
            self.putptr(node + (0x50 if self.bits == 64 else 0x28), name_address)
        head = ldr + list_offset
        self.putptr(head, nodes[0]); self.putptr(head + self.ptr, nodes[-1])
        for i, node in enumerate(nodes):
            self.putptr(node, nodes[i + 1] if i + 1 < len(nodes) else head)
            self.putptr(node + self.ptr, nodes[i - 1] if i else head)
        if self.bits == 64:
            self.cpu.reg_write(self.reg.UC_X86_REG_GS_BASE, self.ENV)
        else:
            # Flat protected-mode segments plus a guest TEB FS segment.
            def descriptor(base, limit, access, flags):
                return struct.pack('<Q', (limit & 0xffff) | ((base & 0xffffff) << 16)
                                   | (access << 40) | (((limit >> 16) & 15) << 48)
                                   | (flags << 52) | (((base >> 24) & 255) << 56))
            gdt = self.ENV + 0x10000
            self.cpu.mem_write(gdt, bytes(8) + descriptor(0,0xfffff,0x9b,0xc)
                               + descriptor(0,0xfffff,0x93,0xc) + descriptor(self.ENV,0x1ffff,0x93,0x4))
            self.cpu.reg_write(self.reg.UC_X86_REG_GDTR, (0,gdt,31,0))
            for name, value in [('CS',8),('DS',16),('ES',16),('SS',16),('FS',24),('GS',16)]:
                self.cpu.reg_write(getattr(self.reg,'UC_X86_REG_'+name), value)
        stack = self.STACK + 0xff000 - 8
        self.end = self.ENV + 0x1f000; self.putptr(stack, self.end)
        self.cpu.reg_write(self.sp, stack)
        for i, value in enumerate(self.args):
            if value is None: value = 0
            if type(value) is not int or not 0 <= value < (1 << self.bits):
                self.stop('native-argument-unresolved')
            if self.bits == 64 and i < 4:
                self.cpu.reg_write([self.reg.UC_X86_REG_RCX,self.reg.UC_X86_REG_RDX,self.reg.UC_X86_REG_R8,self.reg.UC_X86_REG_R9][i],value)
            else:
                self.putptr(stack + (0x28 + (i-4)*8 if self.bits == 64 else 4 + i*4),value)

    def arguments(self, count):
        sp = self.cpu.reg_read(self.sp)
        regs = [self.reg.UC_X86_REG_RCX,self.reg.UC_X86_REG_RDX,self.reg.UC_X86_REG_R8,self.reg.UC_X86_REG_R9]
        return [self.cpu.reg_read(regs[i]) if self.bits == 64 and i < 4 else
                self.readptr(sp + (0x28 + (i-4)*8 if self.bits == 64 else 4+i*4)) for i in range(count)]

    def api(self, library, name, count):
        args = self.arguments(count); low = name.lower(); wide = name.endswith('W')
        self.emit('native_api_call', api=library + '!' + name)
        if low in ('loadlibrarya','loadlibraryw','getmodulehandlea','getmodulehandlew'):
            result = self.module(self.text(args[0],wide))
            if not result:self.stop('native-library-not-modeled')
            return result
        if low == 'getprocaddress':
            if args[1] < 65536:self.stop('native-ordinal-import-not-modeled')
            requested = self.text(args[1])
            for address,(dll,api,_) in self.imports.items():
                if self.modules[dll] == args[0] and api == requested:return address
            self.stop('native-import-not-modeled')
        if low == 'virtualalloc':
            if args[0]:self.stop('native-fixed-allocation-not-modeled')
            return self.allocate(args[1])
        if low in ('exitthread','exitprocess','rtlexituserthread','rtlexituserprocess'):
            self.result=args[0];self.stop('guest-exit')
        if low == 'sleep':return 0
        if low.startswith('internetopen') and low not in ('internetopenurla',):
            return self.handle({'kind':'session','agent':self.text(args[0],wide)})
        if low.startswith('internetconnect'):
            if self.handles.get(args[0],{}).get('kind') != 'session':self.stop('native-session-unresolved')
            host = self.text(args[1],wide)
            if not host or re.search(r'[\s/@?#\\]',host) or not 0 <= args[2] <= 65535:
                self.stop('native-network-address-unresolved')
            if args[3] or args[4] or args[5] != 3:
                self.stop('native-connection-options-not-modeled')
            return self.handle({'kind':'connection','host':host,'port':args[2]})
        if low.startswith('httpopenrequest'):
            connection=self.handles.get(args[0],{})
            if connection.get('kind')!='connection':self.stop('native-connection-unresolved')
            secure=bool(args[6] & 0x800000);port=connection['port'];scheme='https' if secure else 'http'
            port = port or (443 if secure else 80)
            host=connection['host']
            if ':' in host and not host.startswith('['):host='['+host+']'
            authority=host if port == (443 if secure else 80) else host+':'+str(port)
            return self.handle({'kind':'request','method':self.text(args[1],wide) or 'GET',
                                'url':scheme+'://'+authority+'/'+self.text(args[2],wide).lstrip('/')})
        if low.startswith('httpsendrequest'):
            request=self.handles.get(args[0],{})
            if request.get('kind')!='request':self.stop('native-request-unresolved')
            self.emit('network_request',api='native:'+name,method=request['method'],url=request['url'])
            self.stop('network-response-unavailable')
        if low == 'internetopenurla':
            if self.handles.get(args[0],{}).get('kind') != 'session':self.stop('native-session-unresolved')
            url = self.text(args[1])
            parsed = urllib.parse.urlsplit(url)
            if parsed.scheme not in ('http','https') or not parsed.hostname or re.search(r'\s',url):
                self.stop('native-network-address-unresolved')
            if parsed.port is not None and not 1 <= parsed.port <= 65535:
                self.stop('native-network-address-unresolved')
            self.emit('network_request',api='native:'+name,method='GET',url=url)
            self.stop('network-response-unavailable')
        if low.startswith('internetsetoption'):
            if args[0] not in self.handles:self.stop('native-handle-unresolved')
            # No certificate or network operation is performed by this model.
            return 1
        if low == 'internetclosehandle':
            if args[0] not in self.handles:self.stop('native-handle-unresolved')
            del self.handles[args[0]];return 1
        if low in ('internetreadfile','httpqueryinfoa','recv'):
            self.stop('network-response-unavailable')
        self.stop('native-api-behavior-not-modeled')

    def instruction(self, cpu, address, size, user_data):
        self.steps += 1
        if self.steps > self.MAX_INSTRUCTIONS or time.monotonic() > self.deadline:
            self.stop('native-instruction-or-time-budget')
        if self.steps % 256 == 0:self.owner._tick()
        if address == self.end:
            self.result=cpu.reg_read(self.ax);self.stop('guest-return')
        if address in self.imports:
            library,name,count=self.imports[address];result=self.api(library,name,count)
            stack=cpu.reg_read(self.sp);destination=self.readptr(stack)
            cpu.reg_write(self.ax,result);cpu.reg_write(self.sp,stack+self.ptr+(count*4 if self.bits==32 else 0))
            cpu.reg_write(self.ip,destination)

    def forbidden(self, *args):
        self.stop('guest-system-instruction-blocked')

    def run(self):
        try:
            self.setup()
            self.cpu.hook_add(self.ucmod.UC_HOOK_CODE,self.instruction)
            self.cpu.hook_add(self.ucmod.UC_HOOK_INTR,self.forbidden)
            for op in (self.reg.UC_X86_INS_SYSCALL,self.reg.UC_X86_INS_SYSENTER):
                self.cpu.hook_add(self.ucmod.UC_HOOK_INSN,self.forbidden,None,1,0,op)
            self.reason='native-instruction-or-time-budget'
            self.cpu.emu_start(self.CODE,0,timeout=2000000,count=self.MAX_INSTRUCTIONS)
        except _NativeProfileStop:
            pass
        except self.ucmod.UcError as error:
            self.reason='guest-memory-or-instruction-fault'
            self.emit('unsupported_operation',api='native-cpu',reason=self.reason,error=str(error))
        except (ValueError,OverflowError,UnicodeError):
            self.reason='native-input-or-structure-unresolved'
        for address,size in self.buffers:
            raw=bytes(self.cpu.mem_read(address,size))
            if _has_bounded_pe_layout(raw):self.owner._remember_embedded_payload(raw,'native-guest-memory')
        self.emit('native_emulation',api='native-cpu',engine='unicorn',instructions=self.steps,
                  stop_reason=self.reason,memory_bytes=self.allocated,
                  return_value=self.result,
                  assumptions='synthetic Windows modules/TEB; zero-initialized guest memory/registers; no host API forwarding')
        return self.result if self.reason in ('guest-return','guest-exit') else _Unknown('<native-profile-result>')


class PowerShellEmulator:
    def __init__(self, source, origin="script.ps1", timeout_seconds=DEFAULT_TIMEOUT_SECONDS, include_payload_data=False):
        self.origin = _safe_text(origin, 512)
        source = str(source or "").lstrip("\ufeff")
        self.source_truncated = len(source) > MAX_SOURCE_CHARS
        self.source = str(source or "")[:MAX_SOURCE_CHARS]
        try:
            self.timeout_seconds = max(1, min(int(timeout_seconds or DEFAULT_TIMEOUT_SECONDS), MAX_TIMEOUT_SECONDS))
        except (TypeError, ValueError, OverflowError):
            self.timeout_seconds = DEFAULT_TIMEOUT_SECONDS
        self.started = time.monotonic()
        self.deadline = self.started + self.timeout_seconds

        self.variables = _VariableScopes()
        self._working_directory = None
        self._virtual_files = {}
        self._virtual_file_bytes = 0
        self._guid_counter = 0
        self.objects = {}
        self.functions = {}
        self._script_types = {}
        self._native_declared_types = {}
        self._script_instance_count = 0
        self._script_call_frames = []
        self.aliases = dict(_DEFAULT_COMMAND_ALIASES)
        self.events = []
        self._event_keys = set()
        self._unmodeled_command_count = 0
        self._unmodeled_command_examples = []
        self._unmodeled_static_count = 0
        self._unmodeled_static_examples = []
        self.errors = []
        self.decoded_layers = []
        self._dynamic_depth = 0
        self._dynamic_sources = set()
        self._dynamic_records = {}
        self.embedded_payloads = []
        self._embedded_payload_hashes = set()
        self.include_payload_data = bool(include_payload_data)
        self._exported_payload_bytes = 0
        self.step_count = 0
        self.statement_limit_hit = False
        self.timed_out = False
        self._stored_value_chars = 0
        self._pending_layers = 0
        self._layer_queue = deque()
        self._call_depth = 0
        self._process_depth = 0
        self._process_id = 0
        self._process_budget = {'count': 0}
        self._analyzed_file_contents = set()
        self._exploration_context = {}
        self._entry_arguments = None
        self._called_functions = set()
        self._native_allocated_bytes = 0
        self._native_region_count = 0
        self._expr_depth = 0
        self._reflection_fields = {}
        self._constant_members = {}
        self._numeric_cache = {}
        self.event_limit_hit = False

        # A handful of PowerShell "automatic variables" scripts commonly
        # reference; concrete-but-fake values keep expressions built from
        # them resolvable instead of collapsing to ``_Unknown``.
        self.variables["true"] = True
        self.variables["false"] = False
        self.variables["null"] = None
        self.variables["pshome"] = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0"
        self.variables["env:temp"] = "C:\\Users\\User\\AppData\\Local\\Temp"
        self.variables["env:tmp"] = "C:\\Users\\User\\AppData\\Local\\Temp"
        self.variables["env:appdata"] = "C:\\Users\\User\\AppData\\Roaming"
        self.variables["env:localappdata"] = "C:\\Users\\User\\AppData\\Local"
        self.variables["env:userprofile"] = "C:\\Users\\User"
        self.variables["env:computername"] = "DESKTOP-SANDBOX"
        self.variables["env:username"] = "User"
        self.variables["env:windir"] = "C:\\Windows"
        self.variables["env:systemroot"] = "C:\\Windows"
        self.variables["env:programdata"] = "C:\\ProgramData"
        self.variables["env:programfiles"] = "C:\\Program Files"
        self.variables["env:programfiles(x86)"] = "C:\\Program Files (x86)"
        self.variables["env:public"] = "C:\\Users\\Public"
        self.variables["env:homedrive"] = "C:"
        self.variables["env:homepath"] = "\\Users\\User"
        self.variables["env:comspec"] = "C:\\Windows\\System32\\cmd.exe"
        self.variables["env:allusersprofile"] = "C:\\ProgramData"

    # -- bookkeeping -------------------------------------------------------

    def _tick(self):
        self.step_count += 1
        if self.step_count > MAX_STATEMENTS:
            self.statement_limit_hit = True
            raise TimeoutError("PowerShell emulation statement budget exceeded")
        if time.monotonic() > self.deadline:
            self.timed_out = True
            raise TimeoutError("PowerShell emulation wall-clock budget exceeded")

    def _emit(self, category, **fields):
        if len(self.events) >= MAX_EVENTS:
            self.event_limit_hit = True
            return
        if self._process_id:
            fields['modeled_process_id'] = self._process_id
        fields.update(self._exploration_context)
        clean = {key: _safe_event_value(value) for key, value in fields.items()}
        key = (category, tuple(sorted((name, repr(value)) for name, value in clean.items())))
        if key in self._event_keys:
            return
        self._event_keys.add(key)
        self.events.append({
            "ts": round(time.monotonic() - self.started, 6),
            "category": category,
            **clean,
        })

    def _store_variable(self, name, value):
        key = _normalize_var_name(name)
        if not key or key == "null":
            return
        declarations, declared_key = self.variables.type_slot(key)
        cast = declarations.get(declared_key)
        if cast and not _is_unknown(value):
            value = self._apply_cast(cast, value)
            if cast.lower() in ('byte[]', 'system.byte[]') and isinstance(value, _BinaryValue):
                value = _ByteArray(value.data) if value.complete else _Unknown('<incomplete-byte-array>')
        mappings, stored_key = self.variables._target(key)
        old = mappings[0].get(stored_key)
        old_size = _value_size(old)
        new_size = _value_size(value)
        if old is None and len(self.variables) >= MAX_VARIABLES:
            self._emit("resource_limit", resource="variables", limit=MAX_VARIABLES)
            return
        projected = self._stored_value_chars - old_size + new_size
        if projected > MAX_TOTAL_VALUE_CHARS:
            value = _Unknown(f"<{key}:value-budget-exceeded>")
            new_size = len(str(value))
            projected = self._stored_value_chars - old_size + new_size
            self._emit("resource_limit", resource="stored_value_chars", limit=MAX_TOTAL_VALUE_CHARS)
        self.variables[key] = value
        self._stored_value_chars = max(projected, 0)

    @contextmanager
    def _function_scope(self):
        parent = self.variables
        self.variables = parent.new_child()
        local = self.variables.maps[0]
        try:
            yield
        finally:
            self.variables = parent
            self._stored_value_chars = max(0, self._stored_value_chars - sum(_value_size(v) for v in local.values()))

    def _bind_parameters(self, param_names, args, named_args, params_text=''):
        defaults = {}
        types = {}
        for part in _split_top_level(params_text, ','):
            match = re.search(rf'({_VAR_REF})\s*=(?!=)\s*(.+)$', part.strip(), re.S)
            if match:
                defaults[_normalize_var_name(match[1])] = match[2]
            declaration = re.fullmatch(rf'\s*\[([\w.]+(?:\[\])?)\]\s*({_VAR_REF})(?:\s*=\s*.*)?', part, re.S)
            if declaration:
                types[_normalize_var_name(declaration[2])] = declaration[1]
        position = 0
        for name in param_names:
            if named_args and name in named_args:
                value = named_args[name]
            elif position < len(args):
                value = args[position]
                position += 1
            elif name in defaults:
                value = self._eval_expr(defaults[name])
            else:
                value = None
            if name in types:
                declarations, key = self.variables.type_slot(name)
                declarations[key] = types[name]
            self._store_variable(name, value)
        self._store_variable('args', list(args[position:]))

    # -- expression evaluation ----------------------------------------------

    def _eval_command_arg(self, text):
        """Evaluate a single command-syntax argument *value*
        (``-Method POST``, ``-WindowStyle Hidden``, or a bare positional
        argument like the ``/script`` in ``Invoke-Request /script -Type
        String``) rather than a full pipeline statement. A token here
        that doesn't even start with something an expression could
        plausibly begin with (``$``/quote/``(``/``@``/``[``/a digit) is a
        real PowerShell string literal -- unlike a bareword at
        *statement* position (a real command invocation, which
        ``_eval_expr``'s fallback correctly treats as an attempted call),
        an enum-like value or a path-shaped positional argument has no
        such meaning and would otherwise get misread as a call to a
        nonexistent command, always collapsing to ``_Unknown`` instead of
        the plain string PowerShell would actually bind (breaking things
        like the HTTP method, or a REST route segment, on a captured C2
        beacon request).
        """
        stripped = str(text or "").strip()
        first = stripped[:1]
        looks_numeric = _numeric_literal(stripped) is not None
        if stripped and first not in "$'\"(@[" and not looks_numeric:
            return stripped
        return self._eval_expr(text)

    def _run_foreach_object_stage(self, value, body_text):
        """Run a ``ForEach-Object``/``%`` pipe stage for real: once per
        item in ``value`` with ``$_`` bound, collecting each item's
        result. Shared by ``_eval_pipeline_expr`` (a pipeline used as an
        expression value) and ``_process_pipeline`` (a bare pipeline
        *statement* -- ``@(...) | ForEach-Object { & $_ $script }``, the
        near-universal "try each of these scriptblocks until one works"
        execution-fallback shape, needs the exact same real per-item
        execution or the scriptblocks inside it never actually run).
        """
        if body_text[:1] == "{" and body_text[-1:] == "}":
            body_text = body_text[1:-1]
        compact = re.sub(r'\s+', '', _strip_comments(body_text)).lower().strip(';')
        compact = re.sub(r'^\[int\](\$\w+)=\$_;',r'\1=[int]$_;',compact)
        rotation = re.fullmatch(
            r'\$(?P<c>\w+)=\[int\]\$_;if\(\$(?P=c)-ge65-and\$(?P=c)-le90\)'
            r'\{\[char\]\(65\+\(\(\$(?P=c)-65\+(?P<n>\d{1,2})\)%26\)\)\}'
            r'elseif\(\$(?P=c)-ge97-and\$(?P=c)-le122\)'
            r'\{\[char\]\(97\+\(\(\$(?P=c)-97\+(?P=n)\)%26\)\)\}'
            r'else\{\[char\]\$(?P=c)\}', compact)
        if (rotation and int(rotation['n']) < 26 and isinstance(value,list)
                and all(isinstance(c,str) and len(c)==1 for c in value)):
            out = []
            for i, char in enumerate(value):
                if i % 4096 == 0:
                    self._tick()
                code = ord(char)
                base = 65 if 65 <= code <= 90 else 97 if 97 <= code <= 122 else None
                out.append(chr(base+(code-base+int(rotation['n']))%26) if base is not None else char)
            if value:
                self._store_variable(rotation['c'],ord(value[-1]))
            return out
        if isinstance(value, list):
            items = value
        elif isinstance(value, _BinaryValue):
            # ``[Convert]::FromBase64String($x) | %{[char]($_ -bxor N)}``
            # -- a real ``byte[]`` piped through ``ForEach-Object``
            # iterates one integer per byte in real PowerShell, not the
            # whole buffer as a single opaque item; this is the single
            # most common per-byte XOR/transform idiom that doesn't
            # happen to match one of ``_try_fast_for_loop``'s recognized
            # literal shapes (a static-method result piped directly,
            # rather than assigned to a variable first).
            items = list(value.data) if value.complete else [_Unknown('<incomplete-byte-array>')]
        else:
            items = [] if value is None else [value]
        results = []
        for item in items[:MAX_LOOP_ITERATIONS]:
            self._tick()
            self._store_variable("_", item)
            results.append(self._run_scriptblock_body(body_text))
        return results

    def _run_where_object_stage(self, value, cond_text):
        """``Where-Object``/``?`` -- genuinely evaluates the filter
        scriptblock per item (``$_`` bound), unlike ``Sort-Object``
        (still a pass-through: reordering needs a real comparison this
        emulator has no grounds to trust). An item is dropped ONLY when
        its condition resolves to a definite, known falsy value; an
        ``_Unknown`` result -- the condition itself couldn't be
        evaluated -- keeps the item rather than guessing it doesn't
        match, since silently losing a real candidate (the one
        genuinely resolvable item in a synthetic list, most commonly)
        is worse than one over-inclusive result downstream still has to
        resolve through. This is what makes ``.GetMethods() |
        Where-Object {$_.Name -like "*X*"}`` -- the wildcard-search
        alternative to a literal ``.GetMethod('X')`` call -- actually
        find the real match instead of returning the unfiltered list
        (which ``Select-Object -First 1`` would then blindly take the
        wrong element from).
        """
        if cond_text[:1] == "{" and cond_text[-1:] == "}":
            cond_text = cond_text[1:-1]
        if not isinstance(value, list):
            return value
        kept = []
        for item in value[:MAX_LOOP_ITERATIONS]:
            self._tick()
            self._store_variable("_", item)
            result = self._run_scriptblock_body(cond_text)
            if _is_unknown(result) or _truthy(result):
                kept.append(item)
        if len(kept) == 1 and isinstance(kept[0], _ObjectRef) and kept[0].kind == "reflection.assembly":
            return kept[0]
        return kept

    def _run_select_object_stage(self, value, args_text):
        """Select from known pipeline items, then expand a concrete property.

        This models values after upstream collection; upstream early-stop
        scheduling is not modeled. Unsupported options must not silently
        preserve the input as if selection had succeeded.
        """
        parameters = ('first', 'last', 'skip', 'skiplast', 'expandproperty', 'wait')
        positional, named = self._parse_command_syntax(
            args_text, parameter_names=parameters, switch_params=('wait',))

        def unresolved(reason):
            self._emit('unsupported_operation', api='Select-Object', reason=reason)
            return _Unknown('<select-object-unresolved>')

        if positional or set(named) - set(parameters):
            return unresolved('selection-options-not-modeled')
        if _is_unknown(value):
            return unresolved('pipeline-input-unresolved')
        if 'skiplast' in named and ('first' in named or 'last' in named):
            return unresolved('incompatible-selection-parameters')
        counts = {}
        for key in ('first', 'last', 'skip', 'skiplast'):
            if key in named:
                count = self._eval_expr(named[key])
                if type(count) is not int or not 0 <= count <= 2147483647:
                    return unresolved('selection-count-unresolved-or-invalid')
                counts[key] = count
        if isinstance(value, _BinaryValue):
            if not value.complete:
                return unresolved('pipeline-input-unresolved')
            items = list(value.data)
        else:
            items = value if isinstance(value, list) else ([] if value is None else [value])
        skip = counts.get('skip', 0)
        if 'last' in counts and 'first' not in counts:
            items = items[:-skip] if skip else items
        else:
            items = items[skip:]
        if counts.get('skiplast', 0):
            items = items[:-counts['skiplast']]
        if 'first' in counts and 'last' in counts:
            front = min(counts['first'], len(items))
            back = max(front, len(items) - counts['last'])
            items = items[:front] + items[back:]
        elif 'first' in counts:
            items = items[:counts['first']]
        elif 'last' in counts:
            items = items[-counts['last']:] if counts['last'] else []
        if 'expandproperty' in named:
            member = self._eval_command_arg(named['expandproperty'])
            if not isinstance(member, str) or not re.fullmatch(r'[\w]+', member):
                return unresolved('expanded-property-name-not-modeled')
            expanded = []
            for item in items:
                self._tick()
                prop = self._apply_property(item, member)
                if _is_unknown(prop):
                    return unresolved('expanded-property-unresolved')
                if isinstance(prop, _BinaryValue):
                    if not prop.complete:
                        return unresolved('expanded-property-unresolved')
                    prop = list(prop.data)
                if isinstance(prop, list):
                    expanded.extend(prop)
                elif prop is not None:
                    expanded.append(prop)
                if len(expanded) > MAX_LOOP_ITERATIONS:
                    self._emit('resource_limit', resource='select_expanded_items', limit=MAX_LOOP_ITERATIONS)
                    return _Unknown('<select-expansion-limit>')
            items = expanded
        return items[0] if len(items) == 1 else items

    def _eval_pipeline_expr(self, pipe_parts):
        """A pipeline used as an expression value (see ``_eval_expr``'s
        check for it). Evaluates the first stage for real, then applies
        every stage verb this emulator recognizes.

        ``ForEach-Object``/``%`` genuinely runs its scriptblock once per
        item with ``$_`` bound (see below) -- unlike a filter, skipping
        it doesn't just lose precision, it structurally breaks the
        pipeline (``[char[]]$s | % { [byte][char]$_ }`` is a real,
        common byte-conversion step; passing the char array through
        unconverted silently corrupts every XOR/hex transform built on
        top of it).

        Every other recognized verb (``Sort-Object``, ``Where-Object``,
        ``Select-Object``, ...) is a harmless pass-through instead: it
        never actually filters/reorders the synthetic list a stage like
        ``Get-ChildItem`` produces, but passing the value through
        unchanged is an honest "don't know which items survive" rather
        than a guessed, possibly-wrong subset -- what matters for IOC
        extraction is that ``[0]``/``.FullName`` on the far side still
        resolves to something real instead of collapsing the whole
        chain to ``_Unknown``.
        """
        value = self._eval_expr(pipe_parts[0])
        for stage in pipe_parts[1:]:
            stage = stage.strip()
            # ``%{[char]($_-bxor63)}`` -- ``%``/``foreach``'s scriptblock
            # argument routinely has *no* space before its ``{`` in
            # minified/obfuscated code, the single most common shape in
            # practice. A plain ``^\S+`` verb match swallowed the whole
            # ``%{...}`` (brace included) as one opaque "verb" that never
            # matched anything below, silently dropping the entire
            # per-item transform. ``(?=\s|\{|$)`` (matching every other
            # verb-boundary check in this file) fixes this consistently.
            verb_match = re.match(r"^\S+?(?=\s|\{|$)", stage) or re.match(r"^\S+", stage)
            verb = verb_match.group(0).lower() if verb_match else ""
            if verb in ("foreach-object", "foreach", "%"):
                value = self._run_foreach_object_stage(value, stage[verb_match.end():].strip())
                continue
            if verb in ("select-object", "select"):
                value = self._run_select_object_stage(value, stage[verb_match.end():].strip())
                continue
            if verb in ("where-object", "where", "?"):
                value = self._run_where_object_stage(value, stage[verb_match.end():].strip())
                continue
            if verb == 'get-random':
                positional, named = self._parse_command_syntax(stage[verb_match.end():].strip())
                if positional or set(named) - {'count'}:
                    return _Unknown('<random-pipeline-options-not-modeled>')
                count = self._eval_expr(named['count']) if 'count' in named else 1
                value = self._select_random_model(value, count, 'Get-Random(pipeline)')
                continue
            if verb in ("iex", "invoke-expression"):
                value = self._invoke_dynamic_layer(value, "pipeline|IEX")
                continue
            if stage.startswith('&'):
                value = self._invoke_computed_pipeline(stage, value)
                continue
            if verb in (
                "sort-object", "sort",
                "measure-object", "measure", "group-object", "group",
                "tee-object", "format-list", "format-table", "fl", "ft",
            ):
                continue
            return _Unknown(f"<pipeline:{_safe_text(stage, 60)}>")
        return value

    def _eval_expr(self, expression):
        # Thin depth-tracking wrapper around the real implementation
        # (renamed ``_eval_expr_inner`` just below) -- see
        # ``MAX_EXPR_DEPTH``'s comment for why this exists as a blanket
        # circuit-breaker rather than something specific to one recursive
        # pattern.
        numeric_constant = isinstance(expression, str) and len(expression) <= 1024 and bool(re.fullmatch(r"[\s0-9()+*/%\-]+", expression))
        if numeric_constant and expression in self._numeric_cache:
            self._tick()
            return self._numeric_cache[expression]
        self._expr_depth += 1
        try:
            if self._expr_depth > MAX_EXPR_DEPTH:
                return _Unknown("<expression-too-deep>")
            handled, value = self._eval_numeric_expression(expression)
            if not handled:
                value = self._eval_expr_inner(expression)
            if isinstance(value, int) and value.bit_length() > MAX_INTEGER_BITS:
                self._emit("resource_limit", resource="integer_bits", limit=MAX_INTEGER_BITS)
                return _Unknown("<integer-size-limit>")
            if numeric_constant and type(value) in (int, float):
                if len(self._numeric_cache) >= 256:
                    self._numeric_cache.pop(next(iter(self._numeric_cache)))
                self._numeric_cache[expression] = value
            return value
        finally:
            self._expr_depth -= 1

    def _select_random_model(self, selection, count, api):
        items = selection if isinstance(selection, list) else [selection]
        if type(count) is not int or count < 1 or any(_is_unknown(item) for item in items):
            return _Unknown('<random-selection-input>')
        self._emit('modeled_random', api=api, input_count=len(items), selected_count=min(count, len(items)),
                   representation='deterministic-input-order')
        chosen = items[:min(count, len(items))]
        return chosen[0] if len(chosen) == 1 else chosen

    def _invoke_computed_pipeline(self, stage, value):
        rest = stage[1:].strip()
        parts = _split_top_level_ws(rest)
        target_text = parts[0] if parts else ''
        args_text = rest[len(target_text):].strip()
        target = self._eval_command_arg(target_text) if target_text else None
        name = target.lower() if isinstance(target, str) else ''
        seen = set()
        while name in self.aliases and name not in seen:
            seen.add(name)
            name = self.aliases[name].lower()
        if name in seen or name in self.functions:
            name = ''  # Function pipeline binding is not a builtin invocation.
        if name in ('iex', 'invoke-expression') and not args_text:
            return self._invoke_dynamic_layer(value, 'pipeline|IEX')
        if name in ('select-object', 'select'):
            return self._run_select_object_stage(value, args_text)
        self._emit('unresolved_dynamic_code', api='pipeline|call-operator', reason='pipeline-command-not-modeled')
        return _Unknown('<pipeline-command>')

    def _eval_numeric_expression(self, expression):
        """Evaluate proven scalar arithmetic from tokens, never host code.

        Strings, arrays, methods and assignments use the normal evaluator.
        Reusing the token plan avoids re-parsing every nested sum in noise
        loops without changing their arithmetic or raising the step budget.
        """
        if not isinstance(expression, str) or len(expression) > 4096 or not any(op in expression for op in "+-*/%"):
            return False, None
        program = _numeric_rpn(expression)
        if program is None:
            return False, None
        values = {}
        for token in program:
            if isinstance(token, tuple) and token[0] == "variable":
                name = token[1]
                value = {"null": None, "true": True, "false": False}.get(name) if name in ("null", "true", "false") else self.variables.get(name)
                if value is not None and type(value) not in (int, float, bool):
                    return False, None
                values[name] = value
        stack = []
        self._tick()
        for index, token in enumerate(program):
            if index and index % 128 == 0:
                self._tick()
            if isinstance(token, tuple):
                value = values[token[1]] if token[0] == "variable" else token[1]
            else:
                right = stack.pop()
                left = 0 if token.startswith("u") else stack.pop()
                try:
                    left, right = _numeric_coerce(left), _numeric_coerce(right)
                    if token in ("+", "u+"): value = left + right
                    elif token in ("-", "u-"): value = left - right
                    elif token == "*": value = left * right
                    elif token == "/": value = left / right
                    else: value = left % right
                except (TypeError, ValueError, ArithmeticError):
                    # Fall back for the interpreter's existing unresolved
                    # arithmetic handling, including division by zero.
                    return False, None
            if isinstance(value, int) and value.bit_length() > MAX_INTEGER_BITS:
                return False, None
            stack.append(value)
        return True, stack[0]

    def _eval_expr_inner(self, expression):
        self._tick()
        expr = str(expression or "").strip()
        if not expr:
            return ""
        expr = _strip_backtick_noop_outside_strings(expr)

        unwraps = 0
        while _fully_wrapped(expr, "(", ")") and unwraps < MAX_PARENTHESES_UNWRAP:
            expr = expr[1:-1].strip()
            unwraps += 1
        if unwraps >= MAX_PARENTHESES_UNWRAP:
            return _Unknown("<parentheses-depth-exceeded>")
        assignment = _ASSIGN_RE.match(expr)
        if assignment:
            self._process_statement(expr)
            return self._read_variable(assignment[1])

        # Fuse this exact full-string reversal idiom instead of allocating
        # millions of index integers and character objects. PowerShell indexes
        # UTF-16 code units, so non-ASCII text must not reverse Unicode scalars.
        reverse_join = re.fullmatch(
            r'''(?P<v>\$\w+)\s*\[\s*-1\s*\.\.\s*-\s*(?:\$\(\s*(?P=v)\s*\.\s*Length\s*\)|(?P=v)\s*\.\s*Length)\s*\]\s*-join\s*(?:''|"")''',
            expr, re.I)
        if reverse_join:
            value = self._read_variable(reverse_join['v'])
            if isinstance(value, str):
                if len(value) > MAX_VALUE_CHARS:
                    self._emit('resource_limit', resource='string_reversal', limit=MAX_VALUE_CHARS)
                    return _Unknown('<string-reversal-limit>')
                if value.isascii():
                    return value[::-1]
                raw = value.encode('utf-16-le', errors='surrogatepass')
                reversed_units = bytearray(len(raw))
                reversed_units[0::2] = raw[0::2][::-1]
                reversed_units[1::2] = raw[1::2][::-1]
                return reversed_units.decode('utf-16-le', errors='surrogatepass')

        # ``($files | Sort-Object Length -Descending)[0].FullName`` -- a
        # pipeline used as a *sub-expression*, not a whole statement (see
        # ``_process_pipeline`` for the statement-level case). Checked
        # after the fully-wrapped unwrap loop above so a pipeline that
        # was the *entire* parenthesized expression (``(A | B)``, no
        # trailing suffix) is exposed at top level here too, not just
        # the "paren immediately followed by a suffix" shape handled
        # separately below. Safe to check unconditionally: ``|`` at
        # expression level always means pipeline in PowerShell
        # (bitwise-or is the word operator ``-bor``), so this can never
        # misfire on a legitimate operator.
        pipe_parts = _split_top_level(expr, "|")
        if len(pipe_parts) > 1:
            return self._eval_pipeline_expr(pipe_parts)
        # Call-operator arguments use command syntax: curl's -F is not
        # PowerShell's format operator, and commas belong to the arguments.
        if expr.startswith('&'):
            return self._eval_call_operator(expr[1:].strip())
        if expr.startswith('.') and len(expr) > 1 and expr[1] in " \t('\"":
            return self._eval_call_operator(expr[1:].strip(), dot_source=True)
        # Once a command name is followed by argument syntax, commas
        # belong to its argument values. Splitting them as an expression
        # array first silently truncated Start-Process -ArgumentList.
        command = re.match(rf'^({_COMMAND_IDENT_BACKTICK}(?:-{_COMMAND_IDENT_BACKTICK})*(?:\.(?:exe|com))?)(\s+.+)$', expr, re.I | re.S)
        if command and _numeric_literal(command[1]) is None:
            name = _strip_backtick_noop(command[1])
            if name.lower() == 'new-object':
                return self._eval_new_object(_NEW_OBJECT_RE.match(expr))
            if not _is_unknown_looking_bareword(name):
                return self._eval_command_expression(name, command[2])

        if _fully_wrapped(expr, "@(", ")"):
            inner = expr[2:-1]
            if not inner.strip():
                return []
            if inner.lstrip().startswith(","):
                return self._eval_expr(inner)
            if len(inner) > 1024 and re.fullmatch(r"[0-9,\s]+", inner):
                parts = inner.split(",")
                if len(parts) <= MAX_EMBEDDED_PAYLOAD_BYTES and all(re.fullmatch(r"\s*\d{1,3}\s*", p) and int(p) <= 255 for p in parts):
                    result = []
                    for offset in range(0, len(parts), 4096):
                        self._tick()
                        result.extend(int(p) for p in parts[offset:offset + 4096])
                    return result
            items = _split_top_level(inner, ",")
            if len(items) <= MAX_VARIABLES:
                statements = _split_statements(_strip_comments(inner))
                if len(statements) > 1:
                    collected = []
                    for statement in statements:
                        value = self._process_statement(statement)
                        if value is not None or statement.strip().lower() == '$null':
                            collected.extend(value if isinstance(value, list) else [value])
                        if len(collected) > MAX_VARIABLES:
                            self._emit('resource_limit', resource='array_output', limit=MAX_VARIABLES)
                            return _Unknown('<array-output-limit>')
                    return collected
                # Array subexpressions collect pipeline output. Wrapping an
                # already enumerated pipeline in another list turns a URL
                # collection into one bogus, concatenated request target.
                value = self._eval_expr(inner)
                return value if isinstance(value, list) else [value]
            return _Unknown(expr)

        # ``@{ Ip = $r.ip; Cc = $r.country_code }`` -- a hashtable
        # literal, an extremely common way to bundle up a beacon's POST
        # fields/headers right before they're actually sent. Represented
        # as a plain Python dict (lowercase keys, matching PowerShell's
        # own case-insensitive member lookup) so ``$table.Ip``/
        # ``$table["Ip"]`` (see ``_apply_property``/``_apply_index``)
        # resolve to real values instead of collapsing the whole
        # exfiltration payload to ``_Unknown``.
        if expr[:2] == "@{":
            body, end = _extract_balanced(expr, 1, "{", "}")
            if body is not None and end == len(expr) - 1:
                table = {}
                for entry in _split_statements(_strip_comments(body)):
                    eq_pos = _find_top_level_assign(entry)
                    if eq_pos is None:
                        continue
                    key_text = entry[:eq_pos].strip().strip("'\"")
                    if not key_text:
                        continue
                    table[key_text.lower()] = self._eval_expr(entry[eq_pos + 1:])
                return table

        # ``@curlArgs`` -- the splat operator (expand ``$curlArgs``'s
        # elements as individual arguments), distinct from the ``@(...)``
        # array-literal syntax just above by the absence of a paren.
        splat_match = re.fullmatch(rf"@({_COMMAND_IDENT})", expr)
        if splat_match:
            return self._read_variable("$" + splat_match.group(1))

        # Binary-operator splitting runs *before* any atom-specific parsing
        # below (string/here-string/number/variable/static-member/cast/
        # new-object/paren-suffix/scriptblock-literal): it only does
        # text-level pattern matching (respecting quotes and bracket depth
        # via ``_top_level_matches``), never requires an atom to already be
        # identified, and every one of those atom branches would otherwise
        # have to independently remember to bail out to it whenever what
        # follows isn't a plain ``.``/``[`` suffix chain -- e.g. ``"{0}" -f
        # $x`` or ``$a + $b`` misparsed as "atom with a junk suffix"
        # instead of a binary expression. Concretely: ``(A)[$i] -bxor
        # (B)[$j]`` must split on ``-bxor`` here first, or the
        # paren-suffix branch below greedily treats ``[$i] -bxor (B)[$j]``
        # as one long (invalid) suffix chain on ``(A)`` and leaves the
        # whole right-hand side stuck as unparsed leftover text. Trying
        # every tier here first, once, is both simpler and strictly safer.
        binary = self._split_binary_operator(expr)
        if binary:
            # Peels every top-level split in this chain *iteratively*
            # instead of recursing into ``self._eval_expr(left_text)``
            # once per term: ``_split_binary_operator`` always finds the
            # *last* (rightmost) top-level operator, so the original
            # recursive form -- ``_apply_binary_op(op, self._eval_expr
            # (left_text), right_text)`` -- peels one term off the right
            # per recursive call, costing one real Python stack frame
            # per term in the chain. A long homogeneous ``+``-joined
            # chain (hundreds of terms concatenating a beacon URL's
            # fields, a real and not even especially exotic obfuscation
            # shape) blew straight through Python's default 1000-frame
            # recursion limit and crashed the *entire* emulation with an
            # unhandled ``RecursionError`` -- confirmed against 3 real
            # samples. Collecting every ``(operator, right_text)`` pair
            # right-to-left first, then replaying them left-to-right
            # over a single accumulator, computes the exact same result
            # (each step still calls ``_apply_binary_op`` exactly as
            # before, and the innermost leftover atom is still evaluated
            # through the normal ``self._eval_expr`` path below) with
            # ``O(1)`` stack depth for this loop regardless of chain
            # length -- only genuine nesting (parens, ``$(...)``, method
            # chains) still recurses, which real source rarely takes
            # anywhere near this deep.
            pending = []
            step = binary
            current_left = expr
            while step:
                # Each iteration re-scans ``current_left`` from scratch
                # (``_split_binary_operator`` -> ``_top_level_positions``
                # is O(len(current_left))), so a long chain over a huge
                # expression is quadratic overall -- and unlike the
                # recursive form this loop replaced (where every nested
                # ``_eval_expr`` call means every level got its own
                # ``self._tick()``), nothing here previously re-checked
                # the wall-clock/statement budget mid-loop, so a
                # pathological chain (confirmed against a real ~500KB
                # single-expression sample, an 86-link chain that alone
                # burned multiple GB and several seconds with the outer
                # budget never getting a chance to fire) ran to
                # completion no matter how long it took. Ticking here
                # restores that per-link checkpoint.
                self._tick()
                current_left, current_operator, current_right = step
                pending.append((current_operator, current_right))
                step = self._split_binary_operator(current_left)
            result = self._eval_expr(current_left)
            for operator, right_text in reversed(pending):
                result = self._apply_binary_op(operator, result, right_text)
            return result

        # A parenthesized sub-expression immediately followed by a member/
        # method chain -- ``(New-Object Net.WebClient).DownloadString(...)``
        # -- as opposed to the whole-expression-is-one-paren-group case
        # already unwrapped above, where nothing trails the matching ``)``.
        # Without this, the balanced group is never evaluated and the
        # entire expression falls through to the raw-source ``_Unknown``
        # fallback -- exactly the shape ``IEX (New-Object ...).Download
        # String(...)`` needs to resolve.
        if expr[:1] == "(":
            inner, end_index = _extract_balanced(expr, 0, "(", ")")
            if inner is not None:
                suffix = expr[end_index + 1:].strip()
                if suffix and suffix[0] in (".", "["):
                    return self._eval_suffix(self._eval_expr(inner), suffix)
                if suffix.startswith("::"):
                    return self._eval_type_suffix(self._eval_expr(inner), suffix)

        # ``$(...)`` -- the subexpression operator: runs a real statement
        # list (not just one expression -- ``$( $x = 1; $x + 1 )`` is
        # legal) and yields its last value. Distinct from string
        # interpolation's own ``$(...)`` handling in ``_interpolate``
        # (that one only fires *inside* an already-decoded double-quoted
        # string); this is the same construct used as a bare value --
        # ``Set-Alias -Name $([string]::Concat(...))``, extremely common
        # specifically to keep a computed name/value out of one obvious
        # static string token. Checked here, *after* the binary-operator
        # split above (same reasoning as the plain-paren case just
        # above: ``$(...).Insert(...)+$(...)`` must split on the
        # top-level ``+`` first, or ``_eval_suffix``'s ``.``/``[``-only
        # chain -- reached directly, before any operator got a chance to
        # separate it from the trailing ``+$(...)`` -- greedily eats the
        # unrecognized operator text too and wraps the *whole* already-
        # correctly-resolved value in ``_Unknown`` right along with it).
        if expr[:2] == "$(":
            body, end_index = _extract_balanced(expr, 1, "(", ")")
            if body is not None:
                suffix = expr[end_index + 1:].strip()
                if not suffix:
                    return self._run_scriptblock_body(body)
                if suffix[0] in (".", "["):
                    return self._eval_suffix(self._run_scriptblock_body(body), suffix)
                if suffix[:2] == "::":
                    # ``$(EXPR)::Member(...)`` -- a dynamically-named
                    # static-member call, real PowerShell syntax whenever
                    # ``$(EXPR)`` resolves to a ``[Type]``: the
                    # subexpression spelling of the same dynamic-type-
                    # name trick ``[Type]::GetType("...")`` and
                    # ``"..." -as [Type]`` both reach for, used here
                    # specifically to keep the type name out of any one
                    # bracket-literal token in the source.
                    member_match = re.match(r"^::\s*(\w+)(.*)$", suffix, re.DOTALL)
                    # ``$(TYPE)::$(MEMBER)(...)`` -- the member name
                    # *itself* can be just as dynamic as the type name
                    # (mirrors ``[Type]::($(memberExpr))(...)``'s own
                    # dynamic-member handling elsewhere in this method,
                    # spelled with ``$(...)`` instead of a bare ``(...)``
                    # after the ``::``).
                    dynamic_member_match = None if member_match else re.match(r"^::\s*\$\(", suffix)
                    if member_match or dynamic_member_match:
                        type_value = self._run_scriptblock_body(body)
                        type_name = (
                            type_value.state.get("type_key", "")
                            if isinstance(type_value, _ObjectRef) and type_value.kind == "reflection.type"
                            else ("" if _is_unknown(type_value) else str(type_value))
                        )
                        if type_name:
                            if member_match:
                                return self._eval_static_member(type_name, member_match.group(1), member_match.group(2))
                            member_expr, member_end = _extract_balanced(suffix, 3, "(", ")")
                            if member_expr is not None:
                                member_name = self._run_scriptblock_body(member_expr)
                                if isinstance(member_name, str) and member_name.strip() and not _is_unknown(member_name):
                                    return self._eval_static_member(type_name, member_name.strip(), suffix[member_end + 1:])

        # A scriptblock literal (``{ param($x) ... }``, most often assigned
        # to a variable and invoked later via ``&``/``.Invoke()``).
        if expr[:1] == "{":
            body, end_index = _extract_balanced(expr, 0, "{", "}")
            if body is not None:
                suffix = expr[end_index + 1:].strip()
                # A following comma belongs to an array expression, not to
                # this scriptblock's member chain. Let the comma parser below
                # preserve each callable element (including multiline arrays).
                if not suffix or suffix[0] in (".", "["):
                    ref = _ObjectRef("scriptblock", {"source": body})
                    return self._eval_suffix(ref, suffix) if suffix else ref

        # ``$x = if ($cond) { A } else { B }`` -- PowerShell's
        # if-as-expression form (the executed branch's last statement
        # becomes the whole construct's value), as opposed to ``if`` at
        # *statement* position which every other branch/every
        # control-flow block gets flattened-and-both-run (see
        # ``_normalize_block_syntax``): here the condition is real and
        # only actually needed once, so it's evaluated for real and
        # only the matching branch runs, exactly like real PowerShell.
        if_branches = _try_parse_if_expression(expr)
        if if_branches is not None:
            for cond_text, body_text in if_branches:
                if cond_text is None or _truthy(self._eval_expr(cond_text)):
                    return self._run_scriptblock_body(body_text)
            return None

        for_expr_parts = _try_parse_for_expression(expr)
        if for_expr_parts is not None:
            return self._eval_for_expression(*for_expr_parts)

        if expr[:1] in ("'", '"'):
            end = _string_literal_end(expr)
            if end is None:
                return _Unknown("<unterminated-string>")
            if end >= 1:
                suffix = expr[end:].strip()
                if not suffix or suffix[0] in (".", "["):
                    token = expr[:end]
                    value = self._decode_and_interpolate(token)
                    return self._eval_suffix(value, suffix) if suffix else value

        if expr.startswith(("@\"", "@'")):
            closer = expr[1] + "@"
            end = expr.find(closer, 2)
            if end != -1:
                token = expr[:end + 2]
                suffix = expr[end + 2:].strip()
                if not suffix or suffix[0] in (".", "["):
                    raw = _decode_here_string(token)
                    value = self._interpolate(raw) if token[1] == '"' else raw
                    return self._eval_suffix(value, suffix) if suffix else value

        lower = expr.lower()
        if lower in ("$true", "$false"):
            return lower == "$true"
        if lower in ("$null", "$()"):
            return None

        number = _numeric_literal(expr)
        if number is not None:
            return number

        # Comma at top level (outside an @() array subexpression, handled
        # above, and outside any binary operator's own argument list,
        # already split off above) builds an array too -- PowerShell's own
        # array-literal rule.
        # A Remove-Item argument list belongs to one command. Splitting
        # it as an expression array would invoke only the first path.
        remove_command = re.match(r"^(?:&\s*)?(remove-item|ri|del|rm|erase)(?=\s|$)(.*)$", expr, re.IGNORECASE | re.DOTALL)
        if remove_command:
            return self._eval_command_expression(*remove_command.groups())
        if expr.startswith(","):
            return [self._eval_expr(expr[1:])]
        comma_parts = _split_top_level(expr, ",")
        if len(comma_parts) > 1:
            return [self._eval_expr(part) for part in comma_parts]

        var_match = re.match(rf"^({_VAR_REF})", expr)
        if var_match:
            name = var_match.group(1)
            raw_suffix = expr[var_match.end():]
            suffix = raw_suffix.strip()
            if suffix.startswith("::"):
                value = self._read_variable(name)
                return self._eval_type_suffix(value, suffix)
            if not suffix or suffix[0] in (".", "["):
                value = self._read_variable(name)
                return self._eval_suffix(value, suffix) if suffix else value
            if raw_suffix[:1] == "$":
                # ``-Uri $API$Path`` -- a run of ``$var`` references with
                # *nothing* between them (no space, no operator) in a
                # bareword/command-argument position. PowerShell's real
                # tokenizer treats this exactly like inside a double-
                # quoted string: each variable expands and the results
                # concatenate. Checked against the *unstripped* text
                # specifically so ``$a $b`` (real whitespace between two
                # separate tokens, an entirely different shape) is never
                # misread as concatenation.
                left_value = self._read_variable(name)
                right_value = self._eval_expr(raw_suffix)
                if _is_unknown(left_value) or _is_unknown(right_value):
                    return _Unknown(expr)
                return str(left_value) + str(right_value)

        type_literal = re.fullmatch(r"\[([A-Za-z_][\w.]*(?:\[\])?)\]", expr)
        if type_literal:
            return _ObjectRef("reflection.type", {"type_key": type_literal[1].lower().removeprefix("system.")})
        variable_static = re.match(rf"^\[([A-Za-z_][\w.]*(?:\[\])?)\]\s*(::\s*{_VAR_REF}.*)$", expr, re.DOTALL)
        if variable_static:
            return self._eval_type_suffix(_ObjectRef('reflection.type', {
                'type_key': variable_static[1].lower().removeprefix('system.')}), variable_static[2])
        static_match = re.match(r"^\[([A-Za-z_][\w.\[\],\s]*?)\]\s*::\s*(\w+)", expr)
        type_end = _extract_balanced(expr, 0, '[', ']')[1] if static_match else None
        if static_match and type_end is not None and expr[type_end+1:].lstrip().startswith('::'):
            type_name, member = static_match.groups()
            rest = expr[static_match.end():]
            return self._eval_static_member(type_name.strip(), member, rest)

        # ``[Convert]::(gv('f'+'nEs') -V)((gv('MoW'+'d') -Val))`` -- the
        # *member name* itself built at runtime (through the same
        # dynamic-variable-name trick ``Get-Variable`` reads use)
        # instead of a literal identifier after ``::``, keeping a
        # string like "FromBase64String" out of the source entirely.
        dynamic_static_match = re.match(r"^\[([A-Za-z_][\w.\[\],\s]*?)\]\s*::\s*\(", expr)
        type_end = _extract_balanced(expr, 0, '[', ']')[1] if dynamic_static_match else None
        if dynamic_static_match and type_end is not None and expr[type_end+1:].lstrip().startswith('::'):
            type_name = dynamic_static_match.group(1)
            member_expr, end = _extract_balanced(expr, dynamic_static_match.end() - 1, "(", ")")
            if member_expr is not None:
                member_name = self._eval_expr(member_expr)
                if isinstance(member_name, str) and member_name.strip() and not _is_unknown(member_name):
                    return self._eval_static_member(type_name.strip(), member_name.strip(), expr[end + 1:])

        # ``[Convert].GetMethod('FromBase64String', ...).Invoke($null,
        # @($z))`` -- a reflection-based static call, functionally
        # identical to ``[Convert]::FromBase64String($z)`` but written
        # to keep that literal method-name string out of a plain
        # ``::`` call site (a real AMSI/signature-evasion technique).
        # Distinguished from a *cast* (``[int]$x``, handled just below)
        # by what immediately follows the bracket: a cast operand is a
        # value expression, which never starts with a bare ``.member``.
        type_member_match = re.match(r"^\[([A-Za-z_][\w.]*(?:\[\])?)\]\s*(\.[A-Za-z_]\w*.*)$", expr, re.DOTALL)
        if type_member_match:
            type_name, suffix = type_member_match.groups()
            type_key = type_name.strip("'\"").lower().replace("system.", "", 1)
            return self._eval_suffix(_ObjectRef("reflection.type", {"type_key": type_key}), suffix.strip())

        factory_cast = re.match(r'^\[(?:System\.)?Func\[(?:System\.)?(object|string)\]\]\s*(.+)$', expr, re.I | re.S)
        if factory_cast:
            body = self._eval_expr(factory_cast[2])
            if isinstance(body, _ObjectRef) and body.kind == 'scriptblock':
                return _ObjectRef('managed.valuefactory', {'scriptblock': body, 'return_type': factory_cast[1].lower()})
            return _Unknown('<value-factory-input>')
        reference_match = re.fullmatch(rf"\[(?:ref|System\.Management\.Automation\.PSReference)\]\s*({_VAR_REF})", expr, re.I)
        if reference_match:
            key = _normalize_var_name(reference_match[1])
            mappings, name = self.variables._target(key)
            for mapping in mappings:
                stored_name = 'private:' + name if mapping is self.variables.maps[0] and 'private:' + name in mapping else name
                if stored_name in mapping:
                    types = next(self.variables._type_maps[index] for index, scope in enumerate(self.variables.maps)
                                 if scope is mapping)
                    return _ObjectRef('ps.reference', {'owner': mapping, 'name': stored_name, 'types': types})
            self._emit('unsupported_operation', api='[ref]', reason='reference-variable-not-defined')
            return _Unknown('<reference-variable>')
        cast_match = re.match(r"^\[([A-Za-z_][\w.]*(?:\[\])?)\]\s*(.+)$", expr, re.DOTALL)
        if cast_match:
            type_name, operand = cast_match.groups()
            return self._apply_cast(type_name.strip(), self._eval_expr(operand))

        new_object = _NEW_OBJECT_RE.match(expr)
        if new_object:
            return self._eval_new_object(new_object)

        # ``-join @($p1, $p2, $p3, $p4)`` -- ``-join``/``-split`` used as
        # a *unary* prefix operator (no left-hand operand, joining with
        # the empty string / splitting on whitespace) -- a real, common
        # PowerShell form distinct from the binary ``$array -join ","``
        # one ``_OPERATOR_TIERS`` already handles. Checked before the
        # generic unary-minus fallback right below, which would
        # otherwise misparse this as ``-`` applied to the bareword
        # "join" (an attempted call to a nonexistent command).
        join_split_match = re.match(r"^-(join|split)\b\s*(.+)$", expr, re.IGNORECASE | re.DOTALL)
        if join_split_match:
            operand = self._eval_expr(join_split_match.group(2))
            if join_split_match.group(1).lower() == "join":
                source = operand if isinstance(operand, list) else [operand]
                if any(_is_unknown(item) for item in source):
                    return _Unknown(expr)
                return _cap("".join(str(item) for item in source))
            return operand.split() if isinstance(operand, str) else _Unknown("<split>")

        if expr[:1] == "-" or lower.startswith("-not ") or expr[:1] == "!":
            unary = re.match(r"^(?:-not\s+|!\s*|-\s*)(.+)$", expr, re.IGNORECASE | re.DOTALL)
            if unary:
                operand = self._eval_expr(unary.group(1))
                if lower.startswith("-not") or expr[0] == "!":
                    if _is_unknown(operand):
                        return _Unknown('<boolean-negation>')
                    return not _truthy(operand)
                if isinstance(operand, (int, float)) and not isinstance(operand, bool):
                    return -operand

        # ``I`E`X`` (a trivial static-signature evasion, backticks are
        # no-ops in a bareword) needs its command *name* backtick-
        # stripped to resolve -- but running that same strip over the
        # *whole* expression first (the original approach) corrupted a
        # real, later backtick-escaped quote inside a string argument
        # (``-ArgumentList "/i `"$p`" ..."``), silently misreading where
        # that string ended. Matched against the untouched original text
        # instead, with the strip applied only to the captured name.
        path_call = re.match(r'^((?:\.\.?[\\/]|[A-Za-z]:[\\/])[^\s;"\x27<>|]*\.(?:exe|com))(?=\s|$)(.*)$', expr, re.I | re.S)
        if path_call:
            return self._eval_command_expression(path_call[1], path_call[2])
        call_match = re.match(rf"^({_COMMAND_IDENT_BACKTICK}(?:-{_COMMAND_IDENT_BACKTICK})*(?:\.(?:exe|com))?)(.*)$", expr, re.DOTALL | re.IGNORECASE)
        if call_match:
            name = _strip_backtick_noop(call_match.group(1))
            rest = call_match.group(2)
            if name and not _is_unknown_looking_bareword(name):
                return self._eval_command_expression(name, rest)

        return _Unknown(expr)

    def _eval_call_operator(self, rest, dot_source=False):
        """``& <target> <args>`` -- the call operator obfuscators reach for
        specifically because a concatenated/decoded string
        (``&('I'+'EX')``) can't be written as a bare cmdlet token.
        """
        # A computed quoted command can be immediately followed by its
        # argument group: .'iXXex'.Remove(1,2)($code). Keep the method's
        # arguments separate from the eventual command's arguments.
        if rest.startswith(("'", '"')):
            spans = _scan_ps_text(rest)
            cursor = spans[0][1] if spans and spans[0][0] == 0 else 0
            while cursor and cursor < len(rest):
                method = re.match(r"\.\w+\s*\(", rest[cursor:])
                if not method:
                    break
                _, end = _extract_balanced(rest, cursor + method.end() - 1)
                if end is None:
                    break
                cursor = end + 1
            if cursor and rest[cursor:cursor + 1] == "(":
                arguments, end = _extract_balanced(rest, cursor)
                if end == len(rest) - 1:
                    command = self._eval_expr(rest[:cursor])
                    if isinstance(command, str):
                        return self._eval_command_expression(command, "(" + arguments + ")")
        ws_parts = _split_top_level_ws(rest)
        if not ws_parts:
            return _Unknown("<call-operator>")
        target_text = ws_parts[0]
        remaining_text = rest[len(target_text):].lstrip()
        if (target_text[:1] not in "$'\"([{" and re.search(r'[\\/]', target_text)
                and re.fullmatch(r'[^\r\n<>|]*\.ps1', target_text, re.I)):
            return self._invoke_virtual_script(target_text, remaining_text, dot_source)
        if re.fullmatch(r"[A-Za-z0-9_][\w.-]*\.(exe|com|bat|cmd)", target_text, re.IGNORECASE):
            # ``& curl.exe @curlArgs`` -- a bareword target *with* a real
            # executable extension is unambiguously an external process
            # launch, never a PowerShell expression to evaluate first.
            # Running it through ``_eval_expr`` instead (the general
            # path below) truncated at the ``.`` and misread the
            # extension as member-access text -- worse, for a name like
            # ``curl``/``wget`` that also happens to be a real PowerShell
            # alias for ``Invoke-WebRequest``, the *bare* alias name left
            # over after truncation collided with that unrelated alias
            # and misclassified a real ``curl.exe`` process launch as a
            # web request instead.
            return self._record_native_command(target_text, remaining_text, '&')
        if re.fullmatch(rf"{_COMMAND_IDENT_BACKTICK}(?:-{_COMMAND_IDENT_BACKTICK})*", target_text):
            # ``& FunctionName arg1 arg2`` -- a bareword target with no
            # ``$``/``(``/quote prefix is a direct call by name, never an
            # expression to evaluate first. Routing it through
            # ``self._eval_expr(target_text)`` (as below, for the ``$sbVar``
            # / ``('I'+'EX')`` / ``(Get-Command X)`` cases) would itself
            # invoke the function -- via that method's own bareword
            # command-call fallback -- with *zero* arguments, since
            # ``target_text`` alone carries no visibility into
            # ``remaining_text``. That premature call already runs the
            # function (silently swallowing the real args) before any of
            # the branches below get a chance to redispatch with them.
            stripped_name = _strip_backtick_noop(target_text)
            if stripped_name and not _is_unknown_looking_bareword(stripped_name):
                return self._eval_command_expression(stripped_name, remaining_text, dot_source=dot_source)
        target = self._eval_expr(target_text)
        if isinstance(target, str) and re.fullmatch(r'[^\r\n<>|]*\.ps1', target, re.I):
            return self._invoke_virtual_script(target, remaining_text, dot_source)
        if isinstance(target, _ObjectRef) and target.kind == "scriptblock":
            positional, named = self._parse_command_syntax(remaining_text)
            args = [self._eval_expr(part) for part in positional]
            named_values = {key: self._eval_expr(text) for key, text in named.items()}
            return self._invoke_scriptblock(target, args, named_values, dot_source=dot_source)
        if isinstance(target, str) and (target.lower() in self.functions or re.fullmatch(rf"{_COMMAND_IDENT}(?:-{_COMMAND_IDENT})*", target)):
            return self._eval_command_expression(target, remaining_text, dot_source=dot_source)
        if (isinstance(target, str) and re.fullmatch(r'(?:[A-Za-z]:[\\/]|\.\.?[\\/])?[^\r\n<>|]*\.(?:exe|com|bat|cmd)', target, re.I)):
            return self._record_native_command(target, remaining_text, '&')
        if isinstance(target, str) and target.strip():
            # The call operator resolves one command name/path. It does
            # not parse an arbitrary string as an Invoke-Expression body.
            self._emit('unresolved_command', command=target, arguments=_safe_text(remaining_text),
                       reason='call-target-not-modeled')
            return _Unknown("<call-target>")
        self._emit('unresolved_command', api='dot-source' if dot_source else '&',
                   reason='call-target-unresolved', target_expression=_safe_text(target_text))
        return _Unknown("<call-operator>")

    def _decode_and_interpolate(self, token):
        if token[0] == '"':
            body = token[1:-1] if token.endswith('"') else token[1:]
            return self._interpolate(body, doubled_quotes=True)
        return _decode_ps_string(token)

    def _interpolate(self, text, doubled_quotes=False):
        """Expand variables and escapes in one pass over the raw body.

        An escaped dollar stays literal, including inside here-strings.
        Member access requires $(); `$name.exe` retains the literal suffix.
        """
        out = []
        index = 0
        length = len(text)
        escapes = {'n':'\n','r':'\r','t':'\t','0':'\0','a':'\a','b':'\b','f':'\f','v':'\v'}
        def stringify(value):
            if isinstance(value,list):
                separator = self.variables.get('ofs',' ')
                return str(separator).join('' if item is None else str(item) for item in value)
            return '' if value is None else str(value)
        while index < length:
            ch = text[index]
            if ch == '`' and index+1 < length:
                following = text[index+1]
                if following in '\r\n':
                    index += 3 if text[index+1:index+3] == '\r\n' else 2
                else:
                    out.append(escapes.get(following,following))
                    index += 2
                continue
            if doubled_quotes and text[index:index+2] == '""':
                out.append('"')
                index += 2
                continue
            if ch == "$" and index + 1 < length and text[index + 1] == "(":
                inner, end = _extract_balanced(text, index + 1, "(", ")")
                if inner is not None:
                    value = self._run_scriptblock_body(inner)
                    out.append(stringify(value))
                    index = end + 1
                    continue
            if ch == "$":
                match = re.match(_VAR_REF, text[index:])
                if match:
                    name = match.group(0)
                    value = self._read_variable(name)
                    consumed = match.end()
                    out.append(stringify(value))
                    index += consumed
                    continue
            out.append(ch)
            index += 1
        return _cap("".join(out))

    def _read_variable(self, raw_name):
        # Braces quote a literal variable name, including dots/brackets.
        # ${obj.Prop} is distinct from $obj.Prop or $($obj.Prop).
        key = _normalize_var_name(raw_name)
        if key in self.variables:
            return self.variables[key]
        if key.startswith("env:"):
            self._emit("environment_access", name=key[4:] or "<unknown>")
            return _Unknown(f"<env:{key[4:]}>")
        # A variable this script never assigns anywhere is genuinely
        # ``$null`` at real runtime, not an unknown/unresolvable value --
        # PowerShell reading an undeclared variable never errors, it just
        # yields null (``[string]$null`` -> ``""``, ``$null + 5`` -> ``5``,
        # ``$null -ne ''`` -> ``$true``). Marking it ``_Unknown`` instead
        # was observed cascading through an entire string-concatenation
        # chain built from ~20 ``+``-joined unresolved telemetry fields
        # (leftover template placeholders a real obfuscated sample never
        # populated) into one giant nested ``<unknown:<unknown:...>>``
        # blob that swallowed the one real, resolvable value in it (a
        # live C2 URL). Returning ``None`` -- this emulator's existing
        # ``$null`` representation, already handled correctly by
        # ``[string]`` casts, string concatenation, and ``-eq``/``-ne``
        # comparisons -- matches what real PowerShell would actually do.
        return None

    def _split_binary_operator(self, expr):
        top_level = _top_level_positions(expr)
        if "://" in expr:
            # Slashes and hyphens within a URL argument are data. In
            # particular http://160... must not become division by 160.
            # Copy the cached mask; other consumers still need its original.
            mask = bytearray(top_level.mask)
            for url in re.finditer(r"https?://[^\s'\"<>]+", expr, re.IGNORECASE):
                mask[url.start():url.end()] = b"\0" * (url.end() - url.start())
            top_level = _PositionMask(mask)
        for tier in _OPERATOR_TIERS:
            if tier is _PLUS_MINUS_RE:
                patterns = [tier]
                if expr.startswith(('$', '[')):
                    patterns.append(_VARIABLE_ADD_SUB_RE)
                match = None
                for pattern in patterns:
                    for candidate in pattern.finditer(expr):
                        if candidate.start() not in top_level:
                            continue
                        prefix = expr[:candidate.start(1)].rstrip()
                        # Signs after commas/operators start a new operand:
                        # 1,-2,-3 is an array, not repeated subtraction.
                        if (not prefix or prefix[-1] in ',;=+-*/%('
                                or re.search(r'-(?:bxor|band|bor|shl|shr|eq|ne|lt|le|gt|ge|and|or|xor)\s*$', prefix, re.I)
                                or re.fullmatch(r'(?:\[[A-Za-z_][\w.]*(?:\[\])?\]\s*)+', prefix)):
                            continue
                        if match is None or candidate.start() > match.start():
                            match = candidate
            elif tier in _WORD_OP_PATTERNS:
                match = _word_op_last_match(expr, tier, top_level)
            else:
                match = _last_top_level_match(expr, tier, top_level)
            if match is None:
                continue
            operator = match.group(1).lower()
            left = expr[:match.start()].strip()
            right = expr[match.end():].strip()
            if not left or not right:
                continue
            return left, operator, right
        return None

    def _apply_binary_op(self, operator, left, right_text):
        if operator == "-f":
            args = [self._eval_expr(part) for part in _split_top_level(right_text, ",")]
            return self._format_string(left, args)
        if operator in ("-and",):
            if _is_unknown(left):return _Unknown('<logical-input>')
            if not _truthy(left):return False
            right = self._eval_expr(right_text)
            return _Unknown('<logical-input>') if _is_unknown(right) else _truthy(right)
        if operator in ("-or",):
            if _is_unknown(left):return _Unknown('<logical-input>')
            if _truthy(left):return True
            right = self._eval_expr(right_text)
            return _Unknown('<logical-input>') if _is_unknown(right) else _truthy(right)
        if operator == "-as":
            # ``$value -as [TypeName]`` -- a real conversion attempt (the
            # dropper-favorite ``"System.Convert" -as [Type]`` spelling
            # of ``[Type]::GetType("System.Convert")`` chief among them,
            # specifically to keep that literal method call out of one
            # static token) that returns ``$null`` on failure rather
            # than throwing, unlike a ``[TypeName]`` cast. ``right_text``
            # is the type name's own bracket syntax, never a value
            # expression, so it's read directly rather than through
            # ``_eval_expr`` (which -- ``[Type]`` alone has no operand
            # after it -- can't resolve a bare type-literal on its own).
            type_match = re.match(r"^\[\s*([A-Za-z_][\w.]*(?:\[\])?)\s*\]\s*$", right_text.strip())
            if not type_match:
                return None
            type_name = type_match.group(1)
            if type_name.lower() == "type":
                return _ObjectRef("reflection.type", {"type_key": str(left).strip("'\"").lower().replace("system.", "", 1)}) if not _is_unknown(left) else None
            if _is_unknown(left):
                return None
            return self._apply_cast(type_name, left)
        if operator in ("-is", "-isnot"):
            type_match = re.match(r"^\[\s*([A-Za-z_][\w.]*(?:\[\])?)\s*\]\s*$", right_text.strip())
            type_name = type_match.group(1).lower().replace("system.", "", 1) if type_match else ""
            actual = {
                str: "string", _CharValue: "char", bool: "bool", int: "int", float: "double", list: "array",
            }.get(type(left) if not isinstance(left, bool) else bool, "")
            if isinstance(left, bool):
                actual = "bool"
            if _is_unknown(left):
                return _Unknown('<type-test-input>')
            if isinstance(left, _IntegerArray):
                element_key = type_name[:-2] if type_name.endswith('[]') else ''
                typed_match = (element_key in _INTEGER_CAST_TYPES
                               and _INTEGER_CAST_TYPES[element_key][0] == left.element_type)
                hit = type_name in ('array', 'object') or typed_match
            elif isinstance(left, (_ByteArray, _BinaryValue)):
                hit = type_name in ('array', 'object', 'byte[]')
            elif isinstance(left, _FloatingArray):
                hit = type_name in ('array', 'object', left.element_type.lower() + '[]')
            elif isinstance(left, _ObjectArray):
                hit = type_name in ('array', 'object', 'object[]')
            else:
                hit = (type_name == 'object' and left is not None) or (bool(type_name) and actual == type_name)
            return hit if operator == "-is" else not hit
        right = self._eval_expr(right_text)
        if operator in ("-join",):
            separator = str(right) if right is not None else ""
            source = left if isinstance(left, list) else [left]
            if _is_unknown(right) or any(_is_unknown(item) for item in source):
                return _Unknown('<join-input>')
            return _cap(separator.join('' if item is None else str(item) for item in source))
        if operator == "-split":
            if _is_unknown(left) or _is_unknown(right):
                return _Unknown("<split>")
            if isinstance(right, list):
                return _Unknown("<split-options-not-modeled>")
            # .NET's previous-match anchor is absent from Python re. This
            # exact, zero-width chunk delimiter needs no regex execution.
            chunk = re.fullmatch(r"\(\?<=\\G(\.{1,32}|\.\{([1-9]\d{0,4})\})\)", str(right))
            if chunk:
                width = int(chunk[2]) if chunk[2] else len(chunk[1])
                raw = str(left).encode('utf-16-le', errors='surrogatepass')
                # Default .NET dot excludes LF; once a contiguous match
                # cannot pass it, \G cannot restart later in the string.
                stop = next((i for i in range(0, len(raw), 2) if raw[i:i + 2] == b'\n\0'), len(raw))
                count = (stop // 2) // width
                if count + 1 > MAX_VARIABLES:
                    self._emit('resource_limit', resource='split_elements', limit=MAX_VARIABLES)
                    return _Unknown('<split-elements-limit>')
                size = width * 2
                return [raw[i * size:(i + 1) * size].decode('utf-16-le', errors='surrogatepass')
                        for i in range(count)] + [raw[count * size:].decode('utf-16-le', errors='surrogatepass')]
            try:
                return re.split(str(right) if right is not None else "", str(left), flags=re.IGNORECASE)
            except re.error:
                return _Unknown("<bad-split-pattern>")
        if operator == "-replace":
            parts = _split_top_level(right_text, ",")
            if len(parts) >= 2:
                pattern_val = self._eval_expr(parts[0])
                replacement_val = self._eval_expr(parts[1])
            else:
                pattern_val, replacement_val = right, ""
            if _is_unknown(pattern_val) or _is_unknown(left):
                return _Unknown(f"{left}-replace{right_text}")
            try:
                return _regex_replace(str(pattern_val), str(replacement_val), str(left))
            except re.error:
                return _Unknown(f"<bad-replace-pattern:{pattern_val}>")
            except ValueError:
                self._emit("resource_limit", resource="replacement_output", limit=MAX_VALUE_CHARS)
                return _Unknown("<replacement-output-limit>")
        if operator == "..":
            if _is_unknown(left) or _is_unknown(right):
                return _Unknown(f"{left}..{right}")
            try:
                start_n = int(_numeric_coerce(left))
                end_n = int(_numeric_coerce(right))
            except (TypeError, ValueError):
                return _Unknown(f"{left}..{right}")
            if abs(end_n - start_n) >= MAX_VARIABLES:
                self._emit('resource_limit', resource='range_elements', limit=MAX_VARIABLES)
                return _Unknown("<range-too-large>")
            step = 1 if end_n >= start_n else -1
            return list(range(start_n, end_n + step, step))
        if (_is_unknown(left) or _is_unknown(right)) and operator != "+":
            return _Unknown(f"{left}{operator}{right}")
        if operator in ('-eq', '-ne') and isinstance(left, _CharValue) and isinstance(right, (int, float)):
            hit = ord(left) == right
            return hit if operator == '-eq' else not hit
        if operator == "-eq":
            return str(left).lower() == str(right).lower() if isinstance(left, str) or isinstance(right, str) else left == right
        if operator == "-ne":
            return not (str(left).lower() == str(right).lower() if isinstance(left, str) or isinstance(right, str) else left == right)
        if operator in ("-gt", "-lt", "-ge", "-le"):
            try:
                left_n, right_n = _numeric_coerce(left), _numeric_coerce(right)
            except (TypeError, ValueError):
                # Real PowerShell throws a terminating error comparing a
                # non-numeric string against a number; this bounded
                # emulator can't recover from a bad state the way a real
                # ``try/catch`` around the comparison would, so (matching
                # every other operator here) it degrades to a defined
                # value instead of aborting the whole emulation over one
                # unresolvable comparison deep in a real loop condition.
                return False
            if operator == "-gt":
                return left_n > right_n
            if operator == "-lt":
                return left_n < right_n
            if operator == "-ge":
                return left_n >= right_n
            return left_n <= right_n
        if operator in ("-like", "-notlike"):
            pattern = re.escape(str(right)).replace(r"\*", ".*").replace(r"\?", ".")
            hit = bool(re.fullmatch(pattern, str(left), re.IGNORECASE))
            return hit if operator == "-like" else not hit
        if operator in ("-match", "-notmatch"):
            try:
                hit = bool(re.search(str(right), str(left), re.IGNORECASE))
            except re.error:
                hit = False
            return hit if operator == "-match" else not hit
        if operator in ("-contains", "-notcontains"):
            hit = isinstance(left, list) and any(str(item).lower() == str(right).lower() for item in left)
            return hit if operator == "-contains" else not hit
        if operator in ("-in", "-notin"):
            hit = isinstance(right, list) and any(str(item).lower() == str(left).lower() for item in right)
            return hit if operator == "-in" else not hit
        if operator in ("-band", "-bor", "-bxor", "-shl", "-shr"):
            try:
                li, ri = int(_numeric_coerce(left)), int(_numeric_coerce(right))
            except (TypeError, ValueError):
                return _Unknown(f"{left}{operator}{right}")
            if operator == "-band":
                return li & ri
            if operator == "-bor":
                return li | ri
            if operator == "-bxor":
                return li ^ ri
            if operator == "-shl":
                # Masked to 32 bits, matching real PowerShell/.NET ``int``
                # overflow semantics -- without this, an accumulator
                # repeatedly ``-shl``'d in a tight bit-unpacking loop
                # (a real per-character base32/base64-alphabet decode,
                # thousands of iterations) grows into an arbitrary-
                # precision Python bignum with no natural ceiling, until
                # some later ``str()``/hash of it (event dedup, an error
                # message) blows past Python's int-to-str digit limit and
                # crashes the whole emulation instead of just wrapping
                # like the real 32-bit register would.
                return (li << (ri & 31)) & 0xFFFFFFFF
            if ri < 0:
                # Real PowerShell/.NET never throws here -- a negative
                # shift *count* is masked to its low 5 bits (32-bit int
                # semantics), never propagated as a real negative shift.
                # Left unguarded, a shift-count variable that legitimately
                # goes negative mid decode-loop (bit-unpacking arithmetic
                # miscounting by one is common in real samples) crashed
                # the *entire* emulation with an unhandled ValueError
                # instead of just this one operation.
                return li >> (ri & 31)
            return li >> ri
        if operator == "+":
            if isinstance(left, (int, float)) and isinstance(right, _CharValue):
                return left + ord(right)
            # Unknown numeric operands must stay unknown. Stringifying
            # them here turns a decoder's next multiplication into string
            # repetition. Keep partial text only when an actual string
            # operand establishes concatenation (e.g. a URL prefix).
            if (_is_unknown(left) or _is_unknown(right)) and not isinstance(left, (str, list)) and not isinstance(right, (str, list)):
                return _Unknown("<numeric-addition>")
            if isinstance(left, _BinaryValue) and isinstance(right, _BinaryValue):
                return _BinaryValue(left.data + right.data, complete=left.complete and right.complete)
            if isinstance(left, str) and isinstance(right, list):
                # String + array converts the right operand to string using
                # $OFS. Comma binds more tightly than +, including inside @().
                # Do not silently reinterpret unparenthesized URL fragments
                # as separate array elements, or discard their known prefix.
                separator = self.variables.get('ofs', ' ')
                if separator is None:
                    separator = ''
                if not isinstance(separator, str):
                    return _Unknown('<string-array-separator>')
                parts = []
                size = len(left) + len(separator) * max(0, len(right) - 1)
                for index, item in enumerate(right):
                    if index % 4096 == 0:
                        self._tick()
                    if item is not None and not isinstance(item, (str, int, float, bool, _Unknown)):
                        return _Unknown('<string-array-element>')
                    part = '' if item is None else str(item)
                    size += len(part)
                    if size > MAX_VALUE_CHARS:
                        self._emit('resource_limit', resource='string_concatenation', limit=MAX_VALUE_CHARS)
                        return _Unknown('<string-concatenation-limit>')
                    parts.append(part)
                return left + separator.join(parts)
            if isinstance(left, list) or isinstance(right, list):
                left_list = left if isinstance(left, list) else [left]
                right_list = right if isinstance(right, list) else [right]
                return self._concat_array_values(left_list, right_list)
            if isinstance(left, str) or isinstance(right, str):
                # ``$null`` (``None``) concatenated with a string is ``""``
                # in real PowerShell, not the Python literal text "None".
                left_text = "" if left is None else str(left)
                right_text = "" if right is None else str(right)
                return _cap(left_text + right_text)
            try:
                return _numeric_coerce(left) + _numeric_coerce(right)
            except (TypeError, ValueError):
                left_text = "" if left is None else str(left)
                right_text = "" if right is None else str(right)
                return _cap(left_text + right_text)
        if operator == "-":
            try:
                return _numeric_coerce(left) - _numeric_coerce(right)
            except (TypeError, ValueError):
                return _Unknown(f"{left}-{right}")
        if operator == "*":
            if isinstance(left, str) and isinstance(right, (int, float)):
                count = max(0, int(right))
                if len(left) * count > MAX_VALUE_CHARS:
                    self._emit("resource_limit", resource="string_repetition", limit=MAX_VALUE_CHARS)
                    return _Unknown("<string-repetition-limit>")
                return left * count
            try:
                return _numeric_coerce(left) * _numeric_coerce(right)
            except (TypeError, ValueError):
                return _Unknown(f"{left}*{right}")
        if operator == "/":
            try:
                denom = _numeric_coerce(right)
                return _numeric_coerce(left) / denom if denom else _Unknown("<div-by-zero>")
            except (TypeError, ValueError):
                return _Unknown(f"{left}/{right}")
        if operator == "%":
            try:
                denom = _numeric_coerce(right)
                return _numeric_coerce(left) % denom if denom else _Unknown("<mod-by-zero>")
            except (TypeError, ValueError):
                return _Unknown(f"{left}%{right}")
        return _Unknown(f"{left}{operator}{right}")

    def _format_string(self, template, args):
        if _is_unknown(template):
            return _Unknown(f"<unresolved-format>")

        def replace(match):
            index = int(match.group(1))
            if 0 <= index < len(args) and not _is_unknown(args[index]):
                return str(args[index])
            return match.group(0)

        try:
            return _cap(re.sub(r"\{(\d+)\}", replace, str(template)))
        except (re.error, ValueError):
            return _Unknown(f"<bad-format:{template}>")

    # -- member/method/index chains ------------------------------------------

    def _eval_member_name(self, expression):
        constant = len(expression) <= 4096 and _is_literal_member_expression(expression)
        if constant and expression in self._constant_members:
            self._tick()
            return self._constant_members[expression]
        value = self._run_scriptblock_body(expression)
        if constant and isinstance(value, str) and len(value) <= 256:
            if len(self._constant_members) >= 256:
                self._constant_members.pop(next(iter(self._constant_members)))
            self._constant_members[expression] = value
        return value

    def _eval_suffix(self, value, suffix):
        remaining = suffix.strip()
        while remaining:
            if remaining[0] == ".":
                remaining = '.' + remaining[1:].lstrip()
                if remaining[1:2] in ("$", "("):
                    # ``$obj.$(expr)``/``$obj.$memberNameVar`` -- the
                    # member/method *name itself* computed at runtime,
                    # the same dynamic-name trick ``Get-Variable``/a
                    # dynamic static-member call use, applied to an
                    # instance member instead. Real PowerShell resolves
                    # whatever the ``$(...)``/variable evaluates to as
                    # the literal member name.
                    if remaining[1:3] == "$(" or remaining[1:2] == "(":
                        name_start = 2 if remaining[1:3] == "$(" else 1
                        name_expr, name_end = _extract_balanced(remaining, name_start, "(", ")")
                        if name_expr is None:
                            return _Unknown(f"{value}{remaining}")
                        member_value = self._eval_member_name(name_expr)
                        consumed = name_end + 1
                    else:
                        var_match = re.match(rf"^\.(\${_COMMAND_IDENT})", remaining)
                        if not var_match:
                            return _Unknown(f"{value}{remaining}")
                        member_value = self._read_variable(var_match.group(1))
                        consumed = var_match.end()
                    if _is_unknown(member_value) or not str(member_value).strip():
                        return _Unknown(f"{value}{remaining}")
                    member = str(member_value).strip()
                    rest = remaining[consumed:].lstrip()
                else:
                    member_match = re.match(rf"^\.({_IDENT})", remaining)
                    if not member_match:
                        return _Unknown(f"{value}{remaining}")
                    member = member_match.group(1)
                    rest = remaining[member_match.end():].lstrip()
                if rest[:1] == "(":
                    raw_args, end_index = _extract_balanced(rest, 0, "(", ")")
                    if raw_args is None:
                        return _Unknown(f"{value}.{member}(<unbalanced>)")
                    args = [self._eval_expr(part) for part in _split_top_level(raw_args, ",")] if raw_args.strip() else []
                    value = self._apply_method(value, member, args)
                    remaining = rest[end_index + 1:].strip()
                    continue
                value = self._apply_property(value, member)
                remaining = rest
                continue
            if remaining[0] == "[":
                raw_index, end_index = _extract_balanced(remaining, 0, "[", "]")
                if raw_index is None:
                    return _Unknown(f"{value}{remaining}")
                index_value = self._eval_expr(raw_index)
                value = self._apply_index(value, index_value)
                remaining = remaining[end_index + 1:].strip()
                continue
            return _Unknown(f"{value}{remaining}") if not _is_unknown(value) else value
        return value

    def _apply_index(self, value, index_value):
        if _is_unknown(value) or _is_unknown(index_value):
            return _Unknown("<index>")
        if isinstance(value, _CommandName):
            if isinstance(index_value, list):
                return [value if index in (0, -1) else None for index in index_value]
            return value if index_value in (0, -1) else None
        if isinstance(value, _BinaryValue) and not value.complete:
            return _Unknown('<incomplete-byte-array-index>')
        if isinstance(value, dict):
            # ``$hash["Ip"]`` -- the index-syntax equivalent of
            # ``$hash.Ip`` for a hashtable literal (see ``_eval_expr``'s
            # ``@{...}`` branch); PowerShell hashtable keys are
            # case-insensitive, matching how that dict was built.
            return value.get(str(index_value).lower(), _Unknown(f"<{index_value}>"))
        # ``[Convert]::FromBase64String(...)``/``[Text.Encoding]::...
        # .GetBytes(...)`` return a ``_BinaryValue``, and indexing
        # straight into that result (``$cipherBytes[$i]``, no
        # intermediate ``byte[]`` copy) is extremely common -- treat it
        # exactly like the ``bytes`` it wraps, indexing to a real int
        # per element same as a real PowerShell ``byte[]`` would.
        indexable = value.data if isinstance(value, _BinaryValue) else value
        if isinstance(indexable, str) and not indexable.isascii():
            indexable = _char_units(indexable)
        try:
            if isinstance(index_value, list):
                if isinstance(indexable, (str, list, bytes)):
                    return [_CharValue(indexable[int(i)]) if isinstance(indexable, str) else indexable[int(i)]
                            for i in index_value if -len(indexable) <= int(i) < len(indexable)]
                return _Unknown("<index>")
            index = int(index_value)
        except (TypeError, ValueError):
            return _Unknown("<index>")
        if isinstance(indexable, (str, list, bytes)):
            if -len(indexable) <= index < len(indexable):
                return _CharValue(indexable[index]) if isinstance(indexable, str) else indexable[index]
            if not isinstance(value, _BinaryValue) or value.complete:
                return None
            return _Unknown("<index-out-of-range>")
        return _Unknown("<index>")

    def _apply_property(self, value, member):
        if isinstance(value, _CommandName) and member.lower() == "name":
            return str(value)
        lowered = member.lower()
        if (isinstance(value, _ObjectRef) and value.kind == 'reflection.type'
                and value.state.get('type_key') == 'object' and lowered == 'module'):
            return _ObjectRef('reflection.module', {'name': 'synthetic-core-module'})
        if isinstance(value, dict):
            # ``$table.Ip`` -- PowerShell allows dot-property syntax on
            # a hashtable interchangeably with ``["Ip"]`` indexing (see
            # ``_eval_expr``'s ``@{...}`` literal branch for how these
            # get built).
            if lowered in ("count",):
                return len(value)
            if lowered == "keys":
                return list(value.keys())
            if lowered == "values":
                return list(value.values())
            return value.get(lowered, _Unknown(f"<{member}>"))
        if isinstance(value, _ObjectRef):
            if value.kind == 'powershell.pipeline' and lowered == 'commands':
                return _ObjectRef('powershell.commands', {'pipeline': value})
            if value.kind == 'powershell.instance':
                return value.state['properties'].get(lowered, _Unknown('<script-property-not-defined>'))
            if value.kind == 'ps.reference' and lowered == 'value':
                return value.state['owner'].get(value.state['name'])
            if value.kind == 'lazy.value':
                if lowered == 'isvaluecreated':
                    return value.state.get('created', False)
                if lowered == 'value':
                    if value.state.get('creating'):
                        self._emit('unsupported_operation', api='Lazy.Value', reason='recursive-value-factory')
                        return _Unknown('<recursive-lazy-value>')
                    if not value.state.get('created'):
                        factory = value.state.get('factory')
                        value.state['creating'] = True
                        try:
                            if isinstance(factory, _ObjectRef) and factory.kind == 'managed.valuefactory':
                                result = self._apply_method(factory, 'Invoke', [])
                            else:
                                self._emit('unresolved_dynamic_code', api='Lazy.Value', reason='value-factory-unresolved')
                                result = _Unknown('<lazy-value>')
                            value.state.update(value=result, created=True)
                        finally:
                            value.state['creating'] = False
                    return value.state['value']
            if value.kind in ('io.filestream','io.memorystream'):
                if lowered == 'length':
                    data = value.state.get('data')
                    return len(data) if isinstance(data,bytes) else _Unknown('<stream-length>')
                if lowered == 'position':
                    return value.state.get('position',0)
            if lowered in value.state:
                return value.state[lowered]
            if value.kind == "reflection.type" and lowered == "assembly":
                return _ObjectRef("reflection.assembly")
            if value.kind == "reflection.assembly" and lowered == "entrypoint":
                return _ObjectRef("reflection.method")
            if value.kind == "net.webclient" and lowered == "headers":
                return _Unknown("<webclient-headers>")
            known_methods = {
                'net.webclient': ('downloadfile', 'downloadstring', 'downloaddata', 'uploadstring', 'uploaddata', 'uploadfile'),
                'text.encoding': ('getbytes', 'getstring'),
                'diagnostics.process': ('start',),
            }
            if lowered in known_methods.get(value.kind, ()):
                return _ObjectRef('instance.method', {'receiver': value, 'member': lowered})
            if value.kind == "diagnostics.process" and lowered == "startinfo":
                # Auto-vivify: ``$p.StartInfo.FileName = "cmd.exe"`` reads
                # ``.StartInfo`` before ever assigning to it, and the two
                # objects need to stay linked so a later ``$p.Start()``
                # (see ``_process_method``) can see what was written here.
                start_info = _ObjectRef("diagnostics.processstartinfo", {})
                value.state["startinfo"] = start_info
                return start_info
            return _Unknown(f"<{value.kind}.{member}>")
        if lowered in ("length", "count"):
            if isinstance(value, _BinaryValue):
                return len(value.data)
            if isinstance(value, (str, list)):
                return len(value)
            return _Unknown(f"<{member}>")
        if lowered == "scriptblock" and isinstance(value, str):
            # ``& (Get-Command Verb-Noun).ScriptBlock args`` -- one more
            # layer of indirection on top of the plain ``Get-Command``
            # case (see ``_eval_command_expression``'s handling of it):
            # since a resolved command there already collapses down to
            # just its bareword name as a string, ``.ScriptBlock`` on
            # that string is a pass-through back to the same name, so
            # ``_eval_call_operator``'s bareword-name dispatch still
            # finds and calls the real function.
            return value
        if _is_unknown(value):
            return _Unknown(f"<unresolved:{member}>")
        return _Unknown(f"<{member}>")

    def _apply_method(self, value, member, args):
        lowered = member.lower()
        if isinstance(value,_GuidValue) and lowered == 'tostring':
            fmt = str(args[0]).lower() if args and args[0] is not None else 'd'
            if fmt in ('','d'):
                return str(value)
            if fmt == 'n':
                return value.replace('-','')
            if fmt in ('b','p'):
                return ('{' if fmt=='b' else '(')+str(value)+('}' if fmt=='b' else ')')
            return _Unknown('<guid-format-not-modeled>')
        if _is_unknown(value):
            # Symbolic diagnostics are never input text for .Substring,
            # .ToString, or another byte-producing transformation.
            if (lowered == 'copyto' and args and isinstance(args[0],_ObjectRef)
                    and args[0].kind in ('io.memorystream','io.filestream')):
                args[0].state['data'] = None
            return _Unknown(f'<unresolved:{member}()>')
        if isinstance(value, _ObjectRef):
            kind = value.kind
            if kind == 'reflection.emit.dynamicmethod':
                if lowered == 'getilgenerator' and (not args or len(args) == 1 and type(args[0]) is int and 0 <= args[0] <= 65536):
                    return _ObjectRef('reflection.emit.ilgenerator', {'method': value})
                if lowered == 'invoke':
                    return self._invoke_memory_xor_il(value, args)
            if kind == 'reflection.emit.ilgenerator':
                return self._record_il_operation(value, lowered, args)
            if kind == 'reflection.dynamicconstructor' and lowered == 'invoke':
                return self._new_dynamic_method(args[0]) if len(args) == 1 and isinstance(args[0], list) else _Unknown('<dynamic-constructor-arguments>')
            if kind == 'powershell.instance':
                return self._invoke_script_method(value, lowered, args)
            if kind == 'managed.valuefactory' and lowered == 'invoke':
                if args:
                    self._emit('unsupported_operation', api='Func.Invoke', reason='value-factory-arguments')
                    return _Unknown('<factory-arguments>')
                result = self._invoke_scriptblock(value.state['scriptblock'], [])
                if value.state.get('return_type') == 'string' and not _is_unknown(result):
                    return self._apply_cast('string', result)
                return result
            if kind == 'net.http.httprequestmessage' and lowered == 'dispose':
                value.state['disposed'] = True
                return None
            if kind == 'random' and lowered == 'next':
                if len(args) > 2 or any(type(v) is not int or not -(2**31) <= v < 2**31 for v in args):
                    return _Unknown('<random-bounds-unresolved>')
                minimum, maximum = (args if len(args) == 2 else (0, args[0] if args else 2147483647))
                if maximum < minimum:
                    return _Unknown('<random-bounds-invalid>')
                self._emit('modeled_random', api='Random.Next', minimum=minimum, maximum=maximum,
                           representation='deterministic-range-midpoint')
                return minimum + (maximum - minimum) // 2
            if kind == 'microsoft.csharp.csharpcodeprovider' and lowered == 'compileassemblyfromsource':
                sources = args[1:]
                known = bool(sources) and all(isinstance(s, str) and not _is_unknown(s) for s in sources)
                self._emit('dynamic_code', api='CodeDom.CompileAssemblyFromSource', input_resolved=known,
                           size=sum(len(s) for s in sources) if known else None)
                self._emit('unresolved_dynamic_code', api='CodeDom.CompileAssemblyFromSource',
                           reason='managed-source-not-emulated' if known else 'compiler-source-unresolved')
                return _Unknown('<compiler-results>')
            if kind in ('drawing.bitmap', 'drawing.graphics'):
                if lowered == 'dispose':
                    value.state['disposed'] = True
                    return None
                if value.state.get('disposed'):
                    return _Unknown('<disposed-drawing-object>')
                if kind == 'drawing.graphics' and lowered == 'copyfromscreen' and len(args) in (3, 4, 5, 6):
                    bitmap = value.state['image']
                    if bitmap.state.get('disposed'):
                        return _Unknown('<disposed-drawing-image>')
                    # Record the API attempt without reading the desktop or
                    # inventing pixels, dimensions, or an encoded image file.
                    self._emit('screen_capture', api='Drawing.Graphics.CopyFromScreen',
                               pixels_resolved=False)
                    return None
                if kind == 'drawing.bitmap' and lowered == 'save' and args:
                    if isinstance(args[0], str):
                        self._record_file_write(args[0], _Unknown('<image-pixels-unavailable>'), 'Drawing.Image.Save')
                    elif isinstance(args[0], _ObjectRef) and args[0].kind in ('io.memorystream', 'io.filestream'):
                        args[0].state['data'] = None
                    return None
                return _Unknown('<drawing-operation-not-modeled>')
            if kind == 'security.cryptography.hashalgorithm':
                if lowered in ('dispose','clear'):
                    return None
                if lowered == 'computehash' and len(args) in (1,3):
                    source = args[0]
                    known = ((isinstance(source,_BinaryValue) and source.complete)
                             or (isinstance(source,list) and len(source)<=MAX_EMBEDDED_PAYLOAD_BYTES
                                 and all(type(x) is int and 0<=x<=255 for x in source)))
                    raw = _as_bytes(source) if known else None
                    if raw is not None and len(args)==3:
                        start,count = args[1:]
                        if type(start) is not int or type(count) is not int or not 0<=start<=len(raw) or not 0<=count<=len(raw)-start:
                            raw = None
                        else:
                            raw = raw[start:start+count]
                    if raw is None:
                        return _Unknown('<hash-input-unresolved>')
                    digest = _BinaryValue(hashlib.new(value.state['algorithm'],raw).digest())
                    value.state['hash'] = digest
                    return digest
                return _Unknown('<hash-method-not-modeled>')
            if kind == 'instance.method' and lowered == 'invoke':
                return self._apply_method(value.state['receiver'], value.state['member'], args)
            if kind == "static.method" and lowered == "invoke":
                return self._dispatch_static(value.state['type_key'], value.state['member'], args, True)
            if kind == "native.delegate" and lowered == "invoke":
                return self._invoke_native_model(value, args)
            if kind.startswith("taskschd."):
                return self._task_scheduler_method(value, lowered, args)
            if kind == "net.webclient":
                return self._webclient_method(value, lowered, args)
            if kind in ("net.httpclient", "net.httpwebrequest", "net.webrequest"):
                return self._httpclient_method(value, lowered, args)
            if kind == "diagnostics.process":
                return self._process_method(value, lowered, args)
            if kind in (
                "io.filestream", "io.streamwriter", "io.streamreader", "io.binarywriter",
                "io.memorystream", "io.compression.gzipstream", "io.compression.deflatestream",
            ):
                return self._stream_method(value, lowered, args)
            if kind == "text.stringbuilder":
                return self._stringbuilder_method(value, lowered, args)
            if kind == "text.encoding":
                if lowered == "getbytes" and args:
                    return self._encoding_get_bytes(args[0], value.state.get("name"))
                if lowered == "getstring" and args:
                    return self._encoding_get_string(args[0], value.state.get("name"))
            if kind == "scriptblock":
                if lowered in ("invoke", "invokereturnasis"):
                    return self._invoke_scriptblock(value, args)
            if kind == "powershell.pipeline":
                return self._powershell_pipeline_method(value, lowered, args)
            if kind == 'powershell.commands' and lowered == 'clear' and not args:
                pipeline = value.state['pipeline']
                if not pipeline.state.get('running') and not pipeline.state.get('disposed'):
                    pipeline.state.update(commands=[], tainted=False, source_chars=0)
                    return None
                self._emit('unresolved_dynamic_code', api='PowerShell.Commands.Clear', reason='pipeline-state-not-ready')
                return _Unknown('<pipeline-state>')
            if kind in ('powershell.runspace', 'powershell.runspacepool'):
                if lowered in ('open', 'close', 'dispose') and not args and not value.state.get('disposed'):
                    value.state['opened'] = lowered == 'open'
                    value.state['disposed'] = lowered == 'dispose'
                    return None
                return _Unknown('<runspace-method>')
            if kind == "adodb.stream":
                return self._adodb_stream_method(value, lowered, args)
            if kind == "crypto.aes":
                if lowered in ('dispose', 'clear') and not args:
                    value.state['disposed'] = True
                    return None
                if value.state.get('disposed'):
                    return _Unknown('<disposed-crypto-object>')
                if lowered in ("createdecryptor", "createencryptor"):
                    if _PyCryptoAES is None:
                        self._emit("dependency_unavailable", dependency="pycryptodome", api="AES")
                        return _Unknown("<AES-requires-pycryptodome-in-worker-environment>")
                    return _ObjectRef("crypto.transform", {
                        "key": _as_bytes(value.state.get("key")), "iv": _as_bytes(value.state.get("iv")),
                        "mode": value.state.get("mode", "cbc"), "padding": value.state.get("padding", "pkcs7"),
                        "encrypt": lowered == "createencryptor",
                    })
            if kind == 'crypto.transform' and lowered == 'dispose' and not args:
                value.state['disposed'] = True
                return None
            if kind == "crypto.transform" and lowered in ("transformfinalblock", "transformblock"):
                # ``$decryptor.TransformFinalBlock($cipherBytes, 0,
                # $cipherBytes.Length)`` -- the direct
                # ``ICryptoTransform`` call, functionally identical to
                # (and just as common a spelling as) wrapping the same
                # transform in a ``CryptoStream`` (see
                # ``_cryptostream_method``), reached for here without
                # ever touching a stream at all.
                if value.state.get('disposed'):
                    self._emit('unsupported_operation', api='ICryptoTransform.' + lowered, reason='transform-disposed')
                    return _Unknown('<disposed-crypto-transform>')
                data = _as_bytes(args[0]) if args else None
                if data is None:
                    return _Unknown("<transform-result>")
                try:
                    offset = int(_numeric_coerce(args[1])) if len(args) > 1 and not _is_unknown(args[1]) else 0
                    count = int(_numeric_coerce(args[2])) if len(args) > 2 and not _is_unknown(args[2]) else len(data) - offset
                except (TypeError, ValueError):
                    offset, count = 0, len(data)
                result = _aes_transform(
                    data[offset:offset + count], value.state.get("key"), value.state.get("iv"),
                    value.state.get("mode", "cbc"), bool(value.state.get("encrypt")),
                )
                return _BinaryValue(result) if result is not None else _Unknown("<transform-result>")
            if kind == "security.cryptography.cryptostream":
                return self._cryptostream_method(value, lowered, args)
            if kind == "com.httprequest":
                return self._com_httprequest_method(value, lowered, args)
            if kind == "wmi.win32_process" and lowered == "create":
                command = args[0] if args else _Unknown("<command>")
                self._emit("process_create", command=command, api="Win32_Process.Create")
                return 0
            if kind == "appdomain" and lowered == "getassemblies":
                # Synthetic framework catalog, never host assembly discovery.
                return [_ObjectRef("reflection.assembly", {"framework_model": True,
                                   "globalassemblycache": True, "location": "System.dll"})]
            if kind == 'appdomain' and lowered == 'gettype':
                return _ObjectRef('reflection.type', {'instance_type': 'appdomain'})
            if kind == 'reflection.instancemethod' and lowered == 'invoke':
                receiver = args[0] if args else None
                method_args = args[1] if len(args) > 1 else []
                if method_args is None:
                    method_args = []
                if (isinstance(receiver, _ObjectRef) and receiver.kind == value.state.get('instance_type')
                        and isinstance(method_args, list)):
                    return self._apply_method(receiver, value.state['method'], method_args)
                self._emit('unresolved_dynamic_code', api='Reflection.InstanceMethod.Invoke', reason='receiver-or-arguments-unresolved')
                return _Unknown('<instance-method-input>')
            if kind == "appdomain" and lowered == "load" and args:
                raw = _as_bytes(args[0])
                if raw:
                    self._remember_embedded_payload(raw, "AppDomain.Load")
                self._emit("dynamic_code", api="AppDomain.CurrentDomain.Load", size=len(raw) if raw is not None else None, input_resolved=raw is not None)
                if raw is None:
                    self._emit("unresolved_dynamic_code", api="AppDomain.CurrentDomain.Load", reason="assembly-input-unresolved")
                return _ObjectRef("reflection.assembly")
            if kind == "reflection.assembly":
                if lowered == "gettype" and args and not _is_unknown(args[0]):
                    if value.state.get("framework_model") and str(args[0]).lower() == "microsoft.win32.unsafenativemethods":
                        return _ObjectRef("reflection.type", {"type_key": "microsoft.win32.unsafenativemethods"})
                    return _ObjectRef("reflection.type", {"field_owner": str(args[0]).lower().removeprefix("system.")})
                if lowered == "entrypoint":
                    return _ObjectRef("reflection.method")
                if lowered in ("createinstance",):
                    return _ObjectRef("activator.instance")
            if kind == "reflection.type" and lowered == "getfield" and args and not _is_unknown(args[0]):
                return _ObjectRef("reflection.field", {
                    "owner_type": value.state.get("type_key") or value.state.get("field_owner", ""),
                    "name": str(args[0]).lower(),
                })
            if kind == "reflection.field" and lowered in ("getvalue", "setvalue"):
                owner, field = value.state.get("owner_type", ""), value.state.get("name", "")
                target = args[0] if args else _Unknown("<reflection-target>")
                known_target = target is None or isinstance(target, _ObjectRef)
                # Keep a modeled instance alive as part of the key: an id()
                # alone could be reused for a different temporary object.
                field_key = (owner, field, target if known_target else None)
                if lowered == "setvalue" and len(args) >= 2:
                    if owner and known_target:
                        if field_key in self._reflection_fields or len(self._reflection_fields) < MAX_VARIABLES:
                            self._reflection_fields[field_key] = args[1]
                        else:
                            self._emit("resource_limit", resource="reflection_fields", limit=MAX_VARIABLES)
                    # Only a modeled attempt: no real reflection or host
                    # security setting is accessed.
                    category = "defense_evasion" if "amsi" in owner or "eventprovider" in owner or "etw" in owner else "reflection_field_write"
                    self._emit(category, api="Reflection.FieldInfo.SetValue", type=owner, field=field, value=args[1])
                    return None
                if lowered == "getvalue" and owner and known_target:
                    return self._reflection_fields.get(field_key, _Unknown("<unmodeled-field-value>"))
                return _Unknown("<reflection-field-value>")
            if kind == "reflection.type" and lowered == "getmethods":
                # ``[Type]::GetType("System.Convert").GetMethods() |
                # Where-Object {$_.Name -like "*FromBase64*"} | Select
                # -First 1`` -- a wildcard-search alternative to a
                # literal ``.GetMethod('FromBase64String')`` call,
                # specifically to keep that literal method-name string
                # out of the source too. Real ``.NET`` reflection would
                # enumerate every overload of every method; this only
                # knows the handful of static methods this emulator
                # itself already models a real dispatch for (see
                # ``_dispatch_static``'s ``type_key == "convert"``
                # branch) -- enough for ``Where-Object``'s name-pattern
                # search to find the real one, without pretending to be
                # a full reflection engine.
                type_key = value.state.get("type_key", "")
                # Only expose signatures of methods modeled below. In
                # particular obfuscators select Create by name and arity;
                # returning an empty list used to silently lose that call.
                create_arities = {
                    'scriptblock': (1,),
                    'management.automation.scriptblock': (1,),
                    'security.cryptography.sha256': (0, 1),
                }.get(type_key)
                if create_arities is not None:
                    return [_ObjectRef('reflection.boundmethod', {
                        'type_key': type_key, 'method': 'create', 'name': 'Create',
                        'parameter_count': count,
                    }) for count in create_arities]
                known_methods = {
                    "convert": (
                        "FromBase64String", "ToBase64String", "ToByte", "ToSByte",
                        "ToInt16", "ToUInt16", "ToInt32", "ToInt64", "ToUInt32",
                        "ToUInt64", "ToDouble", "ToString",
                    ),
                }.get(type_key, ())
                return [
                    _ObjectRef("reflection.boundmethod", {"type_key": type_key, "method": name.lower(), "name": name})
                    for name in known_methods
                ]
            if kind == "reflection.type" and lowered == "getmethod":
                # ``[Convert].GetMethod('FromBase64String', ...)`` -- when
                # this ``reflection.type`` came from a bracket type
                # literal (``type_key`` set -- see ``_eval_expr``'s
                # dedicated branch for it), remember which static method
                # was resolved so ``.Invoke(...)`` below can actually run
                # it instead of just logging an opaque reflection call.
                # An assembly-loaded type (``Assembly.Load(...).GetType
                # (x)``, no ``type_key``) keeps the old generic handling --
                # there's no real type name to dispatch on there anyway.
                type_key = value.state.get("type_key")
                if type_key == 'reflection.emit.dynamicmethod' and args and str(args[0]).lower() == 'getilgenerator':
                    return _ObjectRef('reflection.instancemethod', {'instance_type': type_key, 'method': 'getilgenerator'})
                if value.state.get('instance_type') == 'appdomain' and args and str(args[0]).lower() == 'load':
                    return _ObjectRef('reflection.instancemethod', {'instance_type': 'appdomain', 'method': 'load'})
                if type_key and args and not _is_unknown(args[0]):
                    return _ObjectRef("reflection.boundmethod", {"type_key": type_key, "method": str(args[0]).lower()})
                return _ObjectRef("reflection.method")
            if kind == 'reflection.type' and lowered == 'getconstructor' and value.state.get('type_key') == 'reflection.emit.dynamicmethod':
                signature = args[0] if len(args) == 1 and isinstance(args[0], list) else []
                keys = [t.state.get('type_key') if isinstance(t, _ObjectRef) and t.kind == 'reflection.type' else None for t in signature]
                if keys == ['string', 'type', 'type[]', 'reflection.module', 'bool']:
                    return _ObjectRef('reflection.dynamicconstructor')
                self._emit('unresolved_dynamic_code', api='DynamicMethod.GetConstructor', reason='constructor-signature-not-modeled')
                return _Unknown('<dynamic-method-constructor>')
            if kind == "reflection.type" and lowered == "invokemember":
                # Record the reflective call and its readable arguments;
                # arbitrary assembly methods are never executed here.
                invoke_args = args[4] if len(args) > 4 else []
                if not isinstance(invoke_args, list):
                    invoke_args = [invoke_args]
                readable = [item for item in invoke_args if isinstance(item, str) and item.strip()]
                self._emit("dynamic_code", api="Reflection.Type.InvokeMember",
                           type=value.state.get("field_owner") or value.state.get("type_key", ""),
                           member=_safe_text(args[0]) if args else "<unknown>",
                           args=_safe_text(", ".join(readable), 300),
                           arguments_resolved=not any(_is_unknown(item) for item in invoke_args))
                self._emit('unresolved_dynamic_code', api='Reflection.Type.InvokeMember', reason='managed-method-body-not-emulated')
                return _Unknown("<invoke-member-result>")
            if kind == "reflection.boundmethod" and lowered == "invoke":
                # ``.Invoke($target, @(arg1, arg2))`` -- PowerShell's
                # reflection-call convention: the first argument is the
                # instance to invoke on (``$null`` for a static method),
                # the second is the real argument list. Dispatches through
                # the exact same static-method modeling ``[Type]::Member
                # (...)`` uses (see ``_dispatch_static``), so a
                # reflection-obfuscated ``FromBase64String``/``GetString``/
                # ``ToByte``/... call resolves to a real value instead of
                # just being logged as an opaque invocation.
                real_args = args[1] if len(args) > 1 else []
                if not isinstance(real_args, list):
                    real_args = [] if _is_unknown(real_args) else [real_args]
                return self._dispatch_static(value.state["type_key"], value.state["method"], real_args, True)
            if kind == 'reflection.boundmethod' and lowered == 'getparameters':
                count = value.state.get('parameter_count')
                if isinstance(count, int):
                    return [_ObjectRef('reflection.parameter', {'position': index}) for index in range(count)]
                return _Unknown('<method-parameters-not-modeled>')
            if kind == "reflection.method" and lowered == "invoke":
                # The terminal step of a classic AMSI-bypass/loader chain --
                # ``Assembly.Load($bytes).GetType(x).GetMethod(y).Invoke(...)``
                # -- is functionally equivalent to launching a process: a
                # compiled .NET method, not this script, now runs. Its own
                # internal logic (a real C2 URL, a mutex name, ...) is
                # compiled IL this emulator can't disassemble -- but the
                # *arguments* handed to it are still plain PowerShell
                # values, and a process-hollowing/AppDomain-injection
                # loader's argument list almost always includes the real
                # injection target path as one of them (a legitimate,
                # signed .NET binary like ``aspnet_compiler.exe``/
                # ``caspol.exe`` -- a well-known living-off-the-land
                # technique), which is otherwise the only human-readable
                # IOC available from this step at all.
                invoke_args = args[1] if len(args) > 1 else (args[0] if args else None)
                if not isinstance(invoke_args, list):
                    invoke_args = [invoke_args] if invoke_args is not None else []
                readable = [str(item) for item in invoke_args if isinstance(item, str) and item.strip() and not _is_unknown(item)]
                self._emit(
                    "dynamic_code",
                    api="Reflection.MethodInfo.Invoke",
                    size=0,
                    args=_safe_text(", ".join(readable), 300) if readable else "",
                )
                self._emit('unresolved_dynamic_code', api='Reflection.MethodInfo.Invoke', reason='managed-method-body-not-emulated')
                return _Unknown("<invoke-result>")
            return _Unknown(f"<{kind}.{member}()>")

        if isinstance(value, dict):
            # A ``@{...}`` hashtable literal's real ``[Hashtable]``/
            # ``[Dictionary]``-style methods -- ``$table[$k]`` index
            # syntax (see ``_apply_index``) already worked, but a
            # ``.ContainsKey(...)``-guarded lookup loop (the near-
            # universal shape right before per-character decode logic
            # that consumes the table) had no method-call side at all,
            # silently falling through to the generic ``_Unknown``
            # fallback below on every call.
            if lowered == "containskey" and args:
                return not _is_unknown(args[0]) and str(args[0]).lower() in value
            if lowered == "containsvalue" and args:
                return not _is_unknown(args[0]) and args[0] in value.values()
            if lowered in ("add", "set", "additem") and len(args) >= 2:
                if not _is_unknown(args[0]):
                    value[str(args[0]).lower()] = args[1]
                return None
            if lowered == "remove" and args:
                value.pop(str(args[0]).lower(), None)
                return None
            if lowered == "clear":
                value.clear()
                return None
            if lowered == "getenumerator":
                return list(value.keys())

        if lowered == "tostring":
            return "" if value is None else str(value)
        if lowered in ("tolower", "tolowerinvariant"):
            return str(value).lower() if not _is_unknown(value) else value
        if lowered in ("toupper", "toupperinvariant"):
            return str(value).upper() if not _is_unknown(value) else value
        if lowered == "tochararray" and isinstance(value, str):
            # ``$s.ToCharArray()`` -- the per-character iteration step of
            # a real per-character decode loop (custom base32/base64-like
            # alphabets, char-by-char XOR); a real list of single-char
            # strings is what makes the ``foreach``/``%`` right after it
            # actually iterate instead of the whole chain going Unknown.
            return _char_units(value)
        if lowered == "trim":
            return str(value).strip() if not _is_unknown(value) else value
        if lowered == "trimstart":
            return str(value).lstrip() if not _is_unknown(value) else value
        if lowered == "trimend":
            return str(value).rstrip() if not _is_unknown(value) else value
        if lowered == "insert" and isinstance(value, str) and len(args) >= 2 and not _is_unknown(args[0]):
            # ``'literal'.Insert(25,'x').Insert(86,'y')...`` -- a real
            # (if unusual) obfuscation shape that builds a string purely
            # from chained ``.Insert()``/``.Remove()`` calls on a
            # constant, specifically to keep the finished text out of
            # the source as one contiguous token.
            try:
                index = int(_numeric_coerce(args[0]))
            except (TypeError, ValueError):
                return value
            index = max(0, min(index, len(value)))
            return value[:index] + str(args[1]) + value[index:]
        if lowered == "remove" and isinstance(value, str) and args and not _is_unknown(args[0]):
            try:
                start = int(_numeric_coerce(args[0]))
            except (TypeError, ValueError):
                return value
            if len(args) > 1 and not _is_unknown(args[1]):
                try:
                    count = int(_numeric_coerce(args[1]))
                except (TypeError, ValueError):
                    count = len(value) - start
            else:
                count = len(value) - start
            start = max(0, min(start, len(value)))
            count = max(0, min(count, len(value) - start))
            return value[:start] + value[start + count:]
        if lowered == "replace" and len(args) >= 2:
            if _is_unknown(value) or any(_is_unknown(a) for a in args[:2]):
                return _Unknown("<replace>")
            return _cap(str(value).replace(str(args[0]), str(args[1])))
        if lowered == "substring" and args:
            try:
                start = int(args[0])
                text = str(value)
                end = start + int(args[1]) if len(args) > 1 else len(text)
                return text[start:end]
            except (TypeError, ValueError, IndexError):
                return _Unknown("<substring>")
        if lowered == "remove" and args and not _is_unknown(value):
            # ``.Remove(startIndex, count)`` (or the 1-arg "remove to
            # the end" overload) -- string-splicing char-removal is a
            # popular way to hide a literal API/method-name string
            # (``'FromBbPAase64String'.Remove(5,3)`` -> ``FromBase64
            # String``) from a naive static scan of the source text.
            try:
                text = str(value)
                start = int(args[0])
                end = start + int(args[1]) if len(args) > 1 and not _is_unknown(args[1]) else len(text)
                return text[:start] + text[end:]
            except (TypeError, ValueError, IndexError):
                return _Unknown("<remove>")
        if lowered == "split":
            if isinstance(value, str):
                if args and isinstance(args[0], str):
                    return re.split(re.escape(args[0]), value)
                return value.split()
            return _Unknown("<split>")
        if lowered == "contains" and args:
            if isinstance(value, list):
                return not _is_unknown(args[0]) and any(str(item) == str(args[0]) for item in value)
            return not _is_unknown(value) and not _is_unknown(args[0]) and str(args[0]) in str(value)
        if lowered == "equals" and isinstance(value, str) and len(args) == 1:
            return _Unknown("<equals>") if _is_unknown(args[0]) else value == args[0]
        if lowered == "startswith" and args:
            return not _is_unknown(value) and not _is_unknown(args[0]) and str(value).startswith(str(args[0]))
        if lowered == "endswith" and args:
            return not _is_unknown(value) and not _is_unknown(args[0]) and str(value).endswith(str(args[0]))
        if lowered == "indexof" and args:
            return str(value).find(str(args[0])) if not _is_unknown(value) else -1
        if lowered == "invoke":
            return _Unknown("<invoke-result>")
        if lowered in ('append', 'add') and isinstance(value, (_ByteArray, _IntegerArray, _FloatingArray, _ObjectArray)):
            self._emit('unsupported_operation', api='Array.' + lowered, reason='fixed-size-array')
            return _Unknown('<fixed-size-array>')
        if lowered == "append" and isinstance(value, list):
            value.extend(args)
            return value
        if lowered == "add" and isinstance(value, list):
            # A ``System.Collections.Generic.List[T]``/``ArrayList`` --
            # the near-universal alternative to ``$arr[$i] = ...`` index
            # assignment for a byte-decode accumulator loop. Reaches here
            # when the loop body didn't match one of
            # ``_try_fast_for_loop``'s recognized ``.Add(...)`` shapes
            # (an unusual variant, or a loop short enough that falling
            # through to real per-iteration simulation was fine anyway).
            value.append(args[0] if args else None)
            return None
        if lowered == "toarray" and isinstance(value, list):
            return list(value)
        return _Unknown(f"<unresolved:{member}()>") if _is_unknown(value) else _Unknown(f"<{member}()>")

    def _encoding_get_bytes(self, arg, encoding_name=None):
        if arg is None or _is_unknown(arg):
            return _Unknown("<bytes>")
        try:
            return _BinaryValue(str(arg).encode(_dotnet_codec(encoding_name), errors="replace"))
        except Exception:
            return _Unknown("<bytes>")

    def _encoding_get_string(self, arg, encoding_name=None):
        data = _as_bytes(arg) if isinstance(arg, (_BinaryValue, list)) else None
        if data is None:
            return _Unknown("<decoded-string>")
        try:
            return _cap(data.decode(_dotnet_codec(encoding_name), errors="replace"))
        except Exception:
            return _Unknown("<decoded-string>")

    # -- IOC recorders --------------------------------------------------------

    def _record_network(self, url, method="GET", api=""):
        self._emit("network_request", method=_safe_text(method), url=_safe_text(url), api=api)

    def _record_process(self, command, api="", arguments_resolved=None, working_directory=None, executable=None, arguments=None):
        directory = self._working_directory if working_directory is None else working_directory
        fields = {'working_directory': _safe_text(directory)} if directory is not None else {}
        if arguments_resolved is not None:
            fields['arguments_resolved'] = arguments_resolved
        self._emit("process_create", command=_safe_text(command), api=api, **fields)
        if arguments_resolved is not False:
            self._model_child_powershell(command, directory, executable, arguments)
            self._model_native_download(command, executable, arguments)
        else:
            self._emit('unresolved_command', api=api, reason='process-arguments-unresolved')

    def _record_native_command(self, executable, rest, api):
        """Evaluate argument data without losing boundaries or parsing it as code."""
        values = []
        for token in _split_top_level_ws(rest):
            value = self._eval_command_arg(token)
            values.extend(value if isinstance(value, list) else [value])
            if len(values) > MAX_VARIABLES:
                self._emit('resource_limit', resource='native_arguments', limit=MAX_VARIABLES)
                return _Unknown('<native-arguments-limit>')
        resolved = all(isinstance(v, (str, int, float, bool)) and not _is_unknown(v) for v in values)
        encoded_values, total_chars = [], len(executable)
        for value in values:
            text = str(value)
            # Quotes and escaped backslashes can at most double each argument.
            total_chars += 2 * len(text) + 3
            if total_chars > MAX_SOURCE_CHARS:
                self._emit('resource_limit', resource='native_argument_chars', limit=MAX_SOURCE_CHARS)
                return _Unknown('<native-arguments-limit>')
            encoded_values.append(text)
        # list2cmdline is only a Python string encoder; it launches nothing.
        arguments = subprocess.list2cmdline(encoded_values)
        command = subprocess.list2cmdline([executable]) + (' ' + arguments if arguments else '')
        self._record_process(command, api, arguments_resolved=resolved,
                             executable=executable, arguments=arguments)
        if not resolved:
            self._emit('unresolved_command', command=executable, reason='native-arguments-unresolved')
        return _Unknown('<native-command-output>')

    def _model_native_download(self, command, executable=None, arguments=None):
        """Recognize bounded downloader CLI forms; responses remain unknown."""
        if executable is None:
            parts = _split_windows_arguments(command)
            if not parts:
                return
            executable, argv = parts[0], parts[1:]
        else:
            argv = _split_windows_arguments(arguments)
        name = ntpath.basename(executable).lower() if isinstance(executable, str) else ''
        if name not in ('curl.exe', 'certutil', 'certutil.exe'):
            return

        def incomplete(reason):
            self._emit('unsupported_operation', api=name, reason=reason)

        if argv is None:
            incomplete('native-arguments-unresolved')
            return
        url, output, method = None, None, 'GET'
        if name in ('certutil', 'certutil.exe'):
            lowered = [arg.lower() for arg in argv]
            if '-urlcache' not in lowered:
                return
            # A cache listing/deletion is not evidence of a network fetch.
            if 'delete' in lowered or '-f' not in lowered:
                return
            positional = [arg for arg in argv if arg.lower() not in ('-urlcache', '-f', '-split')]
            if not 1 <= len(positional) <= 2 or any(x.startswith('-') for x in positional):
                incomplete('certutil-urlcache-options-not-modeled')
                return
            url = positional[0]
            output = positional[1] if len(positional) == 2 else None
        else:
            urls, outputs, index = [], [], 0
            custom_method, default_method = None, 'GET'
            switches = {'-L', '--location', '-k', '--insecure', '-s', '--silent', '-S', '--show-error',
                        '-f', '--fail', '--compressed', '-q', '--disable', '--globoff', '-g'}
            value_options = {'-o', '--output', '--url', '-X', '--request', '-d', '--data', '--data-raw',
                             '--data-binary', '-F', '--form', '--form-string', '-H', '--header', '-A', '--user-agent', '--retry',
                             '--retry-delay', '--connect-timeout', '--max-time', '-m', '--max-redirs'}
            while index < len(argv):
                option = argv[index]
                if option in ('--help', '-h', '--version', '-V', '--manual', '-M'):
                    return
                if option in switches or re.fullmatch(r'-[LksSf]+', option):
                    index += 1
                    continue
                if option in ('-I', '--head'):
                    default_method = 'HEAD'
                    index += 1
                    continue
                inline = option.split('=', 1) if option.startswith('--') and '=' in option else None
                key = inline[0] if inline else option
                if key in value_options:
                    if inline:
                        value = inline[1]
                        index += 1
                    elif index + 1 < len(argv):
                        value = argv[index + 1]
                        index += 2
                    else:
                        incomplete('curl-option-value-missing')
                        return
                    if key in ('-o', '--output'):
                        outputs.append(value)
                    elif key == '--url':
                        urls.append(value)
                    elif key in ('-X', '--request'):
                        custom_method = value
                    elif key in ('-d', '--data', '--data-raw', '--data-binary', '-F', '--form', '--form-string'):
                        default_method = 'POST'
                    continue
                if option.startswith('-'):
                    incomplete('curl-option-not-modeled')
                    return
                urls.append(option)
                index += 1
            if len(urls) != 1 or len(outputs) > 1:
                incomplete('curl-multiple-or-missing-transfers')
                return
            url, output = urls[0], outputs[0] if outputs else None
            method = custom_method if custom_method is not None else default_method
        if not re.fullmatch(r'https?://[^\s<>\[\]{}]+', url, re.I):
            incomplete('native-download-url-not-modeled')
            return
        self._record_network(url, method, name)
        if output and output != '-':
            self._record_file_write(output, _Unknown('<network-response>'), name)

    def _model_child_powershell(self, command, directory, executable=None, arguments=None):
        if executable is None:
            parts = _split_windows_arguments(command)
            if not parts:
                return
            executable, argv = parts[0], parts[1:]
        else:
            argv = _split_windows_arguments(arguments)
        if not isinstance(executable, str) or ntpath.basename(executable).lower() not in ('powershell', 'powershell.exe', 'pwsh', 'pwsh.exe'):
            return
        label = 'PowerShell child process'
        if argv is None:
            self._emit('unresolved_dynamic_code', api=label, reason='process-arguments-unresolved')
            return
        switches = {'-noprofile', '-nop', '-noninteractive', '-noni', '-nologo', '-nol', '-noexit', '-noe', '-sta', '-mta'}
        options = {'-executionpolicy', '-ep', '-ex', '-windowstyle', '-w', '-wi', '-win', '-window', '-version', '-v', '-inputformat', '-outputformat'}
        index, source, script_path, script_args = 0, None, None, []
        while index < len(argv):
            option = argv[index].lower()
            if option in switches:
                index += 1
            elif option in options and index + 1 < len(argv):
                index += 2
            elif option in ('-command', '-c'):
                source = ' '.join(argv[index + 1:])
                break
            elif option in ('-file', '-f') and index + 1 < len(argv):
                script_path = argv[index + 1]
                if not ntpath.isabs(script_path) and directory is not None:
                    script_path = ntpath.join(directory, script_path) if isinstance(directory, str) else _Unknown('<child-script-directory>')
                source = self._read_virtual_file(script_path, 'PowerShell -File')
                script_args = argv[index + 2:]
                break
            elif option in ('-e', '-en', '-enc', '-encodedcommand') and index + 2 == len(argv):
                token = argv[index + 1]
                try:
                    if len(token) % 4 or token.endswith('==='):
                        raise ValueError('invalid-base64')
                    source = base64.b64decode(token, validate=True).decode('utf-16-le')
                except (ValueError, binascii.Error, UnicodeError):
                    self._emit('unresolved_dynamic_code', api=label, reason='encoded-command-input-invalid')
                    return
                break
            elif not option.startswith('-') and ntpath.basename(executable).lower() in ('powershell', 'powershell.exe'):
                source = ' '.join(argv[index:])
                break
            else:
                self._emit('unresolved_dynamic_code', api=label, reason='process-command-option-not-modeled')
                return
        if not isinstance(source, str) or source.strip() == '-' or re.search(r'<(?:unknown|unresolved|truncated)', source, re.I):
            self._emit('unresolved_dynamic_code', api=label, reason='process-code-not-provided')
            return
        if not source.strip():
            return
        self._analyze_child_source(source, directory, executable, script_path, script_args, label)

    def _analyze_child_source(self, source, directory, executable, script_path, script_args, label,
                              exploration_context=None, record_layer=True, entry_arguments=None,
                              isolate_virtual_writes=False):
        """Analyze known text in fresh model state, sharing evidence and limits."""
        if self._process_depth >= MAX_CHILD_PROCESS_DEPTH or self._process_budget['count'] >= MAX_CHILD_PROCESSES:
            self._emit('resource_limit', resource='modeled_child_processes', limit=MAX_CHILD_PROCESSES, depth_limit=MAX_CHILD_PROCESS_DEPTH)
            return
        if record_layer and not self._record_dynamic_layer(source, label, self._dynamic_depth):
            return
        if script_path is not None:
            self._analyzed_file_contents.add((self._virtual_file_key(script_path),
                hashlib.sha256(source.encode('utf-8', errors='surrogatepass')).hexdigest()))
        self._process_budget['count'] += 1
        # Another instance of this Python model, never an OS process or
        # PowerShell runtime. Script variables, functions and native objects
        # are fresh; only virtual files, evidence and budgets are shared.
        child = PowerShellEmulator(source, origin=self.origin, timeout_seconds=self.timeout_seconds,
                                   include_payload_data=self.include_payload_data)
        child.started, child.deadline = self.started, self.deadline
        child._process_depth, child._process_id = self._process_depth + 1, self._process_budget['count']
        child._dynamic_depth = self._dynamic_depth
        child._exploration_context = dict(self._exploration_context if exploration_context is None else exploration_context)
        child._working_directory = directory
        executable_directory = ntpath.dirname(executable)
        if executable_directory:
            child.variables['pshome'] = executable_directory
        if script_path is not None:
            key = self._virtual_file_key(script_path)
            child.variables['pscommandpath'] = key or _Unknown('<script-path>')
            child.variables['psscriptroot'] = ntpath.dirname(key) if key else _Unknown('<script-directory>')
            positional, named = [], {}
            index = 0
            while index < len(script_args):
                token = script_args[index]
                if re.fullmatch(r'-[A-Za-z_][A-Za-z0-9_-]*', token):
                    name = token[1:].lower()
                    value = True
                    if index + 1 < len(script_args) and not re.fullmatch(r'-[A-Za-z_][A-Za-z0-9_-]*', script_args[index + 1]):
                        index += 1
                        value = script_args[index]
                    named[name] = value
                else:
                    positional.append(token)
                index += 1
            child._entry_arguments = (positional, named)
            child.variables['args'] = list(script_args)
        if entry_arguments is not None:
            child._entry_arguments = (entry_arguments, {})
            child.variables['args'] = list(entry_arguments)
        for key, value in self.variables.items():
            if key.startswith('env:'):
                child.variables[key] = value if value is None or isinstance(value, (str, int, float, bool, _Unknown)) else _Unknown('<inherited-environment-value>')
        for attr in ('events', '_event_keys', 'errors', 'decoded_layers', '_dynamic_sources', '_dynamic_records',
                     'embedded_payloads', '_embedded_payload_hashes', '_virtual_files', '_process_budget', '_analyzed_file_contents'):
            setattr(child, attr, getattr(self, attr))
        if isolate_virtual_writes:
            child._virtual_files = dict(self._virtual_files)
            child._analyzed_file_contents = set(self._analyzed_file_contents)
        counters = ('step_count', '_virtual_file_bytes', '_exported_payload_bytes', '_stored_value_chars',
                    '_native_allocated_bytes', '_native_region_count', '_guid_counter')
        for attr in counters:
            setattr(child, attr, getattr(self, attr))
        try:
            child.run()
        finally:
            for attr in counters:
                if isolate_virtual_writes and attr == '_virtual_file_bytes':
                    continue
                setattr(self, attr, getattr(child, attr))
            for attr in ('timed_out', 'statement_limit_hit', 'event_limit_hit', 'source_truncated'):
                setattr(self, attr, getattr(self, attr) or getattr(child, attr))

    def _virtual_file_key(self, path):
        if (not isinstance(path,str) or not path or '\0' in path
                or re.search(r'<(?:unknown|unresolved|truncated)',path,re.I)):
            return None
        if self._working_directory is not None and not isinstance(self._working_directory,str) and not ntpath.isabs(path):
            return None
        directory = self._working_directory if isinstance(self._working_directory,str) else 'C:\\analysis'
        return ntpath.normcase(ntpath.normpath(ntpath.join(directory,path)))

    def _store_virtual_file(self, path, data):
        key = self._virtual_file_key(path)
        if key is None:
            return
        old = self._virtual_files.get(key)
        size = len(data) if isinstance(data,bytes) else 0
        projected = self._virtual_file_bytes-(len(old) if isinstance(old,bytes) else 0)+size
        if (key not in self._virtual_files and len(self._virtual_files) >= 512) or projected > MAX_EMBEDDED_PAYLOAD_BYTES:
            self._emit('resource_limit',resource='virtual_file_storage',limit=MAX_EMBEDDED_PAYLOAD_BYTES)
            if key in self._virtual_files:
                self._virtual_files[key] = None
                self._virtual_file_bytes -= len(old) if isinstance(old,bytes) else 0
            return
        self._virtual_files[key] = data
        self._virtual_file_bytes = projected

    def _read_virtual_file(self, path, api, as_bytes=False, encoding=None):
        data = self._virtual_files.get(self._virtual_file_key(path))
        if not isinstance(data,bytes):
            self._emit('unresolved_file_read',api=api,path=_safe_text(path),reason='file-content-not-provided')
            return _Unknown('<file-content-not-provided>')
        self._emit('filesystem_read',api=api,path=_safe_text(path),size=len(data),source='modeled-file-write')
        if as_bytes:
            return _BinaryValue(data)
        if encoding is not None and (not isinstance(encoding,str) or encoding.lower() not in _DOTNET_CODECS):
            self._emit('unresolved_file_read',api=api,path=_safe_text(path),reason='text-encoding-not-modeled')
            return _Unknown('<text-encoding-not-modeled>')
        if data.startswith((b'\xff\xfe\0\0',b'\0\0\xfe\xff')):
            codec = 'utf-32'
        elif data.startswith((b'\xff\xfe',b'\xfe\xff')):
            codec = 'utf-16'
        elif data.startswith(b'\xef\xbb\xbf'):
            codec = 'utf-8-sig'
        else:
            if encoding is None and api.lower() in ('get-content','gc','cat','type','powershell script invocation') and not data.isascii():
                self._emit('unresolved_file_read',api=api,path=_safe_text(path),reason='host-ansi-codepage-unknown')
                return _Unknown('<host-ansi-codepage>')
            codec = _dotnet_codec(encoding or 'utf8')
        return data.decode(codec,errors='replace')

    def _forget_virtual_file(self, path):
        old = self._virtual_files.pop(self._virtual_file_key(path),None)
        self._virtual_file_bytes -= len(old) if isinstance(old,bytes) else 0

    def _transfer_virtual_file(self, source, destination, api, move=False):
        # Only bytes already written by the abstract interpreter can flow
        # through this operation. Neither path is opened on the host.
        data = self._virtual_files.get(self._virtual_file_key(source))
        self._store_virtual_file(destination,data)
        if move and self._virtual_file_key(source) != self._virtual_file_key(destination):
            self._forget_virtual_file(source)
        self._emit('filesystem_move' if move else 'filesystem_copy',api=api,
                   source_path=_safe_text(source),path=_safe_text(destination),
                   content_resolved=isinstance(data,bytes))

    def _record_content_command(self, path, content, name, named):
        encoding = self._eval_command_arg(named['encoding']) if 'encoding' in named else None
        if 'encoding' in named and encoding is None:
            encoding = _Unknown('<text-encoding>')
        byte_mode = 'asbytestream' in named or str(encoding).lower() == 'byte'
        if not byte_mode and isinstance(content,list):
            content = '\r\n'.join(str(item) for item in content) if not any(_is_unknown(x) for x in content) else _Unknown('<file-content>')
        if not byte_mode and 'encoding' not in named:
            if name.lower() == 'out-file':
                encoding = 'unicode'  # Windows PowerShell's default.
            elif name.lower() == 'add-content':
                previous = self._virtual_files.get(self._virtual_file_key(path))
                if isinstance(previous,bytes):
                    for bom,codec in ((b'\xff\xfe\0\0','utf32'),(b'\xff\xfe','unicode'),
                                      (b'\xfe\xff','bigendianunicode'),(b'\xef\xbb\xbf','utf8')):
                        if previous.startswith(bom):
                            encoding = codec
                            break
            # The host ANSI code page is unknown. ASCII is invariant;
            # non-ASCII default-encoded bytes must remain unresolved.
            if encoding is None and isinstance(content,str) and not content.isascii():
                encoding = _Unknown('<host-ansi-codepage>')
        self._record_file_write(path,content,name,encoding=None if byte_mode else encoding,
                                append=name.lower()=='add-content' or 'append' in named,
                                newline=not byte_mode and 'nonewline' not in named,
                                utf8_bom=not byte_mode and str(encoding).lower() in ('utf8','utf-8'))

    def _record_file_write(self, path, content="", api="", encoding=None, append=False, newline=False, utf8_bom=False, emit_bom=True):
        path_resolved = (isinstance(path, str) and bool(path.strip()) and '\0' not in path
                         and not re.search(r'<(?:unknown|unresolved|truncated)', path, re.I))
        if not path_resolved:
            # Do not turn null model values into a literal file named "None".
            # Known content can still be retained as payload evidence below.
            if not _is_unknown(path):
                path = _Unknown(path if isinstance(path, str) and path.strip() else '<file-write-path>')
            self._emit('unresolved_file_write', api=api, reason='file-path-unresolved')
        raw = _as_bytes(content)
        if isinstance(content,_BinaryValue) and not content.complete:
            raw = None
        if isinstance(content,list) and len(content)>MAX_EMBEDDED_PAYLOAD_BYTES:
            raw = None
        if isinstance(content,str) and not re.search(r'<(?:unknown|unresolved|truncated)',content,re.I):
            text = content + ('\r\n' if newline else '')
            codec = _dotnet_codec(encoding or 'utf8')
            raw = text.encode(codec,errors='replace')
            if not append and emit_bom:
                raw = {'utf-16-le': b'\xff\xfe', 'utf-16-be': b'\xfe\xff',
                       'utf-32-le': b'\xff\xfe\0\0',
                       'utf-8': b'\xef\xbb\xbf' if utf8_bom else b''}.get(codec,b'')+raw
        elif isinstance(content,str):
            raw = None
        if encoding is not None and (not isinstance(encoding,str) or encoding.lower() not in _DOTNET_CODECS):
            raw = None
        if append:
            key = self._virtual_file_key(path)
            previous = self._virtual_files.get(key)
            raw = previous+raw if isinstance(previous,bytes) and raw is not None else None
        self._store_virtual_file(path,raw)
        size_hint = len(raw) if raw is not None else (0 if _is_unknown(content) else len(str(content)))
        path_text = _safe_text(path)
        suspicious = bool(re.search(r"\.(exe|dll|scr|ps1|vbs|js|bat|cmd|hta|jse|wsf|msi|py|pyw)$", path_text, re.IGNORECASE))
        self._emit("filesystem_write", path=path_text, api=api, size_hint=size_hint, suspicious_ext=suspicious,
                   content_resolved=raw is not None, path_resolved=path_resolved)
        if raw and raw.startswith(b"MZ"):
            self._remember_embedded_payload(raw, f"{api}(file-write)")
        # Retain written scripts as content evidence. If no modeled -File
        # invocation analyzes these exact bytes, inspect them later in fresh
        # synthetic scope, with explicit speculative provenance.
        if raw is not None:
            if re.search(r'\.(ps1|psm1)$', path_text, re.I):
                self._queue_dynamic_layer(self._read_virtual_file(path,api,encoding=encoding),
                                          f"{api}(dropped-script)", written_path=path)
            elif re.search(r'\.(vbs|js|jse|bat|cmd|hta|wsf|py|pyw)$', path_text, re.I):
                self._emit('unparsed_input', kind=path_text.rsplit('.',1)[-1].lower(),
                           reason='dropped-script-language-not-modeled', path=path_text, source=api,
                           size=len(raw), sha256=hashlib.sha256(raw).hexdigest(), evidence='written-content')

    def _record_registry_write(self, path, name="", value="", api=""):
        path_text = _safe_text(path)
        persistence = bool(re.search(r"\\run\b|\\runonce\b|currentversion\\run", path_text, re.IGNORECASE))
        self._emit("registry_write", path=path_text, name=_safe_text(name), value=_safe_text(value), api=api, persistence=persistence)

    @staticmethod
    def _item_provider(path):
        if _is_unknown(path) or not isinstance(path, str):
            return None
        provider = re.match(r'^(?:Microsoft\.PowerShell\.Core\\)?(\w+)::', path, re.I)
        if provider:
            return provider[1].lower()
        if re.match(r'^(?:HKLM|HKCU|HKCR|HKU|HKCC):|^HKEY_(?:LOCAL_MACHINE|CURRENT_USER|CLASSES_ROOT|USERS|CURRENT_CONFIG)\\', path, re.I):
            return 'registry'
        if re.match(r'^[A-Za-z]:[\\/]|^\\\\[^\\]+\\[^\\]+', path):
            return 'filesystem'
        return None

    def _record_item_property(self, path, name, value, api, delete=False):
        # ItemProperty cmdlets dispatch through providers. A filesystem
        # Attributes write is not a registry write or a persistence key.
        for item in path if isinstance(path, list) else [path]:
            text = _safe_text(item)
            provider_name = self._item_provider(item)
            if provider_name == 'registry':
                if delete:
                    for property_name in name if isinstance(name, list) else [name]:
                        self._emit('registry_delete', path=text, name=_safe_text(property_name), api=api, action='delete_value')
                else:
                    self._record_registry_write(item, name, value, api)
            elif provider_name == 'filesystem' and not delete:
                self._emit('filesystem_set_property', path=text, name=_safe_text(name),
                           value=_safe_text(value), api=api)
            else:
                # Relative paths/custom PSDrives depend on an unsupplied
                # provider location. Keep the attempt without guessing it.
                self._emit('unresolved_environment', api=api, path=text,
                           name=_safe_text(name), value=_safe_text(value),
                           reason='item-property-removal-not-modeled' if delete and provider_name else 'item-property-provider-unresolved')

    def _queue_dynamic_layer(self, source_text, api_name, depth=None, written_path=None):
        if _is_unknown(source_text) or source_text is None:
            self._emit("unresolved_dynamic_code", api=api_name, reason="source-value-unresolved")
            return
        text = str(source_text)
        if not text.strip():
            return
        if len(self._layer_queue) >= MAX_DYNAMIC_SOURCES:
            self._emit('resource_limit', resource='pending_dynamic_sources', limit=MAX_DYNAMIC_SOURCES)
            return
        layer_depth = self._dynamic_depth if depth is None else depth
        if not self._record_dynamic_layer(text, api_name, layer_depth, written_path=written_path):
            return
        self._layer_queue.append((text, layer_depth + 1, written_path))

    def _record_dynamic_layer(self, text, api_name, depth, written_path=None):
        if depth >= MAX_DECODED_LAYERS:
            self._emit('resource_limit', resource='decoded_layers', limit=MAX_DECODED_LAYERS)
            return False
        if len(text) > MAX_SOURCE_CHARS:
            self._emit('resource_limit', resource='dynamic_source_chars', limit=MAX_SOURCE_CHARS)
            return False
        digest = hashlib.sha256(text.encode('utf-8', errors='surrogatepass')).hexdigest()
        if digest not in self._dynamic_sources and len(self._dynamic_sources) >= MAX_DYNAMIC_SOURCES:
            self._emit('resource_limit', resource='dynamic_sources', limit=MAX_DYNAMIC_SOURCES)
            return False
        self._dynamic_sources.add(digest)
        key = (api_name, digest, depth)
        record = self._dynamic_records.get(key)
        if record is None:
            self._recover_escaped_byte_literals(text)
            record = {'source': api_name, 'size': len(text), 'sha256': digest, 'depth': depth, 'invocations': 0}
            self._dynamic_records[key] = record
            self.decoded_layers.append(record)
        if written_path is not None:
            record['content_observations'] = record.get('content_observations', 0) + 1
            record['evidence'] = 'written-content'
            self._emit('script_content', api=api_name, size=len(text), sha256=digest,
                       path=_safe_text(written_path), evidence='written-content')
        else:
            record['invocations'] += 1
            self._emit('dynamic_code', api=api_name, size=len(text), sha256=digest)
        return True

    def _drain_dynamic_layers(self):
        while self._layer_queue:
            layer_source, layer_depth, written_path = self._layer_queue.popleft()
            self._tick()
            previous_depth = self._dynamic_depth
            self._dynamic_depth = layer_depth
            try:
                if written_path is None:
                    self._process_layer(layer_source)
                    continue
                digest = hashlib.sha256(layer_source.encode('utf-8', errors='surrogatepass')).hexdigest()
                key = (self._virtual_file_key(written_path), digest)
                if key in self._analyzed_file_contents:
                    continue
                context = {'analysis_context': 'speculative-written-script', 'analysis_source': _safe_text(written_path)}
                self._analyze_child_source(layer_source, self._working_directory, 'powershell.exe',
                                          written_path, [], 'Written script content',
                                          exploration_context=context, record_layer=False)
            finally:
                self._dynamic_depth = previous_depth

    def _invoke_dynamic_layer(self, source_text, api_name):
        """Interpret IEX synchronously so subsequent statements see its values.

        Source stays inside this abstract interpreter; no executable engine
        or host command is involved. The layer budget also bounds recursion.
        """
        if _is_unknown(source_text) or source_text is None:
            self._emit("unresolved_dynamic_code", api=api_name, reason="source-value-unresolved")
            return _Unknown("<dynamic-source>")
        text = str(source_text)
        if not text.strip():
            return None
        if not self._record_dynamic_layer(text, api_name, self._dynamic_depth):
            return _Unknown("<decoded-layer-limit>")
        self._dynamic_depth += 1
        try:
            return self._run_scriptblock_body(text)
        finally:
            self._dynamic_depth -= 1

    def _invoke_virtual_script(self, path, argument_text, dot_source=False):
        """Invoke only known virtual script bytes inside this same model session."""
        api = 'PowerShell script invocation'
        if not re.search(r'[\\/]', path):
            self._emit('unresolved_command', api=api, command=path, reason='script-search-path-not-modeled')
            return _Unknown('<script-search-path>')
        source = self._read_virtual_file(path, api)
        if not isinstance(source, str):
            self._emit('unresolved_dynamic_code', api=api, reason='script-content-not-provided', path=path)
            return _Unknown('<virtual-script-source>')
        if self._call_depth >= MAX_CALL_DEPTH:
            self._emit('resource_limit', resource='virtual_script_call_depth', limit=MAX_CALL_DEPTH)
            return _Unknown('<virtual-script-depth>')
        body = _strip_comments(source).lstrip()
        if re.match(r'^\[CmdletBinding\s*\(', body, re.I):
            _, end = _extract_balanced(body, 0, '[', ']')
            if end is not None:
                body = body[end + 1:].lstrip()
        param_names = _extract_scriptblock_params(body)
        param_match = _PARAM_BLOCK_RE.match(body)
        params_text = _extract_balanced(body, param_match.end() - 1)[0] if param_match else ''
        switch_names = {match[1].lower() for match in re.finditer(
            r'\[(?:switch|System\.Management\.Automation\.SwitchParameter)\]\s*\$(\w+)', params_text or '', re.I)}
        positional, named = self._parse_command_syntax(argument_text, parameter_names=param_names, switch_params=switch_names)
        if '_binding_error' in named:
            self._emit('unresolved_command', api=api, reason='script-argument-binding-unresolved', path=path)
            return _Unknown('<virtual-script-arguments>')
        args = [self._eval_command_arg(part) for part in positional]
        named_values = {key: self._eval_command_arg(value) for key, value in named.items()}
        if not self._record_dynamic_layer(source, api, self._dynamic_depth):
            return _Unknown('<virtual-script-layer-limit>')
        key = self._virtual_file_key(path)
        digest = hashlib.sha256(source.encode('utf-8', errors='surrogatepass')).hexdigest()
        self._analyzed_file_contents.add((key, digest))
        self._emit('script_invocation', api=api, path=path, sha256=digest,
                   scope='current' if dot_source else 'script', source='modeled-file-write')
        saved_functions, saved_aliases = self.functions, self.aliases
        saved_called = set(self._called_functions)
        saved_context = self._exploration_context
        caller_path = self.variables.get('pscommandpath')
        caller_root = self.variables.get('psscriptroot')
        if not dot_source:
            self.functions, self.aliases = ChainMap({}, self.functions), ChainMap({}, self.aliases)
            self._script_call_frames.append((saved_functions, saved_aliases))
        self._exploration_context = dict(saved_context, analysis_context='invoked-virtual-script', analysis_source=path)
        self._call_depth += 1
        self._dynamic_depth += 1
        try:
            with (nullcontext() if dot_source else self._function_scope()):
                if not dot_source:
                    self.variables._script_map = self.variables.maps[0]
                local = self.variables.maps[0]
                automatic_names = ('pscommandpath', 'psscriptroot', 'myinvocation', 'args', 'psboundparameters')
                saved_automatic = {name: local[name] for name in automatic_names if name in local}
                try:
                    self._store_variable('pscommandpath', key)
                    self._store_variable('psscriptroot', ntpath.dirname(key))
                    self._store_variable('myinvocation', _ObjectRef('script.invocation', {
                        'pscommandpath': caller_path, 'psscriptroot': caller_root,
                        'mycommand': _ObjectRef('script.command', {'path': key, 'name': ntpath.basename(key)})}))
                    self._bind_parameters(param_names, args, named_values, params_text or '')
                    for part in _split_top_level(params_text or '', ','):
                        parameter = re.fullmatch(r'\s*\[([\w.]+(?:\[\])?)\]\s*\$(\w+)(?:\s*=\s*.*)?', part, re.S)
                        if parameter:
                            cast, name = parameter[1].lower(), parameter[2].lower()
                            value = self.variables.get(name)
                            if not _is_unknown(value):
                                self._store_variable(name, bool(value) if name in switch_names else self._apply_cast(cast, value))
                    bound, position = {}, 0
                    for name in param_names:
                        if name in named_values:
                            bound[name] = self.variables.get(name)
                        elif position < len(args):
                            bound[name] = self.variables.get(name)
                            position += 1
                    self._store_variable('psboundparameters', bound)
                    return self._run_scriptblock_body(body)
                finally:
                    if dot_source:
                        for name in automatic_names:
                            if name in saved_automatic:
                                self._store_variable(name, saved_automatic[name])
                            else:
                                removed = local.pop(name, None)
                                self._stored_value_chars = max(0, self._stored_value_chars - _value_size(removed))
        finally:
            self._call_depth -= 1
            self._dynamic_depth -= 1
            self._exploration_context = saved_context
            if not dot_source:
                # Calls of inherited functions count as calls in their
                # parent scope; a local definition with the same name does not.
                self._called_functions = saved_called | {name for name in self._called_functions
                    if name in saved_functions and self.functions.get(name) is saved_functions[name]}
                self.functions, self.aliases = saved_functions, saved_aliases
                self._script_call_frames.pop()

    def _invoke_scriptblock(self, ref, args, named_args=None, dot_source=False):
        """Synchronously call a scriptblock (``& $sb args`` / ``$sb.Invoke
        (args)``), unlike ``_queue_dynamic_layer``: droppers commonly stash
        a small "helper function" (hex/XOR decode, base64 wrap, ...) in a
        scriptblock variable specifically *because* they need its return
        value for the next step, not just its side effects -- discarding
        that value (treating this identically to ``IEX``) would leave
        every value built from it ``_Unknown``.
        """
        source = ref.state.get("source", "") if isinstance(ref, _ObjectRef) else ""
        if (isinstance(ref, _ObjectRef) and ref.state.get("source_resolved") is False) or _is_unknown(source):
            self._emit("unresolved_dynamic_code", api="ScriptBlock.Invoke", reason="source-value-unresolved")
            return _Unknown("<scriptblock-source>")
        if not isinstance(source, str) or not source.strip():
            return _Unknown("<scriptblock-result>")
        if self._call_depth >= MAX_CALL_DEPTH:
            return _Unknown("<recursion-limit>")
        param_names = _extract_scriptblock_params(source)
        # ``$args`` -- PowerShell's automatic array of positional
        # arguments not bound to a declared parameter. A one-liner
        # scriptblock with no ``param()`` at all (``{ Invoke-Expression
        # $args[0] }``, the near-universal shape of an obfuscator's
        # "execute this however works" fallback list) depends on it
        # entirely; leaving it unset made every such scriptblock call a
        # silent no-op regardless of what was actually passed in.
        self._call_depth += 1
        try:
            with (nullcontext() if dot_source else self._function_scope()):
                param_match = re.match(r'\s*param\s*\(', source, re.I)
                params_text = _extract_balanced(source, param_match.end()-1)[0] if param_match else ''
                self._bind_parameters(param_names, args, named_args, params_text or '')
                if ref.state.get("generated"):
                    return self._invoke_dynamic_layer(source, "ScriptBlock.Invoke")
                return self._run_scriptblock_body(source)
        finally:
            self._call_depth -= 1

    def _invoke_function(self, name, func_info, args, named_args=None, dot_source=False):
        """Call a named ``function Verb-Noun { ... }`` (bareword command
        syntax, ``Verb-Noun -Param value``) with real parameter binding --
        see ``_try_parse_function_def`` for why this can't just flatten the
        body in at definition time. Any function actually reached this way
        is recorded in ``self._called_functions`` so ``run()``'s post-pass
        (see there) knows not to also sweep it as dead code.
        """
        self._called_functions.add(name)
        if self._call_depth >= MAX_CALL_DEPTH:
            return _Unknown("<recursion-limit>")
        body = func_info.get("body", "")
        params_text = func_info.get("params_text", "")
        param_names = (
            [
                _normalize_var_name(match.group(1))
                for part in _split_top_level(params_text, ",")
                for match in [re.search(rf"({_VAR_REF})\s*(?:=.*)?$", part.strip(), re.DOTALL)]
                if match
            ]
            if params_text.strip() else _extract_scriptblock_params(body)
        )
        self._call_depth += 1
        try:
            with (nullcontext() if dot_source else self._function_scope()):
                if not params_text.strip():
                    param_match = re.match(r'\s*param\s*\(', body, re.I)
                    params_text = _extract_balanced(body, param_match.end()-1)[0] if param_match else ''
                self._bind_parameters(param_names, args, named_args, params_text or '')
                if (len(param_names) == 2 and "','" in body
                        and _pure_decoder_shape(body.replace("','", '0'))
                        == _pure_decoder_shape(_DECIMAL_XOR_FUNCTION_SHAPE.replace("','", '0'))):
                    data, key = [self._read_variable(p) for p in param_names]
                    if not isinstance(data, str) or type(key) is not int or not 0 <= key <= 255:
                        self._emit('unsupported_operation', api='decimal-xor-decoder', reason='decoder-input-unresolved')
                        return _Unknown('<decimal-xor-input>')
                    count = data.count(',') + 1
                    if count > MAX_EMBEDDED_PAYLOAD_BYTES:
                        self._emit('resource_limit', resource='decimal_xor_bytes', limit=MAX_EMBEDDED_PAYLOAD_BYTES)
                        return _Unknown('<decimal-xor-size-limit>')
                    # Stream token matches to avoid a multi-million-element
                    # list of strings. No script, IL, or machine code is run.
                    output = bytearray()
                    for index, token in enumerate(re.finditer(r'[^,]+', data)):
                        if index % 4096 == 0:
                            self._tick()
                        text = token[0].strip()
                        if re.fullmatch(r'[0-9]{1,3}', text) is None or int(text) > 255:
                            self._emit('unsupported_operation', api='decimal-xor-decoder', reason='decimal-token-not-modeled')
                            return _Unknown('<decimal-xor-token>')
                        output.append(int(text) ^ key)
                    if len(output) != count:
                        self._emit('unsupported_operation', api='decimal-xor-decoder', reason='empty-decimal-token-not-modeled')
                        return _Unknown('<decimal-xor-token>')
                    raw = bytes(output)
                    if _has_bounded_pe_layout(raw):
                        self._remember_embedded_payload(raw, 'decimal-xor-function-return')
                    return _BinaryValue(raw)
                alphabet_literal = "'ABCDEFGHIJKLMNOPQRSTUVWXYZab'"
                if (len(param_names) == 1 and alphabet_literal in body
                        and _pure_decoder_shape(body.replace(alphabet_literal, '28'))
                        == _pure_decoder_shape(_BASE28_FUNCTION_SHAPE.replace(alphabet_literal, '28'))):
                    data = self._read_variable(param_names[0])
                    if not isinstance(data, str) or re.fullmatch(r'[A-Zab]*', data) is None:
                        self._emit('unsupported_operation', api='radix28-decoder', reason='decoder-input-unresolved')
                        return _Unknown('<radix28-input>')
                    out = bytearray()
                    alphabet = {char: index for index, char in enumerate('ABCDEFGHIJKLMNOPQRSTUVWXYZab')}
                    for offset in range(0, len(data), 5):
                        if offset % 4095 == 0:
                            self._tick()
                        group = data[offset:offset + 5]
                        count = {5: 3, 4: 2, 2: 1}.get(len(group))
                        if count is None:
                            break
                        value = 0
                        for char in group:
                            value = value * 28 + alphabet[char]
                        out.extend((value & ((1 << (count * 8)) - 1)).to_bytes(count, 'big'))
                        if len(out) > MAX_EMBEDDED_PAYLOAD_BYTES:
                            self._emit('resource_limit', resource='radix28_bytes', limit=MAX_EMBEDDED_PAYLOAD_BYTES)
                            return _Unknown('<radix28-limit>')
                    return _BinaryValue(bytes(out))
                if (len(param_names) == 1
                        and len(body) < 8192
                        and _strip_comments(body).replace('\r\n','\n').strip() in _BASE85_FUNCTION_SHAPES):
                    data = self._read_variable(param_names[0])
                    if not isinstance(data,str):
                        return _Unknown('<base85-input>')
                    encoded = re.sub(r'[\r\n\t ]','',data)
                    if (len(encoded) % 5 == 1 or len(encoded)*4//5 > MAX_EMBEDDED_PAYLOAD_BYTES):
                        return _Unknown('<base85-length>')
                    output = bytearray()
                    try:
                        for offset in range(0,len(encoded),4095):
                            self._tick()
                            output.extend(base64.b85decode(encoded[offset:offset+4095].encode('ascii')))
                    except (ValueError,UnicodeError):
                        return _Unknown('<base85-invalid>')
                    raw = bytes(output)
                    if _has_bounded_pe_layout(raw):
                        self._remember_embedded_payload(raw,'function-return')
                    return _BinaryValue(raw)
                if (len(param_names) == 1 and _pure_decoder_shape(body) is not None
                        and _pure_decoder_shape(body) == _pure_decoder_shape(_BASE52_FUNCTION_SHAPE)):
                    data = self._read_variable(param_names[0])
                    if not isinstance(data, str) or re.fullmatch(r'[A-Za-z]*', data) is None:
                        self._emit('unresolved_dynamic_code', api='radix52-decoder', reason='decoder-input-unresolved')
                        return _Unknown('<radix52-input>')
                    out = bytearray()
                    alphabet = {char: index for index, char in enumerate('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz')}
                    for offset in range(0, len(data), 10):
                        if offset % 4090 == 0:
                            self._tick()
                        group = data[offset:offset+10]
                        count = {10:7,9:6,8:5,6:4,5:3,3:2,2:1}.get(len(group))
                        if count is None:
                            break
                        value = 0
                        for char in group:
                            value = value * 52 + alphabet[char]
                        out.extend((value & ((1 << (count*8))-1)).to_bytes(count, 'big'))
                        if len(out) > MAX_EMBEDDED_PAYLOAD_BYTES:
                            self._emit('resource_limit', resource='radix52_bytes', limit=MAX_EMBEDDED_PAYLOAD_BYTES)
                            return _Unknown('<radix52-limit>')
                    return _BinaryValue(bytes(out))
                # Char-array value helpers need real branch/return scopes:
                # flattening their catch/guard returns can erase a decoded
                # path. Only use structured evaluation for a validated pure
                # subset; all calls still use the same abstract API models.
                value_body = _strip_comments(body)
                param = re.match(r'\s*param\s*\(', value_body, re.I)
                if param:
                    _, end = _extract_balanced(value_body, param.end() - 1)
                    value_body = value_body[end + 1:] if end is not None else ''
                program = (_parse_value_program(value_body)
                           if len(value_body) <= 8192 and re.search(r'\.ToCharArray\s*\(', value_body, re.I)
                           else None)
                if program is not None:
                    try:
                        _, result = self._run_value_program(program)
                    except _ValueUnresolved:
                        self._emit('unresolved_dynamic_code', api='value-function',
                                   reason='decoder-value-unresolved', function=name)
                        result = _Unknown('<value-function>')
                else:
                    result = self._run_scriptblock_body(body)
                # The function's output stream unwraps its one output item.
                # In particular `return ,$bytes` returns the byte array as
                # that item, rather than a synthetic array around it.
                if isinstance(result, list) and len(result) == 1:
                    result = result[0]
                raw = _as_bytes(result) if isinstance(result, (_BinaryValue, _ByteArray)) else None
                if raw is not None and _has_bounded_pe_layout(raw):
                    self._remember_embedded_payload(raw, 'function-return')
                return result
        finally:
            self._call_depth -= 1

    def _checked_value_expression(self, text):
        def known(value):
            if _is_unknown(value) or isinstance(value, _ObjectRef):
                return False
            if isinstance(value, _BinaryValue):
                return value.complete
            if isinstance(value, list):
                return all(known(item) for item in value)
            return value is None or isinstance(value, (str, int, float, bool))

        # Unknown operands must not become false through boolean coercion.
        for start, end, kind in _scan_ps_text(text):
            if kind == 'code':
                for match in re.finditer(_VAR_REF, text[start:end]):
                    if not known(self._read_variable(match[0])):
                        raise _ValueUnresolved()
        value = self._eval_expr(text) if text.strip() else None
        if not known(value):
            raise _ValueUnresolved()
        return value

    def _run_script_method_program(self, nodes):
        for node in nodes:
            self._tick()
            kind = node[0]
            if kind == 'return':
                return True, self._eval_expr(node[1]) if node[1] else None
            if kind == 'statement':
                self._process_statement(node[1])
            elif kind == 'if':
                for condition, child in node[1]:
                    decision = True if condition is None else self._eval_expr(condition)
                    if _is_unknown(decision):
                        raise _ValueUnresolved()
                    if _truthy(decision):
                        returned, value = self._run_script_method_program(child)
                        if returned:
                            return True, value
                        break
            elif kind == 'switch':
                selected = self._eval_expr(node[1])
                if type(selected) not in (int, str):
                    raise _ValueUnresolved()
                matched, fallback = False, None
                for label, child in node[2]:
                    if label is None:
                        fallback = child
                        continue
                    candidate = self._eval_expr(label)
                    if type(candidate) not in (int, str):
                        raise _ValueUnresolved()
                    if str(selected).lower() == str(candidate).lower():
                        matched = True
                        returned, value = self._run_script_method_program(child)
                        if returned:
                            return True, value
                if not matched and fallback is not None:
                    returned, value = self._run_script_method_program(fallback)
                    if returned:
                        return True, value
            elif kind == 'while':
                for _ in range(256):
                    self._tick()
                    decision = self._eval_expr(node[1])
                    if _is_unknown(decision):
                        raise _ValueUnresolved()
                    if not _truthy(decision):
                        break
                    returned, value = self._run_script_method_program(node[2])
                    if returned:
                        return True, value
                else:
                    self._emit('resource_limit', resource='script_method_loop_iterations', limit=256)
                    raise _ValueUnresolved()
        return False, None

    def _set_script_property(self, instance, name, value, coerce=True):
        definition = self._script_types.get(instance.state['type_name'], {})
        declaration = definition.get('properties', {}).get(name)
        if declaration is None:
            self._emit('unsupported_operation', api='PowerShellClass.Property', reason='property-not-declared', property=name)
            return
        value = value if not coerce or _is_unknown(value) or (value is None and declaration[0].endswith('[]')) else self._apply_cast(declaration[0], value)
        properties = instance.state['properties']
        projected = self._stored_value_chars - _value_size(properties.get(name)) + _value_size(value)
        if projected > MAX_TOTAL_VALUE_CHARS:
            self._emit('resource_limit', resource='stored_value_chars', limit=MAX_TOTAL_VALUE_CHARS)
            value = _Unknown('<script-property-size-limit>')
            projected = self._stored_value_chars - _value_size(properties.get(name)) + _value_size(value)
        properties[name] = value
        self._stored_value_chars = max(0, projected)
        if declaration[0] in ('byte[]', 'system.byte[]'):
            data = _as_bytes(value)
            if data and data.startswith(b'MZ'):
                self._remember_embedded_payload(data, 'PowerShellClass.Property')

    def _invoke_script_method(self, instance, name, args, constructor=False):
        definition = self._script_types.get(instance.state['type_name'], {})
        candidates = definition.get('methods', {}).get(name, [])
        candidates = [method for method in candidates if len(method['params']) == len(args)]
        if len(candidates) != 1 or candidates[0]['program'] is None:
            self._emit('unsupported_operation', api='PowerShellClass.Method', method=name,
                       reason='method-overload-or-body-not-modeled')
            return _Unknown('<script-method-not-modeled>')
        method = candidates[0]
        if self._call_depth >= MAX_CALL_DEPTH:
            self._emit('resource_limit', resource='script_method_call_depth', limit=MAX_CALL_DEPTH)
            return _Unknown('<script-method-recursion>')
        self._call_depth += 1
        try:
            with self._function_scope():
                self._store_variable('this', instance)
                for key, cast, value in zip(method['params'], method['types'], args):
                    self._store_variable(key, value if _is_unknown(value) else self._apply_cast(cast, value))
                returned, value = self._run_script_method_program(method['program'])
                if method['return_type'] == 'void':
                    if returned and (constructor or value is not None):
                        self._emit('unsupported_operation', api='PowerShellClass.Method', method=name,
                                   reason='invalid-void-or-constructor-return')
                        return _Unknown('<script-method-return>')
                    return None
                if not returned:
                    self._emit('unsupported_operation', api='PowerShellClass.Method', method=name,
                               reason='non-void-method-return-unresolved')
                    return _Unknown('<script-method-return>')
                return value if _is_unknown(value) else self._apply_cast(method['return_type'], value)
        except _ValueUnresolved:
            self._emit('unsupported_operation', api='PowerShellClass.Method', method=name,
                       reason='method-control-input-unresolved')
            return _Unknown('<script-method-control>')
        finally:
            self._call_depth -= 1

    def _new_script_instance(self, type_key, args):
        definition = self._script_types[type_key]
        if definition['kind'] != 'class':
            return _Unknown('<script-enum-constructor>')
        if self._script_instance_count >= 512 or self._call_depth >= MAX_CALL_DEPTH:
            self._emit('resource_limit', resource='script_class_instances', limit=512, depth_limit=MAX_CALL_DEPTH)
            return _Unknown('<script-instance-limit>')
        constructors = definition['methods'].get(type_key, [])
        if (not constructors and args) or (constructors and sum(len(m['params']) == len(args) for m in constructors) != 1):
            self._emit('unsupported_operation', api='PowerShellClass.Constructor', reason='constructor-overload-not-modeled', type=type_key)
            return _Unknown('<script-constructor>')
        self._script_instance_count += 1
        instance = _ObjectRef('powershell.instance', {'type_name': type_key, 'properties': {}})
        self._call_depth += 1
        try:
            with self._function_scope():
                self._store_variable('this', instance)
                for name, (cast, expression) in definition['properties'].items():
                    default = (False if cast in ('bool', 'boolean', 'system.boolean') else
                               0 if cast in ('int', 'long', 'byte', 'int32', 'int64', 'uint32', 'uint64', 'intptr')
                               or self._script_types.get(cast, {}).get('kind') == 'enum' else None)
                    if expression is None:
                        self._set_script_property(instance, name, default, coerce=False)
                    else:
                        self._set_script_property(instance, name, self._eval_expr(expression))
            if constructors:
                result = self._invoke_script_method(instance, type_key, args, constructor=True)
                if _is_unknown(result):
                    return result
            return instance
        finally:
            self._call_depth -= 1

    def _run_value_program(self, nodes):
        for node in nodes:
            self._tick()
            kind = node[0]
            if kind == 'return':
                return True, self._checked_value_expression(node[1])
            if kind == 'statement':
                assignment = re.fullmatch(r'(\$\w+(?:\[[^\]\r\n]+\])?)\s*(\+=|-=|=)\s*(.+)', node[1], re.S)
                if assignment:
                    # Validate inputs/results before existing bounded lvalue
                    # handling updates the synthetic local scope.
                    self._checked_value_expression(assignment[3])
                self._process_statement(node[1])
                target = assignment[1] if assignment else node[1][:-2]
                self._checked_value_expression(target)
                continue
            if kind == 'if':
                for condition, child in node[1]:
                    if condition is None or _truthy(self._checked_value_expression(condition)):
                        returned, value = self._run_value_program(child)
                        if returned:
                            return True, value
                        break
            elif kind == 'try':
                returned, value = self._run_value_program(node[1])
                if returned:
                    return True, value
            elif kind == 'foreach':
                items = self._checked_value_expression(node[2])
                if isinstance(items, _BinaryValue):
                    items = list(items.data)
                elif items is None:
                    items = []
                elif not isinstance(items, list):
                    items = [items]
                if len(items) > MAX_LOOP_ITERATIONS:
                    self._emit('resource_limit', resource='value_function_iterations', limit=MAX_LOOP_ITERATIONS)
                    raise _ValueUnresolved()
                for item in items:
                    self._store_variable(node[1], item)
                    returned, value = self._run_value_program(node[3])
                    if returned:
                        return True, value
            elif kind == 'for':
                self._run_value_program(node[1])
                iterations = 0
                while _truthy(self._checked_value_expression(node[2])):
                    if iterations >= MAX_LOOP_ITERATIONS:
                        self._emit('resource_limit', resource='value_function_iterations', limit=MAX_LOOP_ITERATIONS)
                        raise _ValueUnresolved()
                    returned, value = self._run_value_program(node[4])
                    if returned:
                        return True, value
                    self._run_value_program(node[3])
                    iterations += 1
        return False, None

    def _run_statement_program(self, nodes, output):
        """Follow the parsed subset in order; return stops the current body.

        Unknown decisions stop this path rather than guessing a false branch.
        Output is the success stream, so earlier expressions survive return.
        """
        def append(value):
            if value is None:
                return
            items = value if isinstance(value, list) else [value]
            size = sum(_value_size(item) for item in items)
            if len(output) + len(items) > MAX_EMBEDDED_PAYLOAD_BYTES or output.value_chars + size > MAX_TOTAL_VALUE_CHARS:
                self._emit('resource_limit', resource='scriptblock_output', limit=MAX_TOTAL_VALUE_CHARS)
                raise _ValueUnresolved()
            output.extend(items)
            output.value_chars += size

        for node in nodes:
            self._tick()
            kind = node[0]
            if kind == 'return':
                append(self._eval_expr(node[1]) if node[1] else None)
                return True
            if kind == 'statement':
                append(self._process_statement(node[1]))
            elif kind == 'if':
                for condition, child in node[1]:
                    if condition is None or _truthy(self._checked_value_expression(condition)):
                        if self._run_statement_program(child, output):
                            return True
                        break
            elif kind == 'while':
                iterations = 0
                while _truthy(self._checked_value_expression(node[1])):
                    if iterations >= MAX_LOOP_ITERATIONS:
                        self._emit('resource_limit', resource='scriptblock_loop_iterations', limit=MAX_LOOP_ITERATIONS)
                        raise _ValueUnresolved()
                    if self._run_statement_program(node[2], output):
                        return True
                    iterations += 1
            elif kind == 'switch':
                selected = self._checked_value_expression(node[1])
                if type(selected) not in (str, int):
                    raise _ValueUnresolved()
                matched, fallback = False, None
                for label, child in node[2]:
                    if label is None:
                        fallback = child
                        continue
                    candidate = self._checked_value_expression(label)
                    if type(candidate) not in (str, int):
                        raise _ValueUnresolved()
                    if str(selected).lower() == str(candidate).lower():
                        matched = True
                        if self._run_statement_program(child, output):
                            return True
                if not matched and fallback is not None:
                    if self._run_statement_program(fallback, output):
                        return True
        return False

    def _run_scriptblock_body(self, source):
        cleaned = _strip_comments(source)
        # Param is a declaration, and does not require a semicolon before
        # the first body statement. Binding already happened in the caller.
        parameter_block = re.match(r'\s*param\s*\(',cleaned,re.I)
        if parameter_block:
            _, end = _extract_balanced(cleaned,parameter_block.end()-1)
            if end is not None:
                cleaned = cleaned[end+1:].lstrip(' \t\r\n;')
        loop = _try_parse_for_expression(cleaned.strip())
        if loop:
            return self._eval_for_expression(*loop)
        program = _parse_script_method_program(cleaned)
        if program is not None:
            output = _PipelineOutput()
            try:
                self._run_statement_program(program, output)
            except _ValueUnresolved:
                self._emit('unsupported_operation', api='PowerShell.ControlFlow',
                           reason='condition-or-output-unresolved')
                return _Unknown('<scriptblock-control-flow-unresolved>')
            return output[0] if len(output) == 1 else (output if output else None)
        normalized = _normalize_block_syntax(cleaned)
        statements = _split_statements(normalized)
        return_value = _Unknown("<scriptblock-result>")
        have_real_return = False
        for statement in statements:
            self._tick()
            stripped = statement.strip()
            return_match = re.match(r"^return\b\s*(.*)$", stripped, re.IGNORECASE | re.DOTALL)
            if return_match:
                expr_text = return_match.group(1).strip()
                candidate = self._eval_expr(expr_text) if expr_text else None
                is_real = candidate is not None and not _is_unknown(candidate)
                # ``if``/``elseif``/``else`` bodies are flattened and run
                # unconditionally (see ``_normalize_block_syntax``), so a
                # guard-clause-then-real-work-then-catch-all-failure
                # function (``if (-not $x) { return $null } ... $y = ...
                # ; if ($y) { return $y } ; return $null``) -- extremely
                # common in decode helpers -- would otherwise let that
                # trailing unconditional failure return always win over
                # the real value computed in between. Once a genuine
                # (non-null/non-Unknown) return has been captured, only
                # another genuine return is allowed to replace it.
                if is_real or not have_real_return:
                    return_value = candidate
                    have_real_return = have_real_return or is_real
                continue
            if re.match(r"^param\s*\(", stripped, re.IGNORECASE):
                continue
            # A bare expression/pipeline statement (``_process_statement``
            # returns its value only for that shape -- every assignment/
            # control-flow branch inside it implicitly returns ``None``)
            # is PowerShell's other, no-``return``-keyword-needed way to
            # produce a scriptblock's output; ``% { [byte][char]$_ }``
            # depends on exactly this, and treating only explicit
            # ``return`` as meaningful left every such conversion
            # silently discarded. Same "prefer a genuine value over a
            # later fallback" precedence as the ``return`` branch above.
            candidate = self._process_statement(statement)
            is_real = candidate is not None and not _is_unknown(candidate)
            if is_real or not have_real_return:
                return_value = candidate if candidate is not None else return_value
                have_real_return = have_real_return or is_real
        return return_value

    def _remember_embedded_payload(self, data, source, payload_type=None, export_binary=False):
        if not data:
            return
        digest = hashlib.sha256(data).hexdigest()
        if digest in self._embedded_payload_hashes:
            return
        self._embedded_payload_hashes.add(digest)
        payload_type = "PE" if data[:2] == b"MZ" else (payload_type or "binary")
        payload = {
            "sha256": digest,
            "size": len(data),
            "type": payload_type,
            "source": source,
        }
        # The worker remains read-only. Opt-in transport sends bytes as
        # data to the trusted analyzer, which chooses the output paths.
        if self.include_payload_data and (payload_type in ("PE", "Shellcode") or export_binary):
            if len(data) <= MAX_EMBEDDED_PAYLOAD_BYTES and self._exported_payload_bytes + len(data) <= MAX_EXPORTED_PAYLOAD_BYTES:
                payload["_data_b64"] = base64.b64encode(data).decode("ascii")
                self._exported_payload_bytes += len(data)
            else:
                payload["dump_status"] = "export-size-limit"
        self.embedded_payloads.append(payload)

    # -- tracked-object behavior models ---------------------------------------

    @staticmethod
    def _runspace_data_known(value, depth=0):
        if depth > 16 or _is_unknown(value):
            return False
        if value is None or isinstance(value, (str, int, float, bool)):
            return True
        if isinstance(value, _BinaryValue):
            return value.complete
        if isinstance(value, list) and len(value) <= MAX_VARIABLES:
            return all(PowerShellEmulator._runspace_data_known(item, depth + 1) for item in value)
        return False

    def _runspace_value_program(self, command):
        """Validate the entire data-only subset before modeling session state."""
        source = _strip_comments(command['source']).strip()
        match = _PARAM_BLOCK_RE.match(source)
        params = ''
        if match:
            params, end = _extract_balanced(source, match.end() - 1)
            if params is None:
                return None
            # Advanced parameter attributes/default expressions need the
            # general binder, whose side effects are not modeled here.
            for parameter in _split_top_level(params, ','):
                if not re.fullmatch(r'\s*(?:\[(?:string|int|byte|bool)\]\s*)?\$\w+\s*', parameter, re.I):
                    return None
            source = source[end + 1:].strip(' \t\r\n;')
        program = _parse_script_method_program(source)
        def valid(nodes):
            for node in nodes:
                kind = node[0]
                if kind == 'statement':
                    text = node[1]
                    assigned = re.fullmatch(r'(\$\w+(?:\[[^\]\r\n]+\])?)\s*(?:\+=|-=|=)\s*(.+)', text, re.S)
                    if assigned:
                        if not all(_value_expression_supported(v) for v in assigned.groups()):return False
                    elif not re.fullmatch(r'\$\w+(?:\+\+|--)', text) and not _value_expression_supported(text):
                        return False
                elif kind == 'return':
                    if node[1] and not _value_expression_supported(node[1]):return False
                elif kind == 'if':
                    if any((condition is not None and not _value_expression_supported(condition)) or not valid(child)
                           for condition, child in node[1]):return False
                elif kind == 'while':
                    if not _value_expression_supported(node[1]) or not valid(node[2]):return False
                else:
                    return False
            return True
        return (program, params) if program is not None and valid(program) else None

    def _invoke_runspace_value_program(self, session, command, parsed, api):
        """A synchronous data-only session, with known shared argument objects."""
        child = session.get('value_model')
        if child is None:
            if self._process_budget['count'] >= MAX_CHILD_PROCESSES:
                self._emit('resource_limit', resource='modeled_child_processes', limit=MAX_CHILD_PROCESSES)
                return _Unknown('<runspace-session-limit>')
            self._process_budget['count'] += 1
            child = PowerShellEmulator('', origin=self.origin, timeout_seconds=self.timeout_seconds,
                                       include_payload_data=self.include_payload_data)
            child.started, child.deadline = self.started, self.deadline
            child._process_budget = self._process_budget
            child._exploration_context = dict(self._exploration_context, analysis_context='modeled-runspace')
            for attr in ('events', '_event_keys', 'embedded_payloads', '_embedded_payload_hashes'):
                setattr(child, attr, getattr(self, attr))
            session['value_model'] = child
        child.step_count = self.step_count
        child._exported_payload_bytes = self._exported_payload_bytes
        output = _PipelineOutput()
        try:
            with child._function_scope() if command['local_scope'] else nullcontext():
                child._store_variable('args', list(command['args']))
                child._bind_parameters(_extract_scriptblock_params(command['source']), command['args'], {}, parsed[1])
                child._run_statement_program(parsed[0], output)
            self._emit('runspace_invocation', api=api, command_count=1,
                       representation='data-only-session', output_count=len(output),
                       scheduling='synchronous' if api.endswith('.invoke') else 'completed-at-EndInvoke')
            if any(not self._runspace_data_known(item) for item in output):
                raise _ValueUnresolved()
            return list(output)
        except _ValueUnresolved:
            session['value_tainted'] = True
            self._emit('unresolved_dynamic_code', api=api, reason='runspace-value-program-unresolved')
            return _Unknown('<runspace-value-unresolved>')
        finally:
            self.step_count = child.step_count
            self._exported_payload_bytes = child._exported_payload_bytes

    def _powershell_pipeline_method(self, ref, method, args):
        """Explore known runspace scripts in isolated abstract scopes, never threads."""
        state = ref.state
        def unresolved(reason):
            self._emit('unresolved_dynamic_code', api='PowerShell.' + method, reason=reason)
            return _Unknown('<runspace-result>')
        if state.get('disposed'):
            return unresolved('pipeline-disposed')
        if method in ('dispose', 'stop') and not args:
            session = state.get('value_session')
            if session is not None and session.get('value_busy') is ref:
                session.pop('value_busy', None)
            state['cancelled'] = True
            state['running'] = False
            state['disposed'] = method == 'dispose'
            return None
        if method == 'endinvoke':
            if (len(args) == 1 and isinstance(args[0], _ObjectRef) and args[0].kind == 'powershell.async'
                    and args[0].state.get('owner') is ref and not args[0].state.get('ended')):
                args[0].state['ended'] = True
                state['running'] = False
                pending = args[0].state.get('value_pending')
                if pending is not None:
                    session, command, parsed = pending
                    session.pop('value_busy', None)
                    if state.get('cancelled') or session.get('disposed') or session.get('opened') is False:
                        return unresolved('runspace-invocation-cancelled-or-closed')
                    return self._invoke_runspace_value_program(session, command, parsed, 'PowerShell.endinvoke')
                return unresolved('runspace-output-and-completion-unresolved')
            return unresolved('async-handle-not-owned-or-already-ended')
        if state.get('running'):
            return unresolved('pipeline-already-started')
        commands = state.setdefault('commands', [])
        if method == 'addscript':
            source = args[0] if args else None
            if isinstance(source, _ObjectRef) and source.kind == 'scriptblock':
                source = source.state.get('source') if source.state.get('source_resolved') is not False else None
            if (len(args) not in (1, 2) or not isinstance(source, str) or _is_unknown(source)
                    or len(args) == 2 and type(args[1]) is not bool):
                state['tainted'] = True
                return unresolved('source-value-or-overload-unresolved')
            total = state.get('source_chars', 0) + len(source)
            if len(commands) >= 32 or total > MAX_SOURCE_CHARS:
                state['tainted'] = True
                self._emit('resource_limit', resource='runspace_command_sources', limit=MAX_SOURCE_CHARS)
                return _Unknown('<runspace-source-limit>')
            commands.append({'source': source, 'args': [], 'local_scope': args[1] if len(args) == 2 else False})
            state['source_chars'] = total
            return ref
        if method == 'addargument':
            if len(args) != 1 or not commands or len(commands[-1]['args']) >= 128:
                state['tainted'] = True
                return unresolved('argument-binding-not-modeled')
            commands[-1]['args'].append(args[0])
            return ref
        if method not in ('invoke', 'begininvoke'):
            state['tainted'] = True
            return unresolved('pipeline-method-not-modeled')
        if args or not commands:
            return unresolved('invocation-overload-or-command-unresolved')
        for field in ('runspace', 'runspacepool'):
            if field in state:
                session = state[field]
                if (not isinstance(session, _ObjectRef) or session.kind not in ('powershell.runspace', 'powershell.runspacepool')
                        or not session.state.get('opened') or session.state.get('disposed')):
                    return unresolved('runspace-not-open-or-unresolved')
        session_ref = state.get('runspace')
        session = session_ref.state if isinstance(session_ref, _ObjectRef) else state
        if session.get('value_busy') is not None:
            return unresolved('runspace-busy')
        parsed = self._runspace_value_program(commands[0]) if len(commands) == 1 else None
        # Async shared mutable arguments admit interleavings we cannot infer.
        # Keep those on the explicit speculative path. Immutable data-only
        # jobs complete at EndInvoke in this cooperative scheduling model.
        immutable = all(v is None or type(v) in (str, int, float, bool) for v in commands[0]['args'])
        if (parsed is not None and not state.get('tainted') and not session.get('value_tainted')
                and 'runspacepool' not in state and (method == 'invoke' or immutable)
                and all(self._runspace_data_known(value) for value in commands[0]['args'])):
            state['cancelled'] = False
            state['value_session'] = session
            if method == 'begininvoke':
                state['running'] = True
                session['value_busy'] = ref
                self._emit('runspace_invocation', api='PowerShell.begininvoke', command_count=1,
                           asynchronous=True, representation='deferred-data-only-session')
                return _ObjectRef('powershell.async', {'owner':ref, 'ended':False,
                                  'value_pending':(session, commands[0], parsed)})
            return self._invoke_runspace_value_program(session, commands[0], parsed, 'PowerShell.invoke')
        session['value_tainted'] = True
        # By-reference objects, scheduling, session persistence and pipeline
        # outputs are unknown. Explore known command text using argument data
        # snapshots, and keep speculative virtual writes out of the caller.
        remaining = [MAX_TOTAL_VALUE_CHARS]
        def snapshot(value, depth=0):
            remaining[0] -= 1
            if depth > 16 or remaining[0] < 0:
                return _Unknown('<runspace-argument-budget>')
            if value is None or type(value) in (bool, int, float) or _is_unknown(value):
                return value
            if isinstance(value, (str, _BinaryValue)):
                remaining[0] -= _value_size(value)
                if remaining[0] < 0:
                    return _Unknown('<runspace-argument-budget>')
                return _BinaryValue(value.data, complete=value.complete) if isinstance(value, _BinaryValue) else value
            if isinstance(value, list):
                if len(value) > MAX_VARIABLES:
                    return _Unknown('<runspace-array-budget>')
                copied = [snapshot(v, depth + 1) for v in value]
                if isinstance(value, _IntegerArray):
                    return _IntegerArray(copied, value.element_type)
                if isinstance(value, _FloatingArray):
                    return _FloatingArray(copied, value.element_type)
                if isinstance(value, _ObjectArray):
                    return _ObjectArray(copied, value.boxed_types)
                return _ByteArray(copied) if isinstance(value, _ByteArray) else copied
            if isinstance(value, dict) and len(value) <= MAX_VARIABLES:
                return {k: snapshot(v, depth + 1) for k, v in value.items()}
            return _Unknown('<runspace-shared-object>')
        self._emit('runspace_invocation', api='PowerShell.' + method, command_count=len(commands),
                   asynchronous=method == 'begininvoke', representation='isolated-argument-snapshots',
                   input_resolved=not state.get('tainted', False))
        unresolved('runspace-scheduling-state-and-output-not-modeled')
        for index, command in enumerate(commands):
            self._tick()
            arguments = [snapshot(v) for v in command['args']]
            context = dict(self._exploration_context, analysis_context='speculative-runspace',
                           runspace_command_index=index, runspace_api='PowerShell.' + method)
            self._analyze_child_source(command['source'], self._working_directory, '', None, [],
                                       'PowerShell.' + method, exploration_context=context,
                                       entry_arguments=arguments, isolate_virtual_writes=True)
        if remaining[0] < 0:
            self._emit('resource_limit', resource='runspace_argument_snapshot', limit=MAX_TOTAL_VALUE_CHARS)
        if method == 'begininvoke':
            state['running'] = True
            return _ObjectRef('powershell.async', {'owner': ref, 'ended': False})
        return _Unknown('<runspace-output>')

    def _new_dynamic_method(self, args):
        def key(value):
            return value.state.get('type_key') if isinstance(value, _ObjectRef) and value.kind == 'reflection.type' else None
        signature = [key(v) for v in args[2]] if len(args) == 5 and isinstance(args[2], list) else []
        if (len(args) == 5 and isinstance(args[0], str) and key(args[1]) == 'void'
                and signature == ['intptr', 'int32', 'byte[]']
                and isinstance(args[3], _ObjectRef) and args[3].kind == 'reflection.module'
                and type(args[4]) is bool):
            return _ObjectRef('reflection.emit.dynamicmethod', {'instructions': [], 'locals': [], 'labels': [], 'valid': True})
        self._emit('unresolved_dynamic_code', api='DynamicMethod.Constructor', reason='signature-not-modeled')
        return _Unknown('<dynamic-method-signature>')

    def _record_il_operation(self, generator, operation, args):
        method = generator.state['method']
        state = method.state
        if not state['valid']:
            return _Unknown('<unmodeled-il>')
        if len(state['instructions']) >= 256 or len(state['locals']) + len(state['labels']) >= 64:
            state['valid'] = False
            self._emit('resource_limit', resource='dynamic_method_il', limit=256)
            return _Unknown('<il-size-limit>')
        if operation == 'declarelocal' and len(args) == 1:
            typename = args[0].state.get('type_key') if isinstance(args[0], _ObjectRef) and args[0].kind == 'reflection.type' else None
            if typename in ('int32', 'int'):
                ref = _ObjectRef('cil.local', {'owner': method, 'index': len(state['locals'])})
                state['locals'].append('int32')
                return ref
        if operation == 'definelabel' and not args:
            ref = _ObjectRef('cil.label', {'owner': method, 'index': len(state['labels'])})
            state['labels'].append(ref)
            return ref
        if operation == 'marklabel' and len(args) == 1:
            label = args[0]
            if isinstance(label, _ObjectRef) and label.kind == 'cil.label' and label.state['owner'] is method:
                state['instructions'].append(('label', label.state['index']))
                return None
        if operation == 'emit' and len(args) in (1, 2) and isinstance(args[0], _ObjectRef) and args[0].kind == 'cil.opcode':
            opcode = args[0].state['name']
            operand = None
            if len(args) == 2:
                ref = args[1]
                expected = 'cil.local' if opcode in ('ldloc', 'stloc') else 'cil.label' if opcode in ('br_s', 'blt_s') else None
                if not isinstance(ref, _ObjectRef) or ref.kind != expected or ref.state['owner'] is not method:
                    state['valid'] = False
                    return _Unknown('<il-operand>')
                operand = ref.state['index']
            state['instructions'].append((opcode, operand))
            return None
        state['valid'] = False
        self._emit('unresolved_dynamic_code', api='ILGenerator.' + operation, reason='il-operation-not-modeled')
        return _Unknown('<il-operation>')

    def _invoke_memory_xor_il(self, method, args):
        state = method.state
        real = args[1] if len(args) == 2 and args[0] is None and isinstance(args[1], list) else []
        known_program = (state['valid'] and state['locals'] == ['int32', 'int32']
                         and len(state['labels']) == 2 and tuple(state['instructions']) == _MEMORY_XOR_IL)
        if known_program and len(real) == 3:
            region, count, key_value = real
            key = _as_bytes(key_value)
            key_known = ((isinstance(key_value, _BinaryValue) and key_value.complete)
                         or isinstance(key_value, list) and all(type(x) is int and 0 <= x <= 255 for x in key_value))
            if type(count) is int and count == 0 and key is not None and key_known:
                return None
            if isinstance(region, _ObjectRef) and region.kind == 'native.memory':
                storage = self._native_region_storage(region)
                raw = storage.get('data')
                if (not storage.get('freed') and isinstance(raw, bytes) and key and key_known
                        and type(count) is int and 0 < count <= len(raw) <= MAX_EMBEDDED_PAYLOAD_BYTES
                        and region.state.get('protection') in (0x04, 0x08, 0x40, 0x80)):
                    result = bytearray(raw)
                    for start in range(0, count, 4096):
                        self._tick()
                        result[start:start + min(4096, count - start)] = bytes(
                            raw[i] ^ key[i % len(key)] for i in range(start, min(start + 4096, count)))
                    storage['data'] = bytes(result)
                    transformed = storage['data'][:count]
                    self._remember_embedded_payload(transformed, 'DynamicMethod.memory-xor')
                    self._emit('memory_transform', api='DynamicMethod.Invoke', operation='repeating-key-xor',
                               size=count, sha256=hashlib.sha256(transformed).hexdigest(), modeled=True,
                               representation='exact-il-shape-data-transform')
                    return None
                storage['data'] = None
        # An unrecognized IL body may mutate every supplied memory region.
        # Ciphertext must not survive as a falsely known decoded value.
        for value in real:
            if isinstance(value, _ObjectRef) and value.kind == 'native.memory':
                self._native_region_storage(value)['data'] = None
        self._emit('unresolved_dynamic_code', api='DynamicMethod.Invoke', reason='il-program-or-input-not-modeled')
        return _Unknown('<dynamic-il-result>')

    def _task_scheduler_method(self, ref, method, args):
        """Task Scheduler COM data model; never touches the host scheduler."""
        kind = ref.kind
        if kind == 'taskschd.service':
            if method == 'connect':
                return None
            if method == 'getfolder' and args:
                return _ObjectRef('taskschd.folder', {'path': args[0]})
            if method == 'newtask':
                return _ObjectRef('taskschd.definition', {
                    'actions': _ObjectRef('taskschd.actions', {'items': []}),
                    'triggers': _ObjectRef('taskschd.triggers', {'items': []}),
                    **{name: _ObjectRef('taskschd.options') for name in ('registrationinfo', 'settings', 'principal')},
                })
        if kind in ('taskschd.actions', 'taskschd.triggers') and method == 'create' and args:
            if len(ref.state['items']) >= 32:
                self._emit('resource_limit', resource='task_components', limit=32)
                return _Unknown('<task-component-limit>')
            item = _ObjectRef('taskschd.action' if kind == 'taskschd.actions' else 'taskschd.trigger',
                              {'type': args[0], 'repetition': _ObjectRef('taskschd.options')})
            ref.state['items'].append(item)
            return item
        if kind == 'taskschd.folder':
            if method == 'deletetask' and args:
                self._emit('scheduled_task_delete', api='TaskFolder.DeleteTask', task_name=_safe_text(args[0]),
                           task_folder=_safe_text(ref.state.get('path')))
                return None
            if method == 'createfolder' and args:
                parent, name = ref.state.get('path'), args[0]
                path = parent.rstrip('\\') + '\\' + name.lstrip('\\') if isinstance(parent, str) and isinstance(name, str) else _Unknown('<task-folder>')
                return _ObjectRef('taskschd.folder', {'path': path})
            if method == 'registertaskdefinition' and len(args) >= 2:
                definition = args[1]
                collection = definition.state.get('actions') if isinstance(definition, _ObjectRef) and definition.kind == 'taskschd.definition' else None
                actions = collection.state.get('items', []) if isinstance(collection, _ObjectRef) and collection.kind == 'taskschd.actions' else []
                if not actions:
                    self._emit('scheduled_task', api='TaskFolder.RegisterTaskDefinition', task_name=args[0],
                               task_folder=ref.state.get('path'), input_resolved=False)
                    self._emit('unresolved_command', api='TaskFolder.RegisterTaskDefinition', reason='task-actions-unresolved')
                for action in actions:
                    fields = action.state
                    execute = fields.get('path')
                    known = isinstance(execute, str) and bool(execute.strip()) and not re.search(r'<(?:unknown|unresolved|truncated)', execute, re.I)
                    self._emit('scheduled_task', api='TaskFolder.RegisterTaskDefinition', task_name=args[0],
                               task_folder=ref.state.get('path'), execute=execute, arguments=fields.get('arguments', ''),
                               working_directory=fields.get('workingdirectory'), action_type=fields.get('type'),
                               flags=args[2] if len(args) > 2 else None, input_resolved=known)
                    if not known:
                        self._emit('unresolved_command', api='TaskFolder.RegisterTaskDefinition', reason='task-action-path-unresolved')
                return _ObjectRef('taskschd.registered', {'name': args[0], 'definition': definition})
        return _Unknown('<taskschd.' + method + '>')

    def _set_reference_value(self, ref, value):
        if not isinstance(ref, _ObjectRef) or ref.kind != 'ps.reference':
            return False
        owner, name = ref.state['owner'], ref.state['name']
        cast = ref.state.get('types', {}).get(name)
        if cast and not _is_unknown(value):
            value = self._apply_cast(cast, value)
            if cast.lower() in ('byte[]', 'system.byte[]') and isinstance(value, _BinaryValue):
                value = _ByteArray(value.data) if value.complete else _Unknown('<incomplete-byte-array>')
        projected = self._stored_value_chars - _value_size(owner.get(name)) + _value_size(value)
        if projected > MAX_TOTAL_VALUE_CHARS:
            self._emit('resource_limit', resource='stored_value_chars', limit=MAX_TOTAL_VALUE_CHARS)
            return False
        owner[name] = value
        self._stored_value_chars = max(0, projected)
        return True

    @staticmethod
    def _native_region_storage(region):
        mapping = region.state.get('mapping')
        return mapping.state if isinstance(mapping, _ObjectRef) and mapping.kind == 'native.mapping' else region.state

    def _copy_native_model(self, args):
        """Copy between byte arrays and synthetic regions; no host pointers."""
        if len(args) == 4 and isinstance(args[1], (list, _BinaryValue)):
            source, dest, start, count = args
            region = isinstance(source, _ObjectRef) and source.kind == 'native.memory'
            storage = self._native_region_storage(source) if region else {}
            raw = storage.get('data') if not storage.get('freed') else None
            bounds = (type(start) is int and type(count) is int and 0 <= start <= len(dest)
                      and 0 <= count <= len(dest) - start and len(dest) <= MAX_EMBEDDED_PAYLOAD_BYTES)
            known = bounds and isinstance(raw, bytes) and count <= len(raw)
            if bounds:
                if isinstance(dest, _BinaryValue):
                    if known:
                        dest.data = dest.data[:start] + raw[:count] + dest.data[start + count:]
                        dest.sha256 = hashlib.sha256(dest.data).hexdigest()
                    elif count:
                        dest.complete = False
                else:
                    dest[start:start + count] = raw[:count] if known else [_Unknown('<native-copy-input>')] * count
            elif _is_unknown(start) or _is_unknown(count):
                if isinstance(dest, _BinaryValue):
                    dest.complete = False
                else:
                    dest[:] = [_Unknown('<native-copy-range>')] * len(dest)
            self._emit('memory_copy', api='Marshal.Copy', direction='native-to-managed',
                       size=count if bounds else None, input_resolved=bool(known),
                       destination_resolved=bool(bounds), modeled=bool(known))
            if not known:
                self._emit('unresolved_dynamic_code', api='Marshal.Copy', reason='copy-input-or-destination-unresolved')
            return None
        raw = _as_bytes(args[0]) if args else None
        start, dest, count = (args[1:4] if len(args) == 4 else (None, None, None))
        complete = bool(args) and ((isinstance(args[0], _BinaryValue) and args[0].complete)
                                  or (isinstance(args[0], list) and len(args[0]) <= MAX_EMBEDDED_PAYLOAD_BYTES
                                      and all(type(n) is int and 0 <= n <= 255 for n in args[0])))
        known = (raw is not None and complete and type(start) is int and type(count) is int
                 and 0 <= start <= len(raw) and 0 <= count <= len(raw) - start)
        region = isinstance(dest, _ObjectRef) and dest.kind == "native.memory"
        copied = bool(known and region and count <= dest.state["size"]
                      and not self._native_region_storage(dest).get('freed'))
        if region:
            # Pointer arithmetic and partially overlapping writes are not
            # modeled. Keep only the bytes certainly known after this copy.
            self._native_region_storage(dest)["data"] = raw[start:start + count] if copied else None
        self._emit("memory_copy", api="Marshal.Copy", size=count if known else None,
                   input_resolved=bool(known), destination_resolved=bool(region), modeled=copied)
        if not copied:
            self._emit("unresolved_dynamic_code", api="Marshal.Copy",
                       reason="copy-input-or-destination-unresolved")
        return None

    def _invoke_native_model(self, delegate, args):
        """Allowlisted symbolic API semantics, with ordinary Python data only."""
        symbol = delegate.state.get("function")
        if isinstance(symbol, _ObjectRef) and symbol.kind == "native.function":
            module = symbol.state.get("module", "").lower()
            name = symbol.state.get("name", "")
        else:
            module, name = "", ""
        api = name.lower() if module in ("kernel32.dll", "kernelbase.dll") else ""
        if api in ('loadlibrarya', 'loadlibraryw') and len(args) == 1:
            if isinstance(args[0], str) and args[0].lower() in ('crypt32.dll', 'kernel32.dll', 'kernelbase.dll'):
                self._emit('native_library_reference', api=name, library=args[0], modeled=True)
                return _ObjectRef('native.module', {'name': args[0].lower()})
        if module == 'crypt32.dll' and name.lower() in ('cryptstringtobinarya', 'cryptstringtobinaryw'):
            return self._crypt_string_to_binary_model(name, args)
        if api in ('createfilemappinga', 'createfilemappingw') and len(args) == 6:
            file_handle, security, protection, high, size, mapping_name = args
            # Only anonymous, pagefile-backed executable/read-write mappings.
            # Named or file-backed mappings depend on unavailable host state.
            if (type(file_handle) is int and file_handle == -1 and security in (None, 0)
                    and type(protection) is int and protection in (0x40, 0x08000040)
                    and type(high) is int and high == 0 and type(size) is int and size > 0
                    and mapping_name in (None, 0)):
                if size > MAX_EMBEDDED_PAYLOAD_BYTES - self._native_allocated_bytes:
                    self._emit('resource_limit', resource='native_memory_model', limit=MAX_EMBEDDED_PAYLOAD_BYTES)
                    return _Unknown('<native-allocation-limit>')
                self._native_allocated_bytes += size
                self._native_region_count += 1
                ref = _ObjectRef('native.mapping', {'id': self._native_region_count, 'size': size,
                                                  'protection': protection & 0xff, 'data': None})
                self._emit('memory_mapping', api=name, size=size, region=ref.state['id'], modeled=True)
                return ref
        if api == 'mapviewoffile' and len(args) == 5:
            mapping, access, high, low, size = args
            if (isinstance(mapping, _ObjectRef) and mapping.kind == 'native.mapping'
                    and type(access) is int and access in (0x22, 0x26, 0xF003F)
                    and type(high) is int and high == 0 and type(low) is int and low == 0
                    and type(size) is int and size in (0, mapping.state['size'])):
                # Full views share one backing store. Partial/offset views are
                # deliberately unresolved until their write semantics are modeled.
                ref = _ObjectRef('native.memory', {'mapping': mapping, 'id': mapping.state['id'],
                                                  'size': mapping.state['size'], 'protection': 0x40})
                self._emit('memory_map_view', api=name, size=ref.state['size'], region=ref.state['id'], modeled=True)
                return ref
        if api == 'virtualfree' and len(args) == 3:
            region, size, mode = args
            if (isinstance(region, _ObjectRef) and region.kind == 'native.memory'
                    and 'mapping' not in region.state and not region.state.get('freed')
                    and type(size) is int and size == 0 and type(mode) is int and mode == 0x8000):
                region.state.update(data=None, freed=True)
                self._emit('memory_free', api='VirtualFree', region=region.state['id'], modeled=True)
                return True
        if isinstance(symbol, _ObjectRef) and symbol.kind == 'native.memory':
            raw = self._native_region_storage(symbol).get('data')
            if raw:
                self._remember_embedded_payload(raw, 'NativeDelegate.Invoke', payload_type='Shellcode')
            if raw:
                self._emulate_native_region(raw, args, 'NativeDelegate.Invoke')
            else:
                self._emit('unresolved_dynamic_code', api='NativeDelegate.Invoke', reason='native-code-not-emulated',
                           payload_available=False)
            return _Unknown('<native-call-result>')
        if api == "virtualalloc" and len(args) == 4:
            size = args[1]
            if type(size) is int and size > 0:
                if size > MAX_EMBEDDED_PAYLOAD_BYTES or self._native_allocated_bytes + size > MAX_EMBEDDED_PAYLOAD_BYTES:
                    self._emit("resource_limit", resource="native_memory_model", limit=MAX_EMBEDDED_PAYLOAD_BYTES)
                    return _Unknown("<native-allocation-limit>")
                self._native_region_count += 1
                self._native_allocated_bytes += size
                ref = _ObjectRef("native.memory", {"id": self._native_region_count, "size": size,
                                                  "protection": args[3], "data": None})
                self._emit("memory_allocate", api="VirtualAlloc", size=size, region=ref.state["id"],
                           protection=args[3], allocation_type=args[2], modeled=True)
                return ref
        if api == "virtualprotect" and len(args) == 4:
            region, size, protection = args[:3]
            if (isinstance(region, _ObjectRef) and region.kind == "native.memory"
                    and not self._native_region_storage(region).get('freed')
                    and type(size) is int and 0 < size <= region.state["size"] and type(protection) is int):
                self._emit("memory_protect", api="VirtualProtect", region=region.state["id"], size=size,
                           old_protection=region.state["protection"], protection=protection, modeled=True)
                region.state["protection"] = protection
                return True
        if api == "createthread" and len(args) == 6:
            region = args[2]
            known = isinstance(region, _ObjectRef) and region.kind == "native.memory"
            raw = self._native_region_storage(region).get("data") if known else None
            self._emit("thread_create", api="CreateThread", region=region.state["id"] if known else None,
                       flags=args[4], input_resolved=bool(raw), modeled=True)
            config = None
            if raw:
                self._remember_embedded_payload(raw, "CreateThread.start_address", payload_type="Shellcode")
                config = _recover_x64_wininet_config(raw)
                if config:
                    self._emit("embedded_payload_config", source="CreateThread.start_address",
                               evidence="static-analysis", payload_sha256=hashlib.sha256(raw).hexdigest(), **config)
            if raw:
                self._emulate_native_region(raw, [args[3]], 'CreateThread.start_address')
            else:
                self._emit("unresolved_dynamic_code", api="CreateThread.start_address", reason="native-code-not-emulated",
                           payload_available=False, configuration_recovered=bool(config))
            return _ObjectRef("native.thread", {"region": region})
        if api == "waitforsingleobject" and len(args) == 2:
            if isinstance(args[0], _ObjectRef) and args[0].kind == "native.thread":
                self._emit("thread_wait", api="WaitForSingleObject", timeout=args[1], modeled=True)
                return _Unknown("<native-thread-completion>")
        self._emit("unresolved_dynamic_code", api=name or "NativeDelegate.Invoke",
                   reason="native-code-not-emulated")
        return _Unknown("<native-call-result>")

    def _emulate_native_region(self, raw, args, source):
        """Explore guest instructions; synthetic profiles never establish caller state."""
        count = getattr(self, '_native_cpu_count', 0)
        if count >= 4:
            self._emit('resource_limit', resource='native_cpu_profiles', limit=4)
            return
        self._native_cpu_count = count + 1
        bits = 32 if raw.startswith(b'\xfc\xe8') else 64
        try:
            profile = _NativeCPUProfile(self, raw, bits, args)
            profile.run()
        except TimeoutError:
            raise
        except (ImportError, OSError) as error:
            self._emit('dependency_unavailable', api=source, dependency='unicorn', error=str(error))
        except Exception as error:
            # Engine/model errors must stay visible, not terminate PS recovery.
            self._emit('unsupported_operation', api=source, reason='native-engine-error', error=str(error))
        self._emit('unresolved_dynamic_code', api=source,
                   reason='native-profile-does-not-establish-caller-state',
                   payload_available=True, size=len(raw),
                   assumptions='x86 for conventional FC-E8 entry; otherwise x64 profile')

    def _crypt_string_to_binary_model(self, name, args):
        if len(args) == 7:
            source, length, flags, dest, length_ref, skip_ref, flags_ref = args
            reference = lambda value: isinstance(value, _ObjectRef) and value.kind == 'ps.reference'
            if (isinstance(source, str) and type(length) is int and 0 <= length <= len(source)
                    and type(flags) is int and flags == 1 and reference(length_ref)
                    and (skip_ref in (None, 0) or reference(skip_ref))
                    and (flags_ref in (None, 0) or reference(flags_ref))):
                text = source[:length] if length else source.split('\0', 1)[0]
                compact = re.sub(r'[\t\r\n ]', '', text)
                try:
                    raw = base64.b64decode(compact, validate=True)
                except (ValueError, binascii.Error):
                    raw = None
                if raw is not None and len(raw) <= MAX_EMBEDDED_PAYLOAD_BYTES:
                    query = dest in (None, 0)
                    capacity = self._apply_property(length_ref, 'Value')
                    region = isinstance(dest, _ObjectRef) and dest.kind == 'native.memory'
                    writable = region and dest.state.get('protection') in (0x04, 0x08, 0x40, 0x80)
                    if query or (writable and type(capacity) is int and len(raw) <= capacity <= dest.state['size']):
                        if not self._set_reference_value(length_ref, len(raw)):
                            return _Unknown('<reference-write-limit>')
                        if not query:
                            self._native_region_storage(dest)['data'] = raw
                        if reference(skip_ref):
                            self._set_reference_value(skip_ref, 0)
                        if reference(flags_ref):
                            self._set_reference_value(flags_ref, 1)
                        self._emit('data_decode', api=name, size=len(raw), length_query=query, modeled=True)
                        return True
        self._emit('unresolved_dynamic_code', api=name, reason='conversion-input-or-destination-not-modeled')
        return _Unknown('<native-conversion-result>')

    def _webclient_method(self, ref, method, args):
        url = args[0] if args else _Unknown("<url>")
        if method == "downloadstring":
            self._record_network(url, "GET", "WebClient.DownloadString")
            return _Unknown(f"<downloaded:{url}>")
        if method == "downloaddata":
            self._record_network(url, "GET", "WebClient.DownloadData")
            return _Unknown(f"<downloaded-bytes:{url}>")
        if method == "downloadfile":
            self._record_network(url, "GET", "WebClient.DownloadFile")
            dest = args[1] if len(args) > 1 else _Unknown("<path>")
            self._record_file_write(dest, _Unknown('<downloaded-file>'), "WebClient.DownloadFile")
            return None
        if method in ('uploadstring', 'uploaddata', 'uploadfile'):
            if len(args) not in (2, 3):
                self._emit('unsupported_operation', api='WebClient.' + method, reason='upload-overload-not-modeled')
                return _Unknown('<upload-input>')
            verb = args[1] if len(args) == 3 else None
            if verb is None:
                verb = 'STOR' if isinstance(url, str) and url.lower().startswith('ftp://') else 'POST'
            api = 'WebClient.UploadString' if method == 'uploadstring' else 'WebClient.' + method
            self._record_network(url, verb, api)
            if method == 'uploadfile':
                self._read_virtual_file(args[-1], api, as_bytes=True)
            return _Unknown("<upload-response>")
        if method == "adddefaultheaders" or method == "add" or method == "headers":
            return None
        return _Unknown(f"<webclient.{method}()>")

    def _httpclient_method(self, ref, method, args):
        if ref.kind == 'net.httpclient' and method in ('send', 'sendasync'):
            request = args[0] if args else None
            if not isinstance(request, _ObjectRef) or request.kind != 'net.http.httprequestmessage':
                self._emit('unsupported_operation', api='HttpClient.' + method, reason='http-request-message-unresolved')
                return _Unknown('<http-response>')
            if request.state.get('disposed') or request.state.get('sent'):
                self._emit('unsupported_operation', api='HttpClient.' + method, reason='http-request-message-not-reusable')
                return _Unknown('<http-response>')
            url = request.state.get('requesturi')
            if isinstance(url, _ObjectRef) and url.kind == 'uri':
                url = url.state.get('absoluteuri')
            verb = request.state.get('method')
            if isinstance(verb, _ObjectRef) and verb.kind == 'net.http.httpmethod':
                verb = verb.state.get('method')
            if not isinstance(url, str) or not re.match(r'^https?://', url, re.I) or not isinstance(verb, str):
                self._emit('unsupported_operation', api='HttpClient.' + method, reason='request-method-or-absolute-uri-unresolved')
                return _Unknown('<http-response>')
            request.state['sent'] = True
            self._record_network(url, verb, 'HttpClient.' + method)
            return _Unknown('<http-response>')
        if ref.kind in ('net.webrequest', 'net.httpwebrequest') and method in ('getresponse', 'begingetresponse'):
            self._record_network(ref.state.get('url', _Unknown('<url>')), ref.state.get('method', 'GET'), 'HttpWebRequest.' + method)
            return _Unknown('<http-response-not-provided>')
        if method in ("getstringasync", "getstring", "getasync", "get", "getbytearrayasync"):
            url = args[0] if args else _Unknown("<url>")
            self._record_network(url, "GET", f"HttpClient.{method}")
            return _Unknown("<http-response>")
        if method in ("postasync", "post"):
            url = args[0] if args else _Unknown("<url>")
            self._record_network(url, "POST", f"HttpClient.{method}")
            return _Unknown("<http-response>")
        return _Unknown(f"<httpclient.{method}()>")

    def _process_method(self, ref, method, args):
        if method == "start":
            start_info = ref.state.get("startinfo")
            source_state = start_info.state if isinstance(start_info, _ObjectRef) else ref.state
            filename = source_state.get("filename")
            arguments = source_state.get("arguments", "")
            if (not isinstance(filename, str) or not filename.strip()
                    or re.search(r'<(?:unknown|unresolved|truncated)', filename, re.I)):
                self._emit("unresolved_command", api="Diagnostics.Process.Start", reason="process-filename-unresolved",
                           path=_safe_text(filename), arguments=_safe_text(arguments))
                return _Unknown("<process-result>")
            command = f"{filename} {arguments}".strip() if not _is_unknown(filename) else str(filename)
            self._record_process(command, "Diagnostics.Process.Start", executable=filename, arguments=arguments)
            return True
        return _Unknown(f"<process.{method}()>")

    def _stream_method(self, ref, method, args):
        if ref.kind == 'security.cryptography.cryptostream':
            return self._cryptostream_method(ref, method, args)
        if ref.kind == 'io.streamreader':
            if method in ('close', 'dispose'):
                ref.state['closed'] = True
                source = ref.state.get('source')
                if isinstance(source, _ObjectRef) and ref.state.get('leave_open') is False:
                    self._stream_method(source, 'close', [])
                    source.state['closed'] = True
                return None
            if ref.state.get('closed'):
                return _Unknown('<closed-stream-reader>')
            if method == 'readtoend' and not args:
                source = ref.state.get('source')
                if isinstance(source, _ObjectRef) and source.kind == 'security.cryptography.cryptostream':
                    self._materialize_crypto_read(source)
                state = source.state if isinstance(source, _ObjectRef) else ref.state
                data, position = state.get('data'), state.get('position', 0)
                encoding = ref.state.get('encoding', 'utf8')
                if (not isinstance(data, bytes) or type(position) is not int or position < 0
                        or state.get('closed') or type(ref.state.get('detect_bom')) is not bool
                        or not isinstance(encoding, str) or encoding.lower() not in _DOTNET_CODECS):
                    return _Unknown('<stream-reader-input-unresolved>')
                data = data[position:]
                state['position'] = position + len(data)
                codec = _dotnet_codec(encoding)
                preamble = {'utf-8': b'\xef\xbb\xbf', 'utf-16-le': b'\xff\xfe', 'utf-16-be': b'\xfe\xff',
                            'utf-32-le': b'\xff\xfe\0\0'}.get(codec, b'') if ref.state.get('encoding_preamble', True) else b''
                if preamble and data.startswith(preamble):
                    data = data[len(preamble):]
                if ref.state.get('detect_bom', True):
                    if data.startswith((b'\xff\xfe\0\0', b'\0\0\xfe\xff')):
                        codec = 'utf-32'
                    elif data.startswith((b'\xff\xfe', b'\xfe\xff')):
                        codec = 'utf-16'
                    elif data.startswith(b'\xef\xbb\xbf'):
                        codec = 'utf-8-sig'
                return _cap(data.decode(codec, errors='replace'))
            self._emit('unsupported_operation', api='StreamReader.' + method, reason='reader-overload-not-modeled')
            return _Unknown('<stream-reader-operation>')
        if (ref.state.get('closed') and method not in ('close','dispose')
                and not (ref.kind == 'io.memorystream' and method == 'toarray')):
            return _Unknown('<closed-stream>')
        if method == "copyto" and args and isinstance(args[0], _ObjectRef):
            # ``$deflateStream.CopyTo($memStream)`` -- the standard
            # ``[IO.Compression.DeflateStream]``/``GZipStream`` read-out
            # idiom (as opposed to a constructor-time source, the other
            # shape already modeled): drains *this* stream's decoded
            # ``data`` into the destination stream's, so a later
            # ``$memStream.ToArray()`` sees the real decompressed bytes
            # instead of an empty buffer.
            source_data = ref.state.get("data")
            dest = args[0]
            if isinstance(source_data, (bytes, bytearray)):
                position = ref.state.get('position', 0)
                if type(position) is not int or not 0<=position<=len(source_data):
                    dest.state['data'] = None
                    return None
                self._write_stream_bytes(dest,[bytes(source_data[position:]),0,len(source_data)-position])
                ref.state['position'] = len(source_data)
            else:
                dest.state['data'] = None
            return None
        if method == 'read' and len(args) == 3:
            data = ref.state.get('data')
            target, offset, count = args
            if (not isinstance(target,(list,_BinaryValue))
                    or type(offset) is not int or type(count) is not int or offset < 0 or count < 0
                    or offset+count > (len(target.data) if isinstance(target,_BinaryValue) else len(target))):
                return _Unknown('<stream-read-input>')
            if not isinstance(data,bytes):
                if isinstance(target,list):
                    target[offset:offset+count] = [_Unknown('<unavailable-stream-byte>')]*count
                elif count:
                    target.complete = False
                return _Unknown('<stream-data>') if count else 0
            position = ref.state.get('position',0)
            if type(position) is not int or position<0:
                return _Unknown('<stream-position>')
            part = data[position:position+count]
            if isinstance(target,list):
                target[offset:offset+len(part)] = part
            else:
                target.data = target.data[:offset]+part+target.data[offset+len(part):]
                target.sha256 = hashlib.sha256(target.data).hexdigest()
            ref.state['position'] = position+len(part)
            return len(part)
        if ref.kind == 'io.filestream':
            if method == 'write':
                return self._write_stream_bytes(ref,args)
            if method in ('close','dispose','flush'):
                if ref.state.get('writable') and not ref.state.get('closed'):
                    data = ref.state.get('data')
                    self._record_file_write(ref.state.get('path'),data if data is not None else _Unknown('<stream-data>'),f'FileStream.{method}')
                if method != 'flush':
                    ref.state['closed'] = True
                return None
        if ref.kind == "io.memorystream":
            # Kept on real bytes in ``state["data"]`` throughout (not the
            # string ``buffer`` the text-oriented stream kinds below use)
            # -- a ``CryptoStream``/``GZipStream`` wrapping this needs to
            # read genuine binary content back out, not a stringified
            # approximation of it.
            if method == "write":
                return self._write_stream_bytes(ref,args)
            if method == "toarray":
                data = ref.state.get('data',b'')
                return _BinaryValue(data) if data is not None else _Unknown('<stream-data>')
            if method in ("close", "dispose", "flush", "seek", "setlength"):
                return None
        if method in ("write", "writeline"):
            data = args[0] if args else ""
            ref.state["buffer"] = str(ref.state.get("buffer", "")) + str(data)
            return None
        if method in ("writeallbytes", "writeallbytesasync"):
            return None
        if method in ("close", "dispose", "flush"):
            path = ref.state.get("path")
            if path:
                self._record_file_write(path, ref.state.get("buffer", ""), f"{ref.kind}.{method}")
            return None
        if method == "read" or method == "readtoend":
            data = ref.state.get("data")
            if data is None:
                return _Unknown("<stream-data>")
            try:
                return _cap(data.decode("utf-8", errors="replace"))
            except Exception:
                return _Unknown("<stream-data>")
        return _Unknown(f"<{ref.kind}.{method}()>")

    def _write_stream_bytes(self, ref, args):
        if ref.kind not in ('io.memorystream','io.filestream'):
            ref.state['data'] = None
            return _Unknown('<stream-destination-not-modeled>')
        if ref.kind=='io.filestream' and not ref.state.get('writable'):
            return _Unknown('<stream-not-writable>')
        raw = _as_bytes(args[0]) if args else None
        previous,position = ref.state.get('data'),ref.state.get('position',0)
        offset = args[1] if len(args)>1 else 0
        count = args[2] if len(args)>2 else len(raw) if raw is not None else None
        if (raw is None or not isinstance(previous,bytes) or type(position) is not int or position<0
                or type(offset) is not int or type(count) is not int or not 0<=offset<=len(raw) or not 0<=count<=len(raw)-offset):
            ref.state['data'] = None
            return None
        end = position+count
        if end>MAX_EMBEDDED_PAYLOAD_BYTES:
            ref.state['data'] = None
            self._emit('resource_limit',resource='stream_bytes',limit=MAX_EMBEDDED_PAYLOAD_BYTES)
            return None
        ref.state['data'] = previous[:position]+b'\0'*max(0,position-len(previous))+raw[offset:offset+count]+previous[end:]
        ref.state['position'] = end
        return None

    def _stringbuilder_method(self, ref, method, args):
        if method == "append" and args:
            ref.state["text"] = str(ref.state.get("text", "")) + str(args[0])
            return ref
        if method == "tostring":
            return _cap(str(ref.state.get("text", "")))
        if method == "clear":
            ref.state["text"] = ""
            return ref
        return _Unknown(f"<stringbuilder.{method}()>")

    def _adodb_stream_method(self, ref, method, args):
        if method == "open":
            return None
        if method == "write" or method == "writetext":
            data = args[0] if args else ""
            ref.state["buffer"] = ref.state.get("buffer", b"" if isinstance(data, (bytes, _BinaryValue)) else "")
            if isinstance(data, _BinaryValue):
                ref.state["buffer"] = (ref.state["buffer"] if isinstance(ref.state["buffer"], bytes) else b"") + data.data
            else:
                ref.state["buffer"] = str(ref.state.get("buffer", "")) + str(data)
            self._emit("stream_write", api=f"ADODB.Stream.{method}", size_hint=len(str(data)))
            return None
        if method == "savetofile":
            path = args[0] if args else _Unknown("<path>")
            self._record_file_write(path, ref.state.get("buffer", ""), "ADODB.Stream.SaveToFile")
            return None
        if method in ("close",):
            return None
        return _Unknown(f"<adodb.{method}()>")

    def _materialize_crypto_read(self, ref):
        if 'data' in ref.state or ref.state.get('closed'):
            return
        ref.state['data'] = None
        source, transform = ref.state.get('target'), ref.state.get('transform')
        if (ref.state.get('mode') != 'read' or not isinstance(source, _ObjectRef)
                or source.kind not in ('io.memorystream', 'io.filestream')
                or source.state.get('closed') or not isinstance(transform, _ObjectRef)
                or transform.kind != 'crypto.transform'):
            return
        data, position = source.state.get('data'), source.state.get('position', 0)
        if (not isinstance(data, bytes) or type(position) is not int
                or not 0 <= position <= len(data)):
            return
        result = _aes_transform(data[position:], transform.state.get('key'),
                                transform.state.get('iv'), transform.state.get('mode', 'cbc'),
                                bool(transform.state.get('encrypt')))
        if result is not None and len(result) <= MAX_EMBEDDED_PAYLOAD_BYTES:
            source.state['position'] = len(data)
            ref.state['data'] = result
            ref.state['position'] = 0

    def _cryptostream_method(self, ref, method, args):
        if method in ('close', 'dispose') and ref.state.get('mode') == 'read':
            ref.state['closed'] = True
            source = ref.state.get('target')
            if isinstance(source, _ObjectRef) and ref.state.get('leave_open') is False:
                source.state['closed'] = True
            return None
        if method == "write":
            data = _as_bytes(args[0]) if args else None
            if data is None:
                return None
            try:
                offset = int(_numeric_coerce(args[1])) if len(args) > 1 and not _is_unknown(args[1]) else 0
                count = int(_numeric_coerce(args[2])) if len(args) > 2 and not _is_unknown(args[2]) else len(data) - offset
            except (TypeError, ValueError):
                offset, count = 0, len(data)
            ref.state["pending"] = ref.state.get("pending", b"") + data[offset:offset + count]
            return None
        if method in ("flushfinalblock", "close", "dispose", "flush"):
            pending = ref.state.get("pending", b"")
            transform = ref.state.get("transform")
            target = ref.state.get("target")
            if pending and isinstance(transform, _ObjectRef) and transform.kind == "crypto.transform" and isinstance(target, _ObjectRef):
                result = _aes_transform(
                    pending, transform.state.get("key"), transform.state.get("iv"),
                    transform.state.get("mode", "cbc"), bool(transform.state.get("encrypt")),
                )
                if result is not None:
                    target.state["data"] = target.state.get("data", b"") + result
                    ref.state["pending"] = b""
            return None
        return _Unknown(f"<cryptostream.{method}()>")

    def _com_httprequest_method(self, ref, method, args):
        if method == "open":
            # ``.Open("GET", $url, $false)`` -- records the request's
            # shape; the real network attempt (matching ``WebClient``'s
            # own timing) is emitted on ``.Send()`` below, not here.
            ref.state["method"] = args[0] if args else "GET"
            ref.state["url"] = args[1] if len(args) > 1 else _Unknown("<url>")
            return None
        if method == "setrequestheader" or method == "setproxy" or method == "setcredentials":
            return None
        if method == "send":
            http_method = ref.state.get("method", "GET")
            method_text = str(http_method).upper() if not _is_unknown(http_method) else "GET"
            self._record_network(ref.state.get("url", _Unknown("<url>")), method_text, f"{ref.kind}.Send")
            ref.state["responsetext"] = _Unknown("<http-response>")
            ref.state["responsebody"] = _Unknown("<http-response>")
            ref.state["status"] = 200
            return None
        if method == "waitforresponse":
            return True
        if method in ("getallresponseheaders", "getresponseheader"):
            return _Unknown("<http-headers>")
        return _Unknown(f"<{ref.kind}.{method}()>")

    # -- static (``[Type]::Member``) and cast (``[Type]expr``) evaluation ----

    def _eval_static_member(self, type_name, member, rest):
        type_key = type_name.lower().replace("system.", "", 1)
        member_key = member.lower()
        rest = rest.lstrip()
        is_call = rest[:1] == "("
        args = []
        suffix = rest
        if is_call:
            raw_args, end_index = _extract_balanced(rest, 0, "(", ")")
            if raw_args is None:
                return _Unknown(f"[{type_name}]::{member}(<unbalanced>)")
            args = [self._eval_expr(part) for part in _split_top_level(raw_args, ",")] if raw_args.strip() else []
            suffix = rest[end_index + 1:].strip()
        value = self._dispatch_static(type_key, member_key, args, is_call)
        return self._eval_suffix(value, suffix) if suffix else value

    def _eval_type_suffix(self, value, suffix):
        if not isinstance(value, _ObjectRef) or value.kind != "reflection.type":
            return _Unknown("<unresolved-static-type>")
        text = suffix[2:].lstrip()
        if text.startswith("("):
            expression, end = _extract_balanced(text, 0, "(", ")")
            if expression is None:
                return _Unknown("<unresolved-static-member>")
            member = self._eval_member_name(expression)
            rest = text[end + 1:]
        elif text.startswith('$'):
            match = re.match(rf'^({_VAR_REF})(.*)$', text, re.DOTALL)
            if not match:
                return _Unknown('<unresolved-static-member>')
            member = self._read_variable(match[1])
            rest = match[2]
        else:
            match = re.match(r"^(\w+)(.*)$", text, re.DOTALL)
            if not match:
                return _Unknown("<unresolved-static-member>")
            member, rest = match.groups()
        if not isinstance(member, str) or not member.strip():
            return _Unknown("<unresolved-static-member>")
        return self._eval_static_member(value.state.get("type_key", ""), member.strip(), rest)

    def _dispatch_static(self, type_key, member_key, args, is_call):
        if type_key == 'reflection.emit.opcodes' and not is_call:
            return _ObjectRef('cil.opcode', {'name': member_key})
        if type_key == 'reflection.emit.dynamicmethod' and member_key == 'new' and is_call:
            return self._new_dynamic_method(args)
        if type_key in self._native_declared_types and is_call:
            symbol = self._native_declared_types[type_key].get(member_key)
            if symbol:
                return self._invoke_native_model(_ObjectRef('native.delegate', {
                    'function': _ObjectRef('native.function', symbol)}), args)
        if type_key in self._script_types:
            definition = self._script_types[type_key]
            if definition['kind'] == 'enum' and not is_call:
                return definition['members'].get(member_key, _Unknown('<enum-member>'))
            if member_key == 'new' and is_call:
                return self._new_script_instance(type_key, args)
            self._emit('unsupported_operation', api='PowerShellClass.StaticMember', type=type_key, member=member_key)
            return _Unknown('<script-static-member>')
        if type_key in ('intptr', 'uintptr') and member_key == 'zero' and not is_call:
            return 0
        if type_key == 'net.http.httprequestmessage' and member_key == 'create':
            self._emit('unsupported_operation', api='HttpRequestMessage.Create', reason='method-does-not-exist-use-constructor')
            return _Unknown('<invalid-http-request-factory>')
        if type_key == 'net.http.httpmethod' and not is_call and member_key in ('get', 'post', 'put', 'delete', 'head', 'options', 'trace', 'patch', 'connect'):
            return _ObjectRef(type_key, {'method': member_key.upper()})
        if type_key in ('regex', 'text.regularexpressions.regex') and member_key == 'escape' and is_call:
            if len(args) != 1 or not isinstance(args[0], str):
                return _Unknown('<regex-escape-input>')
            escapes = {'\t': r'\t', '\n': r'\n', '\r': r'\r', '\f': r'\f'}
            return _cap(''.join(escapes.get(c, '\\' + c if c in '\\*+?|{[()^$.# ' else c) for c in args[0]))
        if type_key == 'windows.forms.systeminformation' and member_key == 'virtualscreen' and not is_call:
            self._emit('unresolved_environment', api='SystemInformation.VirtualScreen', reason='screen-geometry-not-provided')
            return _ObjectRef('drawing.rectangle', {name: _Unknown('<screen-geometry>') for name in ('left', 'top', 'width', 'height')})
        if type_key == 'drawing.graphics' and member_key == 'fromimage' and len(args) == 1:
            if isinstance(args[0], _ObjectRef) and args[0].kind == 'drawing.bitmap' and not args[0].state.get('disposed'):
                return _ObjectRef('drawing.graphics', {'image': args[0]})
            return _Unknown('<graphics-image-unresolved>')
        if type_key in _HASH_TYPES and member_key in ('create','new'):
            return self._instantiate(type_key,args)
        if type_key in ('bigint', 'numerics.biginteger'):
            if member_key == 'parse' and args and isinstance(args[0], str) and re.fullmatch(r'[+-]?\d{1,1300}', args[0].strip()):
                return int(args[0])
            if member_key in ('divide','remainder') and len(args) == 2 and all(type(n) is int for n in args) and args[1] != 0:
                quotient = (abs(args[0]) // abs(args[1])) * (-1 if (args[0] < 0) != (args[1] < 0) else 1)
                return quotient if member_key == 'divide' else args[0] - quotient * args[1]
            return _Unknown('<bigint-operation>')
        if type_key == 'math' and member_key == 'abs' and is_call:
            if len(args) == 1:
                value = args[0]
                # Signed minimum values overflow their respective overload;
                # plain Python integers cannot prove a wider CLR provenance.
                if (type(value) is int and -(1 << 63) < value < (1 << 63)
                        and value not in (-128, -32768, -(1 << 31))):
                    return abs(value)
                if type(value) is float and math.isfinite(value):
                    return abs(value)
            self._emit('unsupported_operation', api='Math.Abs', reason='numeric-overload-or-overflow-unresolved')
            return _Unknown('<math-abs>')
        if type_key == 'math' and member_key in ('floor', 'ceiling', 'truncate'):
            if len(args) == 1 and type(args[0]) in (int, float):
                try:
                    return {'floor': math.floor, 'ceiling': math.ceil, 'truncate': math.trunc}[member_key](args[0])
                except (ValueError, OverflowError):
                    pass
            return _Unknown('<math-input>')
        if type_key in ('net.webrequest', 'net.httpwebrequest') and member_key in ('create', 'createhttp') and args:
            return _ObjectRef('net.httpwebrequest', {'url': args[0], 'method': 'GET'})
        if type_key == "microsoft.win32.unsafenativemethods":
            if member_key == "getmodulehandle" and args and isinstance(args[0], str):
                return _ObjectRef("native.module", {"name": args[0].lower()})
            if member_key == "getprocaddress" and len(args) >= 2:
                module = args[0]
                if isinstance(module, _ObjectRef) and module.kind == "native.handleref":
                    module = module.state.get("handle")
                if isinstance(module, _ObjectRef) and module.kind == "native.module" and isinstance(args[1], str):
                    return _ObjectRef("native.function", {"module": module.state["name"], "name": args[1]})
            return _Unknown("<native-symbol>")
        if type_key == "management.automation.scriptblock":
            type_key = "scriptblock"
        if type_key in ("powershell", "management.automation.powershell") and member_key == "create":
            if not args:
                return _ObjectRef("powershell.pipeline")
            self._emit('unresolved_dynamic_code', api='PowerShell.Create', reason='creation-overload-not-modeled')
            return _Unknown('<runspace-creation>')
        if type_key in ('runspacefactory', 'management.automation.runspaces.runspacefactory'):
            if member_key == 'createrunspace' and not args:
                return _ObjectRef('powershell.runspace', {'opened': False})
            if member_key == 'createrunspacepool' and (not args or len(args) == 2 and
                    all(type(x) is int for x in args) and 1 <= args[0] <= args[1] <= 32):
                return _ObjectRef('powershell.runspacepool', {'opened': False})
        if not is_call and type_key == "reflection.assembly" and member_key in ("load", "loadwithpartialname", "loadfrom", "loadfile"):
            return _ObjectRef("static.method", {"type_key": type_key, "member": member_key})
        if type_key == 'bitconverter' and member_key == 'tostring':
            raw = None
            if 1 <= len(args) <= 3:
                source = args[0]
                if isinstance(source, _BinaryValue) and source.complete:
                    raw = source.data
                elif (isinstance(source, list) and len(source) <= MAX_EMBEDDED_PAYLOAD_BYTES
                      and all(type(x) is int and 0 <= x <= 255 for x in source)):
                    raw = bytes(source)
            start = args[1] if len(args) >= 2 else 0
            count = args[2] if len(args) == 3 else (len(raw) - start if raw is not None and type(start) is int else None)
            # .NET permits start=0 for an empty array, but otherwise the
            # start index must refer to an existing byte, even for count=0.
            if (raw is None or type(start) is not int or type(count) is not int
                    or start < 0 or (start >= len(raw) and start != 0)
                    or count < 0 or count > len(raw) - start):
                self._emit('unsupported_operation', api='BitConverter.ToString', reason='input-or-range-unresolved-or-invalid')
                return _Unknown('<bitconverter-string>')
            if max(0, count * 3 - 1) > MAX_VALUE_CHARS:
                self._emit('resource_limit', resource='bitconverter_string', limit=MAX_VALUE_CHARS)
                return _Unknown('<bitconverter-string-limit>')
            return raw[start:start + count].hex('-').upper()
        if type_key == "bitconverter" and member_key == "getbytes" and len(args) == 1:
            value = args[0]
            # Model concrete Int32/bool overloads with Windows byte order.
            if isinstance(value, bool):
                return _BinaryValue(bytes([int(value)]))
            if isinstance(value, int) and -(2 ** 31) <= value < 2 ** 31:
                return _BinaryValue(struct.pack("<i", value))
            self._emit("unsupported_operation", api="BitConverter.GetBytes", reason="unresolved-or-unsupported-overload")
            return _Unknown("<bitconverter-bytes>")
        if member_key == "new":
            # ``[System.IO.MemoryStream]::new(...)`` -- the static-call
            # spelling of ``New-Object System.IO.MemoryStream(...)``, and
            # semantically identical to it. Every type this emulator
            # models a real constructor for (``byte[]``, MemoryStream,
            # GzipStream, StreamReader, ...) needs to reach
            # ``_instantiate`` this way too, not just the array-type
            # case -- a real RC4/gzip decode chain reaches for either
            # spelling interchangeably.
            return self._instantiate(type_key, args)
        if type_key == "convert":
            if member_key == "frombase64string" and args and not _is_unknown(args[0]):
                try:
                    # .NET accepts whitespace, but not arbitrary discarded
                    # characters or automatically repaired missing padding.
                    encoded = re.sub(r'[ \t\r\n]', '', str(args[0]))
                    if len(encoded) % 4 or encoded.endswith('==='):
                        raise ValueError('invalid-base64-length')
                    return _BinaryValue(base64.b64decode(encoded, validate=True))
                except (ValueError, binascii.Error):
                    self._emit('unparsed_input', api='Convert.FromBase64String', kind='invalid-base64', reason='invalid-base64-input')
                    return _Unknown("<bad-base64>")
            if member_key == "tobase64string" and args:
                raw = _as_bytes(args[0])
                return base64.b64encode(raw).decode("ascii") if raw is not None else _Unknown("<base64-encode>")
            if member_key in (
                "tobyte", "tosbyte", "toint16", "touint16", "toint32", "toint64",
                "touint32", "touint64", "todouble", "tostring",
            ) and args:
                # A 2-arg overload (``ToByte("1A", 16)``, ``ToInt32(str,
                # base)``) parses a string in the given base -- the exact
                # idiom a hex-decode loop uses per byte pair. Anything else
                # falls back to plain numeric coercion.
                if len(args) >= 2 and isinstance(args[0], str) and not _is_unknown(args[1]):
                    try:
                        base = int(_numeric_coerce(args[1]))
                        return int(args[0].strip(), base)
                    except (TypeError, ValueError):
                        return _Unknown(f"<{member_key}>")
                try:
                    coerced = _numeric_coerce(args[0])
                    if member_key == "tostring":
                        return str(coerced)
                    return float(coerced) if member_key == "todouble" else int(coerced)
                except (TypeError, ValueError):
                    return _Unknown(f"<{member_key}>")
        if type_key in ("text.encoding", "encoding"):
            if member_key in ("utf8", "ascii", "unicode", "utf32", "default", "bigendianunicode"):
                return _ObjectRef("text.encoding", {"name": member_key})
            if member_key == "getencoding":
                # ``[System.Text.Encoding]::GetEncoding("Unicode")`` -- the
                # method-call spelling of the ``::Unicode``/``::UTF8``
                # static-property shorthand above. Losing the requested
                # *name* here (the previous bare-placeholder behavior)
                # meant every ``.GetString()``/``.GetBytes()`` downstream
                # silently assumed UTF-8 regardless of what was actually
                # asked for -- garbling any UTF-16 ("Unicode", .NET's
                # default for this exact reflection-based decode idiom)
                # payload into null-interleaved noise instead of readable
                # text.
                name = str(args[0]).lower() if args and not _is_unknown(args[0]) else "utf8"
                return _ObjectRef("text.encoding", {"name": name})
        if type_key in ("io.file", "file"):
            if member_key == 'openread' and args:
                return self._instantiate('io.filestream',[args[0],'open','read'])
            if member_key == 'openwrite' and args:
                return self._instantiate('io.filestream',[args[0],'openorcreate','write'])
            if member_key == 'create' and args:
                return self._instantiate('io.filestream',[args[0],'create','readwrite'])
            if member_key in ("writeallbytes", "writealltext") and len(args) >= 2:
                encoding = args[2].state.get('name') if len(args)>2 and isinstance(args[2],_ObjectRef) else None
                self._record_file_write(args[0], args[1], f"IO.File.{member_key}",encoding=encoding,
                                        utf8_bom=encoding in ('utf8','utf-8'),
                                        emit_bom=args[2].state.get('emit_bom',True) if len(args)>2 and isinstance(args[2],_ObjectRef) else True)
                return None
            if member_key == "exists":
                return self._virtual_file_key(args[0]) in self._virtual_files if args else False
            if member_key in ("delete", "copy", "move", "appendalltext"):
                if member_key == "appendalltext" and len(args) >= 2:
                    encoding = args[2].state.get('name') if len(args)>2 and isinstance(args[2],_ObjectRef) else None
                    self._record_file_write(args[0], args[1], "IO.File.AppendAllText",encoding=encoding,append=True)
                elif member_key in ('copy','move') and len(args)>=2:
                    self._transfer_virtual_file(args[0],args[1],f'IO.File.{member_key}',move=member_key=='move')
                elif member_key == 'delete' and args:
                    self._forget_virtual_file(args[0])
                    self._emit('filesystem_delete',path=_safe_text(args[0]),api='IO.File.Delete')
                return None
            if member_key in ("readallbytes", "readalltext", "readalllines"):
                encoding = args[1].state.get('name') if len(args)>1 and isinstance(args[1],_ObjectRef) else None
                value = self._read_virtual_file(args[0] if args else None,f'IO.File.{member_key}',as_bytes=member_key=='readallbytes',encoding=encoding)
                return value.splitlines() if member_key=='readalllines' and isinstance(value,str) else value
        if type_key in ("io.directory", "directory"):
            if member_key in ("createdirectory",):
                return None
            if member_key == "exists":
                return False
        if type_key in ("io.path", "path"):
            # A dropper's "write the payload to a temp file, then spawn
            # a process pointed at it" step almost always builds that
            # temp path through here first -- leaving it ``_Unknown``
            # (the previous behavior) meant the write/spawn events that
            # follow could never show a real path or command line at
            # all, only ``<unknown:...>``.
            if member_key == "gettempfilename":
                return "C:\\Users\\User\\AppData\\Local\\Temp\\tmp8F3A.tmp"
            if member_key == "gettemppath":
                return "C:\\Users\\User\\AppData\\Local\\Temp\\"
            if member_key == "getrandomfilename":
                return "a1b2c3d4.tmp"
            if member_key == "combine" and args:
                parts = args[0] if len(args) == 1 and isinstance(args[0], list) else args
                if any(not isinstance(part, str) or '\0' in part or
                       re.search(r'<(?:unknown|unresolved|truncated)', part, re.I) for part in parts):
                    self._emit('unsupported_operation', api='IO.Path.Combine', reason='path-component-unresolved')
                    return _Unknown('<combined-path>')
                # Windows Path.Combine preserves rooted components and resets
                # the preceding path when a later component is rooted. Missing
                # components must not be silently removed from the result.
                combined = ''
                for part in parts:
                    if not part:
                        continue
                    if not combined or part.startswith(('\\', '/')) or (len(part) > 1 and part[1] == ':'):
                        combined = part
                    else:
                        combined += ('' if combined.endswith(('\\', '/', ':')) else '\\') + part
                    if len(combined) > MAX_VALUE_CHARS:
                        self._emit('resource_limit', resource='combined_path_chars', limit=MAX_VALUE_CHARS)
                        return _Unknown('<combined-path-limit>')
                return combined
            if member_key in ("getextension", "getfilename", "getfilenamewithoutextension", "getdirectoryname"):
                path_text = str(args[0]) if args and not _is_unknown(args[0]) else None
                if path_text is None:
                    return _Unknown("<path>")
                normalized = path_text.replace("\\", "/")
                base = normalized.rsplit("/", 1)[-1]
                if member_key == "getdirectoryname":
                    return normalized.rsplit("/", 1)[0] if "/" in normalized else ""
                if member_key == "getfilename":
                    return base
                stem, _, ext = base.rpartition(".")
                if member_key == "getextension":
                    return f".{ext}" if stem else ""
                return stem if stem else base
        if type_key == "guid":
            if member_key == "newguid":
                self._guid_counter += 1
                self._emit('modeled_random',api='Guid.NewGuid',representation='deterministic-unique-guid')
                # Common droppers use only Substring(0, 8) as a filename.
                # A counter confined to the tail made every such name collide.
                # An odd multiplier permutes the first 32 bits without collisions
                # within our statement budget; the rest is deterministic data.
                prefix = f'{(self._guid_counter * 0x9e3779b1) & 0xffffffff:08x}'
                tail = hashlib.sha256(f'qu1cksc0pe-guid-{self._guid_counter}'.encode()).hexdigest()
                return _GuidValue(f'{prefix}-{tail[:4]}-4{tail[4:7]}-8{tail[7:10]}-{tail[10:22]}')
            if member_key == "empty":
                return _GuidValue('00000000-0000-0000-0000-000000000000')
            if member_key in ('parse','new'):
                return self._instantiate('guid',args)
        if type_key in ("diagnostics.process", "process"):
            if member_key == "start" and args:
                # ``[Diagnostics.Process]::Start($startInfo)`` -- the
                # single-argument overload, taking an already-built
                # ``ProcessStartInfo`` object -- as opposed to the
                # ``Start(filename, arguments)`` 2-arg overload below.
                # Treating that whole object as a literal filename
                # stringified it to an opaque ``<object:...>`` repr
                # instead of the real command.
                if isinstance(args[0], _ObjectRef) and args[0].kind == "diagnostics.processstartinfo":
                    filename = args[0].state.get("filename", "<process>")
                    arguments = args[0].state.get("arguments", "")
                else:
                    filename = args[0]
                    arguments = args[1] if len(args) > 1 else ""
                if filename is None or _is_unknown(filename) or not str(filename).strip():
                    self._emit("unresolved_command", api="Diagnostics.Process.Start", reason="process-filename-unresolved")
                    return _Unknown("<process-result>")
                command = f"{filename} {arguments}".strip() if not _is_unknown(filename) else str(filename)
                self._record_process(command, "Diagnostics.Process.Start", executable=filename, arguments=arguments)
                return _ObjectRef("diagnostics.process", {"filename": filename, "arguments": arguments})
            if member_key == "getcurrentprocess":
                return _ObjectRef("diagnostics.process")
        if type_key in ("reflection.assembly", "assembly"):
            if member_key in ("load", "loadfile", "loadwithpartialname", "loadfrom", "unsafeloadfrom") and args:
                # These overloads accept a display name or a file path,
                # not embedded assembly bytes. Never dump the reference
                # string itself as a recovered payload or read the host.
                reference_only = member_key != 'load' or isinstance(args[0], str)
                if reference_only:
                    reference = args[0]
                    resolved = isinstance(reference, str) and not _is_unknown(reference)
                    self._emit('assembly_reference', api=f'Reflection.Assembly.{member_key}',
                               reference=reference if resolved else None,
                               reference_resolved=resolved, content_available=False)
                    return _ObjectRef('reflection.assembly')
                raw = _as_bytes(args[0])
                if raw:
                    self._remember_embedded_payload(raw, f"Reflection.Assembly.{member_key}")
                self._emit("dynamic_code", api=f"Reflection.Assembly.{member_key}", size=len(raw) if raw is not None else None, input_resolved=raw is not None)
                if raw is None:
                    self._emit("unresolved_dynamic_code", api=f"Reflection.Assembly.{member_key}", reason="assembly-input-unresolved")
                return _ObjectRef("reflection.assembly")
        if type_key == 'threading.thread' and member_key == 'getdomain':
            return _ObjectRef('appdomain')
        if type_key == "appdomain":
            if member_key == "currentdomain":
                return _ObjectRef("appdomain")
        if type_key == "scriptblock":
            if member_key == "create" and args:
                source = args[0]
                resolved = isinstance(source, str) and not _is_unknown(source)
                return _ObjectRef("scriptblock", {"source": source if resolved else "",
                                                  "source_resolved": resolved, "generated": True})
        if type_key == "uri":
            if member_key in ("escapedatastring", "escapeuristring") and args and not _is_unknown(args[0]):
                # ``[Uri]::EscapeDataString($x)`` -- URL-encoding a
                # value right before it's appended to a query string is
                # the near-universal last step of building a C2 beacon
                # URL; a real (if approximate -- ``EscapeUriString``
                # leaves a few more characters unescaped than
                # ``EscapeDataString`` does) percent-encoding here is
                # what lets the *whole* URL resolve instead of leaving
                # this one segment -- and everything concatenated after
                # it -- as ``_Unknown``.
                return urllib.parse.quote(str(args[0]), safe="")
            if member_key == "unescapedatastring" and args and not _is_unknown(args[0]):
                try:
                    return urllib.parse.unquote(str(args[0]))
                except Exception:
                    return _Unknown("<unescape>")
        if type_key == "environment":
            if member_key == "getenvironmentvariable" and args:
                name = str(args[0]).lower() if not _is_unknown(args[0]) else ""
                self._emit("environment_access", name=name or "<unknown>")
                return self.variables.get(f"env:{name}", _Unknown(f"<env:{name}>"))
            if member_key == "is64bitprocess":
                return True
            if member_key in ("expandenvironmentvariables",) and args:
                return args[0]
            if member_key == "getfolderpath":
                # ``[Environment]::GetFolderPath([Environment+SpecialFolder]::
                # ApplicationData)`` -- the .NET spelling of the same
                # ``$env:APPDATA``-style paths this emulator already
                # models; the argument is normally a bareword enum
                # member (``ApplicationData``), which resolves to a
                # plain string here (an enum literal, not a real
                # variable/cmdlet), so a lower-cased string match covers
                # both that and an explicit ``"ApplicationData"`` string.
                folder = str(args[0]).lower().rsplit(".", 1)[-1] if args and not _is_unknown(args[0]) else ""
                folder_paths = {
                    "applicationdata": "C:\\Users\\User\\AppData\\Roaming",
                    "localapplicationdata": "C:\\Users\\User\\AppData\\Local",
                    "commonapplicationdata": "C:\\ProgramData",
                    "userprofile": "C:\\Users\\User",
                    "desktop": "C:\\Users\\User\\Desktop",
                    "desktopdirectory": "C:\\Users\\User\\Desktop",
                    "mydocuments": "C:\\Users\\User\\Documents",
                    "personal": "C:\\Users\\User\\Documents",
                    "startup": "C:\\Users\\User\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup",
                    "system": "C:\\Windows\\System32",
                    "systemx86": "C:\\Windows\\SysWOW64",
                    "windows": "C:\\Windows",
                    "temp": "C:\\Users\\User\\AppData\\Local\\Temp",
                    "programfiles": "C:\\Program Files",
                    "programfilesx86": "C:\\Program Files (x86)",
                }
                return folder_paths.get(folder, "C:\\Users\\User\\AppData\\Roaming")
        if type_key == "array":
            if member_key == 'clear':
                if len(args) not in (1, 3) or not isinstance(args[0], (_BinaryValue, list)):
                    self._emit('unsupported_operation', api='Array.Clear', reason='array-or-overload-not-modeled')
                    return _Unknown('<array-clear-input>')
                target = args[0]
                start, count = args[1:] if len(args) == 3 else (0, len(target))
                # Null and Boolean have unambiguous Int32 parameter
                # conversions; other non-integer bindings stay symbolic.
                start = 0 if start is None else int(start) if type(start) is bool else start
                count = 0 if count is None else int(count) if type(count) is bool else count
                if type(start) is not int or type(count) is not int:
                    # A possibly performed mutation cannot leave the old
                    # bytes available as a known post-call value.
                    if isinstance(target, _BinaryValue):
                        target.complete = False
                    else:
                        target[:] = [_Unknown('<array-clear-range>')] * len(target)
                    self._emit('unsupported_operation', api='Array.Clear', reason='clear-range-unresolved')
                    return _Unknown('<array-clear-range>')
                if (start < 0 or count < 0 or start > 2147483647 or count > 2147483647
                        or start > len(target) or count > len(target) - start):
                    self._emit('unsupported_operation', api='Array.Clear', reason='invalid-clear-range')
                    return _Unknown('<array-clear-range>')
                if not count:
                    return None
                if isinstance(target, _BinaryValue):
                    # Preserve aliases and previously copied native/stream
                    # buffers: replace this managed byte array's data only.
                    target.data = target.data[:start] + bytes(count) + target.data[start + count:]
                    target.sha256 = hashlib.sha256(target.data).hexdigest()
                    self._emit('memory_clear', api='Array.Clear', offset=start, size=count,
                               target='managed-byte-array', output_resolved=target.complete)
                    return None
                if isinstance(target, (_ByteArray, _IntegerArray, _FloatingArray)):
                    target[start:start + count] = [0.0 if isinstance(target, _FloatingArray) else 0] * count
                    self._emit('memory_clear', api='Array.Clear', offset=start, size=count,
                               target='managed-byte-array' if isinstance(target, _ByteArray) else 'managed-integer-array',
                               output_resolved=all(type(x) in (int, float) for x in target))
                    return None
                if isinstance(target, _ObjectArray):
                    target[start:start + count] = [None] * count
                    self._emit('memory_clear', api='Array.Clear', offset=start, size=count,
                               target='managed-object-array', output_resolved=True)
                    return None
                # Plain list values currently do not retain the CLR array's
                # element type. Object[] needs null, Int32[] needs zero, etc.
                target[start:start + count] = [_Unknown('<array-element-default>')] * count
                self._emit('unsupported_operation', api='Array.Clear', reason='array-element-type-unresolved')
                return _Unknown('<array-clear-element-type>')
            if member_key in ('reverse', 'copy'):
                return self._array_data_operation(member_key, args)
        if type_key == 'char' and member_key in ('toupper', 'tolower', 'toupperinvariant', 'tolowerinvariant'):
            if len(args) == 1 and isinstance(args[0], str) and not _is_unknown(args[0]) and len(args[0]) == 1:
                char = args[0]
                invariant = member_key.endswith('invariant')
                upper = member_key.startswith('toupper')
                # One UTF-16 code unit is required. Do not use Python's
                # full Unicode casing, which can expand a char into text.
                # Without a modeled culture, dotted/dotless I is unknown.
                if ord(char) < 128 and (invariant or char != ('i' if upper else 'I')):
                    return _CharValue(char.upper() if upper else char.lower())
                if 0xD800 <= ord(char) <= 0xDFFF:
                    return _CharValue(char)
            self._emit('unsupported_operation', api='Char.' + member_key,
                       reason='character-or-culture-not-modeled')
            return _Unknown('<character-case>')
        if type_key == "char" and member_key == "convertfromutf32" and args:
            try:
                return chr(int(_numeric_coerce(args[0])))
            except (TypeError, ValueError, OverflowError):
                return _Unknown("<char>")
        if type_key == 'string' and member_key == 'format' and len(args) >= 2:
            items = args[1] if len(args) == 2 and isinstance(args[1], list) else args[1:]
            if not isinstance(args[0], str) or any(_is_unknown(item) for item in items):
                return _Unknown('<format-input>')
            return self._format_string(args[0], items)
        if type_key == "string" and member_key in ('concat', 'join'):
            return self._string_combine(member_key, args)
        if type_key == "string" and member_key == "isnullorempty":
            if args and _is_unknown(args[0]):
                return _Unknown('<string-null-or-empty>')
            return args[0] is None or (isinstance(args[0], str) and args[0] == "") if args else True
        if type_key == "type" and member_key == "gettype" and args and not _is_unknown(args[0]):
            # ``[Type]::GetType("Sys"+"tem.Con"+"vert")`` -- a dynamically
            # *named* type reference, functionally identical to the
            # literal ``[System.Convert]`` spelling once the concatenated
            # string resolves, used specifically to keep that type name
            # out of the source as a plain static-signature string.
            # Resolved to the same ``reflection.type`` shape the literal
            # bracket syntax already produces (see the ``type_member_match``
            # branch in ``_eval_expr``) so ``.GetMethods()``/``.Invoke()``
            # chains built on it have something real to work with instead
            # of every one of them collapsing to ``_Unknown``.
            type_key_resolved = str(args[0]).strip("'\"").lower().replace("system.", "", 1)
            return _ObjectRef("reflection.type", {"type_key": type_key_resolved})
        if type_key == "activator" and member_key == "createinstance":
            return _ObjectRef("activator.instance")
        if type_key in (
            "security.cryptography.ciphermode", "security.cryptography.paddingmode",
            "security.cryptography.cryptostreammode",
            "io.filemode", "io.fileaccess",
        ):
            # ``[CipherMode]::CBC``/``[PaddingMode]::PKCS7``/
            # ``[CryptoStreamMode]::Write`` -- resolved to the plain
            # lowercase member name rather than falling through to the
            # generic unmodeled-static-member ``_Unknown``, since the AES
            # decrypt/encrypt modeling below (``crypto.aes``/
            # ``security.cryptography.cryptostream``) needs a real value
            # to read back, not a symbolic placeholder.
            return member_key
        if type_key in (
            "security.cryptography.aescryptoserviceprovider", "security.cryptography.aesmanaged",
            "security.cryptography.aes", "security.cryptography.rijndaelmanaged",
        ) and member_key == "create":
            return _ObjectRef("crypto.aes", {"mode": "cbc", "padding": "pkcs7"})
        if type_key in ("marshal", "runtime.interopservices.marshal"):
            if member_key == "getdelegateforfunctionpointer":
                pointer = args[0] if args else None
                return _ObjectRef("native.delegate", {"function": pointer})
            if member_key == "copy":
                return self._copy_native_model(args)
            return _Unknown(f"<marshal.{member_key}>")
        if type_key in ("gc",):
            return None
        if is_call:
            self._unmodeled_static_count += 1
            example = f'[{type_key}]::{member_key}'[:120]
            if len(self._unmodeled_static_examples) < 8 and example not in self._unmodeled_static_examples:
                self._unmodeled_static_examples.append(example)
        return _Unknown(f"[{type_key}]::{member_key}" + ("()" if is_call else ""))

    def _string_combine(self, member, args):
        """Known String.Concat/Join overloads without marker text or truncation."""
        api = 'String.' + member.title()

        def unresolved(reason):
            self._emit('unsupported_operation', api=api, reason=reason)
            return _Unknown('<string-' + member + '>')

        def items_of(value):
            if isinstance(value, _BinaryValue):
                return value.data if value.complete else None
            return value if isinstance(value, list) else [value]

        separator = ''
        if member == 'concat':
            items = items_of(args[0]) if len(args) == 1 else args
        else:
            if len(args) < 2:
                return unresolved('overload-not-modeled')
            separator = '' if args[0] is None else args[0]
            if not isinstance(separator, str):
                return unresolved('separator-unresolved')
            if len(args) == 4 and isinstance(args[1], (list, _BinaryValue)):
                items = items_of(args[1])
                start = _convert_integer_value(args[2], -(1 << 31), (1 << 31) - 1)
                count = _convert_integer_value(args[3], -(1 << 31), (1 << 31) - 1)
                if items is None or start is None or count is None:
                    return unresolved('range-or-input-unresolved')
                if start < 0 or count < 0 or start > len(items) or count > len(items) - start:
                    return unresolved('invalid-join-range')
                # This range overload requires String[]. Do not guess a
                # conversion from numeric/opaque array element types.
                if not all(v is None or isinstance(v, str) for v in items):
                    return unresolved('range-array-conversion-not-modeled')
                items = items[start:start + count]
            elif len(args) == 2:
                if args[1] is None:
                    return unresolved('null-join-array')
                items = items_of(args[1])
            else:
                items = args[1:]
        if items is None:
            return unresolved('input-incomplete')
        if len(items) > MAX_EMBEDDED_PAYLOAD_BYTES:
            self._emit('resource_limit', resource='string_combine_elements', limit=MAX_EMBEDDED_PAYLOAD_BYTES)
            return _Unknown('<string-combine-limit>')
        parts, size = [], 0
        for i, item in enumerate(items):
            if i % 1024 == 0:
                self._tick()
            if item is None:
                part = ''
            elif isinstance(item, str):
                part = item
            elif type(item) in (bool, int):
                part = str(item)
            elif isinstance(item, (_IntegerArray, _FloatingArray)):
                part = 'System.' + item.element_type + '[]'
            elif isinstance(item, (_ByteArray, _BinaryValue)):
                part = 'System.Byte[]'
            elif isinstance(item, _ObjectArray):
                part = 'System.Object[]'
            else:
                return unresolved('element-string-conversion-unresolved')
            size += len(part) + (len(separator) if i else 0)
            if size > MAX_VALUE_CHARS:
                self._emit('resource_limit', resource='string_combine_chars', limit=MAX_VALUE_CHARS)
                return _Unknown('<string-combine-limit>')
            parts.append(part)
        return separator.join(parts)

    def _array_data_operation(self, member, args):
        """Bounded one-dimensional managed array operations, with aliasing."""
        api = 'Array.' + member.title()

        def unsupported(reason, target=None, start=0, count=None):
            if isinstance(target, _BinaryValue):
                target.complete = False
            elif isinstance(target, list):
                count = len(target) - start if count is None else count
                target[start:start + count] = [_Unknown('<array-mutation>')] * count
            self._emit('unsupported_operation', api=api, reason=reason)
            return _Unknown('<array-' + member + '>')

        if member == 'reverse':
            if len(args) not in (1, 3) or not isinstance(args[0], (list, _BinaryValue)):
                return unsupported('array-or-overload-not-modeled')
            target = args[0]
            raw_start, raw_count = args[1:] if len(args) == 3 else (0, len(target))
            start = _convert_integer_value(raw_start, -(1 << 31), (1 << 31) - 1)
            count = _convert_integer_value(raw_count, -(1 << 31), (1 << 31) - 1)
            if start is None or count is None:
                return unsupported('reverse-range-unresolved', target)
            if start < 0 or count < 0 or start > len(target) or count > len(target) - start:
                return unsupported('invalid-reverse-range')
            if count < 2:
                return None
            if count > MAX_EMBEDDED_PAYLOAD_BYTES:
                return unsupported('array-operation-limit', target)
            self._tick()
            if isinstance(target, _BinaryValue):
                target.data = target.data[:start] + target.data[start:start + count][::-1] + target.data[start + count:]
                target.sha256 = hashlib.sha256(target.data).hexdigest()
            else:
                types = target.boxed_types[start:start + count][::-1] if isinstance(target, _ObjectArray) else None
                target[start:start + count] = target[start:start + count][::-1]
                if types is not None:target.boxed_types[start:start + count] = types
            return None

        if len(args) == 3:
            source, target, raw_count = args
            raw_source_start = raw_target_start = 0
        elif len(args) == 5:
            source, raw_source_start, target, raw_target_start, raw_count = args
        else:
            return unsupported('array-or-overload-not-modeled')
        if not isinstance(target, (list, _BinaryValue)):
            return unsupported('copy-destination-unresolved')
        if not isinstance(source, (list, _BinaryValue)):
            return unsupported('copy-source-unresolved', target)
        source_start, target_start, count = (
            _convert_integer_value(v, -(1 << 31), (1 << 31) - 1)
            for v in (raw_source_start, raw_target_start, raw_count))
        if source_start is None or target_start is None or count is None:
            return unsupported('copy-range-unresolved', target)
        if (source_start < 0 or target_start < 0 or count < 0
                or source_start > len(source) or target_start > len(target)
                or count > len(source) - source_start or count > len(target) - target_start):
            return unsupported('invalid-copy-range')
        if not count:
            return None
        if count > MAX_EMBEDDED_PAYLOAD_BYTES:
            return unsupported('array-operation-limit', target, target_start, count)

        def bounds(value):
            if isinstance(value, (_BinaryValue, _ByteArray)):
                return (0, 255)
            if isinstance(value, _IntegerArray):
                return _INTEGER_CAST_TYPES[value.element_type.lower()][1:]
            return None

        source_bounds, target_bounds = bounds(source), bounds(target)
        def primitive_type(value):
            if isinstance(value, (_BinaryValue, _ByteArray)):return 'Byte'
            if isinstance(value, (_IntegerArray, _FloatingArray)):return value.element_type
            return None
        source_type, target_type = primitive_type(source), primitive_type(target)
        boxed_types = None
        # Primitive widening and identical array types are supported. Plain
        # lists do not retain enough CLR type information for boxing/unboxing.
        compatible = source is target or (source_bounds is not None and target_bounds is not None
                                         and target_bounds[0] <= source_bounds[0]
                                         and source_bounds[1] <= target_bounds[1])
        if isinstance(target, _FloatingArray):
            compatible = source_bounds is not None or (isinstance(source, _FloatingArray)
                         and (source.element_type == target.element_type or target.element_type == 'Double'))
        if isinstance(target, _ObjectArray):
            compatible = source_type is not None or isinstance(source, _ObjectArray)
            boxed_types = (source.boxed_types[source_start:source_start + count] if isinstance(source, _ObjectArray)
                           else [source_type] * count)
        elif isinstance(source, _ObjectArray) and target_type is not None:
            compatible = all(kind == target_type for kind in source.boxed_types[source_start:source_start + count])
        if not compatible:
            return unsupported('copy-element-types-not-modeled', target, target_start, count)
        self._tick()
        if isinstance(source, _BinaryValue):
            if not source.complete:
                return unsupported('copy-source-incomplete', target, target_start, count)
            chunk = source.data[source_start:source_start + count]
        else:
            # Snapshot first: source and destination may overlap.
            chunk = source[source_start:source_start + count]
        if isinstance(target, _FloatingArray):
            chunk = [self._cast_floating_value(target.element_type.lower(), item) for item in chunk]
        if isinstance(target, _BinaryValue):
            data = _as_bytes(chunk)
            if data is None:
                return unsupported('copy-source-elements-unresolved', target, target_start, count)
            target.data = target.data[:target_start] + data + target.data[target_start + count:]
            target.sha256 = hashlib.sha256(target.data).hexdigest()
            # A coarse incomplete flag may mean the stored length is only a
            # prefix, so even a full stored-range copy cannot establish it.
            resolved = target.complete
        else:
            target[target_start:target_start + count] = chunk
            if boxed_types is not None:target.boxed_types[target_start:target_start + count] = boxed_types
            resolved = not any(_is_unknown(v) for v in chunk)
        self._emit('memory_copy', api=api, source_offset=source_start, destination_offset=target_start,
                   elements=count, output_resolved=resolved)
        return None

    def _cast_integer_value(self, type_key, value):
        _, minimum, maximum = ('Byte', 0, 255) if type_key == 'byte' else _INTEGER_CAST_TYPES[type_key]
        converted = _convert_integer_value(value, minimum, maximum)
        if converted is None:
            self._emit('unsupported_operation', api='cast:' + type_key,
                       reason='integer-conversion-unresolved-or-out-of-range')
            return _Unknown('<integer-cast>')
        return converted

    def _cast_string_value(self, value):
        """PowerShell array-to-string conversion, without Python repr output."""
        if _is_unknown(value):
            return value
        if value is None:
            return ''
        if isinstance(value, str):
            return value
        if isinstance(value, (list, _BinaryValue)):
            if isinstance(value, _BinaryValue) and not value.complete:
                return _Unknown('<string-array-input>')
            separator = self.variables.get('ofs')
            separator = ' ' if separator is None else separator
            if type(separator) in (bool, int):
                separator = str(separator)
            if not isinstance(separator, str) or _is_unknown(separator):
                self._emit('unsupported_operation', api='cast:string', reason='output-field-separator-unresolved')
                return _Unknown('<string-array-separator>')
            items = value.data if isinstance(value, _BinaryValue) else value
            parts, size = [], 0
            for i, item in enumerate(items):
                if i % 1024 == 0:
                    self._tick()
                if isinstance(item, (_IntegerArray, _FloatingArray)):
                    part = 'System.' + item.element_type + '[]'
                elif isinstance(item, (_ByteArray, _BinaryValue)):
                    part = 'System.Byte[]'
                elif isinstance(item, _ObjectArray):
                    part = 'System.Object[]'
                elif isinstance(item, list):
                    # Plain lists do not retain all CLR array types.
                    self._emit('unsupported_operation', api='cast:string', reason='nested-array-type-unresolved')
                    return _Unknown('<nested-array-string>')
                else:
                    part = self._cast_string_value(item)
                if _is_unknown(part):
                    return part
                size += len(part) + (len(separator) if parts else 0)
                if size > MAX_VALUE_CHARS:
                    self._emit('resource_limit', resource='array_to_string', limit=MAX_VALUE_CHARS)
                    return _Unknown('<array-string-limit>')
                parts.append(part)
            return separator.join(parts)
        if type(value) in (bool, int):
            return str(value)
        if isinstance(value, _ObjectRef) and value.kind == 'scriptblock' and isinstance(value.state.get('source'), str):
            return value.state['source']
        self._emit('unsupported_operation', api='cast:string', reason='object-string-conversion-not-modeled')
        return _Unknown('<object-string>')

    def _cast_floating_value(self, key, value):
        try:
            if _is_unknown(value) or isinstance(value, (list, _ObjectRef, _BinaryValue)):
                raise ValueError()
            number = float(ord(value)) if isinstance(value, _CharValue) else float(0 if value is None else value)
            if key in ('single', 'float'):
                number = struct.unpack('<f', struct.pack('<f', number))[0]
            if not math.isfinite(number):
                raise ValueError()
            return number
        except (ValueError, TypeError, OverflowError, struct.error):
            self._emit('unsupported_operation', api='cast:' + key, reason='floating-conversion-unresolved-or-nonfinite')
            return _Unknown('<floating-cast>')

    def _apply_cast(self, type_name, value):
        is_array = type_name.endswith("[]")
        key = type_name[:-2].lower() if is_array else type_name.lower()
        integer_key = key.removeprefix('system.')
        if integer_key == 'object' and is_array:
            if value is None or _is_unknown(value) or isinstance(value, _ObjectArray):return value
            if isinstance(value, _BinaryValue):
                if not value.complete:return _Unknown('<object-array-input>')
                if len(value) > MAX_VARIABLES:
                    self._emit('resource_limit', resource='object_array_elements', limit=MAX_VARIABLES)
                    return _Unknown('<object-array-limit>')
                return _ObjectArray(value.data, ['Byte'] * len(value))
            items = value if isinstance(value, list) else [value]
            if len(items) > MAX_VARIABLES:
                self._emit('resource_limit', resource='object_array_elements', limit=MAX_VARIABLES)
                return _Unknown('<object-array-limit>')
            element = ('Byte' if isinstance(value, _ByteArray) else
                       value.element_type if isinstance(value, (_IntegerArray, _FloatingArray)) else None)
            return _ObjectArray(items, [element] * len(items))
        if integer_key in ('double', 'single', 'float'):
            if not is_array:
                return self._cast_floating_value(integer_key, value)
            if value is None or _is_unknown(value):return value
            element = 'Double' if integer_key == 'double' else 'Single'
            if isinstance(value, _FloatingArray) and value.element_type == element:return value
            if isinstance(value, _BinaryValue):
                if not value.complete:return _Unknown('<floating-array-input>')
                items = value.data
            else:
                items = value if isinstance(value, list) else [value]
            if len(items) > MAX_VARIABLES:
                self._emit('resource_limit', resource='floating_array_elements', limit=MAX_VARIABLES)
                return _Unknown('<floating-array-limit>')
            converted = []
            for index, item in enumerate(items):
                if index % 1024 == 0:self._tick()
                number = self._cast_floating_value(integer_key, item)
                if _is_unknown(number):return _Unknown('<floating-array-conversion>')
                converted.append(number)
            return _FloatingArray(converted, element)
        if integer_key in _INTEGER_CAST_TYPES:
            if not is_array:
                return self._cast_integer_value(integer_key, value)
            if value is None or _is_unknown(value):
                return value
            element_type = _INTEGER_CAST_TYPES[integer_key][0]
            if isinstance(value, _IntegerArray) and value.element_type == element_type:
                return value
            if isinstance(value, _BinaryValue):
                if not value.complete:
                    return _Unknown('<integer-array-input>')
                items = value.data
            else:
                items = value if isinstance(value, list) else [value]
            if len(items) > MAX_VARIABLES:
                self._emit('resource_limit', resource='integer_array_elements', limit=MAX_VARIABLES)
                return _Unknown('<integer-array-limit>')
            converted = []
            for i, item in enumerate(items):
                if i % 1024 == 0:
                    self._tick()
                number = self._cast_integer_value(integer_key, item)
                if _is_unknown(number):
                    return _Unknown('<integer-array-conversion>')
                converted.append(number)
            return _IntegerArray(converted, element_type)
        if key in ('guid','system.guid') and not is_array:
            return self._instantiate('guid',[value])
        if key in ('uri','system.uri') and not is_array:
            return self._instantiate('uri',[value]) if isinstance(value,str) else _Unknown('<uri>')
        if key in ("type", "system.type") and not is_array:
            if isinstance(value, _ObjectRef) and value.kind == "reflection.type":
                return value
            if isinstance(value, str) and re.fullmatch(r"[A-Za-z_][\w.]*", value.strip()):
                return _ObjectRef("reflection.type", {"type_key": value.strip().lower().removeprefix("system.")})
            return _Unknown("<type>")
        if key in ("char", "system.char"):
            if is_array:
                if isinstance(value, _BinaryValue):
                    return [_CharValue(chr(item)) for item in value.data] if value.complete else _Unknown('<char[]>')
                if isinstance(value, str):
                    return _char_units(value)
                return [self._apply_cast("char", item) for item in value] if isinstance(value, list) else _Unknown("<char[]>")
            if isinstance(value, (int, float)) and not isinstance(value, bool):
                try:
                    return _CharValue(chr(int(value))) if 0 <= int(value) <= 65535 else _Unknown('<char>')
                except (ValueError, OverflowError):
                    return _Unknown("<char>")
            if isinstance(value, str) and len(value) == 1 and ord(value) <= 65535:
                return _CharValue(value)
            return _Unknown("<char>")
        if key in ("byte", "system.byte"):
            if is_array:
                if value is None or _is_unknown(value) or isinstance(value, (_ByteArray, _BinaryValue)):
                    return value
                items = value if isinstance(value, list) else [value]
                if len(items) > MAX_EMBEDDED_PAYLOAD_BYTES:
                    self._emit('resource_limit', resource='byte_array_elements', limit=MAX_EMBEDDED_PAYLOAD_BYTES)
                    return _Unknown('<byte-array-limit>')
                converted = bytearray()
                for i, item in enumerate(items):
                    if i % 4096 == 0:
                        self._tick()
                    number = self._cast_integer_value('byte', item)
                    if _is_unknown(number):
                        return _Unknown("<byte[]>")
                    converted.append(number)
                return _BinaryValue(converted)
            return self._cast_integer_value('byte', value)
        if integer_key == 'decimal':
            self._emit('unsupported_operation', api='cast:decimal', reason='decimal-precision-not-modeled')
            return _Unknown('<decimal-cast>')
        if key in ("string", "system.string"):
            if is_array:
                if value is None or _is_unknown(value):
                    return value
                if isinstance(value, _BinaryValue):
                    if not value.complete:
                        return _Unknown('<string[]>')
                    items = value.data
                else:
                    items = value if isinstance(value, list) else [value]
                return [self._apply_cast('string', item) for item in items]
            return self._cast_string_value(value)
        if key in ("bool", "boolean"):
            return _Unknown('<boolean-input>') if _is_unknown(value) else _truthy(value)
        if key == "scriptblock":
            return _ObjectRef("scriptblock", {"source": value if isinstance(value, str) else ""})
        if key == "array" and not isinstance(value, list):
            return [value]
        return value

    # -- ``New-Object`` --------------------------------------------------------

    def _parse_command_syntax(self, text, single_token_params=(), parameter_names=(), switch_params=()):
        """Split PowerShell "command syntax" (space-separated, ``-Param
        value`` pairs, no parens) into ``(positional_arg_texts,
        {param_name: value_text})``. Values are left as unevaluated text --
        callers decide which need ``_eval_expr`` and which (bare switches)
        don't.
        """
        text = text.strip()
        if not text:
            return [], {}
        def resolve_parameter(name):
            lowered = name.lower()
            if lowered in parameter_names:
                return lowered
            matches = [candidate for candidate in parameter_names if candidate.startswith(lowered)]
            if len(matches) == 1:
                return matches[0]
            if len(matches) > 1:
                return None
            return lowered
        # Expand argument splats as references to the existing abstract
        # values. Never stringify a hashtable into a URL, or reparse its
        # string contents as PowerShell expressions.
        if '@' in text:
            expanded = []
            for token in _split_top_level_ws(text):
                splat = re.fullmatch(rf'@({_IDENT}(?::{_IDENT})?)', token)
                if not splat:
                    expanded.append(token)
                    continue
                variable = '$' + splat[1]
                value = self._read_variable(variable)
                if isinstance(value, dict) and len(value) <= MAX_VARIABLES:
                    for key in value:
                        if not isinstance(key, str) or not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_-]*', key):
                            self._emit('unsupported_operation', api='parameter-binding', reason='splat-key-not-modeled')
                            continue
                        reference = variable + "['" + key + "']"
                        if resolve_parameter(key) in switch_params:
                            expanded.append('-' + key + ':' + reference)
                        else:
                            expanded.extend(('-' + key, reference))
                elif isinstance(value, list) and len(value) <= MAX_VARIABLES:
                    expanded.extend(variable + '[' + str(index) + ']' for index in range(len(value)))
                else:
                    self._emit('unsupported_operation', api='parameter-binding', reason='splat-input-unresolved')
                    expanded.append(token)
            text = ' '.join(expanded)
        matches = list(_top_level_matches(text, _PARAM_TOKEN_RE))
        if not matches:
            return _split_top_level_ws(text), {}
        positional = _split_top_level_ws(text[:matches[0].start()])
        named = {}
        for index, match in enumerate(matches):
            name = resolve_parameter(match.group(1))
            value_start = match.end()
            value_end = matches[index + 1].start() if index + 1 < len(matches) else len(text)
            value_text = text[value_start:value_end].strip()
            if name is None:
                self._emit('unsupported_operation', api='parameter-binding',
                           reason='ambiguous-parameter-prefix', parameter=match.group(1))
                named['_binding_error'] = True
                continue
            if name in switch_params:
                if value_text.startswith(':'):
                    parts = _split_top_level_ws(value_text[1:].lstrip())
                    named[name] = parts[0] if parts else '$true'
                    positional.extend(parts[1:])
                else:
                    named[name] = '$true'
                    positional.extend(_split_top_level_ws(value_text))
                continue
            if name in _SINGLE_TOKEN_PARAMS or name in single_token_params:
                # A real single-value enum/switch parameter
                # (``-WindowStyle Hidden``) takes exactly one token --
                # unlike most named params here, everything up to the
                # *next* ``-Param`` isn't its value. Without this,
                # ``-WindowStyle Hidden powershell`` (a bare positional
                # filename with no ``-FilePath``, immediately after)
                # swallowed "powershell" into WindowStyle's value and
                # left the actual command with no filename at all.
                parts = _split_top_level_ws(value_text)
                if len(parts) > 1:
                    named[name] = parts[0]
                    positional.extend(parts[1:])
                    continue
            named[name] = value_text
        return positional, named

    def _parse_variable_alias_args(self, rest):
        """Parse ``Get-Variable``/``Set-Variable``-style call arguments,
        tolerating a space-optional multi-parenthesized-group styling
        some obfuscators use for these specifically (``sv('name')
        (value)``, no comma, no whitespace between the two groups) on
        top of normal command syntax. Returns a list of raw
        (unevaluated) argument-expression texts, in order.
        """
        text = rest.strip()
        args = []
        while text.startswith("("):
            inner, end = _extract_balanced(text, 0, "(", ")")
            if inner is None:
                break
            text = text[end + 1:].lstrip()
            if text.startswith("."):
                suffix = _split_top_level_ws(text)[0]
                inner = "(" + inner + ")" + suffix
                text = text[len(suffix):].lstrip()
            args.append(inner)
        if text:
            positional, named = self._parse_command_syntax(text)
            args.extend(positional)
            for key in ("name", "value"):
                if key in named and named[key] not in args:
                    args.append(named[key])
        return args

    def _eval_new_object(self, match):
        raw = match.group(1).strip()
        # ``New-Object System.IO.MemoryStream(,$bytes)`` -- a dotted type
        # name immediately followed by a parenthesized, comma-separated
        # argument list with *no* space before the ``(``. Real
        # ``New-Object`` command syntax is space-separated
        # (``New-Object Type arg1,arg2``), so without special-casing
        # this shape ``_parse_command_syntax`` (whitespace-split) reads
        # the whole ``Type(...)`` chunk as one opaque positional token --
        # common in stream/compression construction chains a decode
        # helper needs resolved to reach the real payload underneath.
        # The leading comma before the first real argument is PowerShell's
        # "don't treat this array as a params splat" marker, not a
        # second (empty) argument -- dropped via the blank-part filter.
        fused_match = re.match(rf"^({_VAR_REF}|[A-Za-z_][\w.]*(?:\[\])?)\s*\(", raw)
        if fused_match:
            args_text, end = _extract_balanced(raw, fused_match.end() - 1, "(", ")")
            if args_text is not None and end == len(raw) - 1:
                arg_parts = [part.strip() for part in _split_top_level(args_text, ",")]
                args = [self._eval_expr(part) for part in arg_parts if part]
                type_name = self._read_variable(fused_match.group(1)) if fused_match.group(1).startswith('$') else fused_match.group(1)
                if not isinstance(type_name,str):
                    return _Unknown('<new-object-type>')
                type_key = type_name.strip("'\"").lower().removeprefix('system.')
                return self._instantiate(type_key, args)
        positional, named = self._parse_command_syntax(raw)
        is_com = "comobject" in named
        type_text = named.get("typename") or named.get("comobject")
        if not type_text and positional:
            type_text = positional[0]
            positional = positional[1:]
        if not type_text:
            return _Unknown("<new-object>")
        type_text = type_text.strip()
        # A bare dotted type name (``Net.WebClient``, ``System.Text.
        # StringBuilder``) is not valid PowerShell *expression* syntax on
        # its own -- it is a plain type-name literal here, not something to
        # evaluate as an expression (which would misread the dots as member
        # access on a nonexistent variable). Anything else (``$typeVar``,
        # a quoted string, ``[Type]``) genuinely is an expression.
        if re.fullmatch(r"[A-Za-z_][\w.]*(?:\[[\w.\[\],]*\])?", type_text):
            # ``[]`` (a plain array) as well as a generic type argument
            # (``System.Collections.Generic.List[byte]``) -- both a
            # literal type-name token, never something to evaluate as an
            # expression (the ``else`` branch below would misread the
            # bracketed part, or -- worse -- the dotted name outside it,
            # as real PowerShell syntax and collapse the whole thing to
            # ``_Unknown`` before ``_instantiate`` ever saw it).
            type_name = type_text
        else:
            type_name = self._eval_expr(type_text)
        arg_text = named.get("argumentlist")
        positional_text = ' '.join(positional)
        if arg_text is not None or len(positional) == 1 or len(_split_top_level(positional_text, ',')) > 1:
            # ArgumentList is an object[] parameter. Evaluate the entire
            # argument-list expression, then enumerate exactly its outer
            # array. Splitting whitespace first wrapped ``$stream,$mode``
            # in another list, passing one argument to a two-argument ctor.
            # A unary comma still protects an array-valued ctor argument.
            argument_list = self._eval_expr(arg_text if arg_text is not None else positional_text)
            args = list(argument_list) if isinstance(argument_list, list) else [argument_list]
        else:
            args = [self._eval_expr(part) for part in positional]
        if _is_unknown(type_name):
            return _Unknown("<new-object>")
        type_key = str(type_name).strip("'\"").lower().replace("system.", "", 1)
        return self._instantiate(type_key, args, is_com=is_com)

    def _instantiate(self, type_key, args, is_com=False):
        if type_key == 'reflection.emit.dynamicmethod':
            return self._new_dynamic_method(args)
        if type_key in self._script_types and not is_com:
            return self._new_script_instance(type_key, args)
        if type_key == 'net.http.httpmethod':
            if len(args) == 1 and isinstance(args[0], str) and re.fullmatch(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+", args[0]):
                return _ObjectRef(type_key, {'method': args[0]})
            return _Unknown('<http-method-input>')
        if type_key == 'net.http.httprequestmessage':
            if not args:
                return _ObjectRef(type_key, {'method': _ObjectRef('net.http.httpmethod', {'method': 'GET'}), 'requesturi': None})
            if len(args) == 2:
                return _ObjectRef(type_key, {'method': args[0], 'requesturi': args[1]})
            return _Unknown('<http-request-constructor>')
        if re.fullmatch(r'lazy\[(?:system\.)?(?:object|string)\]', type_key):
            factory = args[0] if len(args) == 1 else None
            return _ObjectRef('lazy.value', {'factory': factory, 'created': False})
        if type_key == 'drawing.bitmap':
            if len(args) == 1 and isinstance(args[0], list):
                args = args[0]
            if len(args) != 2 or any(type(n) is int and n <= 0 for n in args):
                return _Unknown('<bitmap-constructor-not-modeled>')
            width, height = args
            return _ObjectRef('drawing.bitmap', {'width': width, 'height': height,
                'size': _ObjectRef('drawing.size', {'width': width, 'height': height})})
        if type_key == 'io.filestream':
            path = args[0] if args else _Unknown('<file-path>')
            mode = str(args[1]).lower() if len(args)>1 else ''
            access = str(args[2]).lower() if len(args)>2 else 'readwrite'
            mode = {'1':'createnew','2':'create','3':'open','4':'openorcreate','5':'truncate','6':'append'}.get(mode,mode)
            access = {'1':'read','2':'write','3':'readwrite'}.get(access,access)
            known_mode = mode in ('create','open','truncate','append','createnew','openorcreate') and access in ('read','write','readwrite')
            data = self._virtual_files.get(self._virtual_file_key(path))
            if known_mode and mode in ('create','truncate') and access!='read':
                data = b''
                self._record_file_write(path,b'','FileStream.create')
            elif known_mode and mode=='open' and data is None:
                self._emit('unresolved_file_read',api='FileStream.open',path=_safe_text(path),reason='file-content-not-provided')
            if not known_mode:
                data = None
            return _ObjectRef('io.filestream',{'path':path,'data':data,'position':len(data) if isinstance(data,bytes) and mode=='append' else 0,
                                             'writable':known_mode and access!='read'})
        if type_key == 'text.utf8encoding' and len(args)<=2 and all(type(x) is bool for x in args):
            return _ObjectRef('text.encoding',{'name':'utf8','emit_bom':args[0] if args else False})
        if type_key == 'text.unicodeencoding' and len(args)<=3 and all(type(x) is bool for x in args):
            return _ObjectRef('text.encoding',{'name':'bigendianunicode' if args and args[0] else 'unicode',
                                             'emit_bom':args[1] if len(args)>1 else True})
        if type_key in _HASH_TYPES:
            return _ObjectRef('security.cryptography.hashalgorithm',{'algorithm':_HASH_TYPES[type_key]})
        if type_key == 'guid':
            text = args[0].strip() if args and isinstance(args[0],str) else ''
            if (text.startswith('{') and text.endswith('}')) or (text.startswith('(') and text.endswith(')')):
                text = text[1:-1]
            if not re.fullmatch(r'[0-9a-fA-F]{32}|[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}',text):
                return _Unknown('<guid-input>')
            text = text.replace('-','').lower()
            return _GuidValue('-'.join((text[:8],text[8:12],text[12:16],text[16:20],text[20:])))
        if type_key == "runtime.interopservices.handleref" and len(args) == 2:
            return _ObjectRef("native.handleref", {"handle": args[1]})
        if type_key == "string" and len(args) == 1:
            chars = args[0]
            if isinstance(chars, list) and all(isinstance(c, str) and len(c) == 1 for c in chars):
                return _cap("".join(chars))
            return _Unknown("<string-constructor>")
        if type_key.endswith("[]"):
            # ``New-Object byte[] $count`` -- a plain sized array, the
            # near-universal setup for a byte-wise XOR/hex decode loop's
            # output buffer. A real Python list here (not another
            # ``_ObjectRef``) is what makes ``$bytes[$i] = ...`` index
            # assignment and the ``for``/``foreach`` loop bodies that fill
            # it actually work.
            try:
                count = int(_numeric_coerce(args[0])) if args else 0
            except (TypeError, ValueError):
                return _Unknown('<array-length-unresolved>')
            element_type = type_key[:-2]
            # A byte-array decode buffer specifically needs the much
            # larger embedded-payload cap, not the general variable-
            # count one: capping it at ``MAX_VARIABLES`` made the
            # buffer's own ``.Length`` (read right back by the fill
            # loop right after -- ``0..($b.Length-1) | % {...}``, the
            # near-universal shape) disagree with the real payload size
            # for anything over 8,000 bytes, which silently broke every
            # hex-decode fast-path verification for a payload above
            # that size (a very ordinary payload size in practice).
            cap = MAX_EMBEDDED_PAYLOAD_BYTES if element_type in ("byte", "sbyte") else MAX_VARIABLES
            count = max(0, min(count, cap))
            fill = 0 if element_type in ("byte", "int", "int32", "int64", "long", "short", "double", "float", "single") else None
            if element_type in _INTEGER_CAST_TYPES:
                return _IntegerArray([0] * count, _INTEGER_CAST_TYPES[element_type][0])
            if element_type in ('double', 'float', 'single'):
                return _FloatingArray([0.0] * count, 'Double' if element_type == 'double' else 'Single')
            if element_type == 'object':
                return _ObjectArray([None] * count)
            return _ByteArray([fill] * count) if element_type == 'byte' else [fill] * count
        if type_key.startswith("collections.generic.list") or type_key in (
            "collections.arraylist", "collections.generic.list",
        ):
            # ``New-Object System.Collections.Generic.List[byte]`` /
            # ``ArrayList`` -- the ``.Add(...)``-based alternative to a
            # sized ``byte[]`` + index assignment for a decode
            # accumulator loop. A real Python list (growable, same as
            # the ``byte[]`` case above) is what makes ``.Add()``/
            # ``.ToArray()`` (see ``_apply_method``) work correctly even
            # when ``_try_fast_for_loop`` doesn't recognize this
            # particular loop shape and falls back to real simulation.
            return []
        if is_com:
            self._emit("com_create", progid=type_key, variable="<temporary>")
            if type_key == 'schedule.service':
                return _ObjectRef('taskschd.service')
            if type_key == "wscript.shell":
                return _ObjectRef("wscript.shell")
            if type_key == "scripting.filesystemobject":
                return _ObjectRef("scripting.filesystemobject")
            if type_key == "adodb.stream":
                return _ObjectRef("adodb.stream")
            if type_key in ("winhttp.winhttprequest.5.1", "msxml2.xmlhttp", "msxml2.serverxmlhttp", "microsoft.xmlhttp"):
                # ``New-Object -ComObject WinHTTP.WinHttpRequest.5.1`` /
                # ``MSXML2.XMLHTTP`` -- the COM-based HTTP request
                # mechanism, at least as common in real loaders as
                # ``Net.WebClient``/``Invoke-WebRequest`` (and reached
                # for specifically because it doesn't touch either).
                return _ObjectRef("com.httprequest")
            return _ObjectRef(f"com:{type_key}")
        if type_key in ("net.webclient", "webclient"):
            return _ObjectRef("net.webclient")
        if type_key in ("net.http.httpclient", "http.httpclient", "net.httpclient", "httpclient"):
            return _ObjectRef("net.httpclient")
        if type_key == "net.webrequest":
            return _ObjectRef("net.webrequest")
        if type_key == "diagnostics.process":
            return _ObjectRef("diagnostics.process")
        if type_key == "diagnostics.processstartinfo":
            state = {}
            if args and not _is_unknown(args[0]):
                state["filename"] = args[0]
            if len(args) > 1 and not _is_unknown(args[1]):
                state["arguments"] = args[1]
            return _ObjectRef("diagnostics.processstartinfo", state)
        if type_key == "text.stringbuilder":
            initial = args[0] if args and not _is_unknown(args[0]) else ""
            return _ObjectRef("text.stringbuilder", {"text": str(initial)})
        if type_key == "io.memorystream":
            # A byte buffer decode chain almost always starts here
            # (``New-Object System.IO.MemoryStream(,$bytes)``) and ends
            # at a ``GzipStream``/``DeflateStream`` wrapping it -- real
            # decompressed content out the other end depends on this
            # stage actually holding the bytes, not just being an opaque
            # placeholder object.
            # New-Object MemoryStream @(,$bytes) passes one byte-array
            # constructor argument, rather than an array of byte arrays.
            if (len(args) == 1 and isinstance(args[0], list) and len(args[0]) == 1
                    and isinstance(args[0][0], (list, _BinaryValue))):
                args = args[0]
            data = _as_bytes(args[0]) if args else b''
            return _ObjectRef("io.memorystream", {"data": data})
        if type_key in (
            "security.cryptography.aescryptoserviceprovider", "security.cryptography.aesmanaged",
            "security.cryptography.aes", "security.cryptography.rijndaelmanaged",
        ):
            # ``New-Object System.Security.Cryptography.AesCryptoServiceProvider``
            # -- the ``.Key``/``.IV``/``.Mode``/``.Padding`` properties get
            # filled in afterward via ordinary property assignment
            # (``_handle_property_assignment`` already writes any property
            # into ``state`` generically), then ``.CreateDecryptor()``
            # reads them back to build the actual transform.
            return _ObjectRef("crypto.aes", {"mode": "cbc", "padding": "pkcs7"})
        if type_key == "security.cryptography.cryptostream":
            # ``New-Object System.Security.Cryptography.CryptoStream($ms,
            # $decryptor, [CryptoStreamMode]::Write)`` -- the near-
            # universal AES-decrypt-and-execute shape (a real, static key
            # and IV embedded right in the sample, only the payload
            # itself base64-encoded) actually performs the decrypt for
            # real here rather than leaving the whole thing symbolic:
            # this is a pure data transform on bytes already present in
            # the source text, the same category of thing the existing
            # RC4/hex/XOR fast-path decoders already do, never a real
            # host operation.
            target = args[0] if args else None
            transform = args[1] if len(args) > 1 else None
            mode_text = str(args[2]).lower() if len(args) > 2 and not _is_unknown(args[2]) else "write"
            return _ObjectRef("security.cryptography.cryptostream", {
                "target": target, "transform": transform, "mode": mode_text, "pending": b"",
                "leave_open": args[3] if len(args) > 3 else False,
            })
        if type_key in ("io.compression.gzipstream", "io.compression.deflatestream"):
            source = args[0] if args else None
            source_data = source.state.get("data") if isinstance(source, _ObjectRef) else None
            mode_text = str(args[1]).lower() if len(args) > 1 and not _is_unknown(args[1]) else "decompress"
            decompressed = None
            if source_data and "compress" in mode_text and "decompress" not in mode_text:
                pass  # compression direction not modeled; nothing to read back either way
            elif source_data:
                try:
                    wbits = 16 + zlib.MAX_WBITS if type_key == "io.compression.gzipstream" else -zlib.MAX_WBITS
                    decoder = zlib.decompressobj(wbits)
                    decompressed = decoder.decompress(source_data, MAX_VALUE_CHARS + 1)
                    if len(decompressed) > MAX_VALUE_CHARS:
                        self._emit("resource_limit", resource="decompressed_bytes", limit=MAX_VALUE_CHARS)
                        decompressed = None
                    elif not decoder.eof or decoder.unused_data:
                        # Truncated streams and concatenated gzip members are
                        # not a complete decoded value in this model.
                        self._emit("unsupported_operation", api=type_key, reason="incomplete-or-multiple-streams")
                        decompressed = None
                except Exception:
                    decompressed = None
            return _ObjectRef(type_key, {"data": decompressed})
        if type_key == "io.streamreader":
            source = args[0] if args else None
            data = None
            if isinstance(source, str):
                data = _as_bytes(self._read_virtual_file(source, 'StreamReader.open', as_bytes=True))
            encoding = args[1].state.get('name') if len(args)>1 and isinstance(args[1], _ObjectRef) else 'utf8'
            if len(args)>1 and not isinstance(args[1], (_ObjectRef, bool)):
                encoding = _Unknown('<stream-reader-encoding>')
            detect_bom = args[1] if len(args)>1 and isinstance(args[1], bool) else args[2] if len(args)>2 else True
            return _ObjectRef('io.streamreader', {'data': data, 'source': source if isinstance(source, _ObjectRef) else None,
                                                'encoding': encoding, 'detect_bom': detect_bom,
                                                'encoding_preamble': args[1].state.get('emit_bom', True) if len(args)>1 and isinstance(args[1], _ObjectRef) else True,
                                                'leave_open': args[4] if len(args)>4 else False})
        if type_key == "io.streamwriter":
            path = args[0] if args else _Unknown("<path>")
            return _ObjectRef("io.streamwriter", {"path": path, "buffer": ""})
        if type_key == "random":
            return _ObjectRef("random")
        if type_key == "uri":
            # ``[System.Uri]::new($url)`` -- a download step almost
            # always immediately follows up with ``.Segments[-1]`` (the
            # filename) or ``.Host``, and those feed straight into the
            # local file path/registry key/etc. everything after it is
            # built from. A bare unmodeled placeholder made every one of
            # those downstream values ``_Unknown`` too.
            url_text = str(args[0]) if args and not _is_unknown(args[0]) else ""
            try:
                parts = urllib.parse.urlsplit(url_text)
            except ValueError:
                parts = None
            state = {"absoluteuri": url_text}
            if parts is not None:
                path = parts.path or "/"
                segments = [segment + "/" for segment in path.split("/")[1:-1]]
                tail = path.rsplit("/", 1)[-1]
                segments.append(tail if tail else "/")
                if not path.startswith("/"):
                    segments = ["/"] + segments
                state.update({
                    "scheme": parts.scheme,
                    "host": parts.hostname or "",
                    "port": parts.port if parts.port else (443 if parts.scheme == "https" else 80),
                    "absolutepath": path,
                    "pathandquery": path + (("?" + parts.query) if parts.query else ""),
                    "query": ("?" + parts.query) if parts.query else "",
                    "segments": segments,
                })
            return _ObjectRef("uri", state)
        if type_key == "net.sockets.tcpclient":
            host = args[0] if args else _Unknown("<host>")
            port = args[1] if len(args) > 1 else _Unknown("<port>")
            self._emit("network_request", method="TCP", url=f"{host}:{port}", api="Net.Sockets.TcpClient")
            return _ObjectRef("net.sockets.tcpclient")
        if type_key == "net.mail.mailmessage":
            return _ObjectRef("net.mail.mailmessage")
        return _ObjectRef(type_key or "unknown")

    # -- command-syntax dispatch (cmdlets, ``&``, ``IEX``) --------------------

    def _eval_command_expression(self, name, rest, dot_source=False, _alias_source=None):
        lowered_name = name.lower()
        # Resolve only the alias chain here. Keep its cycle guard local:
        # invoking the resolved command may legitimately use the same alias
        # again (for example an IEX layer containing another IEX).
        alias_chain = set()
        while self.aliases.get(lowered_name):
            if lowered_name in alias_chain or len(alias_chain) >= MAX_CALL_DEPTH:
                self._emit('resource_limit', resource='alias_resolution', limit=MAX_CALL_DEPTH)
                return _Unknown('<alias-cycle-or-depth-limit>')
            alias_chain.add(lowered_name)
            alias_target = self.aliases[lowered_name]
            _alias_source = name if _DEFAULT_COMMAND_ALIASES.get(lowered_name) == alias_target else None
            name = alias_target
            lowered_name = name.lower()
        func_info = self.functions.get(lowered_name)
        if isinstance(func_info, dict):
            positional, named = self._parse_command_syntax(rest)
            args = [self._eval_command_arg(part) for part in positional]
            named_values = {key: self._eval_command_arg(text) for key, text in named.items()}
            return self._invoke_function(lowered_name, func_info, args, named_values, dot_source=dot_source)
        if lowered_name in _DEFAULT_COMMAND_ALIASES:
            self._emit('unresolved_command', api=name, reason='removed-alias-no-command-resolved')
            return _Unknown('<removed-alias>')
        if lowered_name in ("iex", "invoke-expression"):
            positional, named = self._parse_command_syntax(rest)
            arg_text = named.get("command") or (positional[0] if positional else "")
            value = self._eval_expr(arg_text) if arg_text else _Unknown("<iex>")
            return self._invoke_dynamic_layer(value, "Invoke-Expression")
        if lowered_name in ("iwr", "invoke-webrequest", "irm", "invoke-restmethod", "curl", "wget"):
            positional, named = self._parse_command_syntax(
                rest, single_token_params=_WEB_PARAMETER_NAMES - _WEB_SWITCH_PARAMS - {'body', 'headers'},
                parameter_names=_WEB_PARAMETER_NAMES, switch_params=_WEB_SWITCH_PARAMS)
            if named.get('_binding_error'):
                return _Unknown('<web-parameter-binding>')
            uri_text = named.get("uri") or named.get("url") or (positional[0] if positional else "")
            url = self._eval_command_arg(uri_text) if uri_text else _Unknown("<uri>")
            method_text = named.get("method")
            method = str(self._eval_command_arg(method_text)).upper() if method_text else "GET"
            self._record_network(url, method, _alias_source or name)
            out_text = named.get("outfile")
            if out_text:
                self._record_file_write(self._eval_command_arg(out_text), _Unknown('<downloaded>'), f"{name} -OutFile")
            return _Unknown("<web-response>")
        if lowered_name in ("start-bitstransfer",):
            positional, named = self._parse_command_syntax(rest)
            source_text = named.get("source") or (positional[0] if positional else "")
            url = self._eval_command_arg(source_text) if source_text else _Unknown("<uri>")
            self._record_network(url, "GET", "Start-BitsTransfer")
            dest_text = named.get("destination")
            if dest_text:
                self._record_file_write(self._eval_command_arg(dest_text), _Unknown('<downloaded>'), "Start-BitsTransfer")
            return None
        if lowered_name in ("start-job",):
            # ``Start-Job { param($a) IEX $a } -Argument $DoIt | Wait-Job |
            # Receive-Job`` -- no real background-job/thread concurrency
            # is modeled (nothing here needs it), but the scriptblock
            # itself has to actually run synchronously or the
            # ``Invoke-Expression`` inside it never fires at all.
            positional, named = self._parse_command_syntax(rest)
            sb_text = named.get("scriptblock") or (positional[0] if positional else "")
            sb_value = self._eval_expr(sb_text) if sb_text else _Unknown("<scriptblock>")
            if not (isinstance(sb_value, _ObjectRef) and sb_value.kind == "scriptblock"):
                return _Unknown("<start-job>")
            arg_text = named.get("argumentlist") or named.get("argument")
            args = []
            if arg_text:
                arg_val = self._eval_expr(arg_text)
                args = arg_val if isinstance(arg_val, list) else [arg_val]
            return self._invoke_scriptblock(sb_value, args)
        if lowered_name in ("start-process", "saps", "start"):
            positional, named = self._parse_command_syntax(rest)
            path_text = named.get("filepath") or (positional[0] if positional else "")
            # ``-FilePath`` is a plain command-syntax argument *value*
            # (``Start-Process powershell ...``, an executable name, not
            # an invocation of it) -- ``_eval_expr`` would otherwise read
            # the bareword as an attempted call to a nonexistent
            # "powershell" command and collapse it to ``_Unknown``.
            filename = self._eval_command_arg(path_text) if path_text else _Unknown("<path>")
            if filename is None or _is_unknown(filename) or (isinstance(filename, str) and not filename.strip()):
                self._emit('unresolved_command', api='Start-Process', reason='process-path-unresolved')
                return _Unknown('<process-path>')
            arg_text = named.get("argumentlist") or named.get("args") or (positional[1] if len(positional) > 1 else "")
            arguments = self._eval_command_arg(arg_text) if arg_text else ""
            arguments_resolved = not _is_unknown(arguments)
            if isinstance(arguments, list):
                # ``-ArgumentList @("-NoProfile", "-WindowStyle", ...)``
                # -- real PowerShell space-joins an array when it's
                # interpolated into the final command line; without this,
                # the command showed as a literal Python list repr.
                arguments_resolved = not any(_is_unknown(a) for a in arguments)
                arguments = " ".join('' if a is None else str(a) for a in arguments)
            command = f"{filename} {arguments}".strip() if not _is_unknown(filename) else str(filename)
            directory = self._eval_command_arg(named['workingdirectory']) if 'workingdirectory' in named else None
            self._record_process(command, "Start-Process", arguments_resolved=arguments_resolved, working_directory=directory,
                                 executable=filename, arguments=arguments)
            return None
        if lowered_name in ("invoke-item", "ii"):
            positional, named = self._parse_command_syntax(rest)
            path_text = named.get("path") or named.get("literalpath") or (positional[0] if positional else "")
            path = self._eval_command_arg(path_text) if path_text else _Unknown("<path>")
            self._record_process(path, "Invoke-Item")
            return None
        if lowered_name in ("invoke-command", "icm"):
            positional, named = self._parse_command_syntax(rest)
            sb_text = named.get("scriptblock") or (positional[0] if positional else "")
            ref = self._eval_expr(sb_text) if sb_text else _Unknown('<scriptblock>')
            if not isinstance(ref, _ObjectRef) or ref.kind != 'scriptblock':
                self._emit('unresolved_dynamic_code', api='Invoke-Command', reason='scriptblock-input-unresolved')
                return _Unknown('<invoke-command-result>')
            source = ref.state.get('source')
            if ref.state.get('source_resolved') is False or not isinstance(source, str):
                self._emit('unresolved_dynamic_code', api='Invoke-Command', reason='source-value-unresolved')
                return _Unknown('<invoke-command-result>')
            if any(key in named for key in ('computername', 'session', 'connectionuri', 'hostname', 'vmname', 'vmid', 'containerid')):
                self._emit('unresolved_dynamic_code', api='Invoke-Command', reason='remote-session-not-modeled')
                self._queue_dynamic_layer(source, 'Invoke-Command(remote-script)')
                return _Unknown('<remote-command-result>')
            argument_text = named.get('argumentlist') or named.get('args')
            values = self._eval_expr(argument_text) if argument_text else []
            values = values if isinstance(values, list) else [values]
            if not self._record_dynamic_layer(source, 'Invoke-Command', self._dynamic_depth):
                return _Unknown('<decoded-layer-limit>')
            return self._invoke_scriptblock(ref, values)
        if lowered_name in ("set-content", "add-content", "out-file"):
            positional, named = self._parse_command_syntax(rest, single_token_params=('encoding', 'width'))
            path_text = named.get("path") or named.get("filepath") or named.get("literalpath") or (positional[0] if positional else "")
            value_text = named.get("value") or named.get("inputobject") or (positional[1] if len(positional) > 1 else "")
            path = self._eval_command_arg(path_text) if path_text else _Unknown("<path>")
            content = self._eval_command_arg(value_text) if value_text else ""
            self._record_content_command(path,content,name,named)
            return None
        if lowered_name in ('move-item','copy-item'):
            positional, named = self._parse_command_syntax(rest)
            source = named.get('literalpath') or named.get('path') or (positional[0] if positional else '')
            destination = named.get('destination') or (positional[1] if len(positional)>1 else '')
            self._transfer_virtual_file(self._eval_command_arg(source),self._eval_command_arg(destination),name,
                                        move=lowered_name=='move-item')
            return None
        if lowered_name in ("new-item",):
            positional, named = self._parse_command_syntax(rest)
            path_text = named.get("path") or named.get("literalpath") or (positional[0] if positional else "")
            path = self._eval_command_arg(path_text) if path_text else _Unknown("<path>")
            item_type = str(self._eval_command_arg(named.get('itemtype',''))).lower()
            content = self._eval_command_arg(named['value']) if 'value' in named else ''
            for item in path if isinstance(path,list) else [path]:
                if self._item_provider(item) == 'registry':
                    self._record_registry_write(item, api="New-Item")
                elif item_type in ('directory','dir'):
                    self._emit('filesystem_create_directory',path=_safe_text(item),api='New-Item')
                else:
                    self._record_file_write(item, content, "New-Item")
            return None
        if lowered_name in ("set-itemproperty", "new-itemproperty", "remove-itemproperty"):
            positional, named = self._parse_command_syntax(rest)
            path_text = named.get("path") or named.get("literalpath") or (positional[0] if positional else "")
            name_text = named.get("name") or (positional[1] if len(positional) > 1 else "")
            value_text = named.get("value") or (positional[2] if len(positional) > 2 else "")
            path = self._eval_command_arg(path_text) if path_text else _Unknown("<path>")
            # ``-Name Attributes`` -- a bareword enum-like value, not an
            # invocation attempt (see ``_eval_command_arg``'s docstring);
            # ``_eval_expr`` misread it as a call to a nonexistent
            # "Attributes" command and collapsed it to ``_Unknown``.
            reg_name = self._eval_command_arg(name_text) if name_text else ""
            reg_value = self._eval_command_arg(value_text) if value_text else ""
            self._record_item_property(path, reg_name, reg_value, name, delete=lowered_name == 'remove-itemproperty')
            return None
        if lowered_name in ("remove-item", "ri", "del", "rm", "erase"):
            positional, named = self._parse_command_syntax(rest)
            path_text = named.get("path") or named.get("literalpath") or " ".join(positional)
            # Command arguments may contain comma-separated paths or a
            # variable/array expression. Evaluate each element separately
            # so a quoted first path cannot consume the rest as a suffix.
            for part in _split_top_level(path_text, ",") if path_text else [""]:
                value = self._eval_command_arg(part) if part.strip() else _Unknown("<path>")
                for path in value if isinstance(value, list) else [value]:
                    namespace = re.fullmatch(r'(alias|function):[\\/]?([\w-]+)', str(path), re.I) if isinstance(path, str) else None
                    if namespace:
                        kind, item = namespace[1].lower(), namespace[2].lower()
                        mapping = self.aliases if kind == 'alias' else self.functions
                        mapping.pop(item, None)
                        self._emit(kind + '_delete', name=item, api=name)
                        continue
                    if self._item_provider(path) == 'registry':
                        self._emit('registry_delete', path=_safe_text(path), api=name, action='delete_key')
                        continue
                    if 'stream' in named:
                        stream = self._eval_command_arg(named['stream'])
                        self._emit('filesystem_delete_stream',path=_safe_text(path),stream=_safe_text(stream),api=name)
                    else:
                        self._forget_virtual_file(path)
                        self._emit("filesystem_delete", path=_safe_text(path), api=name)
            return None
        if lowered_name in ("add-type",):
            positional, named = self._parse_command_syntax(
                rest, parameter_names=_ADD_TYPE_PARAMETER_NAMES,
                switch_params=('passthru', 'ignorewarnings'))
            if named.get('_binding_error'):
                return _Unknown('<add-type-parameter-binding>')
            if 'assemblyname' in named:
                reference = self._eval_command_arg(named['assemblyname'])
                self._emit('assembly_reference',api='Add-Type -AssemblyName',reference=_safe_text(reference),
                           reference_resolved=not _is_unknown(reference),content_available=False)
                return None
            source_text = named.get("typedefinition") or named.get('memberdefinition') or (positional[0] if positional else "")
            if source_text:
                source = self._eval_command_arg(source_text)
                resolved = isinstance(source, str) and not _is_unknown(source)
                self._emit("dynamic_code", api="Add-Type", size=len(source) if resolved else None,
                           input_resolved=resolved)
                declarations = _parse_native_memory_declarations(source) if resolved else None
                if declarations:
                    type_key, methods = declarations
                    reserved = {'array', 'bool', 'boolean', 'byte', 'char', 'console', 'convert', 'datetime',
                                'decimal', 'double', 'environment', 'float', 'guid', 'hashtable', 'int',
                                'int16', 'int32', 'int64', 'intptr', 'long', 'math', 'object', 'regex',
                                'sbyte', 'short', 'single', 'string', 'timespan', 'type', 'uint', 'uint16',
                                'uint32', 'uint64', 'uintptr', 'uri', 'version', 'void'}
                    if (type_key not in reserved and type_key not in self._script_types
                            and type_key not in self._native_declared_types and len(self._native_declared_types) < 128):
                        self._native_declared_types[type_key] = methods
                        self._emit('native_api_declarations', api='Add-Type', type=type_key,
                                   methods=[v['name'] for v in methods.values()], representation='symbolic-declarations-only')
                        return _ObjectRef('reflection.type', {'type_key': type_key}) if 'passthru' in named else None
                self._emit('unresolved_dynamic_code', api='Add-Type',
                           reason='compiled-type-not-emulated' if resolved else 'source-value-unresolved')
            return None
        if lowered_name in ("invoke-cimmethod", "invoke-wmimethod"):
            self._emit("process_create", command=_safe_text(rest.strip()), api=name)
            return None
        if lowered_name in ("get-wmiobject", "gwmi", "get-ciminstance"):
            return _Unknown("<wmi-object>")
        if lowered_name in ("get-childitem", "gci", "ls", "dir"):
            # Enumerate only our modeled writes. A host directory's
            # remaining entries are unavailable; never invent file.exe.
            positional, named = self._parse_command_syntax(rest)
            path_text = named.get("path") or named.get("literalpath") or (positional[0] if positional else "")
            filter_text = named.get("filter")
            path_val = self._eval_command_arg(path_text) if path_text else _Unknown("<path>")
            if _is_unknown(path_val):
                return _Unknown("<childitems>")
            filter_val = self._eval_command_arg(filter_text) if filter_text else None
            base_dir = self._virtual_file_key(path_val)
            if base_dir is None or (filter_text and not isinstance(filter_val,str)):
                return _Unknown('<childitems>')
            filter_str = filter_val.lower() if isinstance(filter_val,str) else '*'
            self._emit('unresolved_environment',api=name,path=_safe_text(path_val),reason='host-directory-entries-not-provided')
            items = []
            for full_path,data in self._virtual_files.items():
                directory,filename = ntpath.split(full_path)
                within = directory == base_dir or ('recurse' in named and directory.startswith(base_dir.rstrip('\\')+'\\'))
                if within and fnmatch.fnmatchcase(filename,filter_str):
                    items.append(_ObjectRef('io.fileinfo',{'fullname':full_path,'name':filename,
                                 'extension':ntpath.splitext(filename)[1],'directoryname':directory,
                                 'length':len(data) if isinstance(data,bytes) else _Unknown('<file-size-not-provided>')}))
            return items if items else _Unknown('<childitems-not-provided>')
        if lowered_name in ("get-item", "gi"):
            # ``(Get-Item -LiteralPath $destDir).FullName`` -- unlike
            # ``Get-ChildItem`` (a wildcard-filtered *listing*, faked
            # with a single synthetic match above), ``Get-Item`` just
            # describes the exact path it was given -- so its
            # ``.FullName`` is that same resolved path, not a
            # fabricated filename.
            positional, named = self._parse_command_syntax(rest)
            path_text = named.get("path") or named.get("literalpath") or (positional[0] if positional else "")
            path_val = self._eval_command_arg(path_text) if path_text else _Unknown("<path>")
            if _is_unknown(path_val):
                return _Unknown("<item>")
            full_path = str(path_val)
            name_part = full_path.replace("/", "\\").rsplit("\\", 1)[-1]
            data = self._virtual_files.get(self._virtual_file_key(path_val))
            return _ObjectRef("io.fileinfo", {
                "fullname": full_path,
                "name": name_part,
                "extension": ("." + name_part.rsplit(".", 1)[-1]) if "." in name_part else "",
                "length": len(data) if isinstance(data,bytes) else _Unknown('<file-size-not-provided>'),
                "directoryname": full_path.replace("/", "\\").rsplit("\\", 1)[0] if "\\" in full_path else full_path,
            })
        if lowered_name in ("get-command", "gcm"):
            # ``& (Get-Command Verb-Noun) args`` -- an indirection
            # obfuscators use specifically to keep the callee's name out
            # of a plain ``&``/bareword call site. Real ``Get-Command``
            # returns a CommandInfo object; all this emulator's call
            # sites for it need is the resolved *name* passed through as
            # a plain string, so ``_eval_call_operator``'s bareword-name
            # dispatch still finds and invokes the real function.
            positional, named = self._parse_command_syntax(rest)
            name_text = (named.get("name") or (positional[0] if positional else "")).strip()
            if not name_text:
                return _Unknown("<command-name>")
            # A bareword function name (the overwhelmingly common case)
            # must be returned as-is, *not* run through ``_eval_expr``:
            # that would read it as a command invocation of its own and
            # actually call the target function right here, with no
            # arguments, as a side effect of merely resolving its name.
            # Only ``Get-Command $var``/``Get-Command "Name"`` -- a real
            # variable or string literal -- needs evaluating.
            if name_text[:1] not in ("$", '"', "'"):
                resolved = name_text.strip("'\"")
            else:
                resolved = self._eval_expr(name_text)
            if not isinstance(resolved, str):
                return _Unknown("<command-name>")
            if any(c in resolved for c in "*?["):
                catalog = _NOOP_CMDLETS | {"write", "irm", "iwr", "iex", "invoke-expression", "invoke-restmethod", "invoke-webrequest", "start", "start-process", "get-command", "get-variable", "set-variable"} | set(self.functions) | set(self.aliases)
                matches = sorted(name for name in catalog if fnmatch.fnmatchcase(name.lower(), resolved.lower()))
                self._emit("command_resolution", pattern=resolved, matches=matches,
                           scope="modeled-command-catalog; host commands may differ")
                if len(matches) != 1:
                    return _Unknown("<ambiguous-or-unmodeled-command>")
                resolved = matches[0]
            return _CommandName(resolved)
        if lowered_name in ("get-variable", "gv"):
            # ``(gv('lf'+'Uy') -V)`` -- reading a variable by a
            # dynamically *built* name string instead of a real ``$var``
            # reference, specifically to keep that name out of a plain
            # ``$name`` token any simple deobfuscator would grep for.
            # This emulator's flat namespace makes the fix exactly the
            # same lookup ``$var`` itself uses -- just keyed by the
            # resolved string instead of a literal token.
            args_text = self._parse_variable_alias_args(rest)
            if not args_text:
                return _Unknown("<get-variable>")
            name_val = self._eval_expr(args_text[0])
            if _is_unknown(name_val) or not str(name_val).strip():
                return _Unknown("<get-variable>")
            key = _normalize_var_name("$" + str(name_val))
            return self.variables.get(key, _Unknown(f"<uninitialized:{name_val}>"))
        if lowered_name in ("set-variable", "sv", "new-variable", "nv"):
            args_text = self._parse_variable_alias_args(rest)
            if not args_text:
                return None
            name_val = self._eval_expr(args_text[0])
            if _is_unknown(name_val) or not str(name_val).strip():
                return None
            value = self._eval_expr(args_text[1]) if len(args_text) > 1 else None
            self._store_variable("$" + str(name_val), value)
            return None
        if lowered_name in ("get-content", "gc", "cat", "type"):
            positional, named = self._parse_command_syntax(rest)
            path_text = named.get("path") or named.get("literalpath") or (positional[0] if positional else "")
            path = self._eval_command_arg(path_text) if path_text else _Unknown("<path>")
            encoding = self._eval_command_arg(named['encoding']) if 'encoding' in named else None
            value = self._read_virtual_file(path,name,as_bytes='asbytestream' in named or str(encoding).lower()=='byte',encoding=encoding)
            if isinstance(value,str) and 'raw' not in named:
                lines = value.splitlines()
                return lines[0] if len(lines)==1 else lines
            return value
        if lowered_name in ('set-location', 'cd', 'chdir', 'sl'):
            positional, named = self._parse_command_syntax(rest)
            path_text = named.get('literalpath') or named.get('path') or (positional[0] if positional else '')
            self._working_directory = self._eval_command_arg(path_text) if path_text else _Unknown('<working-directory>')
            self._emit('filesystem_chdir', api=name, path=_safe_text(self._working_directory), modeled=True)
            return None
        if lowered_name == 'measure-command':
            positional, named = self._parse_command_syntax(rest)
            source_text = named.get('expression') or (positional[0] if positional else '')
            block = self._eval_expr(source_text) if source_text else None
            if isinstance(block, _ObjectRef) and block.kind == 'scriptblock':
                self._invoke_scriptblock(block, [])
            else:
                self._emit('unresolved_dynamic_code', api=name, reason='scriptblock-input-unresolved')
            return _Unknown('<measured-duration>')
        if lowered_name == 'get-scheduledtask':
            self._emit('unresolved_environment', api=name, reason='host-task-definitions-not-provided')
            return _Unknown('<scheduled-task-definitions>')
        if lowered_name in ('start-scheduledtask', 'stop-scheduledtask', 'unregister-scheduledtask'):
            positional, named = self._parse_command_syntax(rest)
            name_text = named.get('taskname') or (positional[0] if positional else '')
            task_name = self._eval_command_arg(name_text) if name_text else _Unknown('<task-name>')
            folder = self._eval_command_arg(named['taskpath']) if named.get('taskpath') else '\\'
            category = {'start-scheduledtask': 'scheduled_task_start', 'stop-scheduledtask': 'scheduled_task_stop',
                        'unregister-scheduledtask': 'scheduled_task_delete'}[lowered_name]
            self._emit(category, api=name, task_name=_safe_text(task_name), task_folder=_safe_text(folder))
            return None
        if lowered_name == "join-path":
            # Extremely common right before a download/write/execute
            # step (``$filePath = Join-Path $workDir $fileName``);
            # leaving it unmodeled meant every path built this way (and
            # everything derived from it downstream -- the write, the
            # extraction, the relaunch) stayed ``_Unknown``.
            positional, named = self._parse_command_syntax(rest)
            parent_text = named.get("path") or named.get("literalpath") or (positional[0] if positional else "")
            child_text = named.get("childpath") or (positional[1] if len(positional) > 1 else "")
            parent = self._eval_expr(parent_text) if parent_text else _Unknown("<path>")
            child = self._eval_expr(child_text) if child_text else _Unknown("<path>")
            if not isinstance(parent, str) or not isinstance(child, str):
                return _Unknown(f"<{parent}\\{child}>")
            parent_trimmed = str(parent).rstrip("\\/")
            child_trimmed = str(child).lstrip("\\/")
            return parent_trimmed + "\\" + child_trimmed
        if lowered_name == 'split-path':
            positional,named = self._parse_command_syntax(rest)
            source = named.get('literalpath') or named.get('path') or (positional[0] if positional else '')
            path = self._eval_command_arg(source) if source else _Unknown('<path>')
            if not isinstance(path,str) or 'resolve' in named:
                return _Unknown('<split-path-input>')
            if 'leaf' in named:
                return ntpath.basename(path.rstrip('\\/'))
            if 'qualifier' in named:
                return ntpath.splitdrive(path)[0]
            if 'noqualifier' in named:
                return ntpath.splitdrive(path)[1]
            if 'isabsolute' in named:
                return ntpath.isabs(path)
            return ntpath.dirname(path.rstrip('\\/'))
        if lowered_name == "get-random":
            # ``Get-Random -Minimum 1000 -Maximum 9999`` -- a dropped
            # binary's randomized filename (``svchost_<rand>.exe``, the
            # near-universal shape) is built from this. A fixed
            # mid-range value, not a real random draw: this emulator
            # never guesses a *specific* answer, but a concrete-if-fake
            # number here is what lets the surrounding path/command
            # resolve to something readable at all instead of collapsing
            # the whole string to ``_Unknown``.
            positional, named = self._parse_command_syntax(rest)
            input_text = named.get('inputobject') or (positional[0] if positional else None)
            selection = self._eval_command_arg(input_text) if input_text else None
            if isinstance(selection, list) or 'inputobject' in named:
                items = selection if isinstance(selection, list) else [selection]
                try:
                    count = int(_numeric_coerce(self._eval_expr(named['count']))) if 'count' in named else 1
                except (ValueError, TypeError, OverflowError):
                    return _Unknown('<random-selection-count>')
                return self._select_random_model(items, count, name)
            minimum_text = named.get("minimum") or named.get('min')
            maximum_text = named.get("maximum") or named.get('max') or (positional[0] if positional else None)
            try:
                minimum = int(_numeric_coerce(self._eval_expr(minimum_text))) if minimum_text else 0
            except (TypeError, ValueError):
                minimum = 0
            try:
                maximum = int(_numeric_coerce(self._eval_expr(maximum_text))) if maximum_text else 2147483647
            except (TypeError, ValueError):
                maximum = 2147483647
            return max(minimum, min(maximum - 1, minimum + (maximum - minimum) // 2)) if maximum > minimum else minimum
        if lowered_name in ("set-executionpolicy", "set-mppreference", "add-mppreference"):
            self._emit("defense_evasion", api=name, args=_safe_text(rest.strip(), 512))
            return None
        if lowered_name in ('stop-process', 'kill', 'spps'):
            positional, named = self._parse_command_syntax(rest)
            key = 'name' if 'name' in named else 'id'
            raw = named.get(key) or (positional[0] if positional else None)
            target = self._eval_command_arg(raw) if raw else _Unknown('<process-target>')
            targets = target if isinstance(target, list) else [target]
            for item in targets[:MAX_VARIABLES]:
                self._emit('process_terminate', api=name, **{key: _safe_text(item)},
                           target_resolved=not _is_unknown(item) and item is not None)
            return None
        if lowered_name in ("new-scheduledtaskaction", "new-scheduledtasktrigger", "new-scheduledtasksettingsset", "new-scheduledtaskprincipal", "register-scheduledtask"):
            positional, named = self._parse_command_syntax(rest)
            fields = {key: self._eval_command_arg(text) if text else True for key, text in named.items()}
            if lowered_name != "register-scheduledtask":
                return _ObjectRef("scheduledtask.options", fields)
            action = fields.get("action")
            action_fields = action.state if isinstance(action, _ObjectRef) and action.kind == "scheduledtask.options" else {}
            execute = action_fields.get("execute")
            self._emit("scheduled_task", api=name, task_name=_safe_text(fields.get("taskname")),
                       execute=_safe_text(execute) if execute is not None else None,
                       arguments=_safe_text(action_fields.get("argument", "")),
                       input_resolved=isinstance(execute, str) and bool(execute.strip()))
            return _Unknown("<scheduled-task-result>")
        if lowered_name in ("if", "elseif", "while", "until", "switch"):
            # ``_normalize_block_syntax`` only turns a flattened block's
            # own ``{``/``}`` into statement separators -- the leading
            # ``if (COND)``/``while (COND)`` text in front of that brace
            # survives untouched as ordinary statement text. Without this
            # branch it falls through to the generic bareword-command
            # dispatch, which reads "if"/"while"/... as an attempted call
            # to a nonexistent command and returns ``_Unknown`` *without
            # ever evaluating* ``COND`` -- silently dropping any
            # side-effecting call inside a condition (``if (& Download $u
            # $p) {...}``), even though this emulator's flatten-and-run-
            # both-branches design already runs the body unconditionally.
            # Evaluating the condition here for its value/side effects
            # (the boolean result itself is never needed, since the body
            # runs regardless) closes that gap.
            cond_text = rest.strip()
            if cond_text[:1] == "(":
                body, end = _extract_balanced(cond_text, 0, "(", ")")
                if body is not None:
                    self._eval_expr(body)
            return None
        if lowered_name in _NOOP_CMDLETS:
            return None
        if lowered_name in ("set-alias", "new-alias"):
            positional, named = self._parse_command_syntax(rest)
            alias_text = named.get("name") or (positional[0] if positional else "")
            target_text = named.get("value") or (positional[1] if len(positional) > 1 else "")
            alias_val = self._eval_command_arg(alias_text) if alias_text else _Unknown("<alias>")
            target_val = self._eval_command_arg(target_text) if target_text else _Unknown("<target>")
            if not _is_unknown(alias_val) and not _is_unknown(target_val):
                alias_name, target_name = str(alias_val).strip().lower(), str(target_val).strip()
                scope = self._eval_command_arg(named['scope']) if 'scope' in named else None
                if isinstance(scope, str) and scope.lower() == 'global' and self._script_call_frames:
                    self._script_call_frames[0][1][alias_name] = target_name
                else:
                    self.aliases[alias_name] = target_name
            return None
        # Windows resolves mshta without an extension. Preserve command
        # resolution precedence: a user-defined function/alias wins above.
        # Explicit executable names also need to retain their extension,
        # particularly curl.exe, which is not the PowerShell curl alias.
        if (lowered_name in ('mshta','cmd','powershell','pwsh','wscript','cscript','rundll32','regsvr32','certutil','bitsadmin','schtasks','reg','msiexec')
                or lowered_name.endswith((".exe", ".com"))):
            return self._record_native_command(name, rest, 'native-command')
        literal_urls = re.findall(r"https?://[^\s<>\"']+", rest, re.IGNORECASE)
        if literal_urls:
            self._emit("unresolved_command", command=name, reason="command-not-modeled")
            for url in dict.fromkeys(literal_urls):
                self._emit("static_ioc", kind="url", value=url, source="unresolved-command")
        else:
            self._unmodeled_command_count += 1
            example = name[:80]
            if len(self._unmodeled_command_examples) < 8 and example not in self._unmodeled_command_examples:
                self._unmodeled_command_examples.append(example)
        return _Unknown(f"<{name} {rest.strip()}>".strip())

    # -- statement-level dispatch ----------------------------------------------

    def _run_simple_assignment_branches(self, branches):
        def evaluate(node):
            if node is None:
                return True
            if node[0] in ('atom', 'null-or-empty'):
                value = self._eval_expr(node[1])
                if node[0] == 'null-or-empty' and not _is_unknown(value):
                    return value is None or value == ''
                return value
            left = evaluate(node[1])
            if node[0] == '-not':
                return left if _is_unknown(left) else not _truthy(left)
            conjunction = node[0] == '-and'
            if not _is_unknown(left) and _truthy(left) != conjunction:
                return not conjunction
            right = evaluate(node[2])
            if not _is_unknown(right) and _truthy(right) != conjunction:
                return not conjunction
            if _is_unknown(left) or _is_unknown(right):
                return _Unknown('<conditional-predicate>')
            return conjunction

        initial = self.variables.copy()
        targets = {_normalize_var_name(name) for _, body in branches for name, _ in body}
        states, fallthrough = [], True
        for condition, body in branches:
            value = evaluate(condition)
            if not _is_unknown(value) and not _truthy(value):
                continue
            self.variables = initial.copy()
            try:
                for name, expression in body:
                    self._tick()
                    self._store_variable(name, self._eval_expr(expression))
                states.append({name: self.variables.get(name) for name in targets})
            finally:
                self.variables = initial.copy()
            if not _is_unknown(value):
                fallthrough = False
                break
        if fallthrough:
            states.append({name: initial.get(name) for name in targets})
        for name in targets:
            candidates = [state.get(name) for state in states]
            value = candidates[0]
            if any(type(other) is not type(value) or other != value for other in candidates[1:]):
                value = _Unknown('<conditional-value>')
            self._store_variable(name, value)
        if len(states) > 1:
            self._emit('unsupported_operation', api='if', reason='unknown-condition-values-merged')

    def _process_statement(self, statement):
        stripped = statement.strip()
        if not stripped or stripped in ("}", "{"):
            return
        branches = _try_parse_if_expression(stripped)
        prepared_branches = _simple_assignment_branches(branches) if branches is not None else None
        if prepared_branches is not None:
            return self._run_simple_assignment_branches(prepared_branches)
        typed_assignment = re.match(rf"^\[([A-Za-z_][\w.]*(?:\[\])?)\]\s*({_VAR_REF})\s*=(?!=)\s*(.+)$", stripped, re.DOTALL)
        if typed_assignment:
            type_name, name, expression = typed_assignment.groups()
            raw_value = None
            literal = expression.strip()
            if literal.startswith("(") and literal.endswith(")"):
                literal = literal[1:-1].strip()
            literal_bytes = (type_name.lower() in ("byte[]", "system.byte[]") and len(literal) > 1024
                             and re.fullmatch(r"[0-9a-fA-FxX,\s]+", literal) is not None)
            if literal_bytes:
                parts = literal.split(",")
                if len(parts) > MAX_EMBEDDED_PAYLOAD_BYTES:
                    self._emit("resource_limit", resource="byte_array_elements", limit=MAX_EMBEDDED_PAYLOAD_BYTES)
                    raw_value = _Unknown("<byte-array-size-limit>")
                elif all(re.fullmatch(r"\s*(?:\d{1,3}|0[xX][0-9a-fA-F]{1,2})\s*", part)
                         and int(part, 16 if part.strip().lower().startswith('0x') else 10) <= 255 for part in parts):
                    # Literal data only, with bounded work checkpoints; no
                    # expression interpreter is needed for every byte.
                    data = bytearray()
                    for offset in range(0, len(parts), 4096):
                        self._tick()
                        data.extend(int(part, 16 if part.strip().lower().startswith('0x') else 10)
                                    for part in parts[offset:offset + 4096])
                    raw_value = _BinaryValue(bytes(data))
                else:
                    literal_bytes = False
            if not literal_bytes:
                raw_value = self._eval_expr(expression)
            value = None if raw_value is None and type_name.endswith("[]") else self._apply_cast(type_name, raw_value)
            if type_name.lower() in ("byte[]", "system.byte[]") and isinstance(value, _BinaryValue):
                # Declared byte arrays support subsequent indexed writes.
                value = _ByteArray(value.data) if value.complete else _Unknown('<incomplete-byte-array>')
            declarations, declared_key = self.variables.type_slot(_normalize_var_name(name))
            declarations[declared_key] = type_name
            self._store_variable(name, value)
            if type_name.lower() in ("byte[]", "system.byte[]"):
                data = _as_bytes(value)
                if data and data.startswith(b"MZ"):
                    self._remember_embedded_payload(data, "typed-byte-array")
            return
        func_def = _try_parse_function_def(stripped)
        if func_def:
            name, params_text, body = func_def
            info = {"params_text": params_text, "body": body}
            if re.match(r'^function\s+global:', stripped, re.I) and self._script_call_frames:
                self._script_call_frames[0][0][name.lower()] = info
            else:
                self.functions[name.lower()] = info
            return

        if re.match(r'^(?:class|enum)\s+\w+', stripped, re.I):
            declaration = _parse_script_type_definition(stripped)
            if declaration is None:
                self._emit('unsupported_operation', api='PowerShellClass.Definition', reason='type-declaration-not-modeled')
            elif len(self._script_types) >= 128:
                self._emit('resource_limit', resource='script_type_definitions', limit=128)
            else:
                name, definition = declaration
                self._script_types[name] = definition
                if any(method['program'] is None for overloads in definition.get('methods', {}).values() for method in overloads):
                    self._emit('unsupported_operation', api='PowerShellClass.Definition', type=name,
                               reason='one-or-more-method-bodies-not-modeled')
            return
        if re.match(r'^while\s*\(\s*\$\w+\.\w+\(\)\s*\)\s*\{', stripped, re.I):
            program = _parse_script_method_program(stripped)
            try:
                if program is None:
                    raise _ValueUnresolved()
                return self._run_script_method_program(program)[1]
            except _ValueUnresolved:
                self._emit('unresolved_loop', reason='method-condition-loop-unresolved')
                return

        state_machine = _try_parse_state_machine(stripped)
        if state_machine:
            return self._handle_state_machine(*state_machine)

        radix_loop = _scan_bigint_byte_loop(stripped) if re.match(r'while\b', stripped, re.I) else None
        if radix_loop:
            number_name, output_name, end = radix_loop
            number = self.variables.get(number_name)
            output = self.variables.get(output_name)
            if type(number) is not int or not isinstance(output, list):
                self._emit('unresolved_loop', reason='bigint-byte-loop-input-unresolved')
                return
            while number > 0:
                self._tick()
                if len(output) >= MAX_VARIABLES:
                    self._emit('resource_limit', resource='bigint-byte-loop-output', limit=MAX_VARIABLES)
                    return
                output.append(chr(number % 256))
                number //= 256
            self._store_variable(number_name, number)
            tail = stripped[end:].strip()
            return self._run_scriptblock_body(tail) if tail else None

        do_loop = _scan_do_loop(stripped) if re.match(r'do\b', stripped, re.I) else None
        if do_loop:
            body, condition, mode, end = do_loop
            self._handle_do_loop(body, condition, mode)
            tail = stripped[end:].strip()
            return self._run_scriptblock_body(tail) if tail else None

        for_header = _try_parse_for_header(stripped)
        if for_header:
            self._handle_for_loop(*for_header)
            return

        foreach_header = _try_parse_foreach_header(stripped)
        if foreach_header:
            self._handle_foreach_loop(*foreach_header)
            return

        range_foreach = _try_parse_range_foreach(stripped)
        if range_foreach and self._try_fast_range_foreach(*range_foreach):
            return

        incr_match = _INCREMENT_RE.match(stripped)
        if incr_match:
            self._apply_increment(incr_match.group(1) or incr_match.group(4), incr_match.group(2) or incr_match.group(3))
            return

        chained_assign = _try_parse_chained_assign(stripped)
        if chained_assign:
            self._handle_chained_assignment(*chained_assign)
            return

        multi_assign = _try_parse_multi_assign(stripped)
        if multi_assign:
            self._handle_multi_assignment(*multi_assign)
            return

        index_assign = _try_parse_index_assign(stripped)
        if index_assign:
            self._handle_index_assignment(*index_assign)
            return

        generic_index_assign = _try_parse_generic_index_assign(stripped)
        if generic_index_assign:
            self._handle_generic_index_assignment(*generic_index_assign)
            return

        prop_match = _PROPERTY_ASSIGN_RE.match(stripped)
        if prop_match:
            self._handle_property_assignment(*prop_match.groups())
            return

        assign_match = _ASSIGN_RE.match(stripped)
        if assign_match:
            self._handle_assignment(*assign_match.groups())
            return

        return self._process_pipeline(stripped)

    def _prepare_loop_body(self, body_text):
        # Parsed once per loop, not once per iteration: a decode loop
        # commonly runs tens or hundreds of thousands of times over real
        # payload data, and re-running ``_strip_comments``/
        # ``_normalize_block_syntax``/``_split_statements`` (each its own
        # full scan of the body text) on every single iteration was, by
        # far, the dominant cost of executing one -- confirmed via
        # profiling a real hex/XOR decode sample that otherwise burned its
        # entire statement budget well before finishing.
        cleaned = _strip_comments(body_text)
        normalized = _normalize_block_syntax(cleaned)
        return _split_statements(normalized)

    def _handle_do_loop(self, body, condition, mode):
        statements = self._prepare_loop_body(body)
        # Nested control transfers need their branch semantics; flattening
        # them would turn conditional exits into unconditional ones.
        if any(re.search(r'\b(?:break|continue|return)\b', s, re.I)
               for s in _split_statements(body) if s.strip().lower() not in ('break', 'continue')):
            self._emit('unresolved_loop', reason='do-loop-control-transfer-unmodeled')
            return
        monitor = condition.strip().lower() == ('$true' if mode == 'while' else '$false')
        random_retry = bool(re.fullmatch(r'\s*\$\w+\s*=\s*Get-Random\b[^;{}]*;?\s*', body, re.I))
        previous_state = None
        for iteration in range(MAX_LOOP_ITERATIONS):
            self._tick()
            for statement in statements:
                control = statement.strip().lower()
                if control == 'break':
                    return
                if control == 'continue':
                    break
                self._tick()
                self._process_statement(statement)
            decision = self._eval_expr(condition)
            if _is_unknown(decision):
                self._emit('unresolved_loop', reason='do-loop-condition-unresolved', condition=_safe_text(condition, 200))
                return
            if _truthy(decision) == (mode == 'until'):
                return
            if monitor or random_retry:
                # Only serialize our synthetic state; never deserialize
                # sample data. Stable model state summarizes repeated
                # polling without pretending that the real loop terminates.
                state = pickle.dumps((self.variables.maps, self.aliases, self.functions, self.objects,
                                      self._reflection_fields, self._layer_queue, self._working_directory,
                                      self._virtual_files, self._native_allocated_bytes, self._native_region_count, len(self.events)), protocol=4)
                fingerprint = hashlib.sha256(state).digest()
                if fingerprint == previous_state:
                    if random_retry and not monitor:
                        self._emit('unresolved_loop', reason='repeated-random-model-state', iterations=iteration + 1,
                                   runtime_behavior='random retries may choose other values; termination is unresolved')
                        return
                    self._emit('loop_summary', reason='repeated-abstract-state', iterations=iteration+1,
                               runtime_behavior='unbounded-loop; external state remains unknown')
                    return
                previous_state = fingerprint
        self._emit('resource_limit', resource='loop_iterations', limit=MAX_LOOP_ITERATIONS)

    def _run_loop_body_once(self, statements):
        output = None
        for statement in statements:
            self._tick()
            returned = re.match(r'^return\b\s*(.*)$',statement.strip(),re.I | re.S)
            if returned:
                value = self._eval_expr(returned[1]) if returned[1] else None
                self._emit('unresolved_loop',reason='loop-return-control-transfer-not-modeled')
                return value
            candidate = self._process_statement(statement)
            if candidate is not None and not _is_unknown(candidate):
                output = candidate
        return output

    def _apply_increment(self, name, op):
        key = _normalize_var_name(name)
        old = self.variables.get(key, 0)
        try:
            old_n = _numeric_coerce(old)
        except (TypeError, ValueError):
            old_n = 0
        self._store_variable(name, old_n + (1 if op == "++" else -1))

    def _try_lcg_subtract_loop(self, loop_var, cond_text, incr_text, statements):
        if len(statements) != 2 or self.variables.get(loop_var) != 0 or _extract_incr_step(loop_var, incr_text) != 1:
            return False
        compact = re.sub(r'\s+', '', ';'.join(statements)).lower()
        literal = r'(?:0x[0-9a-f]+|\d+)'
        match = re.fullmatch(
            r'\$(?P<out>\w+)\[\$(?P<i>\w+)\]=\(\$(?P<data>\w+)\[\$(?P=i)\]-\(\$(?P<k>\w+)-band(?:0xff|255)\)\+256\)-band(?:0xff|255);'
            r'\$(?P=k)=\(\$(?P=k)\*(?P<mul>' + literal + r')\+(?P<add>' + literal + r')\)-band(?P<mask>' + literal + r')', compact)
        if (not match or match['i'] != loop_var or len({match[n] for n in ('out','i','data','k')}) != 4
                or not _cond_matches_length(loop_var, match['data'], cond_text)):
            return False
        source, target = self.variables.get(match['data']), self.variables.get(match['out'])
        state = self.variables.get(match['k'])
        mul, add, mask = (_numeric_literal(match[n]) for n in ('mul','add','mask'))
        if (type(state) is not int or not all(type(n) is int and 0 <= n <= 0x7fffffff for n in (state,mul,add,mask))
                or mask != 0x7fffffff or mul > 65535 or add > 65535
                or not isinstance(target, list) or not isinstance(source, (list,_BinaryValue))):
            return False
        if isinstance(source, _BinaryValue) and not source.complete:
            return False
        if isinstance(source, list) and not all(type(n) is int and 0 <= n <= 255 for n in source):
            return False
        data = _as_bytes(source)
        if data is None or len(data) > MAX_EMBEDDED_PAYLOAD_BYTES or len(target) < len(data):
            return False
        for i, byte in enumerate(data):
            if i % 4096 == 0:
                self._tick()
            target[i] = (byte - (state & 255) + 256) & 255
            state = (state * mul + add) & mask
        self._store_variable(match['k'], state)
        self._store_variable(loop_var, len(data))
        return True

    def _try_fast_for_loop(self, loop_var, cond_text, incr_text, core_statements):
        """Recognize the hex-decode/XOR-decrypt loop-body shapes matched
        by ``_HEX_LOOP_BODY_RE``/``_XOR_LOOP_BODY_RE``/``_HEX_ADD_*_RE``
        and, when every variable/operator lines up, compute the loop's
        entire effect in one native Python pass instead of ticking
        through it. Returns True only when it fully handled (and
        mutated state for) the loop; any mismatch returns False so the
        caller falls through to the real per-iteration simulation --
        this never fabricates a partial or guessed result.
        """
        start = self.variables.get(loop_var)
        if not isinstance(start, int) or isinstance(start, bool) or start != 0:
            return False
        if self._try_lcg_subtract_loop(loop_var, cond_text, incr_text, core_statements):
            return True
        if len(core_statements) == 4 and _extract_incr_step(loop_var, incr_text) == 1:
            compact = re.sub(r'\s+', '', ';'.join(core_statements)).lower()
            rotate = re.fullmatch(
                r'\$(?P<s>\w+)\[\$(?P<i>\w+)\]=\$(?P=s)\[\$(?P=i)\]-bxor\$(?P<v>\w+)\[\$(?P=i)-band15\];'
                r'\$(?P<r>\w+)=\(\$(?P<k>\w+)\[\(\$(?P=i)\+7\)-band31\]%7\)\+1;'
                r'\$(?P<b>\w+)=\[int\]\$(?P=s)\[\$(?P=i)\];'
                r'\$(?P=s)\[\$(?P=i)\]=\[byte\]\(\(\(\(\$(?P=b)-shr\$(?P=r)\)-bor\(\$(?P=b)-shl\(8-\$(?P=r)\)\)\)-band0xff\)-bxor\$(?P=k)\[\$(?P=i)%\$(?P<kl>\w+)\]-bxor\$(?P=k)\[\(\$(?P=i)\+17\)-band31\]\)', compact)
            if rotate and rotate['i'] == loop_var and len(set(rotate.groupdict().values())) == len(rotate.groupdict()):
                source = self.variables.get(rotate['s'])
                key, iv = self.variables.get(rotate['k']), self.variables.get(rotate['v'])
                bound = re.fullmatch(r'\s*\$' + re.escape(loop_var) + r'\s*-lt\s*\$(\w+)\s*', cond_text, re.I)
                if (isinstance(source, list) and isinstance(key, list) and isinstance(iv, list)
                        and len(key) == 32 and len(iv) == 16 and self.variables.get(rotate['kl']) == 32
                        and bound and bound[1].lower() not in {rotate['i'],rotate['r'],rotate['b']}
                        and self.variables.get(bound[1].lower()) == len(source)
                        and all(type(n) is int and 0 <= n <= 255 for values in (source,key,iv) for n in values)):
                    for i, byte in enumerate(source):
                        if i % 4096 == 0:
                            self._tick()
                        value = byte ^ iv[i & 15]
                        rotation = key[(i + 7) & 31] % 7 + 1
                        source[i] = (((value >> rotation) | (value << (8-rotation))) & 255) ^ key[i % 32] ^ key[(i+17) & 31]
                    self._store_variable(loop_var, len(source))
                    if source:
                        self._store_variable(rotate['r'], rotation)
                        self._store_variable(rotate['b'], value)
                    return True

        if len(core_statements) == 7:
            compact_body = re.sub(r"\s+", "", ";".join(s.strip().rstrip(";") for s in core_statements)).lower()
            prga = _RC4_PRGA_RE.fullmatch(compact_body)
            if prga and prga['i'] == loop_var and len(set(prga.groupdict().values())) == len(prga.groupdict()) and _extract_incr_step(loop_var, incr_text) == 1 and _cond_matches_length(loop_var, prga['data'], cond_text):
                box = self.variables.get(prga['s'])
                source = self.variables.get(prga['data'])
                target = self.variables.get(prga['out'])
                x, y = self.variables.get(prga['x']), self.variables.get(prga['y'])
                if isinstance(source, (list, _BinaryValue)) and isinstance(target, list) and isinstance(box, list) and source is not box and target is not box and len(box) == 256 and all(type(n) is int for n in box) and sorted(box) == list(range(256)) and type(x) is int and type(y) is int and 0 <= x < 256 and 0 <= y < 256 and len(source) == len(target) and 0 < len(source) <= MAX_EMBEDDED_PAYLOAD_BYTES:
                    data = _as_bytes(source)
                    if data is not None and (not isinstance(source, _BinaryValue) or source.complete):
                        for index, byte in enumerate(data):
                            if index % 4096 == 0:
                                self._tick()
                            x = (x + 1) % 256
                            y = (y + box[x]) % 256
                            temporary = box[x]
                            box[x], box[y] = box[y], box[x]
                            key_byte = box[(box[x] + box[y]) % 256]
                            target[index] = byte ^ key_byte
                        self.variables.update({prga['x']: x, prga['y']: y, prga['t']: temporary, prga['k']: key_byte, loop_var: len(data)})
                        return True

        if len(core_statements) == 2:
            index_temp = re.fullmatch(r"\$(\w+)\s*=\s*\$(\w+)\s*%\s*\$(\w+)\.Length", core_statements[0].strip(), re.IGNORECASE)
            if index_temp and index_temp[2].lower() == loop_var and _extract_incr_step(loop_var, incr_text) == 1:
                temp, _, key_name = (part.lower() for part in index_temp.groups())
                write = re.fullmatch(rf"\$(\w+)\[\s*\${re.escape(loop_var)}\s*\]\s*=\s*\$(\w+)\[\s*\${re.escape(loop_var)}\s*\]\s*-bxor\s*\${re.escape(key_name)}\[\s*\${re.escape(temp)}\s*\]", core_statements[1].strip(), re.IGNORECASE)
                if write and len({temp, key_name, loop_var, write[1].lower(), write[2].lower()}) == 5:
                    target = self.variables.get(write[1].lower())
                    source = _as_bytes(self.variables.get(write[2].lower()))
                    key_value = self.variables.get(key_name)
                    key = _as_bytes(key_value)
                    if (source and key and isinstance(target, list) and target is not key_value
                            and len(target) == len(source) <= MAX_EMBEDDED_PAYLOAD_BYTES
                            and _cond_matches_length(loop_var, write[2].lower(), cond_text)):
                        for index, byte in enumerate(source):
                            if index % 4096 == 0:
                                self._tick()
                            target[index] = byte ^ key[index % len(key)]
                        self._store_variable(temp, (len(source) - 1) % len(key))
                        self._store_variable(loop_var, len(source))
                        return True
            temp_match = _HEX_ADD_TEMP_RE.match(core_statements[0].strip().rstrip(";").strip())
            second_stripped = core_statements[1].strip().rstrip(";").strip()
            write_match = _HEX_ADD_RE.match(second_stripped) or _HEX_INDEX_TEMP_RE.match(second_stripped)
            if (
                temp_match and write_match
                and temp_match.group("temp").lower() == write_match.group("temp").lower()
                and temp_match.group("idx").lower() == loop_var
                and _extract_incr_step(loop_var, incr_text) == 2
                # the index-assign variant carries its own loop-index
                # group that must also line up with the loop counter
                and (not write_match.groupdict().get("idx1") or write_match.group("idx1").lower() == loop_var)
            ):
                source_key = temp_match.group("source").lower()
                if _cond_matches_length(loop_var, source_key, cond_text):
                    source_val = self.variables.get(source_key)
                    if isinstance(source_val, str):
                        try:
                            decoded = bytes.fromhex(source_val)
                        except ValueError:
                            decoded = None
                        if decoded is not None:
                            self.variables[write_match.group("target").lower()] = list(
                                decoded[:MAX_EMBEDDED_PAYLOAD_BYTES]
                            )
                            return True

            xor_temp_match = _XOR_KEYBYTE_TEMP_RE.match(core_statements[0].strip().rstrip(";").strip())
            xor_write_match = _XOR_KEYBYTE_WRITE_RE.match(second_stripped)
            if (
                xor_temp_match and xor_write_match
                and xor_temp_match.group("temp").lower() == xor_write_match.group("temp").lower()
                and xor_temp_match.group("idx1").lower() == loop_var
                and xor_write_match.group("idx2").lower() == loop_var
                and xor_write_match.group("idx3").lower() == loop_var
                and _extract_incr_step(loop_var, incr_text) == 1
            ):
                keylen_name = xor_temp_match.group("keylen")
                if not keylen_name or keylen_name.lower() == xor_temp_match.group("key").lower():
                    source_key = xor_write_match.group("source").lower()
                    if _cond_matches_length(loop_var, source_key, cond_text, allow_count=isinstance(self.variables.get(source_key), (list, _BinaryValue))):
                        source_bytes = _as_bytes(self.variables.get(source_key))
                        key_bytes = _as_bytes(self.variables.get(xor_temp_match.group("key").lower()))
                        keylen_ok = bool(keylen_name)
                        if not keylen_ok and key_bytes:
                            keylenvar = xor_temp_match.group("keylenvar")
                            try:
                                keylen_ok = int(_numeric_coerce(self.variables.get(keylenvar.lower()))) == len(key_bytes)
                            except (TypeError, ValueError):
                                keylen_ok = False
                        if source_bytes and key_bytes and keylen_ok:
                            key_len = len(key_bytes)
                            decoded = bytes(
                                b ^ key_bytes[i % key_len]
                                for i, b in enumerate(source_bytes[:MAX_EMBEDDED_PAYLOAD_BYTES])
                            )
                            self.variables[xor_write_match.group("target").lower()] = list(decoded)
                            return True
            return False

        if len(core_statements) != 1:
            return False
        stripped = core_statements[0].strip().rstrip(";").strip()

        indexed_xor = _XOR_INDEX_MOD_RE.fullmatch(re.sub(r"\s+", "", stripped).lower())
        if indexed_xor and indexed_xor['i'] == loop_var and _extract_incr_step(loop_var, incr_text) == 1 and _cond_matches_length(loop_var, indexed_xor['data'], cond_text, allow_count=True):
            source = self.variables.get(indexed_xor['data'])
            target = self.variables.get(indexed_xor['out'])
            key, modulus = int(indexed_xor['key']), int(indexed_xor['mod'])
            if isinstance(source, (list, _BinaryValue)) and isinstance(target, list) and len(source) == len(target) and 0 <= key <= 255 and 1 <= modulus <= 256 and len(source) <= MAX_EMBEDDED_PAYLOAD_BYTES:
                data = _as_bytes(source)
                if data is not None and (not isinstance(source, _BinaryValue) or source.complete):
                    for index, byte in enumerate(data):
                        if index % 4096 == 0:
                            self._tick()
                        target[index] = byte ^ key ^ (index % modulus)
                    self.variables[loop_var] = len(data)
                    return True

        scaled = _HEX_LOOP_BODY_SCALED_RE.fullmatch(stripped)
        if scaled and scaled['idx1'].lower() == loop_var and scaled['idx2'].lower() == loop_var and _extract_incr_step(loop_var, incr_text) == 1:
            target_name, source_name = scaled['target'].lower(), scaled['source'].lower()
            source_value = self.variables.get(source_name)
            target_value = self.variables.get(target_name)
            if isinstance(source_value, str) and isinstance(target_value, list) and _cond_matches_length(loop_var, target_name, cond_text):
                try:
                    decoded = bytes.fromhex(source_value)
                except ValueError:
                    return False
                if len(decoded) == len(target_value) and len(source_value) == len(decoded) * 2 and len(decoded) <= MAX_EMBEDDED_PAYLOAD_BYTES:
                    target_value[:] = decoded
                    self.variables[loop_var] = len(decoded)
                    return True

        hex_match = _HEX_LOOP_BODY_RE.match(stripped)
        if hex_match:
            if not (
                hex_match.group("idx1").lower() == loop_var
                and hex_match.group("idx2").lower() == loop_var
                and _extract_incr_step(loop_var, incr_text) == 2
            ):
                return False
            source_key = hex_match.group("source").lower()
            if not _cond_matches_length(loop_var, source_key, cond_text):
                return False
            source_val = self.variables.get(source_key)
            if not isinstance(source_val, str):
                return False
            try:
                decoded = bytes.fromhex(source_val)
            except ValueError:
                return False
            self.variables[hex_match.group("target").lower()] = list(
                decoded[:MAX_EMBEDDED_PAYLOAD_BYTES]
            )
            return True

        xor_match = _XOR_LOOP_BODY_RE.match(stripped)
        if xor_match:
            if not (
                xor_match.group("idx1").lower() == loop_var
                and xor_match.group("idx2").lower() == loop_var
                and xor_match.group("idx3").lower() == loop_var
                and _extract_incr_step(loop_var, incr_text) == 1
            ):
                return False
            keylen_name = xor_match.group("keylen")
            if keylen_name and keylen_name.lower() != xor_match.group("key").lower():
                return False
            source_key = xor_match.group("source").lower()
            if not _cond_matches_length(loop_var, source_key, cond_text, allow_count=isinstance(self.variables.get(source_key), (list, _BinaryValue))):
                return False
            source_bytes = _as_bytes(self.variables.get(source_key))
            key_bytes = _as_bytes(self.variables.get(xor_match.group("key").lower()))
            if not source_bytes or not key_bytes:
                return False
            if not keylen_name:
                # ``% $keyCount`` (a separate precomputed variable) --
                # only trust it once it's confirmed to actually equal the
                # real key length; anything else falls through to the
                # general simulator rather than risk a wrong transform.
                keylenvar = xor_match.group("keylenvar")
                try:
                    if int(_numeric_coerce(self.variables.get(keylenvar.lower()))) != len(key_bytes):
                        return False
                except (TypeError, ValueError):
                    return False
            key_len = len(key_bytes)
            decoded = bytes(
                b ^ key_bytes[i % key_len]
                for i, b in enumerate(source_bytes[:MAX_EMBEDDED_PAYLOAD_BYTES])
            )
            self.variables[xor_match.group("target").lower()] = list(decoded)
            return True

        return False

    def _try_fast_range_foreach(self, range_end_text, body_text):
        """``0..($b.Length-1) | % { $b[$_] = ... }`` -- the range+pipe+
        ``ForEach-Object`` spelling of the same hex-decode/XOR-decrypt
        shapes ``_try_fast_for_loop`` recognizes for a real ``for``
        statement, with ``$_`` standing in for a named loop counter.
        Without this, a large payload processed this way has no fast
        path at all: real per-item ``ForEach-Object`` simulation (see
        ``_eval_pipeline_expr``) ticks the statement budget once per
        byte, and a multi-hundred-KB payload burns through
        ``MAX_STATEMENTS`` long before finishing either loop. Returns
        True only when fully handled; any mismatch returns False so the
        caller falls through to that real simulation instead of
        fabricating a partial/guessed result.
        """
        stripped = body_text.strip().rstrip(";").strip()

        hex_match = _HEX_LOOP_BODY_RE.match(stripped) or _HEX_LOOP_BODY_SCALED_RE.match(stripped)
        if hex_match:
            if not (hex_match.group("idx1").lower() == "_" and hex_match.group("idx2").lower() == "_"):
                return False
            source_key = hex_match.group("source").lower()
            source_val = self.variables.get(source_key)
            if not isinstance(source_val, str):
                return False
            try:
                decoded = bytes.fromhex(source_val)
            except ValueError:
                return False
            end_val = self._eval_expr(range_end_text)
            try:
                if int(_numeric_coerce(end_val)) != len(decoded) - 1:
                    return False
            except (TypeError, ValueError):
                return False
            self.variables[hex_match.group("target").lower()] = list(decoded[:MAX_EMBEDDED_PAYLOAD_BYTES])
            return True

        xor_match = _XOR_LOOP_BODY_RE.match(stripped)
        if xor_match:
            if not (
                xor_match.group("idx1").lower() == "_"
                and xor_match.group("idx2").lower() == "_"
                and xor_match.group("idx3").lower() == "_"
            ):
                return False
            keylen_name = xor_match.group("keylen")
            if keylen_name and keylen_name.lower() != xor_match.group("key").lower():
                return False
            source_key = xor_match.group("source").lower()
            source_bytes = _as_bytes(self.variables.get(source_key))
            key_bytes = _as_bytes(self.variables.get(xor_match.group("key").lower()))
            if not source_bytes or not key_bytes:
                return False
            if not keylen_name:
                keylenvar = xor_match.group("keylenvar")
                try:
                    if int(_numeric_coerce(self.variables.get(keylenvar.lower()))) != len(key_bytes):
                        return False
                except (TypeError, ValueError):
                    return False
            end_val = self._eval_expr(range_end_text)
            try:
                if int(_numeric_coerce(end_val)) != len(source_bytes) - 1:
                    return False
            except (TypeError, ValueError):
                return False
            key_len = len(key_bytes)
            decoded = bytes(
                b ^ key_bytes[i % key_len]
                for i, b in enumerate(source_bytes[:MAX_EMBEDDED_PAYLOAD_BYTES])
            )
            self.variables[xor_match.group("target").lower()] = list(decoded)
            return True

        return False

    def _handle_state_machine(self, state_var, cases):
        """Real, one-case-per-pass dispatch of a ``while ($state -ne -1)
        { switch ($state) { CASE { ...; $state = NEXT } } }`` control-
        flow-flattening block (see ``_scan_state_machine``'s docstring
        for why this can't just flatten like an ordinary switch).
        ``$state``'s starting value is whatever a real preceding
        assignment already stored (processed as an ordinary statement
        before this one, same as any other variable read).
        """
        prepared = [(label, self._prepare_loop_body(body)) for label, body in cases]
        default_statements = None
        numeric_cases = []
        for label, statements in prepared:
            if label.lower() == "default":
                default_statements = statements
                continue
            label_value = self._eval_expr(label)
            try:
                numeric_cases.append((int(_numeric_coerce(label_value)), statements))
            except (TypeError, ValueError):
                continue
        iterations = 0
        output = None
        while iterations < MAX_LOOP_ITERATIONS:
            iterations += 1
            self._tick()
            state_value = self._read_variable(state_var)
            if _is_unknown(state_value):
                break
            try:
                state_num = int(_numeric_coerce(state_value))
            except (TypeError, ValueError):
                break
            if state_num == -1:
                break
            matched = next((stmts for num, stmts in numeric_cases if num == state_num), default_statements)
            if matched is None:
                # No matching case and no ``default`` -- real PowerShell
                # would just fall out of the switch with ``$state``
                # unchanged, which is an infinite loop; safer to treat
                # it as "nothing more this emulator can resolve" and
                # stop rather than spin until the iteration cap.
                break
            candidate = self._run_loop_body_once(matched)
            if candidate is not None and not _is_unknown(candidate):
                output = candidate
            if self._read_variable(state_var) == state_value:
                # State didn't advance -- a real infinite loop (or a
                # case whose ``$state`` update this emulator couldn't
                # resolve). Stop instead of burning the full iteration
                # budget on a pass that will never terminate.
                break
        return output

    def _try_numeric_loop(self, init_match, cond_text, incr_text, statements):
        """Reuse parsed arithmetic for pure scalar loops. This preserves the
        interpreter's existing speculative treatment of flattened guards.
        All iterations are evaluated unless an invariant fixed point is
        proven. Side-effecting or unsupported bodies use the general path.
        """
        if not init_match:
            return False
        counter = _normalize_var_name(init_match.group(1))
        bound = re.fullmatch(rf"\${re.escape(counter)}\s*-lt\s*(-?\d{{1,9}})", cond_text.strip(), re.I)
        if not bound or _extract_incr_step(counter, incr_text) != 1 or type(self.variables.get(counter)) is not int:
            return False
        written, all_reads, plan = set(), set(), []
        for statement in statements:
            assignment = re.fullmatch(r"\$(\w+)\s*=\s*(.+)", statement.strip(), re.S)
            if assignment:
                name, expression = assignment.groups()
                if name.lower() == counter:
                    return False
                written.add(name.lower())
                program = _numeric_rpn(expression)
                if program is None:
                    return False
                plan.append((name.lower(),program))
            else:
                guard = re.fullmatch(r"(?:if|elseif)\s*\((.*)\)", statement.strip(), re.I | re.S)
                if statement.strip().lower() == 'else':
                    continue
                if not guard:
                    return False
                expression = re.sub(r"-(?:eq|ne|lt|le|gt|ge|and|or|not)\b", '+', guard.group(1), flags=re.I)
            reads = re.findall(r"\$(\w+)", expression)
            all_reads.update(name.lower() for name in reads)
            numeric = re.sub(r"\$\w+", '0', expression)
            compact_numeric = re.sub(r"\s+", '', numeric)
            if '++' in compact_numeric or '--' in compact_numeric or not re.fullmatch(r"[\s0-9()+*/%\-]+", numeric):
                return False
        if any(self.variables.get(name) is not None and type(self.variables.get(name)) not in (int,float,bool) for name in all_reads):
            return False
        stop, start = int(bound.group(1)), self.variables[counter]
        names, previous = sorted(written), None
        for iteration, index in enumerate(range(start, min(stop,start+MAX_LOOP_ITERATIONS)),1):
            self._tick()
            self._store_variable(counter,index)
            for name, program in plan:
                self._tick()
                stack = []
                for token in program:
                    if isinstance(token,tuple):
                        value = self.variables.get(token[1]) if token[0]=='variable' else token[1]
                    else:
                        right = stack.pop()
                        left = 0 if token.startswith('u') else stack.pop()
                        try:
                            left, right = _numeric_coerce(left), _numeric_coerce(right)
                            if token in ('+','u+'): value=left+right
                            elif token in ('-','u-'): value=left-right
                            elif token=='*': value=left*right
                            elif token=='/': value=left/right
                            else: value=left%right
                        except (TypeError,ValueError,ArithmeticError):
                            value=_Unknown('<numeric-loop-value>')
                    if isinstance(value,int) and value.bit_length()>MAX_INTEGER_BITS:
                        self._emit('resource_limit',resource='integer_bits',limit=MAX_INTEGER_BITS)
                        value=_Unknown('<integer-size-limit>')
                    stack.append(value)
                self._store_variable(name,stack[0])
            self._store_variable(counter,index+1)
            if counter not in all_reads:
                values=tuple(self.variables.get(name) for name in names)
                if all(value is None or type(value) in (int,float,bool) for value in values):
                    if values==previous:
                        skipped=max(0,stop-index-1)
                        self._store_variable(counter,stop)
                        if skipped:
                            self._emit('loop_summary',reason='invariant-numeric-state',iterations=iteration,skipped_iterations=skipped)
                        return True
                    previous=values
        if stop > start+MAX_LOOP_ITERATIONS:
            self._emit('resource_limit',resource='loop_iterations',limit=MAX_LOOP_ITERATIONS)
        return True

    def _try_base32_index_loop(self, init_text, cond_text, incr_text, body):
        if len(body) > 4096:
            return False
        compact = re.sub(r'\r?\n', ';', _strip_comments(body)).lower()
        compact = re.sub(r'\s+', '', compact)
        compact = re.sub(r';+', ';', compact).strip(';').replace('{;', '{').replace(';}', '}').replace('};', '}')
        m = re.fullmatch(
            r'\$(?P<v>\w+)=\$(?P<table>\w+)\[\$(?P<data>\w+)\[\$(?P<i>\w+)\]\];'
            r'if\(\$(?P=v)-eq255\)\{continue\}'
            r'\$(?P<b>\w+)=\(\$(?P=b)-shl5\)-bor\$(?P=v);\$(?P<bits>\w+)\+=5;'
            r'if\(\$(?P=bits)-ge8\)\{if\(\$(?P<at>\w+)-lt\$(?P<out>\w+)\.length\)\{'
            r'\$(?P=out)\[\$(?P=at)\]=\(\$(?P=b)-shr\(\$(?P=bits)-8\)\)-band0xff;'
            r'\$(?P=at)\+\+\}\$(?P=bits)-=8\}', compact)
        init = _ASSIGN_RE.match(init_text.strip())
        if (not m or not init or _normalize_var_name(init[1]) != m['i']
                or len(set(m.groupdict().values())) != len(m.groupdict())
                or not _cond_matches_length(m['i'],m['data'],cond_text)
                or _extract_incr_step(m['i'],incr_text) != 1
                or any(self.variables.get(m[key]) != 0 for key in ('i','b','bits','at'))):
            return False
        source, table, target = (self.variables.get(m[key]) for key in ('data','table','out'))
        if (not isinstance(source,_BinaryValue) or not source.complete or not isinstance(table,list)
                or len(table) != 256 or not all(type(n) is int and (0 <= n < 32 or n == 255) for n in table)
                or not isinstance(target,list) or target is table):
            return False
        buffer = bits = at = 0
        for index, byte in enumerate(source.data):
            if index % 4096 == 0:
                self._tick()
            value = table[byte]
            if value == 255:
                continue
            buffer = ((buffer << 5) | value) & 0xffffffff
            bits += 5
            if bits >= 8:
                if at < len(target):
                    target[at] = (buffer >> (bits-8)) & 255
                    at += 1
                bits -= 8
        self._store_variable(m['i'],len(source.data))
        self._store_variable(m['b'],buffer if buffer < 0x80000000 else buffer-0x100000000)
        self._store_variable(m['bits'],bits)
        self._store_variable(m['at'],at)
        if source.data:
            self._store_variable(m['v'],value)
        return True

    def _handle_for_loop(self, init_text, cond_text, incr_text, body_text):
        if init_text:
            self._process_statement(init_text)
        if self._try_base32_index_loop(init_text,cond_text,incr_text,body_text):
            return
        # Only an unconditional, top-level break terminates this loop.
        # Detect it before flattening nested if/switch blocks; a break
        # belonging to those blocks must not be promoted to loop scope.
        raw_statements = _split_statements(_strip_comments(body_text))
        # Preserve simple loop-scope conditional breaks before the normal
        # speculative block flattening can detach them from their guards.
        guarded_parts = []
        pending = []
        for statement in raw_statements:
            guard = re.match(r"^if\s*\(", statement.strip(), re.I)
            condition, end = _extract_balanced(statement.strip(), guard.end() - 1) if guard else (None, None)
            if condition is not None and re.fullmatch(r"\s*\{\s*break\s*;?\s*\}\s*", statement.strip()[end + 1:], re.I):
                guarded_parts.append((self._prepare_loop_body(';'.join(pending)), condition))
                pending = []
            else:
                pending.append(statement)
        if guarded_parts:
            guarded_parts.append((self._prepare_loop_body(';'.join(pending)), None))
        break_at = next((i for i, statement in enumerate(raw_statements)
                         if re.fullmatch(r"(?:break|if\s*\(\s*\$true\s*\)\s*\{\s*break\s*;?\s*\})",
                                         statement.strip(), re.IGNORECASE)), None)
        if break_at is not None:
            condition = self._eval_expr(cond_text) if cond_text.strip() else True
            if not _is_unknown(condition) and _truthy(condition):
                self._run_loop_body_once(self._prepare_loop_body(';'.join(raw_statements[:break_at])))
            return
        body_statements = self._prepare_loop_body(body_text)
        # A terminal continue has the same effect as reaching the end of
        # a counted for body. Only discard it when it was at loop scope.
        if raw_statements and raw_statements[-1].strip().lower() == "continue":
            body_statements = self._prepare_loop_body(";".join(raw_statements[:-1]))
        init_match = _ASSIGN_RE.match(init_text.strip()) if init_text else None
        if init_match and not guarded_parts:
            # A bare ``if (cond)`` left over from a bounds-check block's
            # braces being flattened (see ``_normalize_block_syntax``)
            # has no effect once separated from its own body -- strip it
            # out before checking the loop body against a known
            # fast-path shape, so a guarded ``.Add(...)`` accumulator
            # loop (``if ($i+1 -lt $x.Length) { ... }``) still matches.
            core_statements = [s for s in body_statements if not _IF_GUARD_ONLY_RE.match(s.strip())]
            if self._try_fast_for_loop(
                _normalize_var_name(init_match.group(1)), cond_text, incr_text, core_statements
            ):
                return
        if not guarded_parts and self._try_numeric_loop(init_match, cond_text, incr_text, body_statements):
            return
        incr_match = _INCREMENT_RE.match(incr_text.strip()) if incr_text else None
        iterations = 0
        previous_state = None
        unbounded_monitor = not init_text.strip() and not cond_text.strip() and not incr_text.strip()
        while iterations < MAX_LOOP_ITERATIONS:
            self._tick()
            if cond_text:
                cond_value = self._eval_expr(cond_text)
                if _is_unknown(cond_value) or not _truthy(cond_value):
                    break
            if guarded_parts:
                stop_loop = False
                for statements, guard in guarded_parts:
                    self._run_loop_body_once(statements)
                    if guard is not None:
                        decision = self._eval_expr(guard)
                        if _is_unknown(decision):
                            self._emit("unresolved_loop", reason="break-condition-unresolved", condition=_safe_text(guard, 200))
                            stop_loop = True
                        elif _truthy(decision):
                            stop_loop = True
                        if stop_loop:
                            break
                if stop_loop:
                    break
            else:
                self._run_loop_body_once(body_statements)
            if incr_text:
                if incr_match:
                    self._apply_increment(incr_match.group(1) or incr_match.group(4), incr_match.group(2) or incr_match.group(3))
                else:
                    self._process_statement(incr_text)
            iterations += 1
            if unbounded_monitor:
                # Summarize an actual abstract-state fixed point of for(;;).
                # Serialization only: never load/unpickle sample-controlled
                # data. Pickle preserves object sharing and full byte arrays,
                # unlike truncated repr() comparisons that can miss changes.
                state = pickle.dumps((self.variables.maps, self.aliases, self.functions,
                                      self._reflection_fields, self._layer_queue, self._virtual_files,
                                      len(self.events)), protocol=4)
                fingerprint = hashlib.sha256(state).digest()
                if fingerprint == previous_state:
                    self._emit("loop_summary", reason="repeated-abstract-state", iterations=iterations,
                               runtime_behavior="unbounded-loop; external state remains unknown")
                    break
                previous_state = fingerprint

    def _try_nested_xor_output(self, init_text, cond_text, incr_text, body_text):
        """Exact nested key-cycle decoder, including (a -bor b)-(a -band b).

        Validate every statement and bound before replacing the byte-only
        loop. No arbitrary loop body is run by this recognizer.
        """
        def canonical(text):
            def member(match):
                name = self.variables.get(match[1].lower())
                return '.' + name.lower() if isinstance(name, str) and name.lower() in ('length', 'count') else match[0]
            return re.sub(r'\.\(\s*\$(\w+)\s*\)', member, text).strip()
        def unparen(text):
            text = text.strip()
            while _fully_wrapped(text, '(', ')'):
                text = text[1:-1].strip()
            return text.lower()
        def zero_initializer(text):
            m = re.fullmatch(r'\$(\w+)\s*=\s*(.+)', text.strip(), re.S)
            if not m: return None
            plan = _numeric_rpn(m[2])
            if plan is None or any(isinstance(t, tuple) and t[0] == 'variable' for t in plan): return None
            return m[1].lower() if self._eval_expr(m[2]) == 0 else None
        if incr_text.strip(): return None
        outer = zero_initializer(init_text)
        inner_loop = _try_parse_for_expression(body_text.strip())
        if outer is None or inner_loop is None: return None
        inner_init, inner_cond, inner_incr, inner_body = inner_loop
        inner = zero_initializer(inner_init)
        if inner is None or _extract_incr_step(inner, inner_incr) != 1: return None
        statements = _split_statements(_strip_comments(inner_body))
        if len(statements) != 5: return None
        first = re.fullmatch(r'\$(\w+)\s*=\s*\$(\w+)\[\$(\w+)\]', statements[0].strip(), re.I)
        second = re.fullmatch(r'\$(\w+)\s*=\s*\[byte\]\s*\[char\]\s*\$(\w+)\[\$(\w+)\]', statements[1].strip(), re.I)
        if not first or not second: return None
        a, data_name, data_index = [v.lower() for v in first.groups()]
        b, key_name, key_index = [v.lower() for v in second.groups()]
        if len({a,b,data_name,key_name,outer,inner}) != 6 or data_index != outer or key_index != inner: return None
        if not _cond_matches_length(outer, data_name, canonical(cond_text)) or not _cond_matches_length(inner, key_name, canonical(inner_cond)): return None
        cast = re.match(r'^\[byte\]\s*(.*)$', statements[2].strip(), re.I | re.S)
        if not cast: return None
        expression = unparen(cast[1]); op = self._split_binary_operator(expression)
        if not op: return None
        if op[1] == '-bxor':
            valid = unparen(op[0]) == '$'+a and unparen(op[2]) == '$'+b
        elif op[1] == '-':
            left = self._split_binary_operator(unparen(op[0])); right = self._split_binary_operator(unparen(op[2]))
            valid = bool(left and right and left[1] == '-bor' and right[1] == '-band'
                         and all(unparen(v) == expected for v,expected in ((left[0],'$'+a),(left[2],'$'+b),(right[0],'$'+a),(right[2],'$'+b))))
        else: valid = False
        if not valid or _extract_incr_step(outer, statements[3]) != 1: return None
        stop = canonical(statements[4])
        expected_stop = rf'if\s*\(\s*\${outer}\s*-ge\s*\${data_name}\.(?:length|count)\s*\)\s*\{{\s*\${inner}\s*=\s*\${key_name}\.(?:length|count)\s*;?\s*\}}'
        if not re.fullmatch(expected_stop, stop, re.I): return None
        data_value = self.variables.get(data_name); key_value = self.variables.get(key_name)
        if not isinstance(data_value, _BinaryValue) or not data_value.complete or not isinstance(key_value,str): return None
        data = data_value.data
        try: key = key_value.encode('latin-1')
        except UnicodeEncodeError: return None
        if not data or not key or len(data) > MAX_EMBEDDED_PAYLOAD_BYTES: return None
        result = bytearray()
        for start in range(0,len(data),4096):
            self._tick()
            result.extend(data[i]^key[i%len(key)] for i in range(start,min(start+4096,len(data))))
        self._store_variable(outer,len(data)); self._store_variable(inner,len(key)+1)
        self._store_variable(a,data[-1]); self._store_variable(b,key[(len(data)-1)%len(key)])
        return list(result)

    def _try_modulo_xor_output(self, init_text, cond_text, incr_text, body_text):
        """Exact three-statement byte decoder; assignments are not output.

        PowerShell collects the final bare byte expression on every iteration.
        In particular (a+b)-2*(a-band b) equals XOR for resolved byte operands.
        Reject additional statements, changed bounds and unknown input bytes.
        """
        initial = re.fullmatch(r'\$(\w+)\s*=\s*(.+)', init_text.strip(), re.S)
        if not initial:
            return None
        index = initial[1].lower()
        plan = _numeric_rpn(initial[2])
        if plan is None or any(isinstance(t, tuple) and t[0] == 'variable' for t in plan):
            return None
        if self._eval_expr(initial[2]) != 0 or _extract_incr_step(index, incr_text) != 1:
            return None
        def canonical(text):
            def member(match):
                name = self.variables.get(match[1].lower())
                return '.' + name.lower() if isinstance(name, str) and name.lower() in ('length', 'count') else match[0]
            return re.sub(r'\.\(\s*\$(\w+)\s*\)', member, text).strip().lower()
        def unparen(text):
            text = text.strip()
            while _fully_wrapped(text, '(', ')'):
                text = text[1:-1].strip()
            return text
        statements = _split_statements(_strip_comments(body_text))
        if len(statements) != 3:
            return None
        first = re.fullmatch(r'\$(\w+)\s*=\s*\$(\w+)\[\s*\$' + re.escape(index) + r'\s*\]', canonical(statements[0]))
        second = re.fullmatch(r'\$(\w+)\s*=\s*\[byte\]\s*\[char\]\s*\$(\w+)\[(.+)\]', canonical(statements[1]), re.S)
        if not first or not second:
            return None
        a, data_name = first.groups()
        b, key_name, key_index = second.groups()
        if len({index, a, b, data_name, key_name}) != 5:
            return None
        if not _cond_matches_length(index, data_name, canonical(cond_text)):
            return None
        if not re.fullmatch(r'\$' + re.escape(index) + r'\s*%\s*\$' + re.escape(key_name) + r'\.(?:length|count)', unparen(key_index)):
            return None
        cast = re.fullmatch(r'\[byte\]\s*(.+)', canonical(statements[2]), re.S)
        if not cast:
            return None
        expression = re.sub(r'\s+', '', unparen(cast[1]))
        av, bv = re.escape('$' + a), re.escape('$' + b)
        if not any(re.fullmatch(pattern, expression) for pattern in (
                av + r'-bxor' + bv,
                r'\(' + av + r'-bor' + bv + r'\)-\(' + av + r'-band' + bv + r'\)',
                r'\(' + av + r'\+' + bv + r'\)-2\*\(' + av + r'-band' + bv + r'\)')):
            return None
        data = self.variables.get(data_name)
        key = self.variables.get(key_name)
        if not isinstance(data, _BinaryValue) or not data.complete or not isinstance(key, str) or _is_unknown(key):
            return None
        try:
            key_bytes = key.encode('latin-1')
        except UnicodeEncodeError:
            return None
        if not key_bytes:
            return None
        decoded = bytearray()
        for start in range(0, len(data.data), 4096):
            self._tick()
            decoded.extend(data.data[i] ^ key_bytes[i % len(key_bytes)]
                           for i in range(start, min(start + 4096, len(data.data))))
        self._store_variable(index, len(data.data))
        if data.data:
            self._store_variable(a, data.data[-1])
            self._store_variable(b, key_bytes[(len(data.data) - 1) % len(key_bytes)])
        return list(decoded)

    def _eval_for_expression(self, init_text, cond_text, incr_text, body_text):
        """``for (INIT; COND; INCR) { BODY }`` used as an expression (see
        ``_try_parse_for_expression``). Only a body that reduces to a
        single bare statement is modeled for real -- the one shape a
        per-byte transform decode actually takes, and the one case where
        "the collected value is this one expression, evaluated once per
        iteration" is unambiguous. A multi-statement body still runs (for
        its side effects / any IOCs it surfaces along the way) but its
        collected value can't be trusted, so the whole construct still
        resolves to ``_Unknown`` exactly like before this was modeled.
        """
        decoded = self._try_nested_xor_output(init_text, cond_text, incr_text, body_text)
        if decoded is not None:
            return decoded
        decoded = self._try_modulo_xor_output(init_text, cond_text, incr_text, body_text)
        if decoded is not None:
            return decoded
        body_statements = [s for s in self._prepare_loop_body(body_text) if s.strip()]
        incr_match = _INCREMENT_RE.match(incr_text.strip()) if incr_text else None
        if init_text:
            self._process_statement(init_text)
        if len(body_statements) != 1:
            iterations = 0
            while iterations < MAX_LOOP_ITERATIONS:
                self._tick()
                if cond_text:
                    cond_value = self._eval_expr(cond_text)
                    if _is_unknown(cond_value) or not _truthy(cond_value):
                        break
                self._run_loop_body_once(body_statements)
                if incr_text:
                    if incr_match:
                        self._apply_increment(incr_match.group(1) or incr_match.group(4), incr_match.group(2) or incr_match.group(3))
                    else:
                        self._process_statement(incr_text)
                iterations += 1
            return _Unknown("<for-expression>")
        body_expr = body_statements[0]
        results = []
        total_size = 0
        iterations = 0
        while iterations < MAX_LOOP_ITERATIONS:
            self._tick()
            if cond_text:
                cond_value = self._eval_expr(cond_text)
                if _is_unknown(cond_value) or not _truthy(cond_value):
                    break
            value = self._eval_expr(body_expr)
            # The real, common shape this models is a per-byte transform
            # decode -- each iteration's value is a tiny scalar (an int/
            # bool/short string), thousands of which together are still
            # cheap. A body that instead produces a large value every
            # iteration (a real sample seen doing exactly this: chained
            # ``.Insert``/``.Remove``/``.Replace`` calls rebuilding an
            # already-large string from scratch each pass) is a different,
            # much rarer shape this fast path was never meant to carry --
            # collecting thousands of those verbatim is how one otherwise-
            # harmless-looking sample drove this process to a multi-
            # gigabyte RSS and got OOM-killed. Bail to the same "ran for
            # side effects, value untrusted" fallback the multi-statement
            # case already uses the moment either a single item or the
            # running total looks too large to be that per-byte shape.
            item_size = len(value) if isinstance(value, (str, bytes, bytearray, list)) else 1
            total_size += item_size
            if item_size > 4096 or total_size > MAX_EMBEDDED_PAYLOAD_BYTES:
                return _Unknown("<for-expression>")
            results.append(value)
            if len(results) >= MAX_VARIABLES:
                break
            if incr_text:
                if incr_match:
                    self._apply_increment(incr_match.group(1) or incr_match.group(4), incr_match.group(2) or incr_match.group(3))
                else:
                    self._process_statement(incr_text)
            iterations += 1
        if not results:
            return None
        if len(results) == 1:
            return results[0]
        return results

    def _try_fast_alphabet_decode_foreach(self, loop_var, items, body_text):
        """See ``_ALPHABET_DECODE_FOREACH_RE``'s docstring: a custom-
        alphabet bit-unpacking decode loop, computed natively instead of
        per-character simulation -- both for a multi-hundred-KB payload's
        sake, and because the generic simulator structurally cannot
        express this shape's guard clause/conditional emit correctly at
        any budget.
        """
        match = _ALPHABET_DECODE_FOREACH_RE.match(body_text.strip())
        if not match or match.group("loopvar").lower() != _normalize_var_name(loop_var):
            return False
        table = self.variables.get(match.group("table").lower())
        out_list = self.variables.get(match.group("outvar").lower())
        buf_key = match.group("buf").lower()
        bits_key = match.group("bits").lower()
        if not isinstance(table, dict) or not isinstance(out_list, list):
            return False
        try:
            shift_n = int(match.group("shift"))
            threshold = int(match.group("threshold"))
        except ValueError:
            return False
        if not (0 < shift_n <= 32 and 0 < threshold <= 32):
            return False
        buffer = self.variables.get(buf_key, 0)
        bits_left = self.variables.get(bits_key, 0)
        if not isinstance(buffer, int) or not isinstance(bits_left, int):
            return False
        result = bytearray()
        for item in items[:MAX_EMBEDDED_PAYLOAD_BYTES]:
            key = str(item).lower()
            if key not in table:
                continue
            try:
                table_val = int(table[key])
            except (TypeError, ValueError):
                return False
            buffer = ((buffer << shift_n) | table_val) & 0xFFFFFFFF
            bits_left += shift_n
            if bits_left >= threshold:
                bits_left -= threshold
                result.append((buffer >> bits_left) & 0xFF)
        out_list.extend(result[:max(0, MAX_EMBEDDED_PAYLOAD_BYTES - len(out_list))])
        self.variables[buf_key] = buffer
        self.variables[bits_key] = bits_left
        return True

    def _try_fast_xor_foreach(self, var_name, items, body_text):
        # Exact two-statement byte transform. In particular, do not collapse
        # bodies with extra commands, aliased key/output arrays, or unknown
        # values: their effects depend on individual iterations.
        statements = _split_statements(_strip_comments(body_text))
        if len(statements) != 2:
            return False
        compact = re.sub(r"\s+", "", ";".join(statements))
        match = re.fullmatch(
            r"\$(?P<out>\w+)\[\$(?P<index>\w+)\]="
            r"\$(?P<item>\w+)-bxor\$(?P<key>\w+)"
            r"\[\$(?P=index)%\$(?P=key)\.length\];\$(?P=index)\+\+",
            compact.lower(),
        )
        if (not match or match['item'] != _normalize_var_name(var_name)
                or len(set(match.groupdict().values())) != 4
                or not items or len(items) > MAX_LOOP_ITERATIONS):
            return False
        target = self.variables.get(match['out'])
        key = self.variables.get(match['key'])
        start = self.variables.get(match['index'])
        if (type(start) is not int or start < 0 or target is key or target is items
                or not isinstance(target, (list, _BinaryValue))
                or not isinstance(key, (list, _BinaryValue))
                or start + len(items) > len(target)
                or any(type(n) is not int or not 0 <= n <= 255 for n in items)):
            return False
        if any(isinstance(value, _BinaryValue) and not value.complete for value in (target, key)):
            return False
        if isinstance(key, list) and any(type(n) is not int or not 0 <= n <= 255 for n in key):
            return False
        key_bytes = _as_bytes(key)
        if not key_bytes:
            return False
        output = bytearray(len(items))
        for offset, value in enumerate(items):
            if offset % 4096 == 0:
                self._tick()
            output[offset] = value ^ key_bytes[(start + offset) % len(key_bytes)]
        if isinstance(target, list):
            target[start:start + len(items)] = output
        else:
            target.data = target.data[:start] + bytes(output) + target.data[start + len(items):]
        self._store_variable(match['index'], start + len(items))
        self._store_variable(var_name, items[-1])
        return True

    def _handle_foreach_loop(self, var_name, collection_text, body_text):
        collection = self._eval_expr(collection_text)
        if isinstance(collection, list):
            items = collection
        elif isinstance(collection, _BinaryValue):
            items = list(collection.data)
        elif isinstance(collection, str):
            # A bare string is one item to a real ``foreach`` (only
            # explicit char-array casts/``.ToCharArray()`` iterate per
            # character) -- looping it here would silently fabricate a
            # per-character iteration the source never asked for.
            items = [collection]
        else:
            return
        if len(items) > 2000 and self._try_fast_xor_foreach(var_name, items, body_text):
            return
        if len(items) > 2000 and self._try_fast_alphabet_decode_foreach(var_name, items, body_text):
            return
        body_statements = self._prepare_loop_body(body_text)
        for item in items[:MAX_LOOP_ITERATIONS]:
            self._tick()
            self._store_variable(var_name, item)
            self._run_loop_body_once(body_statements)

    def _handle_property_assignment(self, chain, expr_text):
        parts = [part for part in chain.split(".") if part]
        if len(parts) < 2:
            return
        owner = self._eval_expr(parts[0])
        for prop in parts[1:-1]:
            owner = self._apply_property(owner, prop)
        final_prop = parts[-1].lower()
        value = self._eval_expr(expr_text)
        if isinstance(owner, _ObjectRef):
            if owner.kind == 'powershell.instance':
                self._set_script_property(owner, final_prop, value)
                return
            if owner.kind == 'ps.reference' and final_prop == 'value':
                self._set_reference_value(owner, value)
                return
            owner.state[final_prop] = value

    def _assign_index(self, target, index_value, value):
        """Shared write side of ``target[index] = value`` for both a
        real list (``$bytes[$i] = ...``, an int index) and a hashtable
        (``$var_map['key'] = ...``, see ``@{...}``/``_read_variable``'s
        braced-index handling for the read side of this exact idiom --
        without this, the write half silently no-opped for any
        dict-typed target, since only ``list`` was ever handled here).
        """
        if isinstance(target, (_BinaryValue, _ByteArray, _IntegerArray, _FloatingArray, _ObjectArray)):
            # Managed arrays have fixed length. Unknown writes must invalidate
            # the affected data; retaining the old bytes would invent evidence.
            index = _convert_integer_value(index_value, -(1 << 31), (1 << 31) - 1)
            if index is None:
                self._emit('unsupported_operation', api='array-index-write', reason='index-conversion-unresolved')
                if _is_unknown(index_value):
                    if isinstance(target, _BinaryValue):
                        target.complete = False
                    else:
                        target[:] = [_Unknown('<unknown-index-write>')] * len(target)
                return
            if index < 0:
                index += len(target)
            if not 0 <= index < len(target):
                self._emit('unsupported_operation', api='array-index-write', reason='index-out-of-range')
                return
            if isinstance(target, _ObjectArray):
                target[index] = value
                return
            key = target.element_type.lower() if isinstance(target, (_IntegerArray, _FloatingArray)) else 'byte'
            converted = self._cast_floating_value(key, value) if isinstance(target, _FloatingArray) else self._cast_integer_value(key, value)
            if _is_unknown(converted):
                if isinstance(target, _BinaryValue):
                    target.complete = False
                else:
                    target[index] = converted
                return
            if isinstance(target, _BinaryValue):
                target.data = target.data[:index] + bytes((converted,)) + target.data[index + 1:]
                target.sha256 = hashlib.sha256(target.data).hexdigest()
            else:
                target[index] = converted
            return
        if _is_unknown(index_value):
            return
        if isinstance(target, dict):
            target[str(index_value).lower()] = value
            return
        if not isinstance(target, list):
            return
        try:
            index = int(index_value)
        except (TypeError, ValueError):
            return
        if index < 0:
            index += len(target)
        if 0 <= index < len(target):
            target[index] = value
        elif index == len(target) and len(target) < MAX_VARIABLES:
            target.append(value)

    def _handle_index_assignment(self, var_name, index_text, expr_text):
        target = self.variables.get(_normalize_var_name(var_name))
        index_value = self._eval_expr(index_text)
        value = self._eval_expr(expr_text)
        self._assign_index(target, index_value, value)

    def _handle_generic_index_assignment(self, target_text, index_text, expr_text):
        target = self._eval_expr(target_text)
        index_value = self._eval_expr(index_text)
        value = self._eval_expr(expr_text)
        self._assign_index(target, index_value, value)

    def _assign_value_to_target(self, target_text, value):
        """Store an already-evaluated ``value`` into a single LHS target
        (``$var`` or ``$var[index]``) -- the per-target primitive
        ``_handle_multi_assignment`` applies once for each side of a
        tuple assignment, after every RHS expression has already been
        evaluated (real PowerShell tuple-assignment semantics: a swap
        like ``$a[$i], $a[$j] = $a[$j], $a[$i]`` must read both old
        values before either write happens, or the second write would
        read back the first write's already-changed value).
        """
        target_text = target_text.strip()
        index_match = re.match(rf"^({_VAR_REF})\s*\[", target_text)
        if index_match:
            bracket_start = target_text.index("[", index_match.end() - 1)
            index_text, bracket_end = _extract_balanced(target_text, bracket_start, "[", "]")
            if index_text is None or bracket_end != len(target_text) - 1:
                return
            target = self.variables.get(_normalize_var_name(index_match.group(1)))
            index_value = self._eval_expr(index_text)
            if not isinstance(target, list) or _is_unknown(index_value):
                return
            try:
                index = int(index_value)
            except (TypeError, ValueError):
                return
            if index < 0:
                index += len(target)
            if 0 <= index < len(target):
                target[index] = value
            elif index == len(target) and len(target) < MAX_VARIABLES:
                target.append(value)
            return
        if re.fullmatch(_VAR_REF, target_text):
            self._store_variable(target_text, value)

    def _handle_multi_assignment(self, lhs_parts, rhs_parts):
        values = [self._eval_expr(part) for part in rhs_parts]
        for target_text, value in zip(lhs_parts, values):
            self._assign_value_to_target(target_text, value)

    def _handle_chained_assignment(self, targets, expr_text):
        value = self._eval_expr(expr_text)
        for target_text in targets:
            self._assign_value_to_target(target_text, value)

    def _concat_array_values(self, left, right):
        """Preserve complete concatenations; never return a silently cut prefix."""
        size = len(left) + len(right)
        if size <= MAX_VARIABLES:
            return left + right
        # Byte arrays already use the bounded payload budget. The variable
        # count is not a byte-array length limit: encrypted payloads commonly
        # arrive in multiple chunks. Generic object arrays retain their bound.
        if size <= MAX_EMBEDDED_PAYLOAD_BYTES:
            known_bytes = True
            for items in (left, right):
                for index, item in enumerate(items):
                    if index % 4096 == 0:
                        self._tick()
                    if type(item) is not int or not 0 <= item <= 255:
                        known_bytes = False
                        break
                if not known_bytes:
                    break
            if known_bytes:
                return left + right
        self._emit('resource_limit', resource='array_concatenation',
                   elements=size, object_array_limit=MAX_VARIABLES,
                   byte_array_limit=MAX_EMBEDDED_PAYLOAD_BYTES)
        return _Unknown('<array-concatenation-limit>')

    def _handle_assignment(self, name, operator, expr_text):
        value = self._eval_expr(expr_text)
        if operator == "+=":
            old = self.variables.get(_normalize_var_name(name), "")
            if isinstance(old, list):
                value = self._concat_array_values(old, value if isinstance(value, list) else [value])
            elif (
                isinstance(old, (int, float)) and not isinstance(old, bool)
                and isinstance(value, (int, float)) and not isinstance(value, bool)
            ):
                # Numeric ``+=`` (loop counters overwhelmingly) must stay
                # numeric -- falling through to the string-concat branch
                # below would turn ``$i += 2`` into the literal text "02"
                # each iteration, corrupting every later ``-lt``/index use
                # of the counter.
                value = old + value
            else:
                # Always flattens to a plain string rather than gating on
                # "both sides known" -- the same cascading-``_Unknown``
                # trap fixed in ``_apply_binary_op``'s ``+`` handling
                # (see its comment): a char-by-char decode accumulator
                # (``$out += [char](...)``, run hundreds of times) hits
                # one genuinely unresolvable char and used to wrap the
                # *entire* accumulated string in another ``_Unknown``
                # layer on every subsequent ``+=``, swallowing every
                # already-decoded character along with it.
                old_text = "" if old is None else str(old)
                value_text = "" if value is None else str(value)
                value = _cap(old_text + value_text)
        elif operator in ("-=", "*=", "/="):
            old = self.variables.get(_normalize_var_name(name), 0)
            try:
                old_n, val_n = _numeric_coerce(old), _numeric_coerce(value)
                if operator == "-=":
                    value = old_n - val_n
                elif operator == "*=":
                    value = old_n * val_n
                else:
                    value = old_n / val_n if val_n else _Unknown("<div-by-zero>")
            except (TypeError, ValueError):
                value = _Unknown(f"{old}{operator}{value}")
        self._store_variable(name, value)

    def _process_pipeline(self, statement):
        stages = _split_top_level(statement, "|")
        if len(stages) <= 1:
            return self._eval_expr(statement)
        accumulated = None
        for stage in stages:
            stage = stage.strip()
            if not stage:
                continue
            lowered_stage = stage.lower()
            if stage.startswith('&') and accumulated is not None:
                accumulated = self._invoke_computed_pipeline(stage, accumulated)
                continue
            if lowered_stage in ("iex", "invoke-expression") and accumulated is not None:
                accumulated = self._invoke_dynamic_layer(accumulated, "pipeline|IEX")
                continue
            sink_match = re.match(r"^(set-content|add-content|out-file)\b(.*)$", stage, re.IGNORECASE | re.DOTALL)
            if sink_match and accumulated is not None:
                sink_name, rest = sink_match.groups()
                positional, named = self._parse_command_syntax(rest, single_token_params=('encoding', 'width'))
                path_text = named.get("path") or named.get("filepath") or named.get("literalpath") or (positional[0] if positional else "")
                path = self._eval_command_arg(path_text) if path_text else _Unknown("<path>")
                self._record_content_command(path,accumulated,sink_name,named)
                accumulated = None
                continue
            verb_match = re.match(r"^(%|foreach-object|foreach)(?=\s|\{|$)\s*(.*)$", stage, re.IGNORECASE | re.DOTALL)
            if verb_match:
                accumulated = self._run_foreach_object_stage(accumulated, verb_match.group(2).strip())
                continue
            select_match = re.match(r"^(?:select-object|select)(?=\s|$)\s*(.*)$", stage, re.IGNORECASE | re.DOTALL)
            if select_match:
                accumulated = self._run_select_object_stage(accumulated, select_match.group(1).strip())
                continue
            where_match = re.match(r"^(?:where-object|where|\?)(?=\s|\{|$)\s*(.*)$", stage, re.IGNORECASE | re.DOTALL)
            if where_match:
                accumulated = self._run_where_object_stage(accumulated, where_match.group(1).strip())
                continue
            passthrough_match = re.match(
                r"^(sort-object|sort|"
                r"measure-object|measure|group-object|group|tee-object|"
                r"format-list|format-table|fl|ft)(?=\s|\{|$)",
                stage, re.IGNORECASE,
            )
            if passthrough_match:
                # Mirrors ``_eval_pipeline_expr``'s identical pass-through
                # design for these verbs (see its docstring): none of them
                # are simulated for real here, but re-evaluating the stage
                # text as a fresh expression -- the generic fallback below
                # -- routes it through ``_eval_command_expression``, which
                # returns ``None`` for every one of these (they're all in
                # ``_NOOP_CMDLETS``, correct for their *standalone*-statement
                # use), silently wiping out whatever the pipeline had built
                # up so far. ``Get-ChildItem ... | Select-Object -First 1``
                # -- the extremely common "find the dropped payload" shape
                # -- lost its result entirely this way; passing the value
                # through unchanged keeps ``.FullName``/``[0]`` on the far
                # side resolving to something real.
                continue
            accumulated = self._eval_expr(stage)
        return accumulated

    # -- top-level driver -------------------------------------------------------

    def _inspect_non_powershell_artifact(self, source):
        """Keep mislabeled source/data distinct from PowerShell behavior."""
        stripped = source.lstrip()
        plain = re.sub(r'\x1b\[[0-9;]*m', '', stripped[:2048])
        kind = None
        if re.match(r'(?:<!doctype\s+html[^>]*>\s*)?<html\b', stripped, re.I):
            kind = 'html-document'
        elif re.match(r'(?:<\?xml[^>]*>\s*)?<Task\b', stripped, re.I):
            kind = 'scheduled-task-xml'
        elif re.match(r'using\s+System(?:\.[\w.]+)?\s*;', stripped) and re.search(r'\b(?:public|internal)\s+(?:static\s+)?class\s+\w+', stripped[:8192]):
            kind = 'csharp-source'
        elif re.match(r'content\s+Headers\s*\n-+\s+-+', plain, re.I):
            kind = 'formatted-console-output'
        elif (re.match(r'\[version\]\s*\r?\n', stripped, re.I)
              and re.search(r'(?im)^\s*\[DefaultInstall\]\s*$', stripped)
              and re.search(r'(?im)^\s*Signature\s*=\s*["\x27]?\$chicago\$', stripped)):
            kind = 'windows-inf-definition'
        elif stripped.startswith('"\\x'):
            chunks = []
            valid = True
            for start, end, token_kind in _scan_ps_text(stripped):
                token = stripped[start:end]
                if token_kind == 'code' and not token.strip(' \t\r\n;'):
                    continue
                if token_kind != 'dquote' or not re.fullmatch(r'"(?:\\x[0-9a-fA-F]{2})+"', token):
                    valid = False
                    break
                chunks.append(token[1:-1].replace('\\x', ''))
            if valid and chunks:
                kind = 'escaped-byte-data'
                hex_data = ''.join(chunks)
                if len(hex_data) <= MAX_EMBEDDED_PAYLOAD_BYTES * 2:
                    self._remember_embedded_payload(bytes.fromhex(hex_data), 'escaped-byte-data')
                else:
                    self._emit('resource_limit', resource='escaped_byte_data', limit=MAX_EMBEDDED_PAYLOAD_BYTES)
        if kind is None:
            return False
        self._emit('unparsed_input', kind=kind, reason='input-is-source-or-data-not-a-powershell-program')
        for index, match in enumerate(re.finditer(r'https?://[^\s<>"\x27]+', source, re.I)):
            if index >= MAX_EVENTS:
                self.event_limit_hit = True
                break
            self._tick()
            self._emit('static_ioc', kind='url', value=match[0].rstrip(');,'), source=kind)
        if kind == 'html-document':
            for match in re.finditer(r'\bfetch\(\s*([\x27"])(/[^\x27"\r\n]+)\1', source):
                self._emit('static_ioc', kind='relative-url', value=match[2], source='html-fetch-literal')
        if kind == 'windows-inf-definition':
            sections = {}
            section = ''
            for index, line in enumerate(source.splitlines()):
                if index >= MAX_EVENTS:
                    self._emit('resource_limit', resource='inf_lines', limit=MAX_EVENTS)
                    break
                if index % 128 == 0:
                    self._tick()
                line = line.strip()
                header = re.fullmatch(r'\[([\w.-]+)\]', line)
                if header:
                    section = header[1].lower()
                elif line and not line.startswith(';'):
                    sections.setdefault(section, []).append(line)
            for line in sections.get('defaultinstall', []):
                setting = re.match(r'RunPreSetupCommands\s*=\s*([\w., -]+)$', line, re.I)
                if setting:
                    for section in setting[1].lower().split(','):
                        for command in sections.get(section.strip(), []):
                            self._emit('static_command', command=command, source='INF.RunPreSetupCommands', evidence='definition-only')
        if kind == 'csharp-source':
            for match in re.finditer(r'@"([A-Za-z]:\\[^"\r\n]+)"', source):
                self._emit('static_ioc', kind='path', value=match[1], source='csharp-verbatim-literal')
        if kind == 'scheduled-task-xml':
            # Never resolve external entities or allow DTD expansion.
            if re.search(r'<!\s*(?:DOCTYPE|ENTITY)\b', source, re.I):
                self._emit('unsupported_operation', api='TaskXml', reason='doctype-or-entity-not-supported')
            else:
                try:
                    root = _ElementTree.fromstring(source.strip())
                    for element in root.iter():
                        if element.tag.rsplit('}', 1)[-1] != 'Exec':
                            continue
                        fields = {child.tag.rsplit('}', 1)[-1]: child.text or '' for child in element}
                        self._emit('static_task_action', command=fields.get('Command'), arguments=fields.get('Arguments', ''),
                                   working_directory=fields.get('WorkingDirectory'), evidence='xml-definition-only')
                except (_ElementTree.ParseError, ValueError):
                    self._emit('unsupported_operation', api='TaskXml', reason='malformed-xml')
        return True

    def _recover_wrapped_literal_pe_data(self, source):
        """Salvage PE data from damaged wrapping, without repairing program flow.

        This pass never binds recovered bytes to interpreter variables or
        invokes a helper. Every result is static evidence with its assumptions.
        Missing call arguments, newlines in strings and byte-token splits must
        not be silently treated as valid PowerShell semantics.
        """
        spans = _scan_ps_text(source)
        code = ''.join(source[a:b] if kind == 'code' else ' ' * (b - a) for a, b, kind in spans)
        literal_values = {}
        previous = None
        for start, end, kind in spans:
            if kind in ('squote', 'dquote') and previous and previous[2] == 'code':
                assignment = re.search(r'(\$[A-Za-z_]\w*)\s*=\s*$', source[max(previous[0], start - 128):start])
                value = source[start + 1:end - 1]
                if assignment and len(literal_values) < 128:
                    name = assignment.group(1).lower()
                    unresolved = (name in literal_values or end <= start + 1 or source[end - 1] != source[start]
                                  or (kind == 'dquote' and ('$' in value or '`' in value)))
                    literal_values[name] = None if unresolved else value.replace("''", "'")
            previous = (start, end, kind)

        def retain(data, label, **details):
            if not _has_bounded_pe_layout(data):
                return
            digest = hashlib.sha256(data).hexdigest()
            self._remember_embedded_payload(data, label)
            self._emit('static_payload_recovery', source=label, evidence='static-data-recovery',
                       size=len(data), sha256=digest, **details)

        # Numeric tokens split across physical lines cannot be joined as
        # normal PowerShell evaluation. Only a separate, header-validated
        # candidate is retained; the original expression remains untouched.
        for match in re.finditer(r'\[byte\[\]\]\s*(\$[A-Za-z_]\w*)\s*=\s*\(([\d,\s]+)\)', code, re.I):
            self._tick()
            body = match.group(2)
            split_count = len(re.findall(r'\d[ \t]*\r?\n[ \t]*\d', body))
            if not split_count:
                continue
            self._emit('unparsed_input', kind='split-byte-array-tokens', reason='source-line-wrap-ambiguity',
                       variable=match.group(1), split_count=split_count)
            compact = re.sub(r'\s+', '', body)
            if compact.count(',') >= MAX_EMBEDDED_PAYLOAD_BYTES:
                self._emit('resource_limit', resource='static_byte_array', limit=MAX_EMBEDDED_PAYLOAD_BYTES)
                continue
            tokens = compact.split(',')
            if all(re.fullmatch(r'\d{1,3}', token) and int(token) <= 255 for token in tokens):
                retain(bytes(int(token) for token in tokens), 'static-wrapped-byte-array',
                       variable=match.group(1), assumption='remove-newlines-inside-decimal-tokens',
                       split_count=split_count)

        # Match the data transformations and the literal named arguments of
        # a repeating-key XOR helper, even when a broken newline separates
        # the call from its parameter list. No guessed keys are tried.
        attempts = 0
        for name, info in self.functions.items():
            body = _strip_comments(info.get('body', ''))
            if len(body) > 32768 or '-bxor' not in body.lower():
                continue
            loop = re.search(r'(\$\w+)\[(\$\w+)\]\s*=\s*(\$\w+)\[\2\]\s*-bxor\s*(\$\w+)\[\2\s*%\s*\4\.Length\]', body, re.I)
            if not loop:
                continue
            output, index, cipher, key = map(re.escape, loop.groups())
            cipher_param = re.search(cipher + r'\s*=\s*\[(?:System\.)?Convert\]::FromBase64String\((\$\w+)\)', body, re.I)
            key_param = re.search(key + r'\s*=\s*\[(?:System\.)?Text\.Encoding\]::ASCII\.GetBytes\((\$\w+)\)', body, re.I)
            if not cipher_param or not key_param:
                continue
            if not re.search(r'return\s*\[(?:System\.)?Text\.Encoding\]::ASCII\.GetString\(' + output + r'\)', body, re.I):
                continue
            bound = r'for\s*\(\s*' + index + r'\s*=\s*0\s*;\s*' + index + r'\s*-lt\s*' + cipher + r'\.Length\s*;\s*' + index + r'\+\+\s*\)'
            if not re.search(bound, body, re.I):
                continue
            for call in re.finditer(r'=\s*' + re.escape(name) + r'(?=\s|$)', code, re.I):
                tail = code[call.end():call.end() + 512]
                tail = re.split(r'[;{}]|\n\s*\n', tail, maxsplit=1)[0]
                cipher_arg = re.search(r'-' + re.escape(cipher_param.group(1)[1:]) + r'\s+(\$\w+)\b', tail, re.I)
                key_arg = re.search(r'-' + re.escape(key_param.group(1)[1:]) + r'\s+(\$\w+)\b', tail, re.I)
                if not cipher_arg or not key_arg:
                    continue
                encrypted = literal_values.get(cipher_arg.group(1).lower())
                password = literal_values.get(key_arg.group(1).lower())
                if not encrypted or not password or len(password) > 1024 or not password.isascii():
                    continue
                if attempts >= 8:
                    self._emit('resource_limit', resource='static_xor_candidates', limit=8)
                    return
                attempts += 1
                self._tick()
                compact = re.sub(r'\s+', '', encrypted)
                if len(compact) > 4 * ((MAX_EMBEDDED_PAYLOAD_BYTES + 2) // 3):
                    continue
                try:
                    cipher_bytes = base64.b64decode(compact, validate=True)
                    key_bytes = password.encode('ascii')
                    decoded = bytes(value ^ key_bytes[i % len(key_bytes)] for i, value in enumerate(cipher_bytes))
                    data = base64.b64decode(decoded, validate=True)
                except (ValueError, binascii.Error):
                    continue
                retain(data, 'static-literal-base64-xor-base64', function=name,
                       assumption='literal-arguments-and-helper-transform; call-reachability-unresolved')

    def _recover_escaped_byte_literals(self, source):
        """Retain exact escaped-hex serializations as static data, not PS strings."""
        for start, end, kind in _scan_ps_text(source):
            if kind not in ('here_d', 'here_s', 'squote', 'dquote') or end - start < 1024:
                continue
            token = source[start:end]
            if (kind.startswith('here_') and not token.endswith(token[1] + '@')) or (
                    not kind.startswith('here_') and token[-1:] != token[:1]):
                continue
            body = _decode_here_string(token) if kind.startswith('here_') else token[1:-1]
            if '\\x' not in body or len(body) > MAX_SOURCE_CHARS:
                continue
            # No interpolation, other escapes, arbitrary separators or trailing
            # source code. Quoted lines are a common C#/shellcode serialization.
            lines = [line.strip() for line in body.strip().removesuffix(';').splitlines() if line.strip()]
            parts = []
            count = 0
            for line in lines:
                self._tick()
                fragment = line[1:-1] if line.startswith('"') and line.endswith('"') else line
                if re.fullmatch(r'(?:\\x[0-9A-Fa-f]{2})+', fragment) is None:
                    break
                count += len(fragment) // 4
                if count > MAX_EMBEDDED_PAYLOAD_BYTES:
                    self._emit('resource_limit', resource='escaped_hex_bytes', limit=MAX_EMBEDDED_PAYLOAD_BYTES)
                    break
                parts.append(fragment.replace('\\x', ''))
            else:
                if count < 256:
                    continue
                raw = bytes.fromhex(''.join(parts))
                digest = hashlib.sha256(raw).hexdigest()
                self._remember_embedded_payload(raw, 'static-escaped-hex-literal', export_binary=True)
                self._emit('static_payload_recovery', source='static-escaped-hex-literal',
                           evidence='static-data-recovery', size=len(raw), sha256=digest,
                           assumption='decode-exact-hex-serialization; native-execution-not-established')

    def _process_layer(self, source):
        self._recover_escaped_byte_literals(source)
        cleaned = _strip_comments(source)
        attribute = re.match(r'^\s*\[CmdletBinding\s*\(', cleaned, re.I)
        if attribute:
            _, attribute_end = _extract_balanced(cleaned, cleaned.index('[', attribute.start()), '[', ']')
            if attribute_end is not None and _PARAM_BLOCK_RE.match(cleaned[attribute_end + 1:]):
                cleaned = cleaned[attribute_end + 1:]
        parameter_block = _PARAM_BLOCK_RE.match(cleaned)
        if parameter_block:
            params_text, end = _extract_balanced(cleaned, parameter_block.end() - 1)
            if params_text is not None:
                args, named = self._entry_arguments or ([], {})
                self._bind_parameters(_extract_scriptblock_params(cleaned), args, named, params_text)
                self._entry_arguments = None
                cleaned = cleaned[end + 1:].lstrip(' \t\r\n;')
        normalized = _normalize_block_syntax(cleaned)
        statements = _split_statements(normalized)
        if len(statements) > MAX_STATEMENTS:
            statements = statements[:MAX_STATEMENTS]
            self.statement_limit_hit = True
        for statement in statements:
            self._tick()
            self._process_statement(statement)

    def run(self):
        try:
            primary_source = self.source
            if self._inspect_non_powershell_artifact(primary_source):
                return self._build_result()
            # Repository file-type labels and extensions are not a parser
            # guarantee. Do not reinterpret CMD syntax as PS aliases, or a
            # standalone URL as an executed download. Keep literal IOCs
            # explicitly separate from modeled network activity.
            stripped_source = primary_source.strip()
            input_kind = None
            if re.fullmatch(r"https?://[^\s<>\"']+", stripped_source, re.IGNORECASE):
                input_kind = "url-only-data"
            elif (re.match(r"(?:@echo\s+off\s*\n)?\s*set\s+\w+=%\w+%", stripped_source, re.IGNORECASE)
                  and re.search(r"(?im)^\s*(?:for\s+/f\b|cd\s+/d\b|if\s+(?:not\s+)?exist\b)", stripped_source)):
                input_kind = "cmd-batch-syntax"
            elif (re.match(r"(?:var|let|const)\s+[A-Za-z_$][\w$]*\s*=\s*[\[{]", stripped_source)
                  and re.search(r"\bfunction\s*\(", stripped_source)):
                input_kind = "javascript-syntax"
            elif (re.fullmatch(r"[A-Za-z_][\w.-]*=[A-Za-z0-9%+_.~:/@-]*(?:&[A-Za-z_][\w.-]*=[A-Za-z0-9%+_.~:/@-]*)+", stripped_source)
                  and re.search(r"%[0-9a-fA-F]{2}", stripped_source)):
                input_kind = "urlencoded-form-data"
            if input_kind:
                self._emit("unparsed_input", kind=input_kind, reason="not-powershell-syntax")
                for url in dict.fromkeys(re.findall(r"https?://[^\s<>\"']+", stripped_source, re.IGNORECASE)):
                    self._emit("static_ioc", kind="url", value=url, source="literal-input")
                return self._build_result()
            # A raw encoded artifact has no PowerShell expression syntax.
            # In particular, treating its thousands of '/' characters as
            # division creates quadratic work and invents a code path.
            compact = re.sub(r"\s+", "", primary_source) if len(primary_source) >= 256 else ""
            if len(compact) >= 256 and re.fullmatch(r"[A-Za-z0-9+/=]+", compact):
                self._emit("unparsed_input", kind="base64-like-data", reason="no-powershell-syntax")
                reversed_token = compact[::-1]
                candidates = [(compact, "raw-base64-data", None),
                              (reversed_token, "reversed-base64-data", "reverse-entire-input")]
                # Missing terminal padding is a data-recovery hypothesis,
                # never a repair of an expression passed to .NET. Retain it
                # only when the complete candidate has a bounded PE layout.
                padding = (-len(reversed_token)) % 4
                if padding in (1, 2) and re.fullmatch(r"[A-Za-z0-9+/]+", reversed_token):
                    candidates.append((reversed_token + "=" * padding,
                                       "reversed-base64-data-with-padding",
                                       f"reverse-entire-input-and-add-{padding}-padding-characters"))
                for token, label, assumption in candidates:
                    try:
                        data = base64.b64decode(token, validate=True)
                    except (ValueError, binascii.Error):
                        continue
                    if label == "reversed-base64-data-with-padding" and not _has_bounded_pe_layout(data):
                        continue
                    if data.startswith((b"MZ", b"PK\x03\x04", b"\x1f\x8b", b"\x7fELF")):
                        self._remember_embedded_payload(data, label)
                        if assumption:
                            self._emit("static_payload_recovery", source=label,
                                       evidence="static-data-recovery", assumption=assumption,
                                       size=len(data), sha256=hashlib.sha256(data).hexdigest())
                return self._build_result()
            unwrapped = _unwrap_powershell_cli_wrapper(self.source)
            if unwrapped is not None:
                # ``powershell -c "..."`` is a CLI invocation, not a PS
                # script -- process only the unwrapped inner command, not
                # the wrapper text itself (which would just produce noise).
                self._emit("embedded_payload_config", family="powershell-cli-wrapper", hidden_line_count=1)
                primary_source = unwrapped
            self._process_layer(primary_source)
            if any(e['category'] == 'unresolved_dynamic_code' for e in self.events):
                self._recover_wrapped_literal_pe_data(primary_source)
            self._drain_dynamic_layers()
            # Best-effort dead-code sweep, strictly *after* every real call
            # above: a function defined but never reached by any modeled
            # call site is still real attacker code (gated behind an
            # unmodeled condition, or reachable through a caller this
            # interpreter didn't resolve) -- run each one once, with
            # unbound (``_Unknown``) parameters, purely to surface whatever
            # direct/literal IOCs it contains on its own. A function that
            # *was* properly invoked with real arguments is skipped here
            # (via ``self._called_functions``) so it never gets a second,
            # worse run with fabricated empty args.
            for name, func_info in list(self.functions.items()):
                if name in self._called_functions:
                    continue
                self._tick()
                self._invoke_function(name, func_info, [], {})
            self._drain_dynamic_layers()
        except TimeoutError as exc:
            self.errors.append(str(exc))
            self._emit("emulation_timeout", error=str(exc))
        except Exception as exc:  # Malformed samples must not abort static analysis.
            self.errors.append(f"{type(exc).__name__}: {exc}")
            self._emit("emulation_error", error=f"{type(exc).__name__}: {exc}")

        return self._build_result()

    def _build_result(self):
        if self._unmodeled_static_count:
            self._emit('unsupported_operation', api='static-method-dispatch', reason='static-methods-not-modeled',
                       count=self._unmodeled_static_count, examples=self._unmodeled_static_examples,
                       aggregation_scope='current-abstract-process; includes speculative paths')
        if self._unmodeled_command_count:
            self._emit('unresolved_command', api='command-dispatch', reason='commands-not-modeled',
                       count=self._unmodeled_command_count, examples=self._unmodeled_command_examples,
                       aggregation_scope='entire-analysis; includes speculative paths')
        findings = self._build_findings()
        incomplete_reasons = sorted({event["category"] for event in self.events
                                     if event["category"] in ("unresolved_dynamic_code", "unresolved_command", "unresolved_file_read", "unresolved_file_write", "unresolved_environment", "unresolved_loop", "unsupported_operation", "resource_limit", "unparsed_input", "dependency_unavailable")})
        if self.timed_out or self.statement_limit_hit or self.event_limit_hit or self.source_truncated:
            incomplete_reasons.append("analysis_budget")
        if self.errors:
            incomplete_reasons.append("analysis_error")
        network_requests = [
            {key: value for key, value in event.items() if key not in ("ts", "category")}
            for event in self.events if event["category"] == "network_request"
        ]
        process_attempts = [
            {key: value for key, value in event.items() if key not in ("ts", "category")}
            for event in self.events if event["category"] == "process_create"
        ]
        dropped_files = [
            {key: value for key, value in event.items() if key not in ("ts", "category")}
            for event in self.events if event["category"] == "filesystem_write"
        ]
        registry_changes = [
            {key: value for key, value in event.items() if key not in ("ts", "category")}
            for event in self.events if event["category"] in ("registry_write", "registry_delete")
        ]
        return {
            "engine": "native-abstract-powershell",
            "isolated": True,
            "side_effects": "in-memory-only",
            "capabilities": {"aes": _PyCryptoAES is not None},
            "origin": self.origin,
            "elapsed_seconds": round(time.monotonic() - self.started, 4),
            "step_count": self.step_count,
            "source_truncated": self.source_truncated,
            "statement_limit_hit": self.statement_limit_hit,
            "event_limit_hit": self.event_limit_hit,
            "analysis_semantics": "heuristic-path-exploration",
            "analysis_status": "partial" if incomplete_reasons else "bounded",
            "incomplete_reasons": incomplete_reasons,
            "limitations": [
                "Conditional bodies and uncalled functions may be explored speculatively; events do not prove runtime reachability.",
                "Host state and network responses are synthetic or unknown; unsupported PowerShell/.NET behavior is not executed.",
            ],
            "timed_out": self.timed_out,
            "findings": findings,
            "ioc_events": self.events,
            "network_requests": network_requests,
            "embedded_network_configs": [{key: value for key, value in event.items() if key not in ("ts", "category")}
                                         for event in self.events if event["category"] == "embedded_payload_config" and event.get("url")],
            "process_attempts": process_attempts,
            "dropped_files": dropped_files,
            "registry_changes": registry_changes,
            "decoded_layers": self.decoded_layers,
            "embedded_payloads": self.embedded_payloads,
            "errors": self.errors,
        }

    def _build_findings(self):
        categories = {event["category"] for event in self.events}
        findings = []

        def add(rule_id, severity, title, description):
            findings.append({
                "rule_id": rule_id,
                "severity": severity,
                "title": title,
                "description": description,
            })

        if {"network_request", "filesystem_write", "process_create"}.issubset(categories):
            add("PS_DOWNLOAD_WRITE_EXECUTE", "high", "Download/write/execute behavior",
                "The emulated script combines a network request, file creation and process execution.")
        elif "process_create" in categories:
            add("PS_PROCESS_EXECUTION", "high", "Process execution attempt",
                "The script attempts to start a command or child process through a modeled API.")
        if "registry_write" in categories and any(event.get("persistence") for event in self.events if event["category"] == "registry_write"):
            add("PS_REGISTRY_PERSISTENCE", "high", "Registry persistence attempt",
                "The script writes to a registry location commonly used for persistence.")
        if "scheduled_task" in categories:
            add("PS_SCHEDULED_TASK", "high", "Scheduled task registration attempt",
                "The script requests a scheduled task; unresolved action targets remain unknown.")
        if 'process_terminate' in categories:
            add('PS_PROCESS_TERMINATION', 'medium', 'Process termination attempt',
                'The script requests process termination through a modeled command; no host process is accessed.')
        if 'scheduled_task_start' in categories:
            add('PS_SCHEDULED_TASK_START', 'high', 'Scheduled task start attempt',
                'The script requests that a scheduled task start. No host task is accessed or started.')
        if "network_request" in categories:
            add("PS_NETWORK_ACTIVITY", "medium", "Network activity",
                "The script attempts network communication (download cradle, web request, or raw socket).")
        if 'screen_capture' in categories:
            add('PS_SCREEN_CAPTURE', 'medium', 'Screen capture attempt',
                'The script calls a modeled screen-copy API. Desktop pixels are unavailable; no actual screenshot is taken.')
        if any(e['category'] == 'embedded_payload_config' and e.get('url') for e in self.events):
            add("PS_EMBEDDED_NETWORK_CONFIG", "medium", "Embedded network configuration (static)",
                "A recognized native payload layout contains network configuration; no request or runtime reachability is established.")
        if "thread_create" in categories:
            add("PS_NATIVE_THREAD", "high", "Native thread creation attempt",
                "The script passes a start address to a modeled CreateThread API. No host thread or machine code is executed.")
        if 'static_payload_recovery' in categories:
            add('PS_STATIC_PAYLOAD_RECOVERY', 'medium', 'PE data recovered statically',
                'PE bytes were recovered using explicit data-decoding assumptions; this does not resolve the original invocation or establish execution.')
        if any(e['category'] == 'unparsed_input' and e.get('kind') == 'split-byte-array-tokens' for e in self.events):
            add('PS_SOURCE_LINE_WRAP', 'info', 'Source contains split byte-array tokens',
                'Newlines split decimal byte values. Reconstructed PE candidates are separate from the unchanged PowerShell source.')
        if "filesystem_write" in categories:
            severity = "high" if any(event.get("suspicious_ext") for event in self.events if event["category"] == "filesystem_write") else "medium"
            add("PS_FILE_WRITE", severity, "File creation attempt",
                "The script writes content through a modeled filesystem API.")
        if "dynamic_code" in categories:
            add("PS_DYNAMIC_CODE", "medium", "Dynamic code execution",
                "The script passes generated or decoded content to Invoke-Expression, a scriptblock, or a .NET assembly loader.")
            if any(
                event["category"] == "dynamic_code" and _LOLBIN_INJECTION_TARGET_RE.search(str(event.get("args", "")))
                for event in self.events
            ):
                add("PS_LOLBIN_INJECTION", "high", "Process hollowing / LOLBin injection target",
                    "A reflective .NET assembly invocation references a legitimate, signed Windows binary commonly abused as a process-hollowing/AppDomain-injection target.")
        if "com_create" in categories:
            add("PS_COM_OBJECT", "medium", "COM object creation",
                "The script creates a COM object (WScript.Shell, ADODB.Stream, ...) commonly used to bridge into WSH-style execution.")
        if "defense_evasion" in categories:
            add("PS_DEFENSE_EVASION", "medium", "Defense evasion attempt",
                "The script attempts to modify execution policy, security preferences or AMSI/ETW fields.")
        if "unresolved_dynamic_code" in categories:
            add("PS_UNRESOLVED_DYNAMIC_CODE", "info", "Dynamic code analysis incomplete",
                "A dynamic invocation has unresolved inputs or unmodeled native behavior; recovered payload bytes and static configuration are reported separately.")
        if "unresolved_file_read" in categories:
            add("PS_UNRESOLVED_FILE_READ", "info", "Required file content unavailable",
                "A modeled file read has no supplied content. Dependent decoding and payload behavior remain unresolved; host files are not read.")
        if "unresolved_file_write" in categories:
            add("PS_UNRESOLVED_FILE_WRITE", "info", "File destination unresolved",
                "A modeled write has no resolved destination. Known payload content is retained separately; no host file is written by the sample.")
        if 'unresolved_environment' in categories:
            add('PS_UNRESOLVED_ENVIRONMENT', 'info', 'Required host state unavailable',
                'The script depends on host configuration that was not supplied. Values derived from it remain unresolved.')
        if "unresolved_command" in categories:
            add("PS_UNRESOLVED_COMMAND", "info", "Command behavior unresolved",
                "A command has unresolved inputs or unsupported behavior. Literal URLs alone do not establish network requests.")
        if 'unsupported_operation' in categories:
            add('PS_UNSUPPORTED_OPERATION', 'info', 'Operation not fully modeled',
                'An API overload or parameter binding could not be resolved. Dependent values remain unknown.')
        if any(e['category'] == 'unparsed_input' and e.get('kind') == 'invalid-base64' for e in self.events):
            add('PS_INVALID_BASE64', 'info', 'Invalid Base64 input',
                'A modeled .NET decoder received invalid Base64. The input was not silently repaired or treated as decoded code.')
        if any(e["category"] == "unparsed_input" and e.get("kind") == "base64-like-data" for e in self.events):
            add("PS_ENCODED_DATA_INPUT", "info", "Encoded data without PowerShell syntax",
                "The input resembles encoded data, so no PowerShell execution path was inferred. Recognizable embedded binary data was inspected statically.")
        if any(e["category"] == "unparsed_input" and e.get("reason") in ("not-powershell-syntax", "input-is-source-or-data-not-a-powershell-program") for e in self.events):
            add("PS_NON_POWERSHELL_INPUT", "info", "Input is not a standalone PowerShell program",
                "The input contains another source/data format or captured console output. Available literals and configuration are static evidence; no PowerShell execution was inferred.")
        if self.timed_out or self.statement_limit_hit or self.event_limit_hit or "resource_limit" in categories:
            add("PS_EMULATION_LIMIT", "info", "Emulation safety limit reached",
                "The bounded emulator reached a time or statement safety budget.")
        if "dependency_unavailable" in categories:
            add("PS_EMULATION_DEPENDENCY", "info", "Emulation dependency unavailable",
                "A required optional decoder is unavailable in the isolated worker's Python environment.")
        return findings


def _bounded_timeout(timeout_seconds):
    try:
        requested = int(timeout_seconds or DEFAULT_TIMEOUT_SECONDS)
    except (TypeError, ValueError, OverflowError):
        requested = DEFAULT_TIMEOUT_SECONDS
    return max(1, min(requested, MAX_TIMEOUT_SECONDS))


def mark_source_truncated(result):
    """Preserve truncation performed outside the interpreter instance."""
    result["source_truncated"] = True
    result["analysis_status"] = "partial"
    reasons = result.setdefault("incomplete_reasons", [])
    if "analysis_budget" not in reasons:
        reasons.append("analysis_budget")
    findings = result.setdefault("findings", [])
    if not any(f.get("rule_id") == "PS_SOURCE_TRUNCATED" for f in findings):
        findings.append({"rule_id": "PS_SOURCE_TRUNCATED", "severity": "info",
                         "title": "Source size limit reached",
                         "description": "Input was truncated; code beyond the source limit was not analyzed."})
    return result


def _failure_result(origin, elapsed, error, *, timed_out=False, source_truncated=False):
    category = "emulation_timeout" if timed_out else "emulation_error"
    description = (
        "The bounded emulator reached its wall-clock or memory safety budget."
        if timed_out else
        "The isolated PowerShell worker exited without a valid result."
    )
    return {
        "engine": "native-abstract-powershell",
        "isolated": True,
        "side_effects": "in-memory-only",
        "hard_timeout_enforced": True,
        "worker_memory_limit_bytes": MAX_WORKER_MEMORY_BYTES if os.name == "posix" else None,
        "origin": _safe_text(origin, 512),
        "elapsed_seconds": round(elapsed, 4),
        "step_count": 0,
        "source_truncated": source_truncated,
        "statement_limit_hit": False,
        "timed_out": timed_out,
        "findings": [{
            "rule_id": "PS_EMULATION_LIMIT",
            "severity": "info",
            "title": "Emulation safety limit reached" if timed_out else "Emulation worker error",
            "description": description,
        }],
        "ioc_events": [{"ts": round(elapsed, 6), "category": category, "error": _safe_text(error)}],
        "network_requests": [],
        "process_attempts": [],
        "dropped_files": [],
        "registry_changes": [],
        "decoded_layers": [],
        "embedded_payloads": [],
        "errors": [_safe_text(error)],
    }


def _apply_worker_limits(timeout_seconds):
    """Best-effort OS limits for the trusted Python worker on POSIX hosts."""
    if os.name != "posix":
        return
    try:
        import resource

        resource.setrlimit(
            resource.RLIMIT_AS,
            (MAX_WORKER_MEMORY_BYTES, MAX_WORKER_MEMORY_BYTES),
        )
        cpu_limit = _bounded_timeout(timeout_seconds) + 2
        resource.setrlimit(resource.RLIMIT_CPU, (cpu_limit, cpu_limit))
    except (ImportError, OSError, ValueError):
        pass


def _deny_worker_host_operation(event, args):
    """Defense in depth for the trusted worker, not an arbitrary-Python sandbox.

    Python imports may still read installed modules. Source is never compiled
    as Python; all sample operations must go through the in-memory models.
    """
    blocked = event.startswith(("subprocess.", "socket.", "os.exec", "os.spawn", "os.posix_spawn"))
    blocked = blocked or event in {
        "os.system", "os.fork", "os.forkpty", "os.kill", "os.killpg",
        "os.remove", "os.rename", "os.rmdir", "os.mkdir", "os.link",
        "os.symlink", "os.truncate", "os.chmod", "os.chown", "os.utime",
        "os.chdir", "os.putenv", "os.unsetenv", "os.startfile", "os.startfile/2",
    }
    if event == "open":
        mode, flags = args[1], args[2]
        blocked = (isinstance(mode, str) and any(c in mode for c in "wax+")) or (
            isinstance(flags, int) and bool(flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND))
        )
    if blocked:
        raise PermissionError(f"PowerShell emulator blocked host operation: {event}")


def _worker_main():
    timeout_seconds = _bounded_timeout(sys.argv[2] if len(sys.argv) > 2 else DEFAULT_TIMEOUT_SECONDS)
    origin = sys.argv[3] if len(sys.argv) > 3 else "script.ps1"
    _apply_worker_limits(timeout_seconds)
    sys.dont_write_bytecode = True
    sys.addaudithook(_deny_worker_host_operation)
    max_input_bytes = MAX_SOURCE_CHARS * 4
    source_bytes = sys.stdin.buffer.read(max_input_bytes + 1)
    source_truncated = len(source_bytes) > max_input_bytes
    source = source_bytes[:max_input_bytes].decode("utf-8", errors="replace")
    result = PowerShellEmulator(source, origin=origin, timeout_seconds=timeout_seconds,
                                include_payload_data="--payload-data" in sys.argv[4:]).run()
    result["source_truncated"] = bool(result.get("source_truncated") or source_truncated)
    if result["source_truncated"]:
        mark_source_truncated(result)
    result["hard_timeout_enforced"] = True
    result["host_operations_blocked"] = True
    result["worker_memory_limit_bytes"] = MAX_WORKER_MEMORY_BYTES if os.name == "posix" else None
    payload = json.dumps(result, ensure_ascii=True, separators=(",", ":")).encode("ascii")
    sys.stdout.buffer.write(payload)
    sys.stdout.buffer.flush()


def emulate_powershell(source, origin="script.ps1", timeout_seconds=DEFAULT_TIMEOUT_SECONDS, *, include_payload_data=False):
    """Emulate suspicious PowerShell in a resource-limited Python worker.

    Attacker-controlled source is never handed to ``powershell.exe``/
    ``pwsh``, a command shell, or Python ``eval``/``exec``. The child
    executes this trusted abstract interpreter only; every modeled cmdlet/
    .NET API remains a fake in-memory model. A parent-side subprocess
    timeout provides a hard boundary even if a parser helper fails to check
    its cooperative deadline.
    """
    timeout_seconds = _bounded_timeout(timeout_seconds)
    origin = _safe_text(origin, 512).replace("\x00", "?")
    source_text = str(source or "")
    source_truncated = len(source_text) > MAX_SOURCE_CHARS
    source_text = source_text[:MAX_SOURCE_CHARS]
    started = time.monotonic()
    command = [
        sys.executable,
        "-I",
        os.path.abspath(__file__),
        "--worker",
        str(timeout_seconds),
        origin,
    ]
    if include_payload_data:
        command.append("--payload-data")
    try:
        completed = subprocess.run(
            command,
            input=source_text.encode("utf-8", errors="replace"),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout_seconds + WORKER_STARTUP_GRACE_SECONDS,
            check=False,
        )
    except subprocess.TimeoutExpired:
        elapsed = time.monotonic() - started
        return _failure_result(
            origin,
            elapsed,
            f"PowerShell emulation hard timeout exceeded ({timeout_seconds}s)",
            timed_out=True,
            source_truncated=source_truncated,
        )
    except OSError as exc:
        return _failure_result(
            origin,
            time.monotonic() - started,
            f"Worker launch failed: {exc}",
            source_truncated=source_truncated,
        )

    elapsed = time.monotonic() - started
    if completed.returncode != 0:
        stderr = completed.stderr.decode("utf-8", errors="replace")[-2048:].strip()
        return _failure_result(
            origin,
            elapsed,
            f"Worker exited with status {completed.returncode}: {stderr or 'no diagnostic output'}",
            source_truncated=source_truncated,
        )
    try:
        result = json.loads(completed.stdout.decode("ascii"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        return _failure_result(
            origin,
            elapsed,
            f"Worker returned invalid JSON: {exc}",
            source_truncated=source_truncated,
        )
    result["source_truncated"] = bool(result.get("source_truncated") or source_truncated)
    if result["source_truncated"]:
        mark_source_truncated(result)
    result["hard_timeout_enforced"] = True
    return result


if __name__ == "__main__" and len(sys.argv) > 1 and sys.argv[1] == "--worker":
    _worker_main()
