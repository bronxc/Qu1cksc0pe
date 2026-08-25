"""VBA/VBScript value model: sentinels for Empty/Null/Nothing, coercion
helpers approximating Variant conversion rules, and an N-dimensional array
type. Includes resource caps against pathological inputs (verified against
real-world malicious samples during development -- see comments below)."""

from vba_emulator.errors import VBRuntimeError

# Hard cap on any single VBA string value. Without this, a handful of loop
# iterations of `s = s & s` (exponential doubling) or a single
# `String(n, "A")` call with a huge n can exhaust host memory before any
# step/wall-clock budget check gets a chance to fire.
MAX_STRING_LEN = 25_000_000


def check_string_len(length):
    if length > MAX_STRING_LEN:
        raise VBRuntimeError(
            f"Out of memory: string of {length} chars exceeds the "
            f"{MAX_STRING_LEN}-char emulation cap", 7)


class _Sentinel:
    __slots__ = ("name",)

    def __init__(self, name):
        self.name = name

    def __repr__(self):
        return self.name

    def __bool__(self):
        return False


VBEmpty = _Sentinel("Empty")
VBNull = _Sentinel("Null")
VBNothing = _Sentinel("Nothing")


class VBArray:
    """N-dimensional array with per-dimension lower/upper bounds."""

    # A hostile sample can declare `Dim arr(2000000000)` in a single
    # statement -- without a cap that's an uncontrolled allocation that can
    # OOM the analysis host. Real scripts don't need arrays anywhere near
    # this size.
    MAX_ELEMENTS = 5_000_000

    def __init__(self, bounds):
        self.bounds = bounds
        sizes = [hi - lo + 1 if hi >= lo else 0 for lo, hi in bounds]
        total = 1
        for s in sizes:
            total *= s
        if total > self.MAX_ELEMENTS:
            raise VBRuntimeError(
                f"Out of memory: array of {total} elements exceeds the "
                f"{self.MAX_ELEMENTS}-element emulation cap", 7)
        self._sizes = sizes
        self.data = [VBEmpty] * total

    def _flat_index(self, idxs):
        if len(idxs) != len(self.bounds):
            raise VBRuntimeError(f"Wrong number of array subscripts (expected {len(self.bounds)})", 9)
        flat = 0
        for (lo, hi), i in zip(self.bounds, idxs):
            i = int(i)
            if i < lo or i > hi:
                raise VBRuntimeError("Subscript out of range", 9)
            flat = flat * (hi - lo + 1) + (i - lo)
        return flat

    def get(self, idxs):
        return self.data[self._flat_index(idxs)]

    def set(self, idxs, value):
        self.data[self._flat_index(idxs)] = value

    def redim_preserve(self, new_bounds):
        old = self
        new = VBArray(new_bounds)
        if len(new_bounds) == 1 and len(old.bounds) == 1:
            lo, hi = new_bounds[0]
            olo, ohi = old.bounds[0]
            for i in range(max(lo, olo), min(hi, ohi) + 1):
                new.set((i,), old.get((i,)))
        self.bounds = new.bounds
        self._sizes = new._sizes
        self.data = new.data

    def to_list(self):
        return list(self.data)

    def __len__(self):
        return len(self.data)

    def __repr__(self):
        return f"VBArray({self.bounds!r})"


def vb_type_name(v):
    if v is VBEmpty:
        return "Empty"
    if v is VBNull:
        return "Null"
    if v is VBNothing:
        return "Nothing"
    if isinstance(v, bool):
        return "Boolean"
    if isinstance(v, int):
        return "Long"
    if isinstance(v, float):
        return "Double"
    if isinstance(v, str):
        return "String"
    if isinstance(v, (bytes, bytearray)):
        return "Byte()"
    if isinstance(v, VBArray):
        return "Variant()"
    return type(v).__name__


def is_numeric(v):
    return isinstance(v, (int, float)) and not isinstance(v, bool)


def to_number(v):
    if isinstance(v, bool):
        return -1 if v else 0
    if isinstance(v, (int, float)):
        return v
    if v is VBEmpty:
        return 0
    if v is VBNull:
        raise VBRuntimeError("Invalid use of Null", 94)
    if isinstance(v, str):
        s = v.strip()
        # VBA/VBScript recognize "&H.."/"&O.." *string* values as hex/octal
        # too, not just literal tokens in source code -- e.g. CInt("&H24")
        # or arithmetic on a runtime-built "&H" & hexPair string, a common
        # hex-decode idiom seen in real malware. Without this, every such
        # conversion raises Type mismatch, and a per-byte decode loop under
        # On Error Resume Next silently fails every single iteration
        # (looks like a hang on a large payload; it's really hundreds of
        # thousands of caught-and-ignored errors).
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
        try:
            if any(c in low for c in (".", "e")):
                return float(s)
            return int(s)
        except ValueError:
            try:
                return float(s)
            except ValueError:
                raise VBRuntimeError(f"Type mismatch: '{v}'", 13)
    raise VBRuntimeError(f"Type mismatch converting {vb_type_name(v)} to number", 13)


def to_str(v):
    if isinstance(v, bool):
        return "True" if v else "False"
    if v is VBEmpty:
        return ""
    if v is VBNull:
        raise VBRuntimeError("Invalid use of Null", 94)
    if v is VBNothing:
        raise VBRuntimeError("Object variable not set", 91)
    if isinstance(v, float):
        if v == int(v) and abs(v) < 1e15:
            return str(int(v))
        return repr(v)
    if isinstance(v, str):
        return v
    return str(v)


def to_bool(v):
    if isinstance(v, bool):
        return v
    if v is VBEmpty or v is VBNull:
        return False
    if isinstance(v, (int, float)):
        return v != 0
    if isinstance(v, str):
        s = v.strip().lower()
        if s == "true":
            return True
        if s == "false":
            return False
        try:
            return to_number(v) != 0
        except VBRuntimeError:
            raise VBRuntimeError(f"Type mismatch: '{v}' is not a Boolean", 13)
    return bool(v)
