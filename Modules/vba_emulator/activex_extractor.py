"""Recovers the runtime value of ActiveX form controls (TextBox, etc.)
embedded directly in an OOXML Office document (``word/activeX/activeX*.bin``).

This is a real, observed technique: malware hides its payload (as a
comma-separated byte list, base64, hex, ...) in the ``.Value``/``.Text`` of
a hidden control on the document, then a macro's ``AutoOpen``/``AutoClose``
reads ``ActiveDocument.<ControlName>.Value`` and reconstructs it. Without
this, that read returns Empty (unmodeled COM property) and the sample's
actual drop logic never runs.

Deliberately NOT a full [MS-OFORMS] binary parser (oletools' own
``oleform.py`` implements that spec, but for the *UserForm* storage
convention -- paired 'f'/'o' streams under a VBA/UserFormN directory --
which doesn't apply to a single control embedded directly in
word/activeX/activeXN.bin; verified empirically against real samples that
its entrypoint doesn't fit this shape). Instead: the persisted control
stream reliably contains the property value as one long run of printable
ASCII (confirmed against real samples: a comma-separated decimal byte
list starting with `77,90,...` == "MZ..." -- a PE header). Extracting "the
longest printable-ASCII run" is a much smaller claim than implementing the
packed binary layout, and fails safe: if no clean run is found, we simply
recover nothing (same as the pre-existing behavior), never a
confidently-wrong value.
"""

import re
import zipfile
from io import BytesIO

from olefile import OleFileIO, isOleFile

_VB_CONTROL_RE = re.compile(
    r'Attribute\s+VB_Control\s*=\s*"([^",]+)', re.IGNORECASE)
_MIN_RUN_LEN = 16
_PRINTABLE_RUN_RE = re.compile(rb"[\x20-\x7e]{%d,}" % _MIN_RUN_LEN)


def _control_names_in_order(macro_sources):
    """Every module's raw Attribute VB_Control line, in the order the
    modules were extracted in -- the same order the OOXML packager numbers
    word/activeX/activeXN.bin in, for every real sample this was checked
    against."""
    names = []
    for _, code in macro_sources:
        names.extend(_VB_CONTROL_RE.findall(code))
    return names


def _longest_printable_run(data):
    runs = _PRINTABLE_RUN_RE.findall(data)
    if not runs:
        return ""
    best = max(runs, key=len)
    return best.decode("ascii", errors="replace")


def extract_activex_control_values(zip_bytes, macro_sources):
    """Returns {control_name: recovered_value_string}, best-effort.

    Matches word/activeX/activeXN.bin files (sorted numerically) to
    control names pulled from Attribute VB_Control lines (in module
    order) 1:1 -- exactly correct for the common case (one or a few
    controls, declared and numbered in the same order), a no-op rather
    than a wrong guess for anything more unusual (mismatched counts are
    simply left unmatched).
    """
    try:
        zf = zipfile.ZipFile(BytesIO(zip_bytes))
    except (zipfile.BadZipFile, OSError):
        return {}

    bin_names = sorted(
        (n for n in zf.namelist() if re.match(r"word/activeX/activeX\d+\.bin$", n, re.IGNORECASE)),
        key=lambda n: int(re.search(r"(\d+)", n).group(1)),
    )
    if not bin_names:
        return {}

    control_names = _control_names_in_order(macro_sources)
    if not control_names:
        return {}

    result = {}
    for name, bin_name in zip(control_names, bin_names):
        try:
            raw = zf.read(bin_name)
        except KeyError:
            continue
        if not isOleFile(BytesIO(raw)):
            continue
        try:
            ole = OleFileIO(BytesIO(raw))
            if ole.exists("contents"):
                content = ole.openstream("contents").read()
            else:
                streams = ole.listdir()
                if not streams:
                    continue
                stream_name = max(streams, key=lambda s: ole.get_size("/".join(s)))
                content = ole.openstream(stream_name).read()
        except Exception:
            continue
        value = _longest_printable_run(content)
        if value:
            result[name] = value
    return result
