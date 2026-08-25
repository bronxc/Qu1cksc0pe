"""Recovers Ribbon customUI callback function names from an OOXML Office
document, e.g. customUI/customUI14.xml's `<customUI onLoad="rokky">`.

Real, observed technique: Word/Excel invokes a Ribbon customization's
`onLoad` callback automatically the moment the document's ribbon loads --
no user interaction needed, same effective auto-exec behavior as
Document_Open/AutoOpen, but under a macro name that a scan looking only for
the conventional AutoExec Sub names (Document_Open, AutoOpen, ...) never
recognizes as an entry point. Without this, a payload wired up this way
never gets invoked during emulation at all -- the sandboxed run reports
"0 events" and risk_score 0 for a document whose whole point is to
auto-run on open.
"""

import re
import zipfile
from io import BytesIO
from xml.etree import ElementTree as ET

_MAX_XML_SIZE = 2_000_000

# customUI callback attributes all follow this naming convention (the
# [MS-CUSTOMUI]/[MS-CUSTOMUI2] schemas): onLoad, onAction, getLabel,
# getVisible, getEnabled, getImage, getContent, onChange, ... Matching by
# this prefix (rather than an exhaustive attribute allowlist) covers the
# schema's full callback surface, current and future.
_CALLBACK_ATTR_RE = re.compile(r"^(on[A-Z]\w*|get[A-Z]\w*)$")

_CUSTOMUI_PARTS = (
    "customUI/customUI14.xml",
    "customUI/customUI.xml",
)


def extract_customui_callbacks(zip_bytes):
    """Returns a sorted list of unique callback function names referenced
    by any customUI part in the document, best-effort."""
    try:
        zf = zipfile.ZipFile(BytesIO(zip_bytes))
    except (zipfile.BadZipFile, OSError):
        return []

    names = set()
    for part in _CUSTOMUI_PARTS:
        try:
            info = zf.getinfo(part)
        except KeyError:
            continue
        if info.file_size > _MAX_XML_SIZE:
            continue
        raw = zf.read(info)
        if b"<!DOCTYPE" in raw[:4096].upper():
            continue
        try:
            root = ET.fromstring(raw)
        except ET.ParseError:
            continue
        for elem in root.iter():
            for attr_name, attr_value in elem.attrib.items():
                # Attribute names may come through namespace-qualified
                # (e.g. "{...}onLoad") -- match against the local part only.
                local = attr_name.rsplit("}", 1)[-1]
                if _CALLBACK_ATTR_RE.match(local) and attr_value:
                    names.add(attr_value)
    return sorted(names)
