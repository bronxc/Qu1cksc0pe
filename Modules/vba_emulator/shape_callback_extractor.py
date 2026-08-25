"""Recover VBA procedures assigned to clickable Excel drawing shapes.

In OOXML workbooks, a picture/shape can carry a ``macro`` attribute such as
``[0]!Sheet1.RunPayload``.  Excel invokes that procedure when the user clicks
the object.  These callbacks are not conventional AutoExec names and are not
present in the VBA source as event handlers, so source-only emulation otherwise
reports that the workbook did nothing.
"""

import re
import zipfile
from io import BytesIO
from xml.etree import ElementTree as ET

_MAX_XML_SIZE = 2_000_000
_DRAWING_PART_RE = re.compile(r"^xl/drawings/[^/]+\.xml$", re.IGNORECASE)
_VBA_NAME_RE = re.compile(r"^[^\W\d]\w*$", re.UNICODE)


def _procedure_name(binding):
    """Normalize Excel's external-looking macro binding to a VBA name."""
    name = str(binding or "").strip()
    if "!" in name:
        name = name.rsplit("!", 1)[-1]
    name = name.strip().strip("'").strip()
    if "." in name:
        name = name.rsplit(".", 1)[-1]
    name = name.strip()
    return name if _VBA_NAME_RE.match(name) else ""


def extract_shape_macro_callbacks(zip_bytes):
    """Return unique VBA procedure names assigned to Excel drawing objects."""
    try:
        zf = zipfile.ZipFile(BytesIO(zip_bytes))
    except (zipfile.BadZipFile, OSError):
        return []

    names = set()
    for info in zf.infolist():
        if not _DRAWING_PART_RE.match(info.filename) or info.file_size > _MAX_XML_SIZE:
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
                if attr_name.rsplit("}", 1)[-1].lower() != "macro":
                    continue
                name = _procedure_name(attr_value)
                if name:
                    names.add(name)
    return sorted(names, key=str.lower)
