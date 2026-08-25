"""Recovers docProps/custom.xml values from an OOXML Office document.

Real, observed technique: a macro's payload (a download-cradle command, a
process-creation command line fragment, ...) is split across several custom
document properties (Insert > Properties > Advanced Properties > Custom in
Word) instead of living in the macro source itself, then reassembled at
runtime via `ActiveDocument.CustomDocumentProperties("Name").Value`. Without
this, that read returns Empty (unmodeled COM property) and the sample's
actual payload -- often the only place a C2 URL or command line appears
anywhere in the file -- never surfaces during emulation.
"""

import zipfile
from io import BytesIO
from xml.etree import ElementTree as ET

# A real docProps/custom.xml is a handful of KB at most; this is purely a
# sanity cap against a hostile entry claiming a huge uncompressed size
# (zip-bomb-style) for what's meant to be a small best-effort recovery step.
_MAX_XML_SIZE = 5_000_000


def extract_custom_document_properties(zip_bytes):
    """Returns {property_name: value_string}, best-effort, from
    docProps/custom.xml. Doesn't care about the declared vt: type (lpwstr,
    i4, bool, ...) -- joins whatever text content is present, which covers
    the string values malware actually stashes payload fragments in."""
    try:
        zf = zipfile.ZipFile(BytesIO(zip_bytes))
    except (zipfile.BadZipFile, OSError):
        return {}
    try:
        info = zf.getinfo("docProps/custom.xml")
    except KeyError:
        return {}
    if info.file_size > _MAX_XML_SIZE:
        return {}
    raw = zf.read(info)
    # A legitimate custom-properties part never declares a DOCTYPE.
    # xml.etree's underlying expat parser expands internal general
    # entities by default, so a hostile docProps/custom.xml carrying a
    # "billion laughs"-style DOCTYPE could otherwise balloon a
    # few-hundred-byte part into gigabytes in memory during what's meant
    # to be a lightweight, best-effort recovery step -- reject outright
    # rather than parse.
    if b"<!DOCTYPE" in raw[:4096].upper():
        return {}
    try:
        root = ET.fromstring(raw)
    except ET.ParseError:
        return {}

    result = {}
    for prop in root:
        name = prop.attrib.get("name")
        if not name:
            continue
        text = "".join(child.text for child in prop if child.text)
        if text:
            result[name] = text
    return result
