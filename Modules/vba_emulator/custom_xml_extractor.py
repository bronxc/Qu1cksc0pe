"""Recovers customXml/itemN.xml parts from an OOXML Office document, keyed
by their namespace URI.

Real, observed technique: a macro's payload (an encoded byte blob, a
download-cradle command, ...) is stashed as the text content of a Custom XML
Part (Word's "Insert > Custom XML Part" data-binding feature, normally used
for structured document metadata) instead of living in the macro source or
custom document properties, then reassembled at runtime via
`ActiveDocument.CustomXMLParts("namespace-uri").SelectSingleNode("/").Text`.
Without this, that read returns Empty (unmodeled COM property) and the
sample's actual payload never surfaces during emulation.
"""

import re
import zipfile
from io import BytesIO
from xml.etree import ElementTree as ET

# Real customXml parts are typically small metadata/payload blobs; this is
# purely a sanity cap against a hostile entry claiming a huge uncompressed
# size for what's meant to be a lightweight best-effort recovery step.
_MAX_XML_SIZE = 5_000_000

_ITEM_RE = re.compile(r"^customXml/item(\d+)\.xml$", re.IGNORECASE)
_DS_URI_RE = re.compile(rb'ds:uri\s*=\s*"([^"]*)"')


def _safe_parse(zf, name):
    try:
        info = zf.getinfo(name)
    except KeyError:
        return None
    if info.file_size > _MAX_XML_SIZE:
        return None
    raw = zf.read(info)
    # A legitimate customXml part never declares a DOCTYPE -- see
    # doc_properties_extractor.py for why this matters (internal
    # general-entity expansion, "billion laughs").
    if b"<!DOCTYPE" in raw[:4096].upper():
        return None
    try:
        return raw, ET.fromstring(raw)
    except ET.ParseError:
        return None


def extract_custom_xml_parts(zip_bytes):
    """Returns {namespace_uri: text_content}, best-effort.

    Matches customXml/itemN.xml to its namespace URI via the sibling
    customXml/itemPropsN.xml's ds:schemaRef/@ds:uri (same N -- the OOXML
    packager numbers these in lockstep for every real sample this was
    checked against, so a lightweight regex over itemPropsN.xml is enough
    without pulling in the .rels graph)."""
    try:
        zf = zipfile.ZipFile(BytesIO(zip_bytes))
    except (zipfile.BadZipFile, OSError):
        return {}

    result = {}
    for name in zf.namelist():
        m = _ITEM_RE.match(name)
        if not m:
            continue
        n = m.group(1)
        item = _safe_parse(zf, name)
        if item is None:
            continue
        _, root = item
        text = "".join(root.itertext())
        if not text:
            continue

        props_raw = None
        try:
            props_info = zf.getinfo(f"customXml/itemProps{n}.xml")
            if props_info.file_size <= _MAX_XML_SIZE:
                props_raw = zf.read(props_info)
        except KeyError:
            pass

        uris = _DS_URI_RE.findall(props_raw) if props_raw else []
        for uri_b in uris:
            try:
                result[uri_b.decode("utf-8", "replace")] = text
            except Exception:
                continue
        if not uris:
            # No schemaRef found -- still recoverable by the item's own
            # root-element namespace, the other common way scripts key
            # CustomXMLParts lookups.
            if root.tag.startswith("{"):
                result[root.tag[1:].split("}", 1)[0]] = text
    return result
