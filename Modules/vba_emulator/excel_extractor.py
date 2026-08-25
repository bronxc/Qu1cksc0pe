"""Recover cell values from OOXML Excel workbooks for VBA emulation.

Malicious workbooks commonly split a large base64/hex payload across cells
and reconstruct it with code such as ``Sheets("Sheet 1").Range("B9")`` plus
repeated ``Offset(1, 0)`` calls.  Macro extraction alone cannot observe that
payload: the values live in worksheet/sharedStrings XML parts, not in the
VBA project.  This module performs a bounded, read-only recovery of those
values and returns them keyed by workbook-visible sheet name and A1 address.
"""

import posixpath
import zipfile
from io import BytesIO
from xml.etree import ElementTree as ET


_MAIN_NS = "http://schemas.openxmlformats.org/spreadsheetml/2006/main"
_DOC_REL_NS = "http://schemas.openxmlformats.org/officeDocument/2006/relationships"
_PKG_REL_NS = "http://schemas.openxmlformats.org/package/2006/relationships"

_MAX_METADATA_XML = 2_000_000
_MAX_SHARED_STRINGS_XML = 25_000_000
_MAX_WORKSHEET_XML = 25_000_000
_MAX_CELLS = 200_000
_MAX_TOTAL_TEXT = 25_000_000


def _read_xml(zf, name, max_size):
    try:
        info = zf.getinfo(name)
    except KeyError:
        return None
    if info.file_size > max_size:
        return None
    try:
        raw = zf.read(info)
    except (KeyError, OSError, RuntimeError):
        return None
    if b"<!DOCTYPE" in raw[:4096].upper():
        return None
    try:
        return ET.fromstring(raw)
    except ET.ParseError:
        return None


def _relationship_target(target):
    target = str(target or "").replace("\\", "/")
    if target.startswith("/"):
        path = posixpath.normpath(target.lstrip("/"))
    else:
        path = posixpath.normpath(posixpath.join("xl", target))
    # Workbook relationships should never escape the OOXML xl/ subtree.
    return path if path == "xl" or path.startswith("xl/") else ""


def _text_content(node):
    return "".join(part.text or "" for part in node.iter(f"{{{_MAIN_NS}}}t"))


def _shared_strings(zf, path):
    root = _read_xml(zf, path, _MAX_SHARED_STRINGS_XML) if path else None
    if root is None:
        return []
    return [_text_content(si) for si in root.findall(f"{{{_MAIN_NS}}}si")]


def _numeric_value(text):
    try:
        if any(ch in text.lower() for ch in (".", "e")):
            return float(text)
        return int(text)
    except (TypeError, ValueError):
        return text


def _cell_value(cell, shared):
    cell_type = cell.attrib.get("t", "")
    if cell_type == "inlineStr":
        inline = cell.find(f"{{{_MAIN_NS}}}is")
        return _text_content(inline) if inline is not None else ""

    value_node = cell.find(f"{{{_MAIN_NS}}}v")
    if value_node is None or value_node.text is None:
        return None
    raw = value_node.text
    if cell_type == "s":
        try:
            index = int(raw)
            return shared[index] if 0 <= index < len(shared) else ""
        except (TypeError, ValueError):
            return ""
    if cell_type == "b":
        return raw.strip() not in ("", "0", "false", "False")
    if cell_type in ("str", "e", "d"):
        return raw
    return _numeric_value(raw)


def extract_excel_cell_values(zip_bytes):
    """Return ``{sheet_name: {A1_address: value}}`` best-effort.

    Only actual stored/cached cell values are recovered; formulas are not
    evaluated.  Resource limits apply before XML parsing and while collecting
    cells so a hostile workbook cannot turn this enrichment step into an
    unbounded allocation.
    """
    try:
        zf = zipfile.ZipFile(BytesIO(zip_bytes))
    except (zipfile.BadZipFile, OSError):
        return {}

    workbook = _read_xml(zf, "xl/workbook.xml", _MAX_METADATA_XML)
    rels = _read_xml(zf, "xl/_rels/workbook.xml.rels", _MAX_METADATA_XML)
    if workbook is None or rels is None:
        return {}

    relationships = {}
    shared_path = ""
    for rel in rels.findall(f"{{{_PKG_REL_NS}}}Relationship"):
        rel_id = rel.attrib.get("Id", "")
        rel_type = rel.attrib.get("Type", "")
        target = _relationship_target(rel.attrib.get("Target", ""))
        if rel_id and target:
            relationships[rel_id] = (rel_type, target)
        if rel_type.endswith("/sharedStrings") and target:
            shared_path = target

    shared = _shared_strings(zf, shared_path)
    result = {}
    total_cells = 0
    total_text = 0
    for sheet in workbook.iter(f"{{{_MAIN_NS}}}sheet"):
        sheet_name = sheet.attrib.get("name", "")
        rel_id = sheet.attrib.get(f"{{{_DOC_REL_NS}}}id", "")
        rel_type, sheet_path = relationships.get(rel_id, ("", ""))
        if not sheet_name or not rel_type.endswith("/worksheet") or not sheet_path:
            continue
        root = _read_xml(zf, sheet_path, _MAX_WORKSHEET_XML)
        if root is None:
            continue
        cells = {}
        for cell in root.iter(f"{{{_MAIN_NS}}}c"):
            address = cell.attrib.get("r", "").replace("$", "").upper()
            if not address:
                continue
            value = _cell_value(cell, shared)
            if value is None:
                continue
            total_cells += 1
            if total_cells > _MAX_CELLS:
                return result
            if isinstance(value, str):
                total_text += len(value)
                if total_text > _MAX_TOTAL_TEXT:
                    return result
            cells[address] = value
        result[sheet_name] = cells
    return result
