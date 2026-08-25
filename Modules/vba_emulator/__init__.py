"""vba_emulator -- sandboxed, from-scratch VBA/VBScript behavior-emulation
engine, native to Qu1cksc0pe (not a dependency on any external package).

Public API:
  emulate_vba_source(code, origin, timeout_seconds, activex_controls, module_names,
                      custom_doc_properties, custom_xml_parts, extra_entry_points,
                      excel_cells) -> dict
  extract_activex_control_values(zip_bytes, macro_sources) -> dict
  extract_custom_document_properties(zip_bytes) -> dict
  extract_custom_xml_parts(zip_bytes) -> dict
  extract_customui_callbacks(zip_bytes) -> list[str]
  extract_shape_macro_callbacks(zip_bytes) -> list[str]
  extract_excel_cell_values(zip_bytes) -> dict
"""

from vba_emulator.activex_extractor import extract_activex_control_values
from vba_emulator.custom_xml_extractor import extract_custom_xml_parts
from vba_emulator.customui_extractor import extract_customui_callbacks
from vba_emulator.doc_properties_extractor import extract_custom_document_properties
from vba_emulator.excel_extractor import extract_excel_cell_values
from vba_emulator.shape_callback_extractor import extract_shape_macro_callbacks
from vba_emulator.engine import emulate_vba_source

__all__ = ["emulate_vba_source", "extract_activex_control_values", "extract_custom_document_properties",
           "extract_custom_xml_parts", "extract_customui_callbacks", "extract_shape_macro_callbacks",
           "extract_excel_cell_values"]
