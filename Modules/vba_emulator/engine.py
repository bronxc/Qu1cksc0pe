"""Public entrypoint: run VBA/VBScript source through the sandboxed
emulator and return a plain, JSON-serializable dict report.

Nothing here (or anywhere in this package) performs real file/network/
registry/process I/O -- every Windows API a script can reach is
reimplemented as a fake object in com_objects.py that records what it was
asked to do into an in-memory Session instead of doing it. That makes the
emulator itself side-effect-free by construction.
"""

import time
import posixpath

from vba_emulator.interpreter import Interpreter
from vba_emulator.scoring import score
from vba_emulator.session import Session


def _json_safe(value):
    """Recursively coerce a value into something json.dumps can handle.

    Defense in depth: every fake-COM-object call site is expected to
    stringify sample-controlled values with safe_str() before logging them
    as an IOC event field, but a generic property-set fallback (see
    com_objects.ComObject.set_prop) stores whatever raw VBA value a script
    assigns (VBArray, VBEmpty/VBNull/VBNothing sentinels, even another
    ComObject) -- one missed safe_str() call at a single call site
    (found: WshShortcut.Save reading back .TargetPath) is enough to crash
    the caller's json.dump() the moment a report is saved. This makes that
    whole bug *class* non-fatal instead of chasing each call site.
    """
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, (bytes, bytearray)):
        return f"<{len(value)} bytes>"
    if isinstance(value, dict):
        return {str(k): _json_safe(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_safe(v) for v in value]
    return repr(value)


def emulate_vba_source(code, origin="macro", timeout_seconds=15, activex_controls=None, module_names=None,
                        custom_doc_properties=None, custom_xml_parts=None, extra_entry_points=None,
                        excel_cells=None):
    """Runs the given VBA/VBScript source through the sandboxed emulator.

    Returns a plain dict:
      {
        "origin": str,
        "code_length": int,
        "findings": [{"rule_id", "title", "severity", "weight", "evidence"}],
        "ioc_events": [{"category", "ts", ...fields}],
        "script_output": [str],
        "process_log": [str],
        "dropped_files": [{"path","size","is_binary","suspicious_ext","api"}],
        "registry_changes": [{"action","key","value","persistence"}],
        "network_requests": [dict],
        "parser_warnings": [str],
        "step_count": int,
        "elapsed_seconds": float,
      }
    """
    t0 = time.time()
    session = Session(config={"max_seconds": timeout_seconds})
    origin_name = posixpath.basename(str(origin).replace("\\", "/"))
    if not origin_name.lower().endswith((".vbs", ".vbe", ".vba", ".vb", ".bas", ".cls", ".frm")):
        origin_name = "sample.vbs"
    session.script_name = origin_name
    session.script_fullname = session.env_vars["TEMP"] + "\\" + origin_name
    # WScript.ScriptFullName points at the running source in real WSH.
    # Seed only the in-memory VFS so self-reading/self-decoding scripts can
    # observe their own text without touching the analyst's filesystem.
    session.vfs_write(session.script_fullname, code, is_binary=False)
    session.load_excel_cells(excel_cells)
    interp = Interpreter(session, activex_controls=activex_controls, module_names=module_names,
                          custom_doc_properties=custom_doc_properties, custom_xml_parts=custom_xml_parts,
                          extra_entry_points=extra_entry_points)
    try:
        interp.run(code, filename=origin)
    except Exception as e:
        session.ioc.emit("emulation_error", error=str(e), phase="engine")

    events = session.ioc.events
    # Isolated from interp.run() above on purpose: by this point the
    # interpreter has already successfully collected every IOC event
    # (dropped files, registry writes, process spawns, ...), which is the
    # valuable part of the result. A bug in the pattern-matching rules
    # alone (e.g. a regex hitting an unexpected field type) shouldn't
    # discard all of that -- fail open to "no findings" rather than
    # losing the report.
    try:
        findings = score(events, step_count=session.step_count)
    except Exception as e:
        session.ioc.emit("emulation_error", error=str(e), phase="scoring")
        findings = []

    dropped_files = []
    seen_paths = set()
    for e in events:
        cat = e.get("category")
        path = e.get("path") if cat == "filesystem_write" else (
            e.get("dst") if cat in ("filesystem_copy", "filesystem_move") else (
            e.get("destination") if cat == "filesystem_extract" else None))
        if not path or path in seen_paths:
            continue
        seen_paths.add(path)
        dropped_files.append({
            "path": path, "size": e.get("size", 0), "is_binary": e.get("is_binary", False),
            "suspicious_ext": e.get("suspicious_ext", False),
            "executable_content": e.get("executable_content", False),
            "magic": e.get("magic", ""), "api": e.get("api", ""),
        })

    registry_changes = []
    for e in events:
        cat = e.get("category")
        if cat == "registry_write":
            registry_changes.append({"action": "write", "key": e.get("key", ""),
                                      "value": e.get("value", ""), "persistence": e.get("persistence", False)})
        elif cat == "registry_delete":
            registry_changes.append({"action": "delete", "key": e.get("key", "")})
        elif cat == "registry_read":
            registry_changes.append({"action": "read", "key": e.get("key", "")})

    network_requests = [
        {k: v for k, v in e.items() if k != "ts"}
        for e in events if e.get("category") in ("network_request", "network_send")
    ]

    ioc_events = [
        {"category": e["category"], "ts": e["ts"],
         **{k: v for k, v in e.items() if k not in ("category", "ts")}}
        for e in events
    ]

    # _json_safe() applied to the whole report in one pass (rather than at
    # each construction site above) so this guarantee -- "this dict is
    # always safe to json.dump()" -- holds even if a future field is added
    # here or a new fake-COM-object call site forgets to safe_str() a
    # value before logging it.
    return _json_safe({
        "origin": origin,
        "code_length": len(code),
        "findings": [f.to_dict() for f in findings],
        "ioc_events": ioc_events,
        "script_output": list(session.output_log),
        "process_log": list(session.process_log),
        "dropped_files": dropped_files,
        "registry_changes": registry_changes,
        "network_requests": network_requests,
        "parser_warnings": list(interp.warnings),
        "step_count": session.step_count,
        "elapsed_seconds": round(time.time() - t0, 3),
    })
