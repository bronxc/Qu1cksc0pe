"""Fake Win32 API surface reached via VBA's `Declare` statement.

Real, heavily observed technique: a macro Declares direct kernel32.dll (and
friends) exports instead of routing through any COM object, most often to
build a classic process-injection chain (VirtualAlloc[Ex] ->
WriteProcessMemory -> CreateRemoteThread), spraying a shellcode blob into a
process rather than dropping+running a file the way every other technique
in com_objects.py does. None of this ever touches the real Win32 API --
every call here only records into the Session/IOC sink, exactly like the
fake COM objects there.
"""

from vba_emulator.com_objects import _SUSPICIOUS_EXT, _ext, safe_str


def _arg(args, i, default=None):
    return args[i] if len(args) > i else default


def _set_field(obj, name, value):
    if hasattr(obj, "set_prop"):
        obj.set_prop(name, value)


# A shellcode-injection macro conventionally calls WriteProcessMemory (or
# RtlMoveMemory) once *per byte* in a loop -- real samples seen with
# payloads in the hundreds to low thousands of bytes, each call otherwise
# emitting its own full IOC event. Rate-limit per API name the same way
# interpreter.py's _handle_runtime_error already rate-limits repeated
# script_error events, so a large payload can't burn through the global
# IOCSink event cap (20,000) on write-spam alone and starve later,
# possibly more important events of any room to be recorded.
_EMIT_CAP = 5


def _emit(interp, category, **fields):
    counts = interp.session.__dict__.setdefault("_winapi_emit_counts", {})
    key = (category, fields.get("api"))
    n = counts.get(key, 0) + 1
    counts[key] = n
    if n <= _EMIT_CAP:
        interp.ioc.emit(category, **fields)
    elif n == _EMIT_CAP + 1:
        interp.ioc.emit(f"{category}_suppressed", api=fields.get("api"),
                         note=f"further {fields.get('api')} calls are suppressed")


# A fake but stable, nonzero-looking handle/pointer -- many callers branch
# on "did this return nonzero" before proceeding (real Win32 convention),
# and downstream Declare'd calls in the same chain often reuse a prior
# call's return value as an opaque handle/address argument without needing
# it to be a real pointer.
_FAKE_HANDLE = 0x1000
_FAKE_ADDRESS = 0x00400000


def h_virtualalloc(interp, args):
    _emit(interp, "process_injection", api="VirtualAlloc", size=safe_str(_arg(args, 1, "")),
                     protect=safe_str(_arg(args, 3, "")))
    return _FAKE_ADDRESS


def h_virtualallocex(interp, args):
    _emit(interp, "process_injection", api="VirtualAllocEx", size=safe_str(_arg(args, 2, "")),
                     protect=safe_str(_arg(args, 4, "")))
    return _FAKE_ADDRESS


def h_writeprocessmemory(interp, args):
    _emit(interp, "process_injection", api="WriteProcessMemory", size=safe_str(_arg(args, 3, "")))
    return 1


def h_createremotethread(interp, args):
    _emit(interp, "process_injection", api="CreateRemoteThread",
                     start_address=safe_str(_arg(args, 3, "")))
    return _FAKE_HANDLE


def h_createthread(interp, args):
    _emit(interp, "process_injection", api="CreateThread", start_address=safe_str(_arg(args, 2, "")))
    return _FAKE_HANDLE


def h_ntunmapviewofsection(interp, args):
    # Process-hollowing's signature call -- unmaps a legitimately-started
    # process's own image before overwriting it, always paired with the
    # allocate/write/resume sequence above.
    _emit(interp, "process_injection", api="NtUnmapViewOfSection/ZwUnmapViewOfSection")
    return 0


def h_virtualprotect(interp, args):
    _emit(interp, "process_injection", api="VirtualProtect", protect=safe_str(_arg(args, 2, "")))
    return 1


def h_virtualprotectex(interp, args):
    _emit(interp, "process_injection", api="VirtualProtectEx", protect=safe_str(_arg(args, 3, "")))
    return 1


def h_rtlmovememory(interp, args):
    _emit(interp, "process_injection", api="RtlMoveMemory/RtlCopyMemory/memcpy",
                     size=safe_str(_arg(args, 2, "")))
    return 0


def h_createprocess(interp, args):
    app_name = safe_str(_arg(args, 0, ""))
    cmdline = safe_str(_arg(args, 1, ""))
    command = cmdline or app_name
    interp.session.process_log.append(command)
    _emit(interp, "process_create", api="CreateProcessA/W", command=command)
    proc_info = _arg(args, 9)
    _set_field(proc_info, "hprocess", _FAKE_HANDLE)
    _set_field(proc_info, "hthread", _FAKE_HANDLE + 1)
    _set_field(proc_info, "dwprocessid", 4444)
    _set_field(proc_info, "dwthreadid", 4445)
    return 1


def h_winexec(interp, args):
    command = safe_str(_arg(args, 0, ""))
    interp.session.process_log.append(command)
    _emit(interp, "process_create", api="WinExec", command=command)
    return 32  # WinExec's own success convention: >31


def h_shellexecute(interp, args):
    # ShellExecute[A/W](hwnd, lpOperation, lpFile, lpParameters, lpDirectory, nShowCmd)
    file_ = safe_str(_arg(args, 2, ""))
    params = safe_str(_arg(args, 3, ""))
    command = f"{file_} {params}".strip()
    interp.session.process_log.append(command)
    _emit(interp, "process_create", api="ShellExecuteA/W", command=command)
    return 33  # ShellExecute's own success convention: >32


def h_urldownloadtofile(interp, args):
    url = safe_str(_arg(args, 1, ""))
    dest = safe_str(_arg(args, 2, ""))
    _emit(interp, "network_request", api="URLDownloadToFileA/W", method="GET", url=url)
    if dest:
        interp.session.vfs_write(dest, b"", is_binary=True)
        _emit(interp, "filesystem_write", api="URLDownloadToFileA/W", path=dest, size=0,
                         is_binary=True, suspicious_ext=_ext(dest) in _SUSPICIOUS_EXT,
                         downloaded=True, source_url=url)
    return 0


def h_loadlibrary(interp, args):
    _emit(interp, "unmodeled_winapi_call", api="LoadLibraryA/W", lib="", args=[safe_str(_arg(args, 0, ""))])
    return _FAKE_HANDLE


_HANDLERS = {
    "virtualalloc": h_virtualalloc,
    "virtualallocex": h_virtualallocex,
    "writeprocessmemory": h_writeprocessmemory,
    "createremotethread": h_createremotethread,
    "createremotethreadex": h_createremotethread,
    "createthread": h_createthread,
    "ntunmapviewofsection": h_ntunmapviewofsection,
    "zwunmapviewofsection": h_ntunmapviewofsection,
    "virtualprotect": h_virtualprotect,
    "virtualprotectex": h_virtualprotectex,
    "rtlmovememory": h_rtlmovememory,
    "rtlcopymemory": h_rtlmovememory,
    "memcpy": h_rtlmovememory,
    "createprocessa": h_createprocess,
    "createprocessw": h_createprocess,
    "winexec": h_winexec,
    "shellexecutea": h_shellexecute,
    "shellexecutew": h_shellexecute,
    "urldownloadtofilea": h_urldownloadtofile,
    "urldownloadtofilew": h_urldownloadtofile,
    "loadlibrarya": h_loadlibrary,
    "loadlibraryw": h_loadlibrary,
}


def make_declare_handler(stmt):
    """Returns a NativeFunc-compatible fn(interp, args) for a parsed
    DeclareStmt -- a known handler matched by the real DLL export name
    (`alias`, case-insensitive; falls back to the declared VBA-visible
    `name` when there's no explicit `Alias` clause, since some samples
    Declare with the real name directly), or a graceful catch-all for any
    DLL function this doesn't model."""
    handler = _HANDLERS.get(stmt.alias.lower()) or _HANDLERS.get(stmt.name.lower())
    if handler is not None:
        return handler

    def fallback(interp, args):
        _emit(interp, "unmodeled_winapi_call", api=stmt.alias, lib=stmt.lib,
                         args=[safe_str(a) for a in args])
        return 0

    return fallback
