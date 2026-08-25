"""Fake COM/automation objects.

Every unimplemented method or property access degrades gracefully: it is
logged to the IOC sink as an "unknown_com_call" event and returns Empty,
instead of raising -- real-world malicious macros call into a huge surface
of COM APIs, and only a slice of it matters for behavior analysis
(filesystem, process, network, registry, persistence), so unmodeled calls
must not crash the whole emulation.

Nothing in here ever performs a real file write, registry write, or
network call -- not even a HEAD request for URLs (a malicious URL may
point at live attacker infrastructure; issuing a real request would be
unsafe and could tip the attacker that the sample is being analyzed).
Every action is recorded into the in-memory Session and/or the IOC sink
instead of being carried out.
"""

import base64
import binascii
import posixpath
import random
import re
import string

from vba_emulator.errors import VBRuntimeError
from vba_emulator.values import VBEmpty, VBNothing, to_bool, to_str

_SUSPICIOUS_EXT = {".exe", ".dll", ".scr", ".bat", ".cmd", ".ps1", ".vbs",
                    ".js", ".jse", ".hta", ".jar", ".msi", ".lnk", ".vbe", ".wsf"}


def _ext(path):
    return posixpath.splitext(path.replace("\\", "/"))[1].lower()


def executable_magic(content):
    """Identify executable bytes even when malware omits the extension."""
    if not isinstance(content, (bytes, bytearray)):
        return ""
    data = bytes(content[:4])
    if data.startswith(b"MZ"):
        return "PE"
    if data.startswith(b"\x7fELF"):
        return "ELF"
    return ""


def safe_str(v):
    try:
        return to_str(v)
    except Exception:
        return repr(v)


# --------------------------------------------------------------- base ---
class ComObject:
    progid = "Unknown"

    def __init__(self, session, interp=None):
        self.session = session
        self.ioc = session.ioc
        self.interp = interp
        self.props = {}

    def invoke(self, name, args):
        method = getattr(self, "m_" + name.lower(), None)
        if method is not None:
            return method(args)
        self.ioc.emit("unknown_com_call", progid=self.progid, member=name,
                       args=[safe_str(a) for a in args], kind="call")
        return VBEmpty

    def get_prop(self, name):
        # A bare `.member` reference (no parens/args) is ambiguous between
        # a property-get and a zero-arg method call in VBA/VBScript syntax
        # -- try both.
        method = getattr(self, "p_" + name.lower(), None)
        if method is not None:
            return method()
        method = getattr(self, "m_" + name.lower(), None)
        if method is not None:
            return method([])
        key = name.lower()
        if key in self.props:
            return self.props[key]
        self.ioc.emit("unknown_com_call", progid=self.progid, member=name, kind="get")
        return VBEmpty

    def set_prop(self, name, value):
        method = getattr(self, "s_" + name.lower(), None)
        if method is not None:
            return method(value)
        self.props[name.lower()] = value

    def default_index(self, args):
        self.ioc.emit("unknown_com_call", progid=self.progid, member="[default]",
                       args=[safe_str(a) for a in args], kind="call")
        return VBEmpty

    def set_index(self, args, value):
        self.ioc.emit("unknown_com_call", progid=self.progid, member="[default]",
                       args=[safe_str(a) for a in args], kind="set")


# --------------------------------------------------------------- Err ---
class ErrObject(ComObject):
    progid = "Err"

    def p_number(self):
        return self.session.err_number

    def p_description(self):
        return self.session.err_description

    def p_source(self):
        return "vba_emulator"

    def m_clear(self, args):
        self.session.err_number = 0
        self.session.err_description = ""
        return VBEmpty

    def m_raise(self, args):
        number = int(to_str(args[0])) if args else 5
        description = safe_str(args[2]) if len(args) > 2 else (safe_str(args[1]) if len(args) > 1 else "Application-defined error")
        self.session.err_number = number
        self.session.err_description = description
        raise VBRuntimeError(description, number)


# ------------------------------------------------------------- Debug ---
class DebugObject(ComObject):
    """VBA IDE's ambient ``Debug`` object.

    ``Debug.Print`` is diagnostic output, not a host side effect, but it is
    commonly placed between construction and execution of a malicious command.
    Treating ``Debug`` as an undeclared value used to stop emulation before the
    later WScript.Shell call.  Keep the output in the sandbox report and allow
    execution to continue.
    """

    progid = "VBA.Debug"

    def m_print(self, args):
        self.session.output_log.append(" ".join(safe_str(arg) for arg in args))
        return VBEmpty


# ------------------------------------------------------------- files ---
class TextStream(ComObject):
    progid = "Scripting.TextStream"

    def __init__(self, session, interp, path, mode):
        super().__init__(session, interp)
        self.path = path
        self.mode = mode
        self.buffer = [] if mode != "read" else None
        self._read_pos = 0
        self._write_count = 0
        if mode == "read":
            existing = session.vfs_read(path)
            self._content = existing if isinstance(existing, str) else (existing.decode("utf-8", "replace") if existing else "")
        elif mode == "append":
            existing = session.vfs_read(path)
            self.buffer = [existing if isinstance(existing, str) else ""]

    def m_write(self, args):
        self.buffer.append(safe_str(args[0]) if args else "")
        self._write_count += 1
        self._flush(emit_event=(self._write_count == 1))
        return VBEmpty

    def m_writeline(self, args):
        text = safe_str(args[0]) if args else ""
        self.buffer.append(text + "\n")
        self._write_count += 1
        self._flush(emit_event=(self._write_count == 1))
        return VBEmpty

    def m_readall(self, args):
        return self._content[self._read_pos:]

    def m_readline(self, args):
        rest = self._content[self._read_pos:]
        nl = rest.find("\n")
        if nl == -1:
            self._read_pos = len(self._content)
            return rest
        self._read_pos += nl + 1
        return rest[:nl]

    def m_close(self, args):
        self._flush(emit_event=True)
        return VBEmpty

    def p_atendofstream(self):
        return self._read_pos >= len(self._content)

    def _flush(self, emit_event):
        # The virtual-filesystem write happens every call (so e.g. a
        # ReadAll from elsewhere mid-stream sees current content), but the
        # IOC event only fires on the first Write/WriteLine and on Close
        # -- a byte-at-a-time write loop (`For i = 1 To Len(payload):
        # stream.Write Mid(payload,i,1): Next`, a real obfuscation
        # pattern) previously emitted one filesystem_write event per
        # character, and IOCSink.emit() silently no-ops once the global
        # 20,000-event cap is hit with no per-category rate limit (unlike
        # script_error's explicit one) -- burning the whole budget on
        # write spam could starve later, more important events (e.g. the
        # process_create that actually runs the dropped payload) of any
        # room to be recorded at all.
        content = "".join(self.buffer) if self.buffer else ""
        self.session.vfs_write(self.path, content, is_binary=False)
        if emit_event:
            self.ioc.emit("filesystem_write", api="TextStream.Write", path=self.path,
                           size=len(content), preview=content[:200],
                           suspicious_ext=_ext(self.path) in _SUSPICIOUS_EXT)


class FileSystemFolder(ComObject):
    """A virtual FSO Folder with truthful empty child collections.

    The sandbox has no host filesystem view and must never enumerate the
    analyst's real files. Returning empty VBA arrays lets common recursive
    walkers evaluate safely while preserving that isolation boundary.
    """

    progid = "Scripting.Folder"

    def __init__(self, session, interp, path):
        super().__init__(session, interp)
        self.path = path

    def p_path(self):
        return self.path

    def p_name(self):
        return posixpath.basename(self.path.replace("\\", "/").rstrip("/"))

    def p_files(self):
        from vba_emulator.values import VBArray
        return VBArray([(0, -1)])

    def p_subfolders(self):
        from vba_emulator.values import VBArray
        return VBArray([(0, -1)])


class FileSystemObject(ComObject):
    progid = "Scripting.FileSystemObject"

    def m_createtextfile(self, args):
        path = safe_str(args[0])
        self.ioc.emit("filesystem_create", api="FileSystemObject.CreateTextFile", path=path,
                       suspicious_ext=_ext(path) in _SUSPICIOUS_EXT)
        return TextStream(self.session, self.interp, path, "write")

    def m_opentextfile(self, args):
        path = safe_str(args[0])
        iomode = int(to_str(args[1])) if len(args) > 1 else 1
        create = bool(args[2]) if len(args) > 2 else False
        mode = "append" if iomode == 8 else ("write" if iomode == 2 else "read")
        if mode == "read" and not self.session.vfs_exists(path) and not create:
            raise VBRuntimeError(f"File not found: {path}", 53)
        self.ioc.emit("filesystem_access", api="FileSystemObject.OpenTextFile", path=path, mode=mode)
        return TextStream(self.session, self.interp, path, mode)

    def m_copyfile(self, args):
        src, dst = safe_str(args[0]), safe_str(args[1])
        content = self.session.vfs_read(src)
        if content is not None:
            self.session.vfs_write(dst, content)
        self.ioc.emit("filesystem_copy", api="FileSystemObject.CopyFile", src=src, dst=dst,
                       suspicious_ext=_ext(dst) in _SUSPICIOUS_EXT)
        return VBEmpty

    def m_movefile(self, args):
        src, dst = safe_str(args[0]), safe_str(args[1])
        content = self.session.vfs_read(src)
        if content is not None:
            self.session.vfs_write(dst, content)
            self.session.vfs_delete(src)
        self.ioc.emit("filesystem_move", api="FileSystemObject.MoveFile", src=src, dst=dst,
                       suspicious_ext=_ext(dst) in _SUSPICIOUS_EXT)
        return VBEmpty

    def m_deletefile(self, args):
        path = safe_str(args[0])
        self.session.vfs_delete(path)
        self.ioc.emit("filesystem_delete", api="FileSystemObject.DeleteFile", path=path)
        return VBEmpty

    def m_createfolder(self, args):
        self.ioc.emit("filesystem_create", api="FileSystemObject.CreateFolder", path=safe_str(args[0]))
        return VBEmpty

    def m_fileexists(self, args):
        return self.session.vfs_exists(safe_str(args[0]))

    def m_folderexists(self, args):
        return True

    def m_getfolder(self, args):
        path = safe_str(args[0]) if args else ""
        self.ioc.emit("filesystem_access", api="FileSystemObject.GetFolder",
                       path=path, mode="enumerate")
        return FileSystemFolder(self.session, self.interp, path)

    def m_getspecialfolder(self, args):
        idx = int(to_str(args[0]))
        return {0: "C:\\Windows", 1: "C:\\Windows\\System32",
                2: "C:\\Users\\User\\AppData\\Local\\Temp"}.get(idx, "C:\\")

    def m_gettempname(self, args):
        return "rad" + "".join(random.choices(string.hexdigits.lower(), k=5)) + ".tmp"

    def m_buildpath(self, args):
        a, b = safe_str(args[0]), safe_str(args[1])
        return a.rstrip("\\/") + "\\" + b.lstrip("\\/")

    def m_getfilename(self, args):
        return posixpath.basename(safe_str(args[0]).replace("\\", "/"))

    def m_getextensionname(self, args):
        return _ext(safe_str(args[0])).lstrip(".")

    def m_getparentfoldername(self, args):
        return posixpath.dirname(safe_str(args[0]).replace("\\", "/"))


# --------------------------------------------------------------- WMI ---
class SWbemObjectSet(ComObject):
    """Result collection returned by SWbemServices.ExecQuery.

    No real WMI query is issued, so there are no truthful result objects to
    fabricate. A zero Count and empty iteration match the sandbox state and
    keep environment-check branches deterministic.
    """

    progid = "SWbemObjectSet"

    def __init__(self, session, interp, items=None):
        super().__init__(session, interp)
        self.items = list(items or [])

    def p_count(self):
        return len(self.items)

    def m_items(self, args):
        from vba_emulator.values import VBArray
        arr = VBArray([(0, max(len(self.items) - 1, -1))])
        for index, item in enumerate(self.items):
            arr.set((index,), item)
        return arr


class SWbemResultObject(ComObject):
    progid = "SWbemObject"

    def __init__(self, session, interp, **properties):
        super().__init__(session, interp)
        self.props.update({name.lower(): value for name, value in properties.items()})


class SWbemObjectClass(ComObject):
    progid = "SWbemObject"

    def __init__(self, session, interp, classname):
        super().__init__(session, interp)
        self.classname = classname

    def m_create(self, args):
        cmd = safe_str(args[0]) if args else ""
        self.session.process_log.append(cmd)
        self.ioc.emit("process_create", api=f"WMI.{self.classname}.Create", command=cmd)
        return 0

    def m_spawninstance_(self, args):
        # e.g. objWMIService.Get("Win32_ProcessStartup").SpawnInstance_()
        # then .ShowWindow = 0 before passing it into Win32_Process.Create.
        # A plain ComObject already accepts/stores arbitrary property sets
        # via its default set_prop fallback, so nothing dedicated is
        # needed here beyond something that won't error on `.Foo = x`.
        return ComObject(self.session, self.interp)

    def m_methods_(self, args):
        # `.Methods_("Create").InParameters.SpawnInstance_` -- the
        # reflection-style route to a fresh, settable parameters object,
        # as an alternative to calling .Create(...) directly. A real
        # sample used exactly this chain (with the eventual command
        # spliced together from custom document properties) to reach
        # Win32_Process.Create while dodging the simpler, more heavily
        # signatured `.Create(cmd)` call shape.
        return self

    def p_inparameters(self):
        return self


class SWbemServices(ComObject):
    progid = "SWbemServices"

    def m_get(self, args):
        return SWbemObjectClass(self.session, self.interp, safe_str(args[0]) if args else "")

    def m_execquery(self, args):
        query = safe_str(args[0]) if args else ""
        self.ioc.emit("wmi_query", api="SWbemServices.ExecQuery", query=query)
        # A normal interactive Windows host has explorer.exe. Several real
        # samples use that fact as a gate before constructing WshExec; an
        # always-empty WMI model leaves the variable unset and crashes at
        # `.Status`. Keep every other process query empty so AV/tool checks
        # do not become false positives.
        if (re.search(r"\bfrom\s+win32_process\b", query, re.IGNORECASE)
                and re.search(r"\bname\s*=\s*['\"]explorer\.exe['\"]", query,
                              re.IGNORECASE)):
            item = SWbemResultObject(
                self.session, self.interp,
                Name="explorer.exe",
                Path_="Win32_Process.Handle=4242",
                ProcessId=4242,
            )
            return SWbemObjectSet(self.session, self.interp, [item])
        return SWbemObjectSet(self.session, self.interp)

    def m_execmethod(self, args):
        # objWMIService.ExecMethod(className, methodName, inParams) -- the
        # generic reflection-style method-invocation counterpart to
        # objProcess.Methods_(...).InParameters.SpawnInstance_ above; a
        # settable params object built that way carries whatever
        # properties (e.g. CommandLine for Win32_Process.Create) the
        # script assigned onto it before this call.
        classname = safe_str(args[0]) if len(args) > 0 else ""
        method_name = safe_str(args[1]) if len(args) > 1 else ""
        params_obj = args[2] if len(args) > 2 else None
        cmd = safe_str(params_obj.props.get("commandline", "")) if hasattr(params_obj, "props") else ""
        self.session.process_log.append(cmd)
        self.ioc.emit("process_create", api=f"WMI.{classname}.{method_name}", command=cmd)
        return 0


class SWbemLocator(ComObject):
    progid = "WbemScripting.SWbemLocator"

    def m_connectserver(self, args):
        return SWbemServices(self.session, self.interp)


# ---------------------------------------------------- Task Scheduler ---
class TaskRegistrationInfo(ComObject):
    progid = "TaskScheduler.RegistrationInfo"


class TaskSettings(ComObject):
    progid = "TaskScheduler.Settings"


class TaskTrigger(ComObject):
    progid = "TaskScheduler.Trigger"

    def __init__(self, session, interp, trigger_type=0):
        super().__init__(session, interp)
        self.trigger_type = trigger_type


class TaskAction(ComObject):
    progid = "TaskScheduler.Action"

    def __init__(self, session, interp, action_type=0):
        super().__init__(session, interp)
        self.action_type = action_type


class TaskObjectCollection(ComObject):
    def __init__(self, session, interp, item_factory, progid):
        super().__init__(session, interp)
        self.item_factory = item_factory
        self.progid = progid
        self.items = []

    def m_create(self, args):
        item_type = int(args[0]) if args else 0
        item = self.item_factory(self.session, self.interp, item_type)
        self.items.append(item)
        return item

    def p_count(self):
        return len(self.items)


class TaskDefinition(ComObject):
    progid = "TaskScheduler.TaskDefinition"

    def __init__(self, session, interp):
        super().__init__(session, interp)
        self.registration_info = TaskRegistrationInfo(session, interp)
        self.settings = TaskSettings(session, interp)
        self.triggers = TaskObjectCollection(
            session, interp, TaskTrigger, "TaskScheduler.TriggerCollection")
        self.actions = TaskObjectCollection(
            session, interp, TaskAction, "TaskScheduler.ActionCollection")

    def p_registrationinfo(self):
        return self.registration_info

    def p_settings(self):
        return self.settings

    def p_triggers(self):
        return self.triggers

    def p_actions(self):
        return self.actions


class TaskFolder(ComObject):
    progid = "TaskScheduler.TaskFolder"

    def __init__(self, session, interp, folder="\\"):
        super().__init__(session, interp)
        self.folder = folder or "\\"

    def m_registertaskdefinition(self, args):
        name = safe_str(args[0]) if args else ""
        definition = args[1] if len(args) > 1 else None
        action_path = ""
        action_arguments = ""
        trigger_type = ""
        start_boundary = ""
        author = ""
        hidden = False
        if isinstance(definition, TaskDefinition):
            author = safe_str(definition.registration_info.props.get("author", ""))
            hidden = bool(definition.settings.props.get("hidden", False))
            if definition.actions.items:
                action = definition.actions.items[0]
                action_path = safe_str(action.props.get("path", ""))
                action_arguments = safe_str(action.props.get("arguments", ""))
            if definition.triggers.items:
                trigger = definition.triggers.items[0]
                trigger_type = trigger.trigger_type
                start_boundary = safe_str(trigger.props.get("startboundary", ""))
        task_path = self.folder.rstrip("\\") + "\\" + name
        self.ioc.emit(
            "scheduled_task_create",
            api="TaskScheduler.RegisterTaskDefinition",
            name=name,
            task_path=task_path,
            action=action_path,
            arguments=action_arguments,
            trigger_type=trigger_type,
            start_boundary=start_boundary,
            author=author,
            hidden=hidden,
            persistence=True,
        )
        return ComObject(self.session, self.interp)


class TaskService(ComObject):
    progid = "Schedule.Service"

    def m_connect(self, args):
        return VBEmpty

    def m_newtask(self, args):
        return TaskDefinition(self.session, self.interp)

    def m_getfolder(self, args):
        return TaskFolder(self.session, self.interp,
                          safe_str(args[0]) if args else "\\")


# ----------------------------------------------------------- Dictionary ---
class Dictionary(ComObject):
    progid = "Scripting.Dictionary"

    def __init__(self, session, interp):
        super().__init__(session, interp)
        self._data = {}

    def _key(self, v):
        return safe_str(v)

    def default_index(self, args):
        key = self._key(args[0])
        if key not in self._data:
            self._data[key] = VBEmpty
        return self._data[key]

    def m_add(self, args):
        self._data[self._key(args[0])] = args[1]
        return VBEmpty

    def m_item(self, args):
        return self.default_index(args)

    def m_exists(self, args):
        return self._key(args[0]) in self._data

    def m_remove(self, args):
        self._data.pop(self._key(args[0]), None)
        return VBEmpty

    def m_removeall(self, args):
        self._data.clear()
        return VBEmpty

    def m_keys(self, args):
        from vba_emulator.values import VBArray
        arr = VBArray(bounds=[(0, max(len(self._data) - 1, -1))])
        for i, k in enumerate(self._data.keys()):
            arr.set((i,), k)
        return arr

    def m_items(self, args):
        from vba_emulator.values import VBArray
        arr = VBArray(bounds=[(0, max(len(self._data) - 1, -1))])
        for i, v in enumerate(self._data.values()):
            arr.set((i,), v)
        return arr

    def p_count(self):
        return len(self._data)

    def set_index(self, args, value):
        self._data[self._key(args[0])] = value


# -------------------------------------------------------------- network ---
class HttpRequest(ComObject):
    """No real network I/O is ever performed -- not even a HEAD request.
    The request is recorded as an IOC and a synthetic empty-but-successful
    response is returned so scripts that branch on `status = 200` keep
    exploring their download/execute code path."""
    progid = "MSXML2.XMLHTTP"

    def __init__(self, session, interp):
        super().__init__(session, interp)
        self._method = ""
        self._url = ""

    def m_open(self, args):
        self._method = safe_str(args[0]) if args else "GET"
        self._url = safe_str(args[1]) if len(args) > 1 else ""
        self.ioc.emit("network_request", api=f"{self.progid}.Open", method=self._method, url=self._url)
        return VBEmpty

    def m_setrequestheader(self, args):
        if len(args) >= 2:
            self.ioc.emit("network_header", api=f"{self.progid}.setRequestHeader",
                           name=safe_str(args[0]), value=safe_str(args[1]))
        return VBEmpty

    def m_send(self, args):
        body = safe_str(args[0]) if args else ""
        self.ioc.emit("network_send", api=f"{self.progid}.Send", url=self._url,
                       method=self._method, body_preview=body[:200])
        return VBEmpty

    def p_status(self):
        return 200

    def p_readystate(self):
        return 4

    def p_responsetext(self):
        return ""

    def p_responsebody(self):
        return b""


class WinHttpRequest(HttpRequest):
    progid = "WinHttp.WinHttpRequest"


class AdodbStream(ComObject):
    progid = "ADODB.Stream"

    def __init__(self, session, interp):
        super().__init__(session, interp)
        self._buf = bytearray()
        self._text = ""
        self.props["type"] = 2

    def m_open(self, args):
        return VBEmpty

    def m_write(self, args):
        data = args[0] if args else b""
        if isinstance(data, (bytes, bytearray)):
            self._buf.extend(data)
        else:
            self._buf.extend(safe_str(data).encode("utf-8", "replace"))
        self.ioc.emit("stream_write", api="ADODB.Stream.Write", size=len(self._buf))
        return VBEmpty

    def m_writetext(self, args):
        text = safe_str(args[0]) if args else ""
        self._text += text
        self.ioc.emit("stream_write", api="ADODB.Stream.WriteText", size=len(text), preview=text[:200])
        return VBEmpty

    def m_savetofile(self, args):
        path = safe_str(args[0]) if args else ""
        is_binary = self.props.get("type") == 1
        content = bytes(self._buf) if is_binary else self._text
        magic = executable_magic(content)
        self.session.vfs_write(path, content, is_binary=is_binary)
        self.ioc.emit("filesystem_write", api="ADODB.Stream.SaveToFile", path=path,
                       size=len(content), is_binary=is_binary,
                       suspicious_ext=_ext(path) in _SUSPICIOUS_EXT,
                       executable_content=bool(magic), magic=magic)
        return VBEmpty

    def m_loadfromfile(self, args):
        path = safe_str(args[0]) if args else ""
        content = self.session.vfs_read(path)
        if isinstance(content, (bytes, bytearray)):
            self._buf = bytearray(content)
        elif isinstance(content, str):
            self._text = content
        self.ioc.emit("filesystem_access", api="ADODB.Stream.LoadFromFile", path=path)
        return VBEmpty

    def m_readtext(self, args):
        return self._text

    def m_read(self, args):
        return bytes(self._buf)

    def m_close(self, args):
        return VBEmpty

    def p_size(self):
        return len(self._buf) if self.props.get("type") == 1 else len(self._text)


# ------------------------------------------------------------- XML DOM ---
class DomElement(ComObject):
    """Just the createElement/dataType/text/nodeTypedValue idiom used
    pervasively by VBA/VBS malware as a built-in base64 (and hex) codec:

        Set objNode = objXML.createElement("b64")
        objNode.dataType = "bin.base64"
        objNode.text = "<base64 string>"
        data = objNode.nodeTypedValue   ' decoded bytes

    Full XML parsing/XPath is out of scope."""
    progid = "MSXML2.DOMDocument.Element"

    def __init__(self, session, interp):
        super().__init__(session, interp)
        self._datatype = "string"
        self._text = ""

    def p_datatype(self):
        return self._datatype

    def s_datatype(self, value):
        self._datatype = safe_str(value).lower()

    def p_text(self):
        return self._text

    def s_text(self, value):
        self._text = safe_str(value)

    def p_nodetypedvalue(self):
        if self._datatype == "bin.base64":
            try:
                decoded = base64.b64decode(self._text, validate=False)
                self.ioc.emit("decode_base64", api="MSXML2.DOMDocument.nodeTypedValue", length=len(decoded))
                return decoded
            except (binascii.Error, ValueError):
                return b""
        if self._datatype == "bin.hex":
            try:
                decoded = bytes.fromhex("".join(self._text.split()))
                self.ioc.emit("decode_hex", api="MSXML2.DOMDocument.nodeTypedValue", length=len(decoded))
                return decoded
            except ValueError:
                return b""
        return self._text

    def s_nodetypedvalue(self, value):
        data = value if isinstance(value, (bytes, bytearray)) else safe_str(value).encode("utf-8", "replace")
        if self._datatype == "bin.base64":
            self._text = base64.b64encode(bytes(data)).decode("ascii")
        elif self._datatype == "bin.hex":
            self._text = bytes(data).hex()
        else:
            self._text = safe_str(value)


class DomDocument(ComObject):
    progid = "MSXML2.DOMDocument"

    def m_createelement(self, args):
        return DomElement(self.session, self.interp)


# ------------------------------------------------------------- shell ---
_PERSISTENCE_KEYS = re.compile(
    r"\\(run|runonce|winlogon\\shell|winlogon\\userinit|winlogon\\notify|startup|"
    r"userinitmprlogonscript|image file execution options|appinit_dlls|"
    r"shellserviceobjectdelayload|shell\\open\\command|policies\\explorer\\run)\\?",
    re.IGNORECASE,
)


class WshEnvironment(ComObject):
    """Real WSH lets scripts both read AND write through this object
    (``WshShell.Environment("Process")("X") = "y"``), and malware has been
    observed abusing it as an ad-hoc key/value scratch store for
    obfuscated data (many distinct short random-looking keys, not real
    env var names). Deliberately NOT a per-instance dict: every
    `Environment("Process")` call returns a fresh Python object, but real
    WSH semantics expect every such handle to refer to the same
    underlying store -- reading/writing straight through to
    session.env_vars keeps writes from one call visible to reads from
    another."""
    progid = "WshEnvironment"

    def default_index(self, args):
        name = safe_str(args[0]) if args else ""
        return self.session.env_vars.get(name.upper(), self.session.env_vars.get(name, ""))

    def set_index(self, args, value):
        name = safe_str(args[0]) if args else ""
        self.session.env_vars[name] = safe_str(value)
        self.ioc.emit("environment_write", api="WshEnvironment", name=name, value=safe_str(value))

    def m_item(self, args):
        return self.default_index(args)


class WScriptNetwork(ComObject):
    """Read-only host identity exposed by the WSH Network automation object.

    Malware frequently reads ``ComputerName`` for crude sandbox/analyst-host
    checks before it reaches the payload.  Return values from the session's
    fixed fake environment; never expose the analysis machine's real name or
    user identity.
    """

    progid = "WScript.Network"

    def p_computername(self):
        return self.session.env_vars.get("COMPUTERNAME", "DESKTOP-SANDBOX")

    def p_username(self):
        return self.session.env_vars.get("USERNAME", "User")

    def p_userdomain(self):
        return "WORKGROUP"


class WScriptShell(ComObject):
    progid = "WScript.Shell"

    def m_run(self, args):
        cmd = safe_str(args[0]) if args else ""
        window_style = int(to_str(args[1])) if len(args) > 1 else 1
        wait = to_bool(args[2]) if len(args) > 2 else False
        self.session.process_log.append(cmd)
        self.ioc.emit("process_create", api="WScript.Shell.Run", command=cmd,
                       window_style=window_style, wait=wait)
        return 0

    def m_exec(self, args):
        cmd = safe_str(args[0]) if args else ""
        self.session.process_log.append(cmd)
        self.ioc.emit("process_create", api="WScript.Shell.Exec", command=cmd)
        return WshExec(self.session, self.interp, command=cmd)

    def m_regread(self, args):
        key = safe_str(args[0])
        self.ioc.emit("registry_read", api="WScript.Shell.RegRead", key=key)
        return self.session.registry.get(key.lower(), "")

    def m_regwrite(self, args):
        key = safe_str(args[0])
        value = safe_str(args[1]) if len(args) > 1 else ""
        self.session.registry[key.lower()] = value
        is_persist = bool(_PERSISTENCE_KEYS.search(key))
        self.ioc.emit("registry_write", api="WScript.Shell.RegWrite", key=key, value=value,
                       persistence=is_persist)
        return VBEmpty

    def m_regdelete(self, args):
        key = safe_str(args[0])
        self.session.registry.pop(key.lower(), None)
        self.ioc.emit("registry_delete", api="WScript.Shell.RegDelete", key=key)
        return VBEmpty

    def m_expandenvironmentstrings(self, args):
        s = safe_str(args[0])
        for name, val in self.session.env_vars.items():
            s = s.replace(f"%{name}%", val)
        return s

    def m_specialfolders(self, args):
        name = (safe_str(args[0]) if args else "").strip().lower()
        mapping = {
            "startup": "C:\\Users\\User\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup",
            "temp": "C:\\Users\\User\\AppData\\Local\\Temp",
            "appdata": "C:\\Users\\User\\AppData\\Roaming",
            "recent": "C:\\Users\\User\\AppData\\Roaming\\Microsoft\\Windows\\Recent",
            "desktop": "C:\\Users\\User\\Desktop",
            "mydocuments": "C:\\Users\\User\\Documents",
            "programs": "C:\\Users\\User\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs",
            "allusersstartup": "C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Startup",
        }
        return mapping.get(name, "C:\\")

    def m_popup(self, args):
        text = safe_str(args[0]) if args else ""
        self.ioc.emit("ui_prompt", api="WScript.Shell.Popup", text=text)
        return 1

    def m_environment(self, args):
        return WshEnvironment(self.session, self.interp)

    def m_createshortcut(self, args):
        path = safe_str(args[0]) if args else ""
        self.ioc.emit("filesystem_create", api="WScript.Shell.CreateShortcut", path=path, suspicious_ext=True)
        return ShortcutObj(self.session, self.interp, path)


class WshExec(ComObject):
    progid = "WshExec"

    def __init__(self, session, interp, command=""):
        super().__init__(session, interp)
        self.command = command
        if re.match(r"^\s*ping(?:\.exe)?\b", command, re.IGNORECASE):
            target = command.split(None, 1)[1] if len(command.split(None, 1)) > 1 else "host"
            self._stdout_text = (
                f"Ping request could not find host {target}. "
                "Please check the name and try again."
            )
        else:
            self._stdout_text = ""

    def p_stdout(self):
        return WshStream(self.session, self.interp, self._stdout_text)

    def p_stdin(self):
        return WshStream(self.session, self.interp)

    def p_stderr(self):
        return WshStream(self.session, self.interp)

    def p_status(self):
        return 1

    def p_exitcode(self):
        return 0

    def m_terminate(self, args):
        return VBEmpty


class WshStream(ComObject):
    progid = "WshStream"

    def __init__(self, session, interp, content=""):
        super().__init__(session, interp)
        self.content = content

    def m_readall(self, args):
        return self.content

    def p_atendofstream(self):
        return True


class ShortcutObj(ComObject):
    progid = "WshShortcut"

    def __init__(self, session, interp, path):
        super().__init__(session, interp)
        self.path = path

    def m_save(self, args):
        self.session.vfs_write(self.path, "[shortcut]")
        # self.props is populated by the generic ComObject.set_prop
        # fallback, which stores whatever raw VBA value a script assigns
        # (e.g. `link.TargetPath = Array(1,2,3)` is legal, if unusual,
        # VBScript) -- safe_str() it here rather than emitting it as-is,
        # or a VBArray/ComObject/Empty sentinel ends up as an IOC event
        # field and crashes json.dump() the moment --report is used.
        target = safe_str(self.props.get("targetpath", ""))
        self.ioc.emit("filesystem_write", api="WshShortcut.Save", path=self.path,
                       target=target, persistence="startup" in self.path.lower())
        return VBEmpty


class ShellFolderItems(ComObject):
    """Result of ShellNamespace.Items() -- the classic no-external-tool ZIP
    extraction idiom (``Namespace(zip).Items()`` then ``.CopyHere`` into a
    destination Namespace). We never actually downloaded/decoded real
    archive bytes, so there is nothing real to list -- Count 0 rather than
    fabricating file names that don't exist, same reasoning as Dir() on a
    wildcard query."""
    progid = "Shell.Application.FolderItems"

    def __init__(self, session, interp, source_path):
        super().__init__(session, interp)
        self.source_path = source_path

    def p_count(self):
        return 0


class ShellFolderItem(ComObject):
    """Result of ShellNamespace.Self -- the FolderItem for the special
    folder a Namespace(cidl) was constructed from. `.Path`/`.Name` are the
    common real-sample idiom (`Namespace(28).Self.Path`, resolving e.g.
    %LocalAppData% without the more heuristic-flagged Environ() call)."""
    progid = "Shell.Application.FolderItem"

    def __init__(self, session, interp, path):
        super().__init__(session, interp)
        self._path = path

    def p_path(self):
        return self._path

    def p_name(self):
        return self._path.rstrip("\\/").rsplit("\\", 1)[-1]


# Common CSIDL/ssf* special-folder constants malware resolves this way,
# mapped onto this emulator's fake environment (session.env_vars).
_CSIDL_PATHS = {
    0: lambda env: env.get("USERPROFILE", "C:\\Users\\User") + "\\Desktop",
    5: lambda env: env.get("USERPROFILE", "C:\\Users\\User") + "\\Documents",
    7: lambda env: env.get("APPDATA", "C:\\Users\\User\\AppData\\Roaming") +
        "\\Microsoft\\Windows\\Start Menu\\Programs\\Startup",
    26: lambda env: env.get("APPDATA", "C:\\Users\\User\\AppData\\Roaming"),
    28: lambda env: env.get("USERPROFILE", "C:\\Users\\User") + "\\AppData\\Local",
    36: lambda env: env.get("WINDIR", "C:\\Windows"),
    37: lambda env: env.get("WINDIR", "C:\\Windows") + "\\System32",
    38: lambda env: "C:\\Program Files",
    40: lambda env: env.get("USERPROFILE", "C:\\Users\\User"),
}


class ShellNamespace(ComObject):
    progid = "Shell.Application.Namespace"

    def __init__(self, session, interp, path):
        super().__init__(session, interp)
        self.path = path

    def m_items(self, args):
        return ShellFolderItems(self.session, self.interp, self.path)

    def m_copyhere(self, args):
        # args[0] is normally the source FolderItems from another
        # Namespace(); we don't have real archive contents to extract
        # (ShellFolderItems.Count is always 0), but the *destination*
        # path this Namespace was constructed with is still real,
        # observable behavior worth recording.
        self.ioc.emit("filesystem_extract", api="Shell.Application.Namespace.CopyHere",
                       destination=self.path)
        return VBEmpty

    def m_copyfile(self, args):
        return self.m_copyhere(args)

    def p_self(self):
        return ShellFolderItem(self.session, self.interp, self.path)


class ShellApplication(ComObject):
    progid = "Shell.Application"

    def m_shellexecute(self, args):
        target = safe_str(args[0]) if args else ""
        params = safe_str(args[1]) if len(args) > 1 else ""
        self.session.process_log.append(f"{target} {params}".strip())
        self.ioc.emit("process_create", api="Shell.Application.ShellExecute",
                       command=target, params=params)
        return VBEmpty

    def m_open(self, args):
        # Shell.Application.Open(path) -- equivalent to double-clicking
        # the path in Explorer; for a script/executable this runs it via
        # its registered default handler (e.g. a dropped .vbs launches
        # through wscript.exe). A real sample used this specifically as
        # the launch step right after writing its payload out.
        target = safe_str(args[0]) if args else ""
        self.session.process_log.append(target)
        self.ioc.emit("process_create", api="Shell.Application.Open", command=target)
        return VBEmpty

    def m_namespace(self, args):
        # The classic no-external-tool ZIP extraction idiom:
        #   Set objZip = objShell.Namespace(zipPath)
        #   Set objDest = objShell.Namespace(destFolder)
        #   objDest.CopyHere objZip.Items
        # Found missing via a real sample that downloaded a .zip and used
        # exactly this to extract it. Namespace() also accepts a numeric
        # CSIDL/ssf* special-folder constant instead of a path string
        # (e.g. `Namespace(28).Self.Path` to resolve %LocalAppData%,
        # avoiding the more heuristic-flagged Environ() call directly) --
        # resolved against this emulator's own fake environment.
        raw = args[0] if args else ""
        if isinstance(raw, (int, float)) and not isinstance(raw, bool):
            resolver = _CSIDL_PATHS.get(int(raw))
            path = resolver(self.session.env_vars) if resolver else f"<CSIDL {int(raw)}>"
        else:
            path = safe_str(raw)
        self.ioc.emit("com_namespace", api="Shell.Application.Namespace", path=path)
        return ShellNamespace(self.session, self.interp, path)


class WScriptGlobal(ComObject):
    """The ambient WScript object available without CreateObject in VBS."""
    progid = "WScript"

    def m_echo(self, args):
        text = " ".join(safe_str(a) for a in args)
        self.session.output_log.append(text)
        self.ioc.emit("script_output", api="WScript.Echo", text=text)
        return VBEmpty

    def m_sleep(self, args):
        return VBEmpty

    def m_quit(self, args):
        from vba_emulator.runtime_support import ScriptQuit
        raise ScriptQuit(int(to_str(args[0])) if args else 0)

    def m_createobject(self, args):
        return self.interp.create_com_object(safe_str(args[0]))

    def p_scriptfullname(self):
        return getattr(
            self.session,
            "script_fullname",
            "C:\\Users\\User\\AppData\\Local\\Temp\\sample.vbs",
        )

    def p_scriptname(self):
        return getattr(self.session, "script_name", "sample.vbs")

    def p_name(self):
        return "Windows Script Host"

    def p_version(self):
        return "5.812"


# ------------------------------------------------------------ registry ---
_FACTORIES = {
    "wscript.shell": WScriptShell,
    "wshshell": WScriptShell,
    "wscript.network": WScriptNetwork,
    "shell.application": ShellApplication,
    "shell32.shell": ShellApplication,
    "scripting.filesystemobject": FileSystemObject,
    "scripting.dictionary": Dictionary,
    "adodb.stream": AdodbStream,
    "msxml2.xmlhttp": HttpRequest,
    "msxml2.xmlhttp.6.0": HttpRequest,
    "msxml2.xmlhttp.3.0": HttpRequest,
    "msxml2.serverxmlhttp": HttpRequest,
    "microsoft.xmlhttp": HttpRequest,
    "winhttp.winhttprequest.5.1": WinHttpRequest,
    "wbemscripting.swbemlocator": SWbemLocator,
    "schedule.service": TaskService,
    "msxml2.domdocument": DomDocument,
    "msxml2.domdocument.6.0": DomDocument,
    "msxml2.domdocument.4.0": DomDocument,
    "msxml2.domdocument.3.0": DomDocument,
    "microsoft.xmldom": DomDocument,
}


def create_com_object(session, interp, progid):
    key = progid.strip().lower()
    factory = _FACTORIES.get(key)
    is_wmi_moniker = key.startswith("winmgmts:")
    session.ioc.emit("com_create", api="CreateObject", progid=progid,
                     known=factory is not None or is_wmi_moniker)
    if is_wmi_moniker:
        # Some real-world macros pass the WMI moniker to CreateObject rather
        # than GetObject. Windows' automation binding accepts this shape in
        # the samples we need to analyze; model it identically so a direct
        # `.Create(command)` on Win32_Process is not lost.
        rest = progid.strip()[len("winmgmts:"):]
        if ":" in rest:
            classname = rest.rsplit(":", 1)[-1]
        elif rest and "/" not in rest and "\\" not in rest:
            classname = rest
        else:
            classname = ""
        classname = classname.strip("{}!")
        if re.match(r"^[A-Za-z_]\w*$", classname):
            return SWbemObjectClass(session, interp, classname)
        return SWbemServices(session, interp)
    if factory is None:
        class UnknownComObject(ComObject):
            pass
        UnknownComObject.progid = progid
        return UnknownComObject(session, interp)
    obj = factory(session, interp)
    obj.progid = progid
    return obj
