"""Heuristic risk scoring over the raw IOC event stream produced by the
emulator. Each rule looks for a behavioral *pattern* (not a single event
in isolation), since that's what actually distinguishes malicious macros/
scripts from benign automation doing superficially similar things."""

import re

_LOLBIN_RE = re.compile(
    r"\b(powershell(\.exe)?|cmd(\.exe)?|wscript(\.exe)?|cscript(\.exe)?|mshta(\.exe)?|"
    r"regsvr32(\.exe)?|rundll32(\.exe)?|certutil(\.exe)?|bitsadmin(\.exe)?|"
    r"installutil(\.exe)?|msiexec(\.exe)?|schtasks(\.exe)?|forfiles(\.exe)?|"
    r"regasm(\.exe)?|regsvcs(\.exe)?|msbuild(\.exe)?|wmic(\.exe)?|"
    r"explorer(\.exe)?|verclsid(\.exe)?|odbcconf(\.exe)?)\b",
    re.IGNORECASE,
)
_ENCODED_FLAG_RE = re.compile(r"-enc(odedcommand)?\b|-e\s+[A-Za-z0-9+/=]{20,}", re.IGNORECASE)
_LONG_B64_RE = re.compile(r"[A-Za-z0-9+/]{80,}={0,2}")
_SCRIPT_EXTS = (".vbs", ".vbe", ".js", ".jse", ".hta", ".wsf")

_SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


class Finding:
    def __init__(self, rule_id, title, severity, weight, evidence=None):
        self.rule_id = rule_id
        self.title = title
        self.severity = severity
        self.weight = weight
        self.evidence = evidence or []

    def to_dict(self):
        return {"rule_id": self.rule_id, "title": self.title, "severity": self.severity,
                "weight": self.weight, "evidence": self.evidence}


def _by_category(events, *categories):
    cats = set(categories)
    return [e for e in events if e.get("category") in cats]


def _rule_downloader(events):
    net = _by_category(events, "network_request", "network_send")
    process_commands = [str(e.get("command", "")).lower()
                        for e in _by_category(events, "process_create")]
    writes = []
    for event in _by_category(events, "filesystem_write", "filesystem_copy", "filesystem_move"):
        path = str(event.get("path") or event.get("dst") or "")
        # URLDownloadToFile is often given an extensionless or trailing-dot
        # destination specifically to defeat extension heuristics. If that
        # exact downloaded path is subsequently placed on a process command
        # line, the download+execute relationship is explicit regardless of
        # its suffix or unavailable synthetic response bytes.
        downloaded_then_executed = bool(
            event.get("downloaded") and path and
            any(path.lower() in command for command in process_commands))
        if event.get("suspicious_ext") or event.get("executable_content") or downloaded_then_executed:
            writes.append(event)
    if net and writes:
        return Finding("downloader_pattern",
                        "Downloads remote content and writes executable content, an executable-looking file, "
                        "or a downloaded path that is subsequently executed",
                        "critical", 40, evidence=net[:5] + writes[:5])
    return None


def _rule_registry_persistence(events):
    hits = [e for e in _by_category(events, "registry_write") if e.get("persistence")]
    if hits:
        return Finding("registry_persistence",
                        "Writes to a registry Run/RunOnce/Winlogon/Startup/logon-script key (persistence)",
                        "high", 25, evidence=hits[:5])
    return None


def _rule_startup_shortcut(events):
    hits = [e for e in events if e.get("category") == "filesystem_write"
            and e.get("api") == "WshShortcut.Save" and e.get("persistence")]
    if hits:
        return Finding("startup_shortcut_persistence",
                        "Drops a shortcut (.lnk) into the Startup folder (persistence)",
                        "high", 20, evidence=hits[:5])
    return None


def _rule_scheduled_task(events):
    hits = _by_category(events, "scheduled_task_create")
    if hits:
        return Finding(
            "scheduled_task_persistence",
            "Registers a Windows scheduled task that launches a configured action (persistence)",
            "high", 25, evidence=hits[:5])
    return None


def _rule_lolbin(events):
    hits = [e for e in _by_category(events, "process_create") if _LOLBIN_RE.search(e.get("command", ""))]
    if hits:
        return Finding("lolbin_invocation",
                        "Spawns a living-off-the-land binary commonly abused for execution/evasion "
                        "(powershell, mshta, regsvr32, rundll32, certutil, bitsadmin, forfiles, ...)",
                        "high", 20, evidence=hits[:5])
    return None


_INJECTION_ALLOC_APIS = {"virtualalloc", "virtualallocex"}
_INJECTION_WRITE_APIS = {"writeprocessmemory"}
_INJECTION_EXEC_APIS = {"createremotethread", "createremotethreadex", "createthread"}


def _rule_process_injection(events):
    hits = _by_category(events, "process_injection")
    if not hits:
        return None
    apis = {h.get("api", "").split("/")[0].lower() for h in hits}
    has_alloc = bool(apis & _INJECTION_ALLOC_APIS)
    has_write = bool(apis & _INJECTION_WRITE_APIS)
    has_exec = bool(apis & _INJECTION_EXEC_APIS)
    if has_alloc and has_write and has_exec:
        return Finding("process_injection",
                        "Classic shellcode-injection chain via direct Win32 API calls "
                        "(Declare'd VirtualAlloc[Ex] + WriteProcessMemory + CreateRemoteThread/"
                        "CreateThread) -- allocates memory in a process, writes a payload into it, "
                        "and starts a thread there, bypassing every file-based drop-and-execute "
                        "detection in this tool",
                        "critical", 45, evidence=hits[:6])
    # Any single Win32 injection-family primitive on its own is still a
    # strong signal (legitimate macros essentially never Declare these),
    # just not the full confirmed chain.
    return Finding("win32_api_injection_primitive",
                    "Directly calls a Win32 API commonly used for process injection/memory "
                    "manipulation via VBA's Declare statement, without the full "
                    "alloc+write+execute chain being observed",
                    "medium", 15, evidence=hits[:5])


def _rule_wmi_process(events):
    hits = [e for e in _by_category(events, "process_create") if "wmi." in e.get("api", "").lower()]
    if hits:
        return Finding("wmi_process_creation",
                        "Creates a process via WMI (Win32_Process.Create) instead of WScript.Shell.Run, "
                        "a common technique to dodge shell-execution monitoring",
                        "high", 15, evidence=hits[:5])
    return None


def _rule_encoded_command(events):
    hits = [e for e in _by_category(events, "process_create")
            if _ENCODED_FLAG_RE.search(e.get("command", "")) or _LONG_B64_RE.search(e.get("command", ""))]
    if hits:
        return Finding("encoded_command_line",
                        "Process command line contains an encoded/base64-like payload "
                        "(e.g. powershell -EncodedCommand)",
                        "high", 20, evidence=hits[:5])
    return None


def _rule_self_replication(events):
    hits = [e for e in _by_category(events, "filesystem_copy", "filesystem_move")
            if e.get("src", "").lower().endswith(_SCRIPT_EXTS)
            and e.get("dst", "").lower().endswith(_SCRIPT_EXTS)]
    if hits:
        return Finding("self_replication",
                        "Copies itself (or another script) to a new location under a different name -- "
                        "common for staging persistence that survives the original dropper being deleted",
                        "high", 20, evidence=hits[:5])
    return None


def _rule_drop_and_execute(events):
    # Independent of _rule_downloader (requires a direct network_request/
    # network_send too): a real sample wrote several .vbs/.bat/.cmd files
    # via FileSystemObject then launched one with Shell(), with zero
    # direct network calls from the VBA layer -- the actual C2/exfil
    # happened inside the spawned batch script (schtasks persistence,
    # webhook.site exfil via a data: URI), which this emulator only sees
    # as opaque written text, not something it interprets.
    drops = [e for e in _by_category(events, "filesystem_write", "filesystem_create",
                                      "filesystem_copy", "filesystem_move")
             if e.get("suspicious_ext") or e.get("executable_content")]
    # Shell.Application.Namespace(...).CopyHere(...) -- the classic
    # no-external-tool ZIP-extraction dropper idiom (see com_objects.py) --
    # extracts content this emulator never actually unpacks, so it has no
    # extracted filename to check for a suspicious extension. Still counts
    # as a drop on its own: the technique itself is the signal, independent
    # of what's inside the archive.
    extracts = _by_category(events, "filesystem_extract")
    procs = _by_category(events, "process_create")
    if (drops or extracts) and procs:
        return Finding("drop_and_execute",
                        "Writes executable content or executable/script files to disk and also spawns a process "
                        "-- a local dropper pattern, even without an observed direct network fetch "
                        "(the real payload delivery may happen inside a spawned script this emulator "
                        "only wrote as opaque text rather than interpreted, e.g. batch/PowerShell)",
                        "high", 25, evidence=(drops[:3] or extracts[:3]) + procs[:3])
    return None


_STARTUP_PATH_RE = re.compile(
    r"\\(start menu\\programs\\startup|startup)\\", re.IGNORECASE)


def _rule_startup_folder_drop(events):
    # Windows auto-runs anything placed in the Startup folder on next
    # login -- no registry write, scheduled task, or explicit "run" call
    # needed, and no API-specific signature either (WshShortcut.Save is
    # already its own rule above; this catches the same destination
    # reached through *any* write API -- legacy Open/Put/Close, plain
    # FileSystemObject, ADODB.Stream, ...). Found missing via a real
    # sample that dropped a .exe straight into Startup via Open/Put/Close
    # and scored "none" despite that.
    hits = [e for e in events
            if e.get("category") in ("filesystem_write", "filesystem_create",
                                      "filesystem_copy", "filesystem_move")
            and _STARTUP_PATH_RE.search(e.get("path", "") or e.get("dst", "") or "")]
    if hits:
        return Finding("startup_folder_drop",
                        "Writes a file directly into the Startup folder -- runs automatically "
                        "on next login, a persistence mechanism that needs no registry/task/"
                        "shortcut API at all",
                        "high", 25, evidence=hits[:5])
    return None


def _rule_dynamic_execute(events):
    hits = _by_category(events, "dynamic_execute")
    if hits:
        return Finding("dynamic_code_execution",
                        "Builds and executes code dynamically at runtime (Execute/Eval) -- "
                        "a common obfuscation/evasion technique",
                        "medium", 10, evidence=hits[:5])
    return None


def _rule_fingerprint_then_network(events):
    env = _by_category(events, "environment_access")
    net = _by_category(events, "network_request", "network_send")
    if env and net:
        return Finding("fingerprint_then_network",
                        "Reads host/environment information and also performs network requests "
                        "(possible fingerprinting/exfiltration)",
                        "medium", 15, evidence=(env[:3] + net[:3]))
    return None


def _rule_unmodeled_com(events):
    progids = sorted({e.get("progid") for e in events
                       if e.get("category") == "com_create" and not e.get("known") and e.get("progid")})
    if progids:
        return Finding("unmodeled_com_objects",
                        f"Uses COM object(s) not modeled by this emulator: {', '.join(progids)} "
                        "(behavior through them is not observed)",
                        "info", 0, evidence=[{"progids": progids}])
    return None


def _rule_execution_budget(events):
    hits = _by_category(events, "emulation_timeout")
    if hits:
        return Finding("execution_budget_exceeded",
                        "Script exceeded the emulation step/time budget (heavy loop -- possibly "
                        "obfuscation unrolling or an anti-analysis stall)",
                        "low", 5, evidence=hits[:3])
    return None


_HEAVY_STEP_THRESHOLD = 1_000_000
_LOW_EVENT_THRESHOLD = 5


def _rule_heavy_computation_no_iocs(events, step_count):
    # A hand-rolled bytecode-VM script was observed running ~13M
    # interpreter steps to completion with *zero* externally observable
    # behavior through any modeled API. That looks identical to "trivial
    # 3-line script" in a report unless called out explicitly -- heavy
    # internal computation producing no visible effect is itself a signal
    # (custom obfuscation/VM layer, or a payload gated behind an
    # environment/fingerprint check this emulator's synthetic session
    # didn't satisfy), not nothing.
    if step_count >= _HEAVY_STEP_THRESHOLD and len(events) < _LOW_EVENT_THRESHOLD:
        return Finding(
            "heavy_computation_no_iocs",
            f"Performed very heavy internal computation ({step_count:,} interpreter steps) "
            "while touching almost no modeled API -- consistent with a custom obfuscation/VM "
            "layer, or a payload gated behind an environment/fingerprint check this emulator's "
            "synthetic environment didn't satisfy. Worth deeper manual/dynamic analysis.",
            "medium", 15, evidence=[{"step_count": step_count, "ioc_event_count": len(events)}])
    return None


_RULES = [
    _rule_downloader, _rule_drop_and_execute, _rule_registry_persistence, _rule_startup_shortcut,
    _rule_scheduled_task, _rule_startup_folder_drop, _rule_lolbin, _rule_wmi_process, _rule_encoded_command,
    _rule_self_replication, _rule_dynamic_execute, _rule_fingerprint_then_network,
    _rule_process_injection, _rule_unmodeled_com, _rule_execution_budget,
]


def score(events, step_count=0):
    """Returns findings: list[Finding], most-severe first.

    Deliberately doesn't blend these into a single aggregate risk score/
    level: a lone weak-signal finding and several strong ones landing in
    the same numeric bucket invites over-reading a blended number as a
    confident verdict. Each Finding already carries its own severity --
    let the analyst weigh them individually instead."""
    findings = []
    for rule in _RULES:
        f = rule(events)
        if f is not None:
            findings.append(f)
    extra = _rule_heavy_computation_no_iocs(events, step_count)
    if extra is not None:
        findings.append(extra)
    findings.sort(key=lambda f: (-_SEVERITY_ORDER[f.severity], -f.weight))
    return findings
