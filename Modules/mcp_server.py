#!/usr/bin/env python3
"""MCP (Model Context Protocol) server for Qu1cksc0pe.

Exposes Qu1cksc0pe's static-analysis capabilities as MCP tools so an LLM
client (Claude Desktop, Claude Code, etc.) can drive file/malware analysis
directly. Every tool shells out to the existing `qu1cksc0pe.py` CLI (the
same entrypoint the Web UI uses) rather than importing analyzer modules
in-process, so this file carries no dependency on Qu1cksc0pe's own module
resolution (`sc0pe_path`) or its heavier optional dependencies (pefile,
androguard, yara-python, ...) at import time -- only the `mcp` package.

Users should not run this file directly -- launch it through the main CLI
entrypoint instead, which keeps stdout clean for the MCP JSON-RPC channel
(no startup banner) and resolves paths the same way every other Qu1cksc0pe
command does:

    python3 qu1cksc0pe.py --mcp

See the "MCP Server" section in README.md for client configuration.
"""

import json
import logging
import os
import shutil
import subprocess
import sys
import threading
import time
import uuid
from pathlib import Path
from typing import Any, Optional

try:
    from mcp.server import MCPServer
except ModuleNotFoundError:
    print(
        "Error: 'mcp' package not found. Run: pip install -r requirements.txt",
        file=sys.stderr,
    )
    sys.exit(1)

BASE_DIR = Path(__file__).resolve().parent.parent
ENTRYPOINT = BASE_DIR / "qu1cksc0pe.py"
MCP_REPORTS_DIR = BASE_DIR / "sc0pe_reports" / "mcp"
PYTHON_BIN = sys.executable or "python3"

# --------------------------------------------------------------------------
# Logging
# --------------------------------------------------------------------------
# stdout is reserved for the MCP JSON-RPC channel once the server is
# running, so logs must never go there. stderr is always safe; a file sink
# under sc0pe_reports/mcp/ is added on top so logs survive even when the
# launching client doesn't surface the child's stderr anywhere visible
# (common with MCP clients that only show tool results).
LOG_FILE = MCP_REPORTS_DIR / "mcp_server.log"
_REDACTED_KEYS = {"api_key"}


def _setup_logging() -> logging.Logger:
    level_name = os.environ.get("SC0PE_MCP_LOG_LEVEL", "INFO").strip().upper()
    level = getattr(logging, level_name, logging.INFO)

    logger = logging.getLogger("qu1cksc0pe.mcp")
    logger.setLevel(level)
    logger.propagate = False
    if logger.handlers:  # re-entrant import guard
        return logger

    fmt = logging.Formatter(
        fmt="%(asctime)s %(levelname)-7s %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    stream_handler = logging.StreamHandler(sys.stderr)
    stream_handler.setFormatter(fmt)
    logger.addHandler(stream_handler)

    if os.environ.get("SC0PE_MCP_LOG_FILE", "1").strip().lower() not in ("0", "false", "no", "off"):
        try:
            MCP_REPORTS_DIR.mkdir(parents=True, exist_ok=True)
            file_handler = logging.FileHandler(LOG_FILE, encoding="utf-8")
            file_handler.setFormatter(fmt)
            logger.addHandler(file_handler)
        except OSError:
            pass  # best-effort -- stderr logging still works

    return logger


log = _setup_logging()

_VALID_LOG_LEVELS = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}


def _sdk_log_level() -> str:
    raw = os.environ.get("SC0PE_MCP_LOG_LEVEL", "INFO").strip().upper()
    return raw if raw in _VALID_LOG_LEVELS else "INFO"


def _log_call(tool_name: str, **kwargs: Any) -> None:
    redacted = {k: ("<redacted>" if k in _REDACTED_KEYS else v) for k, v in kwargs.items()}
    log.info("tool call: %s(%s)", tool_name, ", ".join(f"{k}={v!r}" for k, v in redacted.items()))

# qu1cksc0pe.py flags a file as "large" at this exact byte threshold and, for
# --analyze, asks an interactive y/N question before proceeding regardless of
# --report. This server runs the CLI with stdin closed (see _run_cli), so
# that prompt would surface as an immediate EOFError rather than a hang --
# but it's still a wasted, confusing round trip. Reject up front instead.
MAX_INPUT_FILE_BYTES = 52_428_800  # 50MB, mirrors qu1cksc0pe.py's own check

STDOUT_CAP = 12_000

# qu1cksc0pe.py derives its own module search path from the process's
# current working directory (not from `qu1cksc0pe.py`'s own location), and
# every analyzer writes its JSON report to a plain relative filename in that
# same cwd. Concurrent invocations sharing BASE_DIR as cwd could therefore
# clobber each other's report file; serialize CLI invocations to rule that
# out entirely.
_CLI_LOCK = threading.Lock()

mcp = MCPServer(
    "qu1cksc0pe",
    version="1.0.0",
    instructions=(
        "Static malware/file analysis via Qu1cksc0pe "
        "(https://github.com/CYB3RMX/Qu1cksc0pe). Supports Windows PE/MSI, "
        "Linux ELF, macOS Mach-O, Android APK/DEX/JAR, PCAP, documents, "
        "scripts (PowerShell/VBA/JS/HTA/batch/LNK) and email files. "
        "Always pass absolute file paths. Files at or above 50MB are "
        "rejected -- analyze a smaller sample or use the interactive CLI "
        "directly. Call list_supported_file_types() to see which tool fits "
        "a given file."
    ),
    log_level=_sdk_log_level(),
)

log.info(
    "Qu1cksc0pe MCP server initialized. base_dir=%s entrypoint=%s python=%s log_file=%s",
    BASE_DIR, ENTRYPOINT, PYTHON_BIN, LOG_FILE if any(isinstance(h, logging.FileHandler) for h in log.handlers) else "(disabled)",
)


# --------------------------------------------------------------------------
# Validation helpers
# --------------------------------------------------------------------------

def _resolve(path_str: str) -> Path:
    p = Path(path_str).expanduser()
    if not p.is_absolute():
        p = Path.cwd() / p
    return p.resolve()


def _validate_file(path_str: str) -> Path:
    if not path_str or not str(path_str).strip():
        raise ValueError("file_path must not be empty.")
    p = _resolve(path_str)
    if not p.exists():
        raise ValueError(f"File not found: {p}")
    if not p.is_file():
        raise ValueError(f"Not a regular file: {p}")
    size = p.stat().st_size
    if size >= MAX_INPUT_FILE_BYTES:
        raise ValueError(
            f"File is {size:,} bytes (>= 50MB limit). qu1cksc0pe.py prompts "
            "interactively for files this large, which an MCP tool call "
            "cannot answer. Use a smaller sample or the interactive CLI."
        )
    return p


def _validate_folder(path_str: str) -> Path:
    if not path_str or not str(path_str).strip():
        raise ValueError("folder_path must not be empty.")
    p = _resolve(path_str)
    if not p.exists():
        raise ValueError(f"Folder not found: {p}")
    if not p.is_dir():
        raise ValueError(f"Not a directory: {p}")
    return p


def _require_exactly_one(file_path: Optional[str], folder_path: Optional[str]) -> None:
    have_file = bool(file_path and str(file_path).strip())
    have_folder = bool(folder_path and str(folder_path).strip())
    if have_file == have_folder:
        raise ValueError("Provide exactly one of file_path or folder_path.")


_CLOUD_AI_PROVIDERS = {"claude", "openai", "deepseek", "kimi", "glm"}
_AI_PROVIDER_CHOICES = {"auto", "ollama"} | _CLOUD_AI_PROVIDERS


def _ai_provider_args(ai_provider: Optional[str]) -> list:
    """Validate and translate an ai_provider tool argument into qu1cksc0pe.py CLI args.

    Raises ValueError on an unrecognized provider name.
    """
    if not ai_provider:
        return []
    normalized = str(ai_provider).strip().lower()
    if normalized not in _AI_PROVIDER_CHOICES:
        raise ValueError(
            f"Unknown ai_provider {ai_provider!r}. Choose one of: {sorted(_AI_PROVIDER_CHOICES)}."
        )
    return ["--ai_provider", normalized]


def _trim(text: Optional[str], limit: int = STDOUT_CAP) -> str:
    text = text or ""
    if len(text) <= limit:
        return text
    return text[:limit] + f"\n...[truncated, {len(text) - limit} more chars]"


# --------------------------------------------------------------------------
# CLI execution
# --------------------------------------------------------------------------

def _report_snapshot() -> dict[Path, int]:
    snap: dict[Path, int] = {}
    for candidate in BASE_DIR.glob("sc0pe_*_report.json"):
        try:
            snap[candidate] = candidate.stat().st_mtime_ns
        except OSError:
            continue
    return snap


def _collect_new_reports(before: dict) -> list:
    changed = []
    for candidate in BASE_DIR.glob("sc0pe_*_report.json"):
        try:
            mtime_ns = candidate.stat().st_mtime_ns
        except OSError:
            continue
        if candidate not in before or mtime_ns > before[candidate]:
            changed.append(candidate)
    return changed


def _run_cli(args: list, *, timeout: int = 300) -> dict[str, Any]:
    """Run `qu1cksc0pe.py <args>` and collect any JSON report(s) it wrote.

    Never raises -- all failure modes (bad interpreter, timeout, crash) are
    reported back in the returned dict so tool functions can return it
    directly.
    """
    command = [PYTHON_BIN, str(ENTRYPOINT), *args]
    env = os.environ.copy()
    env.setdefault("PYTHONIOENCODING", "utf-8")
    env.setdefault("PYTHONUTF8", "1")

    with _CLI_LOCK:
        log.info("dispatch: %s (timeout=%ss)", " ".join(command), timeout)
        before = _report_snapshot()
        started = time.perf_counter()
        timed_out = False
        stdout, stderr, exit_code = "", "", -1
        try:
            completed = subprocess.run(
                command,
                cwd=str(BASE_DIR),
                stdin=subprocess.DEVNULL,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=timeout,
                env=env,
            )
            exit_code = completed.returncode
            stdout, stderr = completed.stdout, completed.stderr
        except subprocess.TimeoutExpired as exc:
            timed_out = True
            exit_code = 124
            stdout = exc.stdout or ""
            stderr = (exc.stderr or "") + "\nAnalysis timed out."
            log.warning("dispatch timed out after %ss: %s", timeout, " ".join(command))
        except OSError as exc:
            stderr = f"Failed to launch qu1cksc0pe.py: {exc}"
            log.error("dispatch failed to launch: %s", exc)
        duration = round(time.perf_counter() - started, 2)

        if not timed_out and exit_code not in (-1,):
            log_fn = log.info if exit_code == 0 else log.warning
            log_fn("dispatch finished: exit_code=%s duration=%.2fs", exit_code, duration)
        if stderr.strip():
            log.debug("dispatch stderr: %s", _trim(stderr, 2000))

        reports: dict = {}
        MCP_REPORTS_DIR.mkdir(parents=True, exist_ok=True)
        for report_path in _collect_new_reports(before):
            try:
                data = json.loads(report_path.read_text(encoding="utf-8"))
            except Exception as exc:  # noqa: BLE001
                data = {"_parse_error": str(exc)}
                log.warning("report parse failed for %s: %s", report_path.name, exc)
            reports[report_path.name] = data
            # Archive a copy outside the working tree, then remove the
            # original so the next call's before/after snapshot stays clean.
            try:
                dest = MCP_REPORTS_DIR / f"{report_path.stem}_{uuid.uuid4().hex[:8]}{report_path.suffix}"
                shutil.move(str(report_path), str(dest))
                log.info("report archived: %s -> %s", report_path.name, dest)
            except OSError as exc:
                log.warning("report archive failed for %s: %s", report_path.name, exc)

    return {
        "ok": exit_code == 0 and not timed_out,
        "exit_code": exit_code,
        "timed_out": timed_out,
        "duration_seconds": duration,
        "command": " ".join(command),
        "stdout": _trim(stdout),
        "stderr": _trim(stderr),
        "reports": reports,
    }


# --------------------------------------------------------------------------
# Tools
# --------------------------------------------------------------------------

@mcp.tool()
def analyze_file(
    file_path: str,
    ai: bool = False,
    ai_provider: Optional[str] = None,
    timeout_seconds: int = 900,
) -> dict[str, Any]:
    """Auto-detect a file's type and run Qu1cksc0pe's full static analysis on it.

    Handles Windows PE/MSI/DLL, Linux ELF, macOS Mach-O, Android APK/DEX/JAR,
    PCAP, PowerShell, VBScript/VBA, HTML/JS/HTA, batch scripts, LNK files and
    email files -- Qu1cksc0pe auto-detects the type. Equivalent to
    `qu1cksc0pe.py --file <file> --analyze --report`. Always returns a
    structured JSON report. Set ai=True to additionally run Qu1cksc0pe's AI
    summarizer over the report. ai_provider selects the backend: "auto" or
    "ollama" (default; local, requires Ollama installed -- no data leaves
    the machine), or a cloud provider -- "claude", "openai", "deepseek",
    "kimi", or "glm" -- each needing configure_ai_api_key(provider=...)
    first. Cloud providers add network latency and send report data
    off-machine.

    Any detected VBScript/VBA source is automatically run through
    Qu1cksc0pe's native sandboxed behavior-emulation engine (fake
    CreateObject/filesystem/registry/network/process APIs -- nothing real
    ever executes). Adds a "findings"/"ioc_events"/... "emulation" section
    to the returned report's document sub-report -- findings are individual
    detected patterns (each with its own severity), not blended into a
    single aggregate risk score. No effect on non-script file types.
    Emulation runs in addition to normal static analysis with a fixed 15s
    per-script/project safety budget, so raise timeout_seconds for large or
    heavily obfuscated inputs when necessary.
    """
    _log_call("analyze_file", file_path=file_path, ai=ai, ai_provider=ai_provider,
               timeout_seconds=timeout_seconds)
    try:
        path = _validate_file(file_path)
        provider_args = _ai_provider_args(ai_provider)
    except ValueError as exc:
        log.warning("analyze_file rejected: %s", exc)
        return {"ok": False, "error": str(exc)}
    args = ["--file", str(path), "--analyze", "--report"]
    if ai:
        args.append("--ai")
    args += provider_args
    return _run_cli(args, timeout=timeout_seconds)


@mcp.tool()
def analyze_document(
    file_path: str,
    ai: bool = False,
    ai_provider: Optional[str] = None,
    timeout_seconds: int = 600,
) -> dict[str, Any]:
    """Analyze a document/macro/VBScript-family file (.doc*, .xls*, .vbs, .vbe, .vba, .vb, .bas, .cls, .frm, ...).

    Equivalent to `qu1cksc0pe.py --file <file> --docs --report`. See
    analyze_file's docstring for AI options and automatic emulation.
    """
    _log_call("analyze_document", file_path=file_path, ai=ai, ai_provider=ai_provider,
               timeout_seconds=timeout_seconds)
    try:
        path = _validate_file(file_path)
        provider_args = _ai_provider_args(ai_provider)
    except ValueError as exc:
        log.warning("analyze_document rejected: %s", exc)
        return {"ok": False, "error": str(exc)}
    args = ["--file", str(path), "--docs", "--report"]
    if ai:
        args.append("--ai")
    args += provider_args
    return _run_cli(args, timeout=timeout_seconds)


@mcp.tool()
def analyze_archive(file_path: str, ai: bool = False, ai_provider: Optional[str] = None, timeout_seconds: int = 600) -> dict[str, Any]:
    """Analyze an archive file (.zip, .rar, .ace, ...): lists contents and scans nested files for IOCs/YARA matches.

    Equivalent to `qu1cksc0pe.py --file <file> --archive --report`. See
    analyze_file's docstring for what ai/ai_provider do.
    """
    _log_call("analyze_archive", file_path=file_path, ai=ai, ai_provider=ai_provider, timeout_seconds=timeout_seconds)
    try:
        path = _validate_file(file_path)
        provider_args = _ai_provider_args(ai_provider)
    except ValueError as exc:
        log.warning("analyze_archive rejected: %s", exc)
        return {"ok": False, "error": str(exc)}
    args = ["--file", str(path), "--archive", "--report"]
    if ai:
        args.append("--ai")
    args += provider_args
    return _run_cli(args, timeout=timeout_seconds)


@mcp.tool()
def detect_packer(
    file_path: Optional[str] = None,
    folder_path: Optional[str] = None,
    report: bool = True,
    ai: bool = False,
    ai_provider: Optional[str] = None,
    timeout_seconds: int = 600,
) -> dict[str, Any]:
    """Check whether a binary (or every file in a folder) is packed with a known packer.

    Provide exactly one of file_path or folder_path. Equivalent to
    `qu1cksc0pe.py --packer (--file <file>|--folder <folder>) [--report] [--ai]`.
    ai=True here runs a separate, Ollama-only "AI-assisted pattern scan"
    built into the packer analyzer itself (packerAnalyzer.py), NOT
    Qu1cksc0pe's report summarizer used by analyze_file/analyze_document/
    analyze_archive -- ai_provider has NO effect on it (cloud providers are
    not supported for this specific tool) and it silently falls back to
    "unavailable" if Ollama isn't reachable.
    """
    _log_call("detect_packer", file_path=file_path, folder_path=folder_path, report=report, ai=ai, ai_provider=ai_provider, timeout_seconds=timeout_seconds)
    if ai and str(ai_provider or "").strip().lower() in _CLOUD_AI_PROVIDERS:
        log.warning(
            "detect_packer: ai_provider=%r has no effect here -- this tool's AI pattern "
            "assist is Ollama-only, unlike the report summarizer.", ai_provider,
        )
    try:
        _require_exactly_one(file_path, folder_path)
        if file_path:
            target = _validate_file(file_path)
            args = ["--file", str(target)]
        else:
            target = _validate_folder(folder_path)
            args = ["--folder", str(target)]
        provider_args = _ai_provider_args(ai_provider)
    except ValueError as exc:
        log.warning("detect_packer rejected: %s", exc)
        return {"ok": False, "error": str(exc)}
    args = args + ["--packer"]
    if report or ai:
        args.append("--report")
    if ai:
        args.append("--ai")
    args += provider_args
    return _run_cli(args, timeout=timeout_seconds)


@mcp.tool()
def detect_language(file_path: str, report: bool = True, ai: bool = False, ai_provider: Optional[str] = None, timeout_seconds: int = 300) -> dict[str, Any]:
    """Fingerprint the programming language(s) used to build a binary.

    Equivalent to `qu1cksc0pe.py --file <file> --lang [--report] [--ai]`.
    ai=True here runs a separate, Ollama-only "AI-assisted pattern scan"
    built into languageDetect.py, NOT Qu1cksc0pe's report summarizer used by
    analyze_file/analyze_document/analyze_archive -- ai_provider has NO
    effect on it (cloud providers are not supported for this specific tool).
    """
    _log_call("detect_language", file_path=file_path, report=report, ai=ai, ai_provider=ai_provider, timeout_seconds=timeout_seconds)
    if ai and str(ai_provider or "").strip().lower() in _CLOUD_AI_PROVIDERS:
        log.warning(
            "detect_language: ai_provider=%r has no effect here -- this tool's AI pattern "
            "assist is Ollama-only, unlike the report summarizer.", ai_provider,
        )
    try:
        path = _validate_file(file_path)
        provider_args = _ai_provider_args(ai_provider)
    except ValueError as exc:
        log.warning("detect_language rejected: %s", exc)
        return {"ok": False, "error": str(exc)}
    args = ["--file", str(path), "--lang"]
    if report or ai:
        args.append("--report")
    if ai:
        args.append("--ai")
    args += provider_args
    return _run_cli(args, timeout=timeout_seconds)


@mcp.tool()
def extract_iocs(file_path: str, report: bool = True, timeout_seconds: int = 300) -> dict[str, Any]:
    """Extract URLs, IP addresses and email addresses embedded in a file.

    Equivalent to `qu1cksc0pe.py --file <file> --domain [--report]`.
    """
    _log_call("extract_iocs", file_path=file_path, report=report, timeout_seconds=timeout_seconds)
    try:
        path = _validate_file(file_path)
    except ValueError as exc:
        log.warning("extract_iocs rejected: %s", exc)
        return {"ok": False, "error": str(exc)}
    args = ["--file", str(path), "--domain"]
    if report:
        args.append("--report")
    return _run_cli(args, timeout=timeout_seconds)


@mcp.tool()
def check_resources(file_path: str, timeout_seconds: int = 180) -> dict[str, Any]:
    """Extract and inspect a PE file's embedded resources (icons, manifests, carved payloads, ...).

    Equivalent to `qu1cksc0pe.py --file <file> --resource`. Console output
    only -- this analyzer does not produce a JSON report.
    """
    _log_call("check_resources", file_path=file_path, timeout_seconds=timeout_seconds)
    try:
        path = _validate_file(file_path)
    except ValueError as exc:
        log.warning("check_resources rejected: %s", exc)
        return {"ok": False, "error": str(exc)}
    return _run_cli(["--file", str(path), "--resource"], timeout=timeout_seconds)


@mcp.tool()
def check_signatures(file_path: str, timeout_seconds: int = 180) -> dict[str, Any]:
    """Scan a file for embedded/carved file signatures (e.g. an EXE hidden inside another file type).

    Equivalent to `qu1cksc0pe.py --file <file> --sigcheck`. Console output
    only -- this analyzer does not produce a JSON report.
    """
    _log_call("check_signatures", file_path=file_path, timeout_seconds=timeout_seconds)
    try:
        path = _validate_file(file_path)
    except ValueError as exc:
        log.warning("check_signatures rejected: %s", exc)
        return {"ok": False, "error": str(exc)}
    return _run_cli(["--file", str(path), "--sigcheck"], timeout=timeout_seconds)


@mcp.tool()
def scan_hash(
    file_path: Optional[str] = None,
    folder_path: Optional[str] = None,
    timeout_seconds: int = 600,
) -> dict[str, Any]:
    """Look up a file's MD5 (or every file under a folder, recursively) against Qu1cksc0pe's local malware hash database.

    Provide exactly one of file_path or folder_path. Requires the local hash
    database; call update_hash_database() first if this reports it's
    missing. Equivalent to
    `qu1cksc0pe.py --hashscan (--file <file>|--folder <folder>)`. Only the
    folder/multi-file form writes a JSON report; a single-file scan returns
    console output only.
    """
    _log_call("scan_hash", file_path=file_path, folder_path=folder_path, timeout_seconds=timeout_seconds)
    try:
        _require_exactly_one(file_path, folder_path)
        if file_path:
            target = _validate_file(file_path)
            args = ["--file", str(target)]
        else:
            target = _validate_folder(folder_path)
            args = ["--folder", str(target)]
    except ValueError as exc:
        log.warning("scan_hash rejected: %s", exc)
        return {"ok": False, "error": str(exc)}

    hash_db = Path.home() / "sc0pe_Base" / "HashDB"
    if not hash_db.exists():
        log.warning("scan_hash rejected: hash database missing at %s", hash_db)
        return {
            "ok": False,
            "error": (
                f"Local hash database not found at {hash_db}. "
                "Call update_hash_database() first."
            ),
        }

    args = args + ["--hashscan"]
    return _run_cli(args, timeout=timeout_seconds)


@mcp.tool()
def scan_virustotal(file_path: str, timeout_seconds: int = 120) -> dict[str, Any]:
    """Look up a file's hash on VirusTotal (does not upload the file).

    Requires a VirusTotal API key configured via configure_virustotal_api_key
    first. Equivalent to `qu1cksc0pe.py --file <file> --vtFile`.
    """
    _log_call("scan_virustotal", file_path=file_path, timeout_seconds=timeout_seconds)
    try:
        path = _validate_file(file_path)
    except ValueError as exc:
        log.warning("scan_virustotal rejected: %s", exc)
        return {"ok": False, "error": str(exc)}
    return _run_cli(["--file", str(path), "--vtFile"], timeout=timeout_seconds)


# provider id -> key filename under ~/sc0pe_Base/, mirrors qu1cksc0pe.py's
# own API_KEY_PROVIDERS registry (kept in sync manually; the two files don't
# import each other since qu1cksc0pe.py only ever reaches this module via
# subprocess).
_API_KEY_PROVIDER_FILES = {
    "virustotal": "sc0pe_VT_apikey.txt",
    "claude": "sc0pe_claude_apikey.txt",
    "openai": "sc0pe_openai_apikey.txt",
    "deepseek": "sc0pe_deepseek_apikey.txt",
    "kimi": "sc0pe_kimi_apikey.txt",
    "glm": "sc0pe_glm_apikey.txt",
}


def _save_provider_key(
    tool_name: str,
    provider_id: str,
    api_key: str,
    timeout_seconds: int,
    *,
    exact_length: Optional[int] = None,
) -> dict[str, Any]:
    """Shared implementation for the configure_*_api_key tools.

    Pipes the key via stdin (never as a CLI arg, never logged) to
    `qu1cksc0pe.py --key_init --key_provider <provider_id>`, which writes it
    to ~/sc0pe_Base/<key_filename>.
    """
    key = (api_key or "").strip()
    if not key:
        log.warning("%s rejected: empty key", tool_name)
        return {"ok": False, "error": "API key must not be empty."}
    if exact_length is not None and len(key) != exact_length:
        log.warning("%s rejected: got %d chars, expected %d", tool_name, len(key), exact_length)
        return {"ok": False, "error": f"API key must be {exact_length} characters long; got {len(key)}."}

    command = [PYTHON_BIN, str(ENTRYPOINT), "--key_init", "--key_provider", provider_id]
    env = os.environ.copy()
    env.setdefault("PYTHONIOENCODING", "utf-8")
    env.setdefault("PYTHONUTF8", "1")
    with _CLI_LOCK:
        log.info("dispatch: %s <redacted stdin> (timeout=%ss)", " ".join(command), timeout_seconds)
        try:
            completed = subprocess.run(
                command,
                cwd=str(BASE_DIR),
                input=key + "\n",
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=timeout_seconds,
                env=env,
            )
        except (subprocess.TimeoutExpired, OSError) as exc:
            log.error("%s dispatch failed: %s", tool_name, exc)
            return {"ok": False, "error": f"Failed to save API key: {exc}"}

    key_file = Path.home() / "sc0pe_Base" / _API_KEY_PROVIDER_FILES[provider_id]
    ok = completed.returncode == 0 and key_file.exists()
    log.info("%s finished: ok=%s exit_code=%s", tool_name, ok, completed.returncode)
    return {
        "ok": ok,
        "exit_code": completed.returncode,
        "message": "API key saved." if ok else _trim(completed.stderr or completed.stdout),
    }


@mcp.tool()
def configure_virustotal_api_key(api_key: str, timeout_seconds: int = 30) -> dict[str, Any]:
    """Save a VirusTotal API key for use by scan_virustotal (equivalent to `qu1cksc0pe.py --key_init --key_provider virustotal`).

    The key is written to ~/sc0pe_Base/sc0pe_VT_apikey.txt and is never
    echoed back in the tool result.
    """
    _log_call("configure_virustotal_api_key", api_key=api_key, timeout_seconds=timeout_seconds)
    return _save_provider_key("configure_virustotal_api_key", "virustotal", api_key, timeout_seconds, exact_length=64)


@mcp.tool()
def configure_ai_api_key(provider: str, api_key: str, timeout_seconds: int = 30) -> dict[str, Any]:
    """Save an API key for one of the cloud AI providers used by ai_provider on the analysis tools.

    provider must be one of: claude, openai, deepseek, kimi, glm. Equivalent
    to `qu1cksc0pe.py --key_init --key_provider <provider>`. A matching env
    var (ANTHROPIC_API_KEY, OPENAI_API_KEY, DEEPSEEK_API_KEY,
    MOONSHOT_API_KEY, ZHIPUAI_API_KEY respectively), if set, takes
    precedence over this. The key is never echoed back in the tool result.
    """
    _log_call("configure_ai_api_key", provider=provider, api_key=api_key, timeout_seconds=timeout_seconds)
    normalized = str(provider or "").strip().lower()
    valid_providers = {"claude", "openai", "deepseek", "kimi", "glm"}
    if normalized not in valid_providers:
        log.warning("configure_ai_api_key rejected: unknown provider %r", provider)
        return {"ok": False, "error": f"Unknown provider {provider!r}. Choose one of: {sorted(valid_providers)}."}
    return _save_provider_key("configure_ai_api_key", normalized, api_key, timeout_seconds)


@mcp.tool()
def update_hash_database(timeout_seconds: int = 600) -> dict[str, Any]:
    """Download/refresh Qu1cksc0pe's local malware hash database (required by scan_hash).

    Equivalent to `qu1cksc0pe.py --db_update`.
    """
    _log_call("update_hash_database", timeout_seconds=timeout_seconds)
    return _run_cli(["--db_update"], timeout=timeout_seconds)


_SUPPORTED_FILE_TYPES = {
    "Windows executables (.exe, .dll, .msi, .bin)": ["analyze_file", "detect_packer", "check_resources", "check_signatures"],
    "Linux executables (.elf, .bin)": ["analyze_file", "detect_packer"],
    "macOS executables (Mach-O)": ["analyze_file"],
    "Android (.apk, .dex, .jar)": ["analyze_file"],
    "Documents / VBScript-VBA family (.vbs, .vbe, .vba, .vb, .bas, .cls, .frm)": ["analyze_document"],
    "HTML / JavaScript / HTA (.html, .htm, .js, .hta)": ["analyze_file"],
    "Windows batch scripts (.bat, .cmd)": ["analyze_file"],
    "Windows shortcuts (.lnk)": ["analyze_file"],
    "Archives (.zip, .rar, .ace)": ["analyze_archive"],
    "PCAP files (.pcap, .pcapng)": ["analyze_file"],
    "PowerShell scripts (.ps1)": ["analyze_file"],
    "Email files (.eml)": ["analyze_file"],
    "Any file (generic)": ["extract_iocs", "scan_hash", "scan_virustotal"],
}


@mcp.tool()
def list_supported_file_types() -> dict[str, Any]:
    """List the file types Qu1cksc0pe recognizes and which tool to use for each. Call this first if unsure which tool applies to a file."""
    _log_call("list_supported_file_types")
    return {"file_types": _SUPPORTED_FILE_TYPES}


_VALID_TRANSPORTS = {"stdio", "sse", "streamable-http"}


def main() -> None:
    # streamable-http (default) binds a local port so the server survives
    # independently of whatever first client attaches -- multiple clients,
    # or a client other than the one that launched it, can all connect to
    # the same running instance. Set SC0PE_MCP_TRANSPORT=stdio for the
    # traditional one-process-per-client model some MCP clients expect.
    transport = os.environ.get("SC0PE_MCP_TRANSPORT", "streamable-http").strip().lower()
    if transport not in _VALID_TRANSPORTS:
        log.warning("Unknown SC0PE_MCP_TRANSPORT=%r; falling back to streamable-http", transport)
        transport = "streamable-http"

    run_kwargs: dict = {}
    if transport in ("sse", "streamable-http"):
        run_kwargs["host"] = os.environ.get("SC0PE_MCP_HOST", "127.0.0.1")
        try:
            run_kwargs["port"] = int(os.environ.get("SC0PE_MCP_PORT", "8765"))
        except ValueError:
            log.warning("Invalid SC0PE_MCP_PORT; falling back to 8765")
            run_kwargs["port"] = 8765
    if transport == "streamable-http":
        run_kwargs["streamable_http_path"] = os.environ.get("SC0PE_MCP_HTTP_PATH", "/mcp")

    endpoint = f" http://{run_kwargs['host']}:{run_kwargs['port']}{run_kwargs.get('streamable_http_path', '')}" if run_kwargs else ""
    log.info("Starting Qu1cksc0pe MCP server (transport=%s%s)", transport, endpoint)
    try:
        mcp.run(transport=transport, **run_kwargs)
    except KeyboardInterrupt:
        # Normal user-initiated shutdown (Ctrl+C), not a crash. KeyboardInterrupt
        # doesn't subclass Exception, so it would otherwise skip straight past
        # the except clause below and exit with a non-zero/signal exit code --
        # which launch_mcp_server() in qu1cksc0pe.py would then misreport as
        # "Failed to launch MCP server" even though the user just stopped it.
        log.info("Interrupted by user")
    except Exception:
        log.exception("MCP server crashed")
        raise
    finally:
        log.info("Qu1cksc0pe MCP server stopped")


if __name__ == "__main__":
    main()
