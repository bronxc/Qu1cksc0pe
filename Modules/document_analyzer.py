#!/usr/bin/python3

import re
import os
import sys
import json
import zlib
import base64
import binascii
import hashlib
import zipfile
import subprocess
import configparser
import urllib.parse
from analysis.multiple.multi import chk_wlist, perform_strings, yara_rule_scanner, calc_hashes
from apple_analyzer import looks_like_applescript
from batch_analyzer import looks_like_batch_script
from utils.helpers import err_exit, get_argv, save_report

# Checking for the native VBA/VBScript sandboxed behavior-emulation engine.
# Self-contained (no external dependency) -- soft-fail like msoffcrypto
# below so a missing emulator never prevents the normal document analysis.
try:
    from vba_emulator import (emulate_vba_source, extract_activex_control_values,
                               extract_custom_document_properties, extract_custom_xml_parts,
                               extract_customui_callbacks, extract_shape_macro_callbacks,
                               extract_excel_cell_values)
except Exception:
    emulate_vba_source = None
    extract_activex_control_values = None
    extract_custom_document_properties = None
    extract_custom_xml_parts = None
    extract_customui_callbacks = None
    extract_shape_macro_callbacks = None
    extract_excel_cell_values = None


def _trunc(value, n=90):
    s = str(value)
    return s if len(s) <= n else f"{s[:n]}... ({len(s)} chars total)"


_EMU_CATEGORY_STYLE = {
    "process_create": "bold red",
    "network_request": "bold magenta", "network_send": "bold magenta", "network_header": "magenta",
    "registry_write": "bold yellow", "registry_delete": "bold yellow", "registry_read": "yellow",
    "filesystem_write": "bold cyan", "filesystem_copy": "bold cyan", "filesystem_move": "bold cyan",
    "filesystem_create": "cyan", "filesystem_delete": "cyan", "filesystem_access": "dim cyan",
    "com_create": "blue", "com_getobject": "blue",
    "dynamic_execute": "bold green",
    "decode_base64": "bold green", "decode_hex": "bold green",
    "script_output": "bold white", "script_error": "bold red", "script_error_suppressed": "red",
    "emulation_error": "bold red", "emulation_timeout": "bold red", "parse_error": "bold red",
    "environment_write": "yellow", "environment_access": "dim yellow",
    "unknown_com_call": "dim", "ui_prompt": "bold white", "wmi_query": "bold red",
    "entry_point_invoked": "bold", "unsupported": "dim",
    "stream_write": "bold cyan", "doc_property_access": "blue",
    "filesystem_extract": "bold cyan", "com_namespace": "blue",
    "process_injection": "bold red", "unmodeled_winapi_call": "dim",
    "scheduled_task_create": "bold yellow",
}


def _humanize_emulation_event(category, f):
    if category == "com_create":
        return f"CreateObject(\"{f.get('progid')}\")" + ("" if f.get("known") else "  [not modeled]")
    if category == "com_getobject":
        return f"GetObject(\"{f.get('moniker','')}\", \"{f.get('progid','')}\")"
    if category == "dynamic_execute":
        return f"{f.get('api')}: {_trunc(f.get('code_preview',''))}"
    if category == "process_create":
        extra = []
        if "window_style" in f:
            extra.append(f"window_style={f['window_style']}")
        if "wait" in f:
            extra.append(f"wait={f['wait']}")
        suffix = f"  ({', '.join(extra)})" if extra else ""
        return f"{f.get('api')}: {_trunc(f.get('command',''), 200)}{suffix}"
    if category in ("network_request", "network_send"):
        return f"{f.get('api')}: {f.get('method','')} {f.get('url','')}".strip()
    if category == "network_header":
        return f"setRequestHeader: {f.get('name')} = {_trunc(f.get('value',''))}"
    if category in ("registry_write", "registry_delete", "registry_read"):
        val = f" = {_trunc(f.get('value',''))}" if f.get("value") else ""
        persist = "  [PERSISTENCE]" if f.get("persistence") else ""
        return f"{f.get('api')}: {f.get('key','')}{val}{persist}"
    if category in ("filesystem_write", "filesystem_create", "filesystem_delete", "filesystem_access"):
        susp = "  [suspicious ext]" if f.get("suspicious_ext") else ""
        executable = f"  [executable content: {f.get('magic', 'unknown')}]" if f.get("executable_content") else ""
        size = f"  ({f['size']} bytes)" if f.get("size") else ""
        return f"{f.get('api')}: {f.get('path','')}{size}{susp}{executable}"
    if category in ("filesystem_copy", "filesystem_move"):
        susp = "  [suspicious ext]" if f.get("suspicious_ext") else ""
        return f"{f.get('api')}: {f.get('src','')}  ->  {f.get('dst','')}{susp}"
    if category == "stream_write":
        return f"{f.get('api')}: {f.get('size',0)} bytes" + (f" - {_trunc(f['preview'])}" if f.get("preview") else "")
    if category in ("environment_write", "environment_access"):
        val = f" = {_trunc(f.get('value',''))}" if f.get("value") else ""
        return f"Environment[{f.get('name','')}]{val}"
    if category == "filesystem_extract":
        return f"{f.get('api')}: extracted into {f.get('destination','')}"
    if category == "com_namespace":
        return f"{f.get('api')}: {f.get('path','')}"
    if category == "doc_property_access":
        note = "" if f.get("recovered") else "  [not recovered]"
        return f"{f.get('api')}: {f.get('name','')}{note}"
    if category == "unknown_com_call":
        args = ", ".join(_trunc(a, 30) for a in f.get("args", []))
        return f"{f.get('progid')}.{f.get('member')}({args})  [not modeled -- logged only]"
    if category == "process_injection":
        extra = [f"{k}={v}" for k, v in f.items()
                 if k not in ("category", "ts", "api") and v not in (None, "")]
        return f"{f.get('api')}" + (f"  ({', '.join(extra)})" if extra else "")
    if category == "scheduled_task_create":
        action = f" -> {_trunc(f.get('action', ''), 120)}" if f.get("action") else ""
        return f"{f.get('api')}: {f.get('task_path', f.get('name', ''))}{action}  [PERSISTENCE]"
    if category == "unmodeled_winapi_call":
        args = ", ".join(_trunc(a, 30) for a in f.get("args", []))
        lib = f" [{f['lib']}]" if f.get("lib") else ""
        return f"{f.get('api')}{lib}({args})  [not modeled -- logged only]"
    if category == "script_output":
        return f"{f.get('api')}: {_trunc(f.get('text',''), 200)}"
    if category == "ui_prompt":
        return f"{f.get('api')}: {_trunc(f.get('text',''))}"
    if category in ("script_error", "script_error_suppressed"):
        return f"Runtime error #{f.get('number')}: {f.get('error')}"
    if category in ("emulation_error", "emulation_timeout", "parse_error"):
        return f"{f.get('error', f.get('detail',''))}" + (f"  (phase: {f['phase']})" if f.get("phase") else "")
    if category == "entry_point_invoked":
        return f"Invoking entry point: {f.get('name')}"
    if category == "wmi_query":
        return f"{f.get('api')}: {_trunc(f.get('query',''))}"
    if category in ("decode_base64", "decode_hex"):
        return f"{f.get('api')}: {f.get('length',0)} bytes decoded"
    if category == "unsupported":
        return f.get("detail", "")
    if category.endswith("_suppressed"):
        return f"{f.get('api', '')}: {f.get('note', 'further occurrences suppressed')}"
    return _trunc(str(f))

# Checking for rich
try:
    from rich import print
    from rich.table import Table
    from rich.markup import escape as _esc
except:
    err_exit("Error: >rich< not found.")

try:
    import yara
except:
    err_exit("Error: >yara< module not found.")

try:
    import msoffcrypto
except:
    msoffcrypto = None

# Checking for oletools
try:
    from oletools.olevba import VBA_Parser
    from oletools.crypto import is_encrypted
    from oletools.oleid import OleID
    from olefile import isOleFile
    from olefile import OleFileIO
except:
    print("Error: >oletools< module not found.")
    print("Try 'sudo -H pip3 install -U oletools' command.")
    sys.exit(1)

# Checking for pdfminer
try:
    from pdfminer.pdfparser import PDFParser
    from pdfminer.pdfdocument import PDFDocument
except:
    err_exit("Error: >pdfminer< module not found.")

# Checking for pyOneNote module
try:
    from pyOneNote.Main import OneDocment
except ImportError:
    print("Error: >pyOneNote< module not found. Don't worry I can handle it...")
    _pip_cmd = [sys.executable, "-m", "pip", "install", "-U",
                "https://github.com/DissectMalware/pyOneNote/archive/master.zip"]
    if sys.prefix == sys.base_prefix:  # not in a venv — avoid breaking system packages
        _pip_cmd += ["--user", "--break-system-packages"]
    subprocess.run(_pip_cmd, check=False)
    print("[bold yellow]Now try to re-execute program again!")
    sys.exit(0)

# Legends
infoS = f"[bold cyan][[bold red]*[bold cyan]][white]"
errorS = f"[bold cyan][[bold red]![bold cyan]][white]"
URL_REGEX = r"https?://[^\s'\"<>()]+"
URL_PATTERN = re.compile(URL_REGEX)

# Target file
targetFile = sys.argv[1]

# Compatibility
path_seperator = "/"
if sys.platform == "win32":
    path_seperator = "\\"

# Gathering Qu1cksc0pe path variable
sc0pe_path = open(os.path.join(os.path.expanduser("~"), ".qu1cksc0pe_path"), "r").read().strip()

# All strings
allstr = "\n".join(perform_strings(targetFile))

# Parsing config file to get rule path
conf = configparser.ConfigParser()
conf.read(f"{sc0pe_path}{path_seperator}Systems{path_seperator}Multiple{path_seperator}multiple.conf", encoding="utf-8-sig")

# Report
report = {
    "filename": "",
    "document_type": "",
    "file_magic": "",
    "hash_md5": "",
    "hash_sha1": "",
    "hash_sha256": "",
    "all_strings": 0,
    "categorized_findings": 0,
    "is_ole_file": False,
    "is_encrypted": False,
    "matched_rules": [],
    "extracted_urls": [],
    "macros": {
        "extracted": False,
        "vba": [],
        "xlm": [],
        "truncated": {
            "vba": 0,
            "xlm": 0
        }
    },
    "script_analysis": {
        "language": "",
        "vbe_encoded": False,
        "categories": {},
        "createobject_values": [],
        "shell_commands": [],
        "decoded_payload_hints": []
    },
    "embedded_files": [],
    "extracted_files": [],
    "sections": {},
    "decryption": {
        "attempted": False,
        "success": False,
        "output_file": "",
        "error": "",
        "auto_analysis": {
            "triggered": False,
            "target_file": "",
            "exit_code": None
        }
    },
    # Sandboxed behavior-emulation results for every extracted VBA project
    # and/or VB-family script. Emulation starts automatically whenever
    # analyzable source is detected and the native engine is available.
    "emulation": {
        "enabled": False,
        "macros": [],
        "script": None
    }
}

class DocumentAnalyzer:
    def __init__(self, targetFile):
        self.targetFile = targetFile
        self.rule_path = conf["Rule_PATH"]["rulepath"]
        self.decrypted_output_file = None
        self.auto_chain_mode = os.environ.get("SC0PE_AUTO_DECRYPT_CHAIN", "0") == "1"
        self._findings_seen = set()
        report["filename"] = self.targetFile
        calc_hashes(self.targetFile, report)
        report["all_strings"] = len(allstr.split("\n"))
        with open(f"{sc0pe_path}{path_seperator}Systems{path_seperator}Multiple{path_seperator}file_sigs.json", "r") as fp:
            self.file_sigs = json.load(fp)
        self.base64_pattern = r'(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{4})'
        with open(f"{sc0pe_path}{path_seperator}Systems{path_seperator}Multiple{path_seperator}malicious_html_codes.json", "r") as fp:
            self.mal_code = json.load(fp)
        with open(f"{sc0pe_path}{path_seperator}Systems{path_seperator}Multiple{path_seperator}malicious_rtf_codes.json", "r") as fp:
            self.mal_rtf_code = json.load(fp)
        self.pat_ct = 0
        self.is_ole_file = None
        self.rtf_exploit_pattern_dict = {
            "bin": {
                "name": "\\binxxx",
                "detect_pattern": rb'\\bin',
                "pattern": rb'[a-f0-9\}]+\\bin[a-f0-9]+',
                "occurence": 0
            },
            "objupdate_1": {
                "name": "\\objupdate",
                "detect_pattern": rb'{\\[^}]+\\objupdate}',
                "pattern": rb'([0-9a-fA-F]+){\\[^}]+\\objupdate}([0-9a-fA-F]+)',
                "occurence": 0
            },
            "objupdate_2": {
                "name": "\\objupdate",
                "detect_pattern": rb'{\\objupdate\}',
                "pattern": rb'([a-f0-9]+){\\objupdate}([a-f0-9]+)',
                "occurence": 0
            },
            "objdata": {
                "name": "\\objdata",
                "detect_pattern": rb'\\objdata[a-f0-9]+',
                "pattern": rb'\\objdata([a-f0-9]+)',
                "occurence": 0
            },
            "ods": {
                "name": "\\ods",
                "detect_pattern": rb'{\\ods[a-f0-9]+',
                "pattern": rb'{\\ods([a-f0-9]+)}([a-f0-9]+)',
                "occurence": 0
            }
        }
        self.rtf_exploit_extract_dict = {
            "CVE-2017-11882": {
                "pattern": [rb'ion.3', rb'ion.2', rb'OLE10naTiVE', rb'\x00i\x00o\x00n'],
                "occurence": 0
            },
            "VBScript": {
                "pattern": [rb'(script|Create|vbscript|Function)'],
                "occurence": 0
            }
        }

    def _emulation_available(self):
        return emulate_vba_source is not None

    def _run_emulation(self, code, origin, activex_controls=None, module_names=None,
                        custom_doc_properties=None, custom_xml_parts=None, extra_entry_points=None,
                        excel_cells=None):
        """Automatically emulate extracted VBA/VBScript source in-memory."""
        if not self._emulation_available():
            return None
        if not code or not code.strip():
            return None
        timeout_seconds = 15

        # origin is (part of) the analyzed filename/macro path -- fully
        # attacker-controlled. _sanitize_text() only replaces non-printable
        # chars; it does NOT escape rich markup, so a filename containing
        # "[...]" (plausible: social-engineered names, or one that happens
        # to collide with real style tags like "[bold red]") gets silently
        # swallowed or mis-rendered by rich's console print() otherwise.
        # Confirmed: a file literally named "[bold red]HACKED[white]evil.vbs"
        # printed as just "HACKEDevil.vbs" before this fix.
        print(f"\n{infoS} Emulating [bold green]{_esc(self._sanitize_text(origin))}[white] "
              f"(sandboxed, up to {timeout_seconds}s)...")
        try:
            result = emulate_vba_source(code, origin=origin, timeout_seconds=timeout_seconds,
                                         activex_controls=activex_controls, module_names=module_names,
                                         custom_doc_properties=custom_doc_properties,
                                         custom_xml_parts=custom_xml_parts,
                                         extra_entry_points=extra_entry_points,
                                         excel_cells=excel_cells)
        except Exception as exc:
            print(f"{errorS} Emulation failed: {_esc(str(exc))}")
            return None

        report["emulation"]["enabled"] = True

        # Emulation itself succeeded and its dict is what actually needs to
        # survive (it's what --report saves) -- folding a couple of its
        # fields into the rest of the report (findings, extracted URLs)
        # must happen regardless of whether rendering it to the terminal
        # works. Do the bookkeeping first, and isolate only the display
        # call: without that isolation, any bug in
        # _display_emulation_results would propagate out of
        # VBScriptAnalysis()/MacroHunter() and, via the module's top-level
        # exception handler, abort the *entire* analysis run (no report
        # saved, no YARA/URL/pattern results either) over what should be,
        # at worst, a cosmetic display issue -- and previously also
        # silently discarded these real findings/URLs even when the
        # underlying emulation result was fine.
        for finding in result.get("findings", []):
            self._add_finding("Emulation", finding.get("rule_id", "finding"))
        for url in result.get("network_requests", []):
            u = url.get("url")
            if u:
                self._append_unique("extracted_urls", u)
        try:
            self._display_emulation_results(result)
        except Exception as exc:
            print(f"{errorS} Emulation completed but rendering its results failed: {_esc(str(exc))}")

        return result

    def _display_emulation_results(self, result):
        # Plain per-line output rather than rich Tables: a fixed-column
        # table degrades badly once real payload chunks (multi-hundred-
        # char base64 blobs, long command lines) show up. This mirrors
        # VBEmu's own `--trace` CLI output style.
        print(f"[dim]>>> Emulation finished "
              f"({result.get('elapsed_seconds', 0)}s, {result.get('step_count', 0):,} steps)[white]")

        for f in result.get("findings", []):
            sev = f.get("severity", "info").upper()
            sev_color = {"CRITICAL": "bold red", "HIGH": "bold red", "MEDIUM": "bold yellow",
                         "LOW": "bold blue", "INFO": "white"}.get(sev, "white")
            print(f"  [{sev_color}][{sev}][white] {_esc(f.get('title', ''))}")

        events = result.get("ioc_events", [])
        print(f"\n[bold cyan]Step-by-step call trace[white]  ({len(events)} events)")
        if not events:
            print("  [dim](no observable API calls -- script did nothing through a modeled API)[white]")
        else:
            t0 = events[0]["ts"]
            for i, e in enumerate(events, 1):
                cat = e["category"]
                fields = {k: v for k, v in e.items() if k not in ("category", "ts")}
                # Sample-controlled strings (paths, command lines, registry
                # values, ...) may contain "[...]" sequences -- rich's
                # console print() treats "[...]" as markup by default, so
                # without escaping, e.g. a literal "[void]" in a payload
                # silently vanishes from the trace instead of being shown.
                desc = _esc(_humanize_emulation_event(cat, fields))
                style = _EMU_CATEGORY_STYLE.get(cat, "")
                cat_col = f"[{style}]{cat:<20}[white]" if style else f"{cat:<20}"
                desc_col = f"[{style}]{desc}[white]" if style else desc
                print(f"  [dim]{i:>4} t+{e['ts'] - t0:6.3f}s[white] {cat_col} {desc_col}")

        net = [e for e in events if e["category"] in ("network_request", "network_send")]
        print("\n[bold cyan]Network activity[white]")
        if net:
            for e in net:
                fields = {k: v for k, v in e.items() if k not in ("category", "ts")}
                style = _EMU_CATEGORY_STYLE.get(e["category"], "")
                text = _esc(_humanize_emulation_event(e["category"], fields))
                print(f"  [{style}]{text}[white]" if style else f"  {text}")
        else:
            print("  [dim]none observed at the VBA/VBS layer[white]")

        if result.get("dropped_files"):
            print("\n[bold cyan]Files written/copied[white]")
            for d in result["dropped_files"]:
                susp = "  [bold red][suspicious ext][/bold red]" if d.get("suspicious_ext") else ""
                print(f"  [bold cyan]{_esc(d.get('path', ''))}[white]{susp}")

        persist = [r for r in result.get("registry_changes", []) if r.get("persistence")]
        if persist:
            print("\n[bold cyan]Persistence[white]")
            for r in persist:
                print(f"  [bold yellow]{_esc(r.get('key', ''))}[white] = {_esc(r.get('value', ''))}")

    def _append_unique(self, key, value):
        if value and value not in report[key]:
            report[key].append(value)

    def _add_finding(self, category, value):
        finding_key = f"{category}:{value}"
        if value and finding_key not in self._findings_seen:
            self._findings_seen.add(finding_key)
            report["categorized_findings"] += 1

    def _register_embedded(self, name, detail):
        entry = {"name": self._sanitize_text(name), "detail": self._sanitize_text(detail)}
        if entry not in report["embedded_files"]:
            report["embedded_files"].append(entry)

    def _register_section(self, key, value):
        report["sections"][key] = value

    def _sanitize_text(self, value):
        sanitized = ""
        for ch in str(value):
            sanitized += ch if ch.isprintable() else f"\\x{ord(ch):02x}"
        return sanitized

    def _sanitize_and_truncate(self, value, max_chars):
        sanitized = self._sanitize_text(value)
        if max_chars is None:
            return sanitized, False
        try:
            max_chars = int(max_chars)
        except Exception:
            max_chars = 0
        if max_chars > 0 and len(sanitized) > max_chars:
            return sanitized[:max_chars] + "\\n...<truncated>...", True
        return sanitized, False

    def _sanitize_stream_name(self, stream_name):
        return "/".join(self._sanitize_text(x) for x in str(stream_name).split("/"))

    def _normalize_url(self, raw_url):
        candidate = raw_url.strip().rstrip(".,;:)]}>\"'")
        parsed = urllib.parse.urlparse(candidate)
        if parsed.scheme not in ("http", "https"):
            return None
        if not parsed.netloc:
            return None
        host = parsed.netloc.split("@")[-1].split(":")[0].strip("[]")
        if host == "":
            return None
        return candidate

    def _extract_normalized_urls(self, text_buffer):
        urls = []
        for raw_url in URL_PATTERN.findall(text_buffer):
            sanitized = self._normalize_url(raw_url)
            if sanitized and chk_wlist(sanitized) and sanitized not in urls:
                urls.append(sanitized)
        return urls

    @staticmethod
    def _trim_to_known_magic(buffer):
        magic_map = {
            "ole": b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1",
            "mz": b"MZ",
            "zip": b"PK\x03\x04",
            "pdf": b"%PDF",
            "rtf": b"{\\rtf",
        }
        best_label = "raw"
        best_offset = -1
        for label, magic in magic_map.items():
            pos = buffer.find(magic)
            if pos != -1 and (best_offset == -1 or pos < best_offset):
                best_offset = pos
                best_label = label

        if best_offset > 0:
            return buffer[best_offset:], best_label, best_offset
        if best_offset == 0:
            return buffer, best_label, 0
        return buffer, best_label, -1

    @staticmethod
    def _is_short_symbolic_string(text):
        if len(text) > 6:
            return False
        symbol_chars = [")", "(", "[", "]", "+", "-", "<", ">", "*", "!"]
        return any(symbol in text for symbol in symbol_chars)

    def _attempt_default_decrypt(self):
        default_password = "VelvetSweatshop"
        if report["decryption"]["attempted"]:
            return

        report["decryption"]["attempted"] = True

        print(f"\n{infoS} FILEPASS detected. Trying automatic decryption...")
        if msoffcrypto is None:
            report["decryption"]["error"] = "msoffcrypto module not found"
            print(f"{errorS} Could not attempt decryption because [bold yellow]msoffcrypto-tool[white] is not installed.")
            return

        out_name = f"qu1cksc0pe_decrypted_{os.path.basename(self.targetFile)}"
        try:
            with open(self.targetFile, "rb") as infile:
                office_file = msoffcrypto.OfficeFile(infile)
                office_file.load_key(password=default_password)
                with open(out_name, "wb") as outfile:
                    office_file.decrypt(outfile)
            report["decryption"]["success"] = True
            report["decryption"]["output_file"] = out_name
            self.decrypted_output_file = out_name
            self._append_unique("extracted_files", out_name)
            self._add_finding("Macro", "default_password_decryption_success")
            print(f"{infoS} Decryption successful. Output file: [bold green]{out_name}[white]")
        except Exception as exc:
            report["decryption"]["error"] = str(exc)
            print(f"{errorS} Automatic decryption failed.")

    def analyze_decrypted_output(self):
        if self.auto_chain_mode:
            return
        if not self.decrypted_output_file:
            return
        if not os.path.exists(self.decrypted_output_file):
            report["decryption"]["auto_analysis"]["triggered"] = False
            report["decryption"]["auto_analysis"]["target_file"] = self.decrypted_output_file
            report["decryption"]["auto_analysis"]["exit_code"] = -1
            return

        print(f"\n{infoS} Automatically analyzing decrypted file...")
        report["decryption"]["auto_analysis"]["triggered"] = True
        report["decryption"]["auto_analysis"]["target_file"] = self.decrypted_output_file

        env = os.environ.copy()
        env["SC0PE_AUTO_DECRYPT_CHAIN"] = "1"
        auto_proc = subprocess.run(
            [sys.executable, __file__, self.decrypted_output_file, "False"],
            env=env
        )
        report["decryption"]["auto_analysis"]["exit_code"] = auto_proc.returncode

    # Checking for file extension
    def CheckExt(self):
        with open(self.targetFile, "rb") as file_ptr:
            magic_buf = file_ptr.read(8)
        doc_type = subprocess.run(["file", self.targetFile], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        decoded_doc_type = doc_type.stdout.decode()
        lower_file = self.targetFile.lower()
        lower_magic = decoded_doc_type.lower()
        report["file_magic"] = decoded_doc_type.strip()
        # Content/magic wins for HTML disguised with a VB-family suffix.
        # Otherwise `payload.vba` beginning with <script language=VBScript>
        # is fed to the bare VBA parser and fails on the markup itself.
        if "html document" in lower_magic:
            return "html"
        if lower_file.endswith((".vbs", ".vbe", ".vba", ".vb", ".bas", ".cls", ".frm", ".applescript")):
            return "vbscript"
        elif "vbscript" in lower_magic or "visual basic" in lower_magic:
            return "vbscript"
        if lower_file.endswith(".js"):
            return "javascript"
        if lower_file.endswith(".hta"):
            return "hta"
        if ("Microsoft Word" in decoded_doc_type or "Microsoft Excel" in decoded_doc_type
                or "Microsoft Office Word" in decoded_doc_type or "OOXML" in decoded_doc_type):
            return "docscan"
        elif "PDF document" in decoded_doc_type:
            return "pdfscan"
        elif self.targetFile.endswith(".one"): # TODO: Look for better solutions!
            return "onenote"
        elif ("Rich Text Format" in decoded_doc_type and binascii.unhexlify(b"7B5C72746631") in magic_buf) or (binascii.unhexlify(b"7B5C7274") in magic_buf):
            return "rtf"
        elif "Zip archive" in decoded_doc_type:
            return "archive_type_doc"
        else:
            return "unknown"

    # Perform analysis against embedded binaries
    def JARCheck(self):
        # Data for JAR analysis
        jar_chek = {}

        # Check if file is an JAR file (for embedded .jar based attacks)
        keywordz = ["JAR", ".class", "META-INF"]
        jTable = Table(title="* Matches *", title_style="bold italic cyan", title_justify="center")
        jTable.add_column("[bold green]Pattern", justify="center")
        jTable.add_column("[bold green]Count", justify="center")
        for key in keywordz:
            jstr = re.findall(key, str(self.binarydata))
            if len(jstr) != 0:
                jTable.add_row(key, str(len(jstr)))
            jar_chek.update({key: len(jstr)})

        # Condition for JAR file
        if jar_chek["JAR"] >= 1 or jar_chek[".class"] >= 2 or jar_chek["META-INF"] >= 1:
            print(f"[bold magenta]>>>[white] Binary Type: [bold green]JAR[white]")
            print(jTable)

    def VBasicCheck(self):
        # Data for VBA analysis
        vba_chek = {}

        # Check if file is an VBA file
        keywordz = [
            "Function", "Sub", "Dim", "End", "Document", "AutoOpen",
            "AutoClose", "AutoExec", "Shell", "CreateObject", "WScript",
            "VBScript", "Eval"
        ]
        vbaTable = Table(title="* Matches *", title_style="bold italic cyan", title_justify="center")
        vbaTable.add_column("[bold green]Pattern", justify="center")
        vbaTable.add_column("[bold green]Count", justify="center")
        for key in keywordz:
            vbastr = re.findall(key, str(self.binarydata))
            if len(vbastr) != 0:
                vbaTable.add_row(key, str(len(vbastr)))
            vba_chek.update({key: len(vbastr)})

        # Condition for VBA file
        if vba_chek["Function"] >= 1 or vba_chek["Sub"] >= 1 or vba_chek["Dim"] >= 1 or vba_chek["End"] >= 1 or vba_chek["Document"] >= 1:
            print(f"[bold magenta]>>>[white] Binary Type: [bold green]Composite Document File V2 Document (Contains possible VBA code!!)[white]")
            print(vbaTable)

    def BinaryAnalysis(self, component, binarydata):
        self.component = component
        self.binarydata = binarydata

        print(f"\n{infoS} Analyzing: [bold red]{self.component}")
        # Check if file is an JAR file (for embedded .jar based attacks)
        self.JARCheck()
        # Check if file is an VBA file
        self.VBasicCheck()
        
    # Function for perform file structure analysis
    def Structure(self):
        # We need to unzip the file and check for interesting files
        print(f"\n{infoS} Analyzing file structure...")
        if not zipfile.is_zipfile(self.targetFile):
            print(f"{infoS} ZIP-based document structure was not detected. Skipping ZIP parser.")
            self._add_finding("Structure", "zip_structure_unavailable")
            return

        try:
            with zipfile.ZipFile(self.targetFile) as document:
                bins = []
                archive_entries = []
                discovered_urls = []

                # Parsing the files
                docTable = Table(title="* Document Structure *", title_style="bold italic cyan", title_justify="center")
                docTable.add_column("[bold green]File Name", justify="center")
                for df in document.namelist():
                    archive_entries.append(df)
                    if ".bin" in df or "embeddings" in df or ".rtf" in df:
                        docTable.add_row(f"[bold red]{df}")
                        bins.append(df)
                        self._register_embedded(df, "archive_member")
                    else:
                        docTable.add_row(df)

                    # Parse links while traversing entries to avoid a second pass.
                    try:
                        entry_data = document.read(df).decode(errors="ignore")
                    except Exception:
                        continue
                    for sanitized_url in self._extract_normalized_urls(entry_data):
                        if sanitized_url not in discovered_urls:
                            discovered_urls.append(sanitized_url)
                print(docTable)
                self._register_section("archive_entries", archive_entries)
                self._add_finding("Structure", f"archive_member_count={len(archive_entries)}")

                # Perform analysis against binaries
                if bins:
                    for b in bins:
                        bdata = document.read(b)
                        self.BinaryAnalysis(b, bdata)

                # Check for interesting external links (effective against follina related samples and IoC extraction)
                print(f"\n{infoS} Searching for interesting links...")
                if discovered_urls:
                    exlinks = Table(title="* Interesting Links *", title_style="bold italic cyan", title_justify="center")
                    exlinks.add_column("[bold green]Link", justify="center")
                    for sanitized_url in discovered_urls:
                        self._append_unique("extracted_urls", sanitized_url)
                        exlinks.add_row(sanitized_url)
                    print(exlinks)
                else:
                    print(f"[bold white on red]There is no interesting links found.")
        except:
            print(f"{errorS} Error: Unable to unzip file.")

    # Macro parser function
    def MacroParser(self, macroList):
        self.macroList = macroList

        answerTable = Table()
        answerTable.add_column("[bold green]Threat Levels", justify="center")
        answerTable.add_column("[bold green]Macros", justify="center")
        answerTable.add_column("[bold green]Descriptions", justify="center")

        for fi in range(0, len(self.macroList)):
            if self.macroList[fi][0] == 'Suspicious':
                if "(use option --deobf to deobfuscate)" in self.macroList[fi][2]:
                    sanitized = f"{self.macroList[fi][2]}".replace("(use option --deobf to deobfuscate)", "")
                    answerTable.add_row(f"[bold yellow]{self.macroList[fi][0]}", f"{self.macroList[fi][1]}", f"{sanitized}")
                elif "(option --decode to see all)" in self.macroList[fi][2]:
                    sanitized = f"{self.macroList[fi][2]}".replace("(option --decode to see all)", "")
                    answerTable.add_row(f"[bold yellow]{self.macroList[fi][0]}", f"{self.macroList[fi][1]}", f"{sanitized}")
                else:
                    answerTable.add_row(f"[bold yellow]{self.macroList[fi][0]}", f"{self.macroList[fi][1]}", f"{self.macroList[fi][2]}")
            elif self.macroList[fi][0] == 'IOC':
                answerTable.add_row(f"[bold magenta]{self.macroList[fi][0]}", f"{self.macroList[fi][1]}", f"{self.macroList[fi][2]}")
            elif self.macroList[fi][0] == 'AutoExec':
                answerTable.add_row(f"[bold red]{self.macroList[fi][0]}", f"{self.macroList[fi][1]}", f"{self.macroList[fi][2]}")
            else:
                answerTable.add_row(f"{self.macroList[fi][0]}", f"{self.macroList[fi][1]}", f"{self.macroList[fi][2]}")
        print(answerTable)

    # A function that finds VBA Macros
    def MacroHunter(self):
        print(f"\n{infoS} Looking for Macros...")
        try:
            with open(self.targetFile, "rb") as file_ptr:
                fileData = file_ptr.read()
            vbaparser = VBA_Parser(self.targetFile, fileData)
            xlm_macro_lines = []
            macroList = []
            try:
                macroList = list(vbaparser.analyze_macros())
            except:
                pass
            try:
                xlm_macro_lines = list(vbaparser.xlm_macros)
            except:
                xlm_macro_lines = []
            macro_state_vba = 0
            macro_state_xlm = 0
            # Checking vba macros
            if vbaparser.contains_vba_macros == True:
                print(f"[bold red]>>>[white] VBA MACRO: [bold green]Found.")
                self._add_finding("Macro", "vba_macros")
                if vbaparser.detect_vba_stomping() == True:
                    print(f"[bold red]>>>[white] VBA Stomping: [bold green]Found.")
                    self._add_finding("Macro", "vba_stomping")

                else:
                    print(f"[bold red]>>>[white] VBA Stomping: [bold red]Not found.")
                self.MacroParser(macroList)
                macro_state_vba += 1
            else:
                print(f"[bold red]>>>[white] VBA MACRO: [bold red]Not found.\n")

            # Checking for xlm macros
            if vbaparser.contains_xlm_macros == True:
                print(f"\n[bold red]>>>[white] XLM MACRO: [bold green]Found.")
                self._add_finding("Macro", "xlm_macros")
                self.MacroParser(macroList)
                macro_state_xlm += 1
            else:
                print(f"\n[bold red]>>>[white] XLM MACRO: [bold red]Not found.")

            filepass_detected = any("FILEPASS" in str(xlm_line).upper() for xlm_line in xlm_macro_lines)
            if not filepass_detected and "FILEPASS" in allstr.upper():
                filepass_detected = True

            if filepass_detected:
                self._add_finding("Macro", "filepass_record")
                self._attempt_default_decrypt()

            # If there is macro we can extract it automatically.
            if macro_state_vba != 0 or macro_state_xlm != 0:
                auto_extract = str(os.environ.get("SC0PE_DOC_AUTO_EXTRACT_MACROS", "1")).strip().lower() not in ("0", "false", "no")
                if auto_extract:
                    print(f"\n{infoS} Automatic macro extraction is enabled. Attempting extraction...\n")
                    report["macros"]["extracted"] = True
                    max_macro_chars = int(os.environ.get("SC0PE_REPORT_MAX_MACRO_CHARS", "50000"))

                    # Populated below only when macro_state_vba != 0, but
                    # referenced after the extraction section (see the
                    # "Sandboxed behavior emulation" block past "Extraction
                    # completed.") regardless of which macro type was found.
                    activex_controls = {}
                    custom_doc_properties = {}
                    custom_xml_parts = {}
                    customui_callbacks = []
                    shape_callbacks = []
                    excel_cells = {}
                    modules_for_emulation = []

                    if macro_state_vba != 0:
                        all_vba_macros = list(vbaparser.extract_all_macros())

                        # Best-effort recovery of ActiveX form-control values
                        # (see vba_emulator/activex_extractor.py) -- a real
                        # technique where a macro's payload is hidden in a
                        # hidden control's .Value/.Text instead of the code
                        # itself, read back via ActiveDocument.<Name>.Value.
                        # Needs every module's code (for the Attribute
                        # VB_Control lines, in module order) plus the raw
                        # OOXML zip bytes (for word/activeX/activeXN.bin) --
                        # both already available here, so it's computed once
                        # up front and threaded into each macro's emulation
                        # run below.
                        if extract_activex_control_values is not None:
                            try:
                                macro_sources_for_activex = [
                                    (m[2] if len(m) > 2 else "", m[3] if len(m) > 3 else "")
                                    for m in all_vba_macros
                                ]
                                activex_controls = extract_activex_control_values(
                                    fileData, macro_sources_for_activex)
                            except Exception:
                                activex_controls = {}

                        # Best-effort recovery of docProps/custom.xml values
                        # (see vba_emulator/doc_properties_extractor.py) --
                        # a real technique where a macro's payload is split
                        # across custom document properties instead of
                        # living in the macro source, read back via
                        # ActiveDocument.CustomDocumentProperties(name).Value.
                        if extract_custom_document_properties is not None:
                            try:
                                custom_doc_properties = extract_custom_document_properties(fileData)
                            except Exception:
                                custom_doc_properties = {}

                        # Best-effort recovery of customXml/itemN.xml parts
                        # (see vba_emulator/custom_xml_extractor.py) -- a
                        # real technique where a macro's payload is stashed
                        # as a Custom XML Part instead of the macro source
                        # or a document property, read back via
                        # ActiveDocument.CustomXMLParts(uri).SelectSingleNode(...).Text.
                        if extract_custom_xml_parts is not None:
                            try:
                                custom_xml_parts = extract_custom_xml_parts(fileData)
                            except Exception:
                                custom_xml_parts = {}

                        # Recover stored worksheet values used by Excel VBA
                        # payloads such as `Sheets("Sheet 1").Range("B9")`
                        # followed by Offset() through a base64 blob. These
                        # values live in worksheet/sharedStrings XML, not in
                        # vbaProject.bin, so macro extraction alone cannot
                        # expose them to the interpreter.
                        if extract_excel_cell_values is not None:
                            try:
                                excel_cells = extract_excel_cell_values(fileData)
                            except Exception:
                                excel_cells = {}

                        # Best-effort recovery of Ribbon customUI callback
                        # names (see vba_emulator/customui_extractor.py) --
                        # e.g. `<customUI onLoad="rokky">` -- Word/Excel
                        # invokes these automatically on ribbon load, the
                        # same effective auto-exec behavior as
                        # Document_Open/AutoOpen under a macro name a scan
                        # of only the conventional AutoExec names would
                        # never invoke during emulation.
                        if extract_customui_callbacks is not None:
                            try:
                                customui_callbacks = extract_customui_callbacks(fileData)
                            except Exception:
                                customui_callbacks = []

                        # Recover procedures assigned to clickable Excel
                        # pictures/shapes (`<xdr:pic macro="...">` and
                        # `<xdr:sp macro="...">`). They are user-action
                        # callbacks rather than automatic open events, but an
                        # analysis sandbox should explore them just like a
                        # clicked lure button; otherwise these workbooks have
                        # no callable entry point and misleadingly report zero
                        # behavior.
                        if extract_shape_macro_callbacks is not None:
                            try:
                                shape_callbacks = extract_shape_macro_callbacks(fileData)
                            except Exception:
                                shape_callbacks = []

                        for mac in all_vba_macros:
                            # oletools typically returns: (container, stream_path, vba_filename, vba_code)
                            try:
                                container = mac[0] if len(mac) > 0 else ""
                                stream_path = mac[1] if len(mac) > 1 else ""
                                vba_filename = mac[2] if len(mac) > 2 else ""
                                vba_code = mac[3] if len(mac) > 3 else ""
                                code, truncated = self._sanitize_and_truncate(vba_code, max_macro_chars)
                                report["macros"]["vba"].append(
                                    {
                                        "container": self._sanitize_text(container),
                                        "stream": self._sanitize_text(stream_path),
                                        "module": self._sanitize_text(vba_filename),
                                        "code": code,
                                        "truncated": truncated,
                                    }
                                )
                                if truncated:
                                    report["macros"]["truncated"]["vba"] += 1

                                if vba_code and vba_code.strip():
                                    modules_for_emulation.append((vba_filename, vba_code))
                            except Exception:
                                code, truncated = self._sanitize_and_truncate(mac, max_macro_chars)
                                report["macros"]["vba"].append({"code": code, "truncated": truncated})
                                if truncated:
                                    report["macros"]["truncated"]["vba"] += 1

                            # Preserve existing console output behaviour.
                            try:
                                for xxx in mac:
                                    print(str(xxx).strip("\r\n"))
                            except Exception:
                                print(str(mac))

                    if macro_state_xlm != 0:
                        for mac in xlm_macro_lines:
                            line, truncated = self._sanitize_and_truncate(mac, max_macro_chars)
                            report["macros"]["xlm"].append({"line": line, "truncated": truncated})
                            if truncated:
                                report["macros"]["truncated"]["xlm"] += 1
                            print(mac)
                    print(f"\n{infoS} Extraction completed.")

                    # Sandboxed behavior emulation, run automatically *once* over
                    # every extracted module concatenated together rather
                    # than once per module -- after extraction/display is
                    # fully done and announced above, since this is a
                    # distinct (and comparatively slow) subsequent phase,
                    # not part of "extraction" itself. A real VBA project is
                    # one shared global namespace -- a Sub in one module can
                    # call a Public Sub in another directly, or
                    # module-qualified (e.g. a Document_Close handler doing
                    # `Module1.Checker` to reach a dropper Sub stashed in a
                    # separate module, a real pattern seen in the wild).
                    # Emulating each module as its own fully isolated
                    # program can never observe that call: the callee
                    # simply doesn't exist in that run, and the whole
                    # cross-module payload silently never executes. Uses
                    # the *full*, untruncated vba_code for every module --
                    # the report's "code" field above is only
                    # display-truncated.
                    if modules_for_emulation:
                        combined_code = "\n\n".join(code for _, code in modules_for_emulation)
                        module_names = [os.path.splitext(fname)[0] for fname, _ in modules_for_emulation if fname]
                        emu_origin = "VBA project: " + ", ".join(module_names) if module_names else "VBA project"
                        emu_result = self._run_emulation(combined_code, emu_origin,
                                                          activex_controls=activex_controls,
                                                          module_names=module_names,
                                                          custom_doc_properties=custom_doc_properties,
                                                          custom_xml_parts=custom_xml_parts,
                                                          extra_entry_points=sorted(
                                                              set(customui_callbacks + shape_callbacks),
                                                              key=str.lower),
                                                          excel_cells=excel_cells)
                        if emu_result is not None:
                            report["emulation"]["macros"].append(emu_result)
                else:
                    print(f"{infoS} Automatic macro extraction disabled by env [bold green]SC0PE_DOC_AUTO_EXTRACT_MACROS=0[white].")

        except:
            print(f"{errorS} An error occured while parsing that file for macro scan.")

    # Gathering basic informations
    def BasicInfoGa(self):
        # Check for ole structures
        if isOleFile(self.targetFile) == True:
            print(f"{infoS} Ole File: [bold green]True[white]")
            self.is_ole_file = True
            report["is_ole_file"] = True
        else:
            print(f"{infoS} Ole File: [bold red]False[white]")
            self.is_ole_file = False
            report["is_ole_file"] = False

        # Check for encryption
        if is_encrypted(self.targetFile) == True:
            print(f"{infoS} Encrypted: [bold green]True[white]")
            report["is_encrypted"] = True
        else:
            print(f"{infoS} Encrypted: [bold red]False[white]")
            report["is_encrypted"] = False

        # Perform file structure analysis
        self.Structure()

        # Perform Yara scan
        print(f"\n{infoS} Performing YARA rule matching...")
        yara_rule_scanner(self.rule_path, self.targetFile, report)

        # Perform Ole file analysis
        if self.is_ole_file:
            self.ole_stream_analysis()

        # VBA_MACRO scanner
        vbascan = OleID(self.targetFile)
        vbascan.check()
        # Sanitizing the array
        vba_params = []
        for vb in vbascan.indicators:
            vba_params.append(vb.id)

        if "vba_macros" in vba_params:
            for vb in vbascan.indicators:
                if vb.id == "vba_macros":
                    if vb.value == True:
                        print(f"{infoS} VBA Macros: [bold green]Found[white]")
                        self.MacroHunter()
                    else:
                        print(f"{infoS} VBA Macros: [bold red]Not Found[white]")
        else:
            self.MacroHunter()

    # Ole Stream analysis
    def ole_stream_analysis(self):
        olfl = OleFileIO(self.targetFile)
        olfl_table = Table(title="* Ole Directory *", title_style="bold italic cyan", title_justify="center")
        olfl_table.add_column("[bold green]Name", justify="center")
        olfl_table.add_column("[bold green]Size", justify="center")
        print(f"\n{infoS} Performing [bold green]Ole[white] file analysis...")

        # Enumerate directories
        olfl_table.add_row(olfl.root.name, str(olfl.root.size))
        ole_streams = [{"name": self._sanitize_stream_name(olfl.root.name), "size": str(olfl.root.size)}]
        dir_stream_buffer = b""
        embedded_ole_streams = 0
        for drc in olfl.listdir():
            dname = "/".join(drc)
            olfl_table.add_row(dname, str(olfl.get_size(dname)))
            sanitized_name = self._sanitize_stream_name(dname)
            ole_streams.append({"name": sanitized_name, "size": str(olfl.get_size(dname))})
            # MBD*/Package, MBD*/Ole and ObjectPool streams are common embedded object carriers.
            if (re.match(r"^MBD[0-9A-Fa-f]+/(Package|\x01?Ole)$", dname) is not None) or ("ObjectPool" in dname):
                self._register_embedded(sanitized_name, "ole_embedded_stream")
                embedded_ole_streams += 1
            dir_stream_buffer += olfl.openstream(dname).read()
        print(olfl_table)
        self._register_section("ole_streams", ole_streams)
        self._add_finding("OLE", f"stream_count={len(ole_streams)}")
        if embedded_ole_streams > 0:
            self._add_finding("OLE", f"embedded_stream_count={embedded_ole_streams}")

        # Extract strings from streams
        strings_base = re.findall(r"[^\x00-\x1F\x7F-\xFF]{4,}".encode(), dir_stream_buffer)
        widestr = re.findall(r"(?:[\x20-\x7E]\x00){4,}".encode(), dir_stream_buffer)
        for s in widestr: # Cleanup "\x00"
            if b"\x00" in s:
                strings_base.append(s.replace(b"\x00", b""))
        self.html_fetch_urls(str(strings_base))

    # Onenote analysis
    def OneNoteAnalysis(self):
        print(f"{infoS} Performing OneNote analysis...")

        # Looking for embedded urls
        urlswitch = 0
        print(f"\n{infoS} Searching for interesting links...")
        url_match = self._extract_normalized_urls(allstr)
        if url_match:
            for sanitized in url_match:
                print(f"[bold magenta]>>>[white] {sanitized}")
                self._append_unique("extracted_urls", sanitized)
                urlswitch += 1
        
        if urlswitch == 0:
            print(f"[bold white on red]There is no interesting links found.")

        # Read and parse
        print(f"\n{infoS} Searching for embedded data/files...")
        if "keyData" in allstr and "encryptedKey" in allstr:
            print(f"\n{infoS} [bold yellow]WARNING![white]: This document seems contain encrypted data. Trying to analyze it anyway...")

        try:
            doc_buffer = open(self.targetFile, "rb")
            onenote_obj = OneDocment(doc_buffer)
        except:
            err_exit(f"{errorS} An exception occured while reading data.")

        # Analysis of embedded file
        embedTable = Table(title="* Embedded Files *", title_style="bold italic cyan", title_justify="center")
        embedTable.add_column("[bold green]File Identity", justify="center")
        embedTable.add_column("[bold green]File Extension", justify="center")

        # Add table
        efs = onenote_obj.get_files()
        onenote_embeds = []
        for key in efs.keys():
            embedTable.add_row(efs[key]["identity"], efs[key]["extension"])
            onenote_embeds.append({"identity": efs[key]["identity"], "extension": efs[key]["extension"]})
            self._register_embedded(efs[key]["identity"], efs[key]["extension"])
        print(embedTable)
        self._register_section("onenote_embedded", onenote_embeds)
        self._add_finding("OneNote", f"embedded_count={len(onenote_embeds)}")

        # Extract embedded files
        print(f"\n{infoS} Performing embedded file extraction...")
        for key in efs.keys():
            with open(f"qu1cksc0pe_carved-{key}{efs[key]['extension']}", "wb") as binfile:
                binfile.write(efs[key]["content"])
            binfile.close()
            print(f"[bold magenta]>>>[white] Embedded file saved as: [bold green]qu1cksc0pe_carved-{key}{efs[key]['extension']}[white]")
            self._append_unique("extracted_files", f"qu1cksc0pe_carved-{key}{efs[key]['extension']}")

        # Perform Yara scan
        print(f"\n{infoS} Performing YARA rule matching...")
        yara_rule_scanner(self.rule_path, self.targetFile, report)

    # PDF analysis
    def PDFAnalysis(self):
        print(f"{infoS} Performing PDF analysis...")

        # Parsing the PDF
        try:
            pdata = open(self.targetFile, "rb")
            pdf = PDFParser(pdata)
            doc = PDFDocument(pdf)
        except Exception as er:
            err_exit(f"{errorS} Error: {er}")

        # Gathering meta information
        print(f"\n{infoS} Gathering meta information...")
        metaTable = Table(title="* Meta Information *", title_style="bold italic cyan", title_justify="center")
        metaTable.add_column("[bold green]Key", justify="center")
        metaTable.add_column("[bold green]Value", justify="center")
        pdf_meta = {}
        if doc.info != [] and doc.info[0] != {}:
            for vals in doc.info[0]:
                metaTable.add_row(f"[bold yellow]{vals}", f"{doc.info[0][vals]}")
                pdf_meta[str(vals)] = str(doc.info[0][vals])
            print(metaTable)
        else:
            print(f"{errorS} No meta information found.")
        self._register_section("pdf_meta", pdf_meta)

        # Gathering PDF catalog
        print(f"\n{infoS} Gathering PDF catalog...")
        suspicious_keys = []
        catalog_keys = []
        catalogTable = Table(title="* PDF Catalog *", title_style="bold italic cyan", title_justify="center")
        catalogTable.add_column("[bold green]Key", justify="center")
        for vals in doc.catalog:
            catalog_keys.append(str(vals))
            if "Type" in vals:
                pass
            elif "AcroForm" in vals or "JavaScript" in vals or "OpenAction" in vals or "JS" in vals or "EmbeddedFile" in vals:
                catalogTable.add_row(f"[bold red]{vals}") # Highlighting suspicious keys
                suspicious_keys.append(vals)
                self._add_finding("PDF", vals)
            else:
                catalogTable.add_row(vals)
        print(catalogTable)
        self._register_section("pdf_catalog_keys", catalog_keys)
        self._register_section("pdf_suspicious_catalog_keys", suspicious_keys)

        # Suspicous PDF strings
        print(f"\n{infoS} Searching for suspicious strings...")
        embedded_switch = 0
        sstr = 0
        suspicious = [
            "/JavaScript", "/JS", "/AcroForm", "/OpenAction", 
            "/Launch", "/LaunchUrl", "/EmbeddedFile", "/URI", 
            "/Action", "cmd.exe", "system32", "%HOMEDRIVE%",
            "<script>",
            r"[a-zA-Z0-9_.]*pdb", r"[a-zA-Z0-9_.]*vbs", 
            r"[a-zA-Z0-9_.]*vba", r"[a-zA-Z0-9_.]*vbe", 
            r"[a-zA-Z0-9_.]*exe", r"[a-zA-Z0-9_.]*ps1",
            r"[a-zA-Z0-9_.]*dll", r"[a-zA-Z0-9_.]*bat",
            r"[a-zA-Z0-9_.]*cmd", r"[a-zA-Z0-9_.]*tmp",
            r"[a-zA-Z0-9_.]*dmp", r"[a-zA-Z0-9_.]*cfg",
            r"[a-zA-Z0-9_.]*lnk", r"[a-zA-Z0-9_.]*config",
            r"[a-zA-Z0-9_.]*7z", r"[a-zA-Z0-9_.]*docx",
            r"[a-zA-Z0-9_.]*zip"
        ]
        sTable = Table(title="* Suspicious Strings *", title_style="bold italic cyan", title_justify="center")
        sTable.add_column("[bold green]String", justify="center")
        sTable.add_column("[bold green]Count", justify="center")
        suspicious_map = {}
        for s in suspicious:
            occur = re.findall(s, allstr)
            if len(occur) != 0:
                if s == "/EmbeddedFile":
                    embedded_switch += 1
                sTable.add_row(f"[bold red]{s}", f"{len(occur)}")
                suspicious_map[s] = len(occur)
                self._add_finding("PDF", f"{s}:{len(occur)}")
                sstr += 1

        if sstr != 0:
            print(sTable)
        else:
            print(f"{errorS} There is no suspicious strings found!")
        self._register_section("pdf_suspicious_strings", suspicious_map)

        # Looking for embedded links
        print(f"\n{infoS} Looking for embedded URL\'s via [bold green]Regex[white]...")
        urlTable = Table(title="* Embedded URL\'s *", title_style="bold italic cyan", title_justify="center")
        urlTable.add_column("[bold green]URL", justify="center")
        uustr = 0
        linkz = self._extract_normalized_urls(allstr)
        if linkz:
            for sanitized in linkz:
                urlTable.add_row(f"[bold yellow]{sanitized}")
                self._append_unique("extracted_urls", sanitized)
                uustr += 1
            if uustr != 0:
                print(urlTable)
            else:
                print(f"{infoS} There is no URL pattern found via regex!\n")
        else:
            print(f"{errorS} There is no URL pattern found via regex!\n")

        # PDF Stream analysis
        print(f"\n{infoS} Performing PDF stream analysis...")
        print(f"{infoS} Analyzing total objects...")
        # Iterate over objects and analyze them!
        number_of_objects = 0
        ext_urls = []
        pdf_objects = []
        for xref in doc.xrefs:
            if "ranges" in str(xref):
                temp_of_objects = xref.ranges[0][1]
            else:
                temp_of_objects = len(xref.get_objids())

            if number_of_objects != temp_of_objects:
                number_of_objects = temp_of_objects
                for obj in xref.get_objids():
                    try:
                        if "PDFStream" in str(doc.getobj(obj)):
                            object_data = doc.getobj(obj).get_rawdata() # Gather buffer from object
                            # Check if there is an zlib compression
                            try:
                                object_data = zlib.decompress(object_data)
                            except:
                                pass
                        else:
                            object_data = None

                        # Check for magic headers
                        if object_data:
                            hex_object_data = binascii.hexlify(object_data)
                            matched_category = None
                            for categ in self.file_sigs:
                                for pattern in self.file_sigs[categ]["patterns"]:
                                    if re.findall(pattern.encode(), hex_object_data):
                                        matched_category = categ
                                        break
                                if matched_category:
                                    break
                            if matched_category:
                                print(f"{infoS} Possible [bold green]{matched_category}[white] detected at [bold green]ObjectID[white]: [bold yellow]{obj}[white]")
                                print(f"{infoS} Attempting to extraction...")
                                self.output_writer(out_file=f"qu1cksc0pe_carved-{matched_category}-{obj}.bin", mode="wb", buffer=object_data)
                                self._register_embedded(f"ObjectID:{obj}", matched_category)
                                self._add_finding("PDF", f"embedded_{matched_category}")
                                pdf_objects.append({"object_id": obj, "category": matched_category})

                        # Check for /URI object
                        if "URI" in str(doc.getobj(obj)):
                            # Method 1
                            try:
                                raw_uri = doc.getobj(obj)["URI"].decode()
                                sanitized_uri = self._normalize_url(raw_uri)
                                if sanitized_uri and sanitized_uri not in ext_urls:
                                    ext_urls.append(sanitized_uri)
                                    self._append_unique("extracted_urls", sanitized_uri)
                            except:
                                pass

                            # Method 2
                            for sanitized in self._extract_normalized_urls(str(doc.getobj(obj))):
                                if sanitized not in ext_urls:
                                    ext_urls.append(sanitized)
                                    self._append_unique("extracted_urls", sanitized)

                        # Check for /EmbeddedFile stream
                        if "EmbeddedFile" in str(doc.getobj(obj)) and "PDFStream" in str(doc.getobj(obj)):
                            print(f"\n{infoS} Performing embedded file extraction...")
                            print(f"{infoS} Checking for compression...")
                            try:
                                decompressed = zlib.decompress(doc.getobj(obj).get_rawdata())
                                self.output_writer(out_file=f"qu1cksc0pe_embedded_decompressed_file-{obj}.bin", mode="wb", buffer=decompressed)
                            except:
                                self.output_writer(out_file=f"qu1cksc0pe_embedded_file-{obj}.bin", mode="wb", buffer=doc.getobj(obj).get_rawdata())
                    except:
                        continue
            else:
                pass

        # Print all
        if ext_urls != []:
            urlTable = Table()
            urlTable.add_column("[bold green]Extracted URI Values From Streams", justify="center")
            for ext in ext_urls:
                urlTable.add_row(ext)
            print(urlTable)
        self._register_section("pdf_stream_objects", pdf_objects)
        self._register_section("pdf_stream_url_count", len(ext_urls))

        # Perform Yara scan
        print(f"\n{infoS} Performing YARA rule matching...")
        yara_rule_scanner(self.rule_path, self.targetFile, report)

    # HTML analysis
    def html_fetch_urls(self, given_buffer):
        print(f"\n{infoS} Checking URL values...")
        url_vals = self._extract_normalized_urls(given_buffer)
        if not url_vals:
            print(f"{errorS} There is no URL value found!")
            return

        for sanitized in url_vals:
            self._append_unique("extracted_urls", sanitized)
        url_table = Table()
        url_table.add_column("[bold green]URL Values", justify="center")
        for url in url_vals:
            url_table.add_row(url)
        print(url_table)
        self._add_finding("Other", f"url_count={len(url_vals)}")

    def output_writer(self, out_file, mode, buffer):
        with open(out_file, mode) as ff:
            ff.write(buffer)
        print(f"{infoS} Data saved as: [bold yellow]{out_file}[white]")
        self._append_unique("extracted_files", out_file)

    def check_exploit_patterns(self, buffer):
        for exp_pattern in self.rtf_exploit_extract_dict:
            for pattern in self.rtf_exploit_extract_dict[exp_pattern]["pattern"]:
                chk_ex = re.findall(pattern, bytes.fromhex(buffer), re.IGNORECASE)
                if chk_ex != []:
                    print(f"{infoS} This file contains possible [bold green]{exp_pattern}[white] exploit. Performing extraction...")
                    self.pat_ct += 1
                    self.output_writer(out_file=f"qu1cksc0pe_extracted_exploit-{len(buffer)}.bin", mode="wb", buffer=binascii.unhexlify(buffer))

    def rtf_check_exploit_main(self, buffer):
        # METHOD 1: Check common patterns
        for exp_pattern in self.rtf_exploit_pattern_dict:
            check = re.findall(self.rtf_exploit_pattern_dict[exp_pattern]["detect_pattern"], buffer, re.IGNORECASE)
            if check != []:
                self.rtf_exploit_pattern_dict[exp_pattern]["occurence"] += 1
                bin_sec = re.findall(self.rtf_exploit_pattern_dict[exp_pattern]["pattern"], buffer, re.IGNORECASE)

                # Parse and extract \binxxx based patterns
                if self.pat_ct == 0 and (bin_sec != [] and exp_pattern == "bin"):
                    if len(bin_sec[-1]) > 20:
                        remove = re.findall(r'\\bin[0]+'.encode(), bin_sec[-1], re.IGNORECASE)
                        remove_1 = bin_sec[-1].replace(remove[0], b"")

                        # Check if any non hex character exist in buffer
                        if b"}}" in remove_1:
                            remove = re.findall(r'[a-z0-9]+\}\}|\}\}'.encode(), remove_1, re.IGNORECASE)
                            finalbuffer = remove_1.replace(remove[0], b"")
                        else:
                            finalbuffer = remove_1

                        print(f"{infoS} Looks like we found [bold green]{self.rtf_exploit_pattern_dict[exp_pattern]['name']}[white] pattern. Attempting to identify and extraction...")
                        self.rtf_check_exploit_parse(exploit_buffer=finalbuffer)

                # Parse and extract {\\?\\objudate} & {\\objupdate} & \\ods based patterns
                if self.pat_ct == 0 and (bin_sec != [] and (exp_pattern == "objupdate_1" or exp_pattern == "objupdate_2" or exp_pattern == "ods")):
                    print(f"{infoS} Looks like we found [bold green]{self.rtf_exploit_pattern_dict[exp_pattern]['name']}[white] pattern. Attempting to identify and extraction...")
                    self.rtf_check_exploit_parse(exploit_buffer=bin_sec[0][0]+bin_sec[0][1])

                # Parse and extract \\objdata based patterns
                if self.pat_ct == 0 and (bin_sec != [] and exp_pattern == "objdata"):
                    print(f"{infoS} Looks like we found [bold green]{self.rtf_exploit_pattern_dict[exp_pattern]['name']}[white] pattern. Attempting to identify and extraction...")
                    # Looking for hex data existence
                    for bsec in bin_sec:
                        if len(bsec) > 15:
                            self.rtf_check_exploit_parse(exploit_buffer=bsec)

        # METHOD 2: Read between brackets
        get_brackets = re.findall(rb'}[a-f0-9]*}}}', buffer, re.IGNORECASE)
        if get_brackets != [] and len(get_brackets[0]) > 15:
            print(f"{infoS} Looks like we found [bold green]possible exploit between brackets[white]. Attempting to identify and extraction...")
            self.pat_ct += 1
            finalbuffer = binascii.unhexlify(get_brackets[0].replace(b'}', b''))
            self.output_writer(out_file=f"qu1cksc0pe_extracted_exploit-{len(finalbuffer)}.bin", mode="wb", buffer=finalbuffer)

        # METHOD 2.1: Read between brackets (Formbook)
        get_brackets = re.findall(rb'}[0-9a-fA-F]+{', buffer, re.IGNORECASE)
        if get_brackets != []:
            for fff in get_brackets:
                if len(fff) > 15 and b"4d5a000000" in fff:
                    print(f"{infoS} Looks like we found [bold green]possible malicious code (Formbook) between brackets[white]. Attempting to identify and extraction...")
                    self.pat_ct += 1
                    finalbuffer = binascii.unhexlify(fff.replace(b"}", b"").replace(b"{", b""))
                    self.output_writer(out_file=f"qu1cksc0pe_extracted_malcode-{len(finalbuffer)}.bin", mode="wb", buffer=finalbuffer)
                    break
            
    def rtf_check_exploit_parse(self, exploit_buffer):
        if len(exploit_buffer) % 2 == 0:
            self.check_exploit_patterns(buffer=exploit_buffer.decode())
        else:
            if exploit_buffer.decode()[0] == "0":
                new_bin_sec = exploit_buffer.decode()[1:]
                self.check_exploit_patterns(buffer=new_bin_sec)
            elif exploit_buffer.decode()[0] == "f":
                new_bin_sec = exploit_buffer.decode()[1:]
                self.check_exploit_patterns(buffer=new_bin_sec)
            else:
                pass

    def rtf_objdata_fallback_carve(self, buffer):
        print(f"{infoS} Trying fallback extraction from [bold green]\\objdata[white] blocks...")
        obj_positions = [match.start() for match in re.finditer(rb'\\objdata', buffer, re.IGNORECASE)]
        if not obj_positions:
            print(f"{errorS} There is no [bold green]\\objdata[white] block for fallback extraction.")
            return 0

        carved_count = 0
        seen_digests = set()
        for idx, start_pos in enumerate(obj_positions):
            end_pos = obj_positions[idx+1] if idx+1 < len(obj_positions) else len(buffer)
            window = buffer[start_pos:end_pos]
            # Keep fallback bounded for performance and to avoid huge noisy scans.
            window = window[:300000]

            # Prefer the longest contiguous hex sequence within the objdata block.
            hex_candidates = re.findall(rb'[0-9a-fA-F]{80,}', window)
            if not hex_candidates:
                continue
            best_hex = max(hex_candidates, key=len)
            if len(best_hex) % 2 != 0:
                best_hex = best_hex[:-1]
            if len(best_hex) < 80:
                continue

            try:
                carved_data = binascii.unhexlify(best_hex)
            except Exception:
                continue
            if len(carved_data) < 32:
                continue

            carved_data, payload_label, payload_offset = self._trim_to_known_magic(carved_data)
            if payload_offset > 0:
                self._add_finding("RTF", f"objdata_magic_offset={payload_offset}")

            digest = hashlib.sha1(carved_data).hexdigest()
            if digest in seen_digests:
                continue
            seen_digests.add(digest)

            out_file = f"qu1cksc0pe_carved_objdata_fallback-{idx+1}-{payload_label}.bin"
            self.output_writer(out_file=out_file, mode="wb", buffer=carved_data)
            self._register_embedded(f"objdata_{idx+1}", "rtf_objdata_fallback")
            carved_count += 1

        if carved_count > 0:
            self._add_finding("RTF", f"objdata_fallback_carved={carved_count}")
            print(f"{infoS} Fallback extraction completed. Carved [bold green]{carved_count}[white] object(s).")
        else:
            print(f"{errorS} Fallback extraction could not recover valid embedded data.")
        return carved_count

    def RTFAnalysis(self):
        # Scan file buffer for interesting patterns
        print(f"{infoS} Performing detection of the malicious code patterns...")
        mal_ind = 0
        for pat in self.mal_rtf_code:
            scan_pattern = pat
            if "\\" in scan_pattern:
                scan_pattern = re.escape(scan_pattern)
            regx = re.findall(scan_pattern, allstr)
            if regx != []:
                mal_ind += 1
                self.mal_rtf_code[pat]["count"] = len(regx)
        if mal_ind != 0:
            att_types = []
            rtf_table = Table()
            rtf_table.add_column("[bold green]Pattern", justify="center")
            rtf_table.add_column("[bold green]Description", justify="center")
            rtf_table.add_column("[bold green]Count", justify="center")

            for pat in self.mal_rtf_code:
                if self.mal_rtf_code[pat]["count"] != 0:
                    rtf_table.add_row(str(pat), str(self.mal_rtf_code[pat]["description"]), str(self.mal_rtf_code[pat]["count"]))
                    self._add_finding("RTF", f"{pat}:{self.mal_rtf_code[pat]['count']}")

                    if self.mal_rtf_code[pat]["type"] not in att_types:
                        att_types.append(self.mal_rtf_code[pat]["type"])
            print(rtf_table)
            print(f"{infoS} Keywords for this sample: [bold red]{att_types}[white]")
            self._register_section("rtf_attack_keywords", att_types)

            # Check for suspicious unescape pattern
            if self.mal_rtf_code["unescape"]["count"] != 0:
                unesc = re.findall(r'unescape\(\s*\'([^\']*)\'\s*\)', allstr)
                if unesc != []:
                    print(f"\n{infoS} Looks like we have obfuscated value via [bold green]unescape[white]. Performing deobfuscation...")
                    for un in unesc:
                        deobf = urllib.parse.unquote(un)
                        self.output_writer(out_file=f"qu1cksc0pe_deobfuscated_unescape-{len(deobf)}.bin", mode="w", buffer=deobf)
        else:
            print(f"{errorS} There is no malicious pattern found!")

        # Exploit detection and extraction
        print(f"\n{infoS} Performing embedded exploit/script detection...")
        fbuffer = open(self.targetFile, "rb").read()
        buf_trim = fbuffer.replace(b"\r", b"").replace(b"\t", b"").replace(b"\n", b"").replace(b" ", b"")
        print(f"{infoS} Looking for embedded binary sections...")
        self.rtf_check_exploit_main(buffer=buf_trim)
        if self.pat_ct == 0:
            print(f"{errorS} There is no suspicious embedded exploit/script pattern detected!")
            self.rtf_objdata_fallback_carve(buffer=buf_trim)
        else:
            self._add_finding("RTF", f"embedded_exploit_count={self.pat_ct}")

        # Get url values
        self.html_fetch_urls(allstr)

        # Perform Yara scan
        print(f"\n{infoS} Performing YARA rule matching...")
        yara_rule_scanner(self.rule_path, self.targetFile, report)

    def archive_type_analyzer(self):
        print(f"{infoS} Parsing contents of the target document...")
        self.Structure()

    def _decode_script_bytes(self, script_bytes):
        # Plain `.decode("utf-8", errors="ignore")` silently mangles any
        # UTF-16 .vbs file (common -- many Windows script editors/droppers
        # save .vbs as UTF-16LE) into mostly-empty text: every ASCII byte
        # is followed by a null byte, and "ignore" just drops most of it.
        # That broke both the pre-existing static pattern analysis (every
        # category showed 0 hits despite YARA matching real UTF-16-encoded
        # "CreateObject" bytes in the same file) and, later, emulation
        # (0 steps / empty program) -- found while wiring up emulation.
        if script_bytes[:2] == b"\xff\xfe":
            return script_bytes[2:].decode("utf-16-le", errors="ignore")
        if script_bytes[:2] == b"\xfe\xff":
            return script_bytes[2:].decode("utf-16-be", errors="ignore")
        if script_bytes[:3] == b"\xef\xbb\xbf":
            return script_bytes[3:].decode("utf-8", errors="ignore")
        # No BOM: a text file that's actually UTF-16 without one still has
        # a very high proportion of null bytes (one per ASCII character).
        # Plain UTF-8/ASCII source essentially never does.
        if script_bytes and (script_bytes.count(b"\x00") / len(script_bytes)) > 0.25:
            try:
                return script_bytes.decode("utf-16-le")
            except UnicodeDecodeError:
                pass
        try:
            return script_bytes.decode("utf-8")
        except UnicodeDecodeError:
            return script_bytes.decode("latin-1", errors="ignore")

    def VBScriptAnalysis(self):
        try:
            with open(self.targetFile, "rb") as fptr:
                script_bytes = fptr.read()
        except Exception as exc:
            err_exit(f"{errorS} Could not read target script. Details: {exc}")

        script_text = self._decode_script_bytes(script_bytes)
        if script_text.strip() == "":
            script_text = allstr

        if looks_like_applescript(script_text):
            report["document_type"] = "applescript"
            report["script_analysis"]["language"] = "AppleScript"
            self._add_finding("AppleScript", "use_analyze_instead_of_docs")
            target = _esc(self._sanitize_text(self.targetFile))
            print(f"{errorS} AppleScript analysis is not supported by [bold green]--docs[white]. "
                  f"Use [bold green]--analyze[white] instead:\n"
                  f"    [bold cyan]python3 qu1cksc0pe.py --file \"{target}\" --analyze[white]")
            return

        if looks_like_batch_script(script_text):
            report["document_type"] = "batch_script"
            report["script_analysis"]["language"] = "Windows Batch"
            self._add_finding("Batch", "use_analyze_instead_of_docs")
            target = _esc(self._sanitize_text(self.targetFile))
            print(f"{errorS} Batch script analysis is not supported by [bold green]--docs[white]. "
                  f"Use [bold green]--analyze[white] instead:\n"
                  f"    [bold cyan]python3 qu1cksc0pe.py --file \"{target}\" --analyze[white]")
            return

        print(f"{infoS} Performing VBScript/VBA static analysis...")

        lower_file = self.targetFile.lower()
        if lower_file.endswith(".vbs") or lower_file.endswith(".vbe"):
            report["script_analysis"]["language"] = "VBScript"
        elif lower_file.endswith(".vba") or lower_file.endswith(".vb") or lower_file.endswith(".bas") or lower_file.endswith(".cls") or lower_file.endswith(".frm"):
            report["script_analysis"]["language"] = "VBA Script"
        else:
            report["script_analysis"]["language"] = "VB Family Script"

        # VBE encoded scripts usually contain this marker.
        if "#@~^" in script_text:
            report["script_analysis"]["vbe_encoded"] = True
            self._add_finding("VBScript", "vbe_encoded_marker")
            print(f"{infoS} Encoded VBE marker detected ([bold yellow]#@~^[white]).")
        else:
            # Automatic sandboxed behavior emulation. MS Script Encoder
            # (.vbe) obfuscated files are skipped -- decoding that cipher
            # is not implemented, so there's no plaintext to emulate.
            emu_result = self._run_emulation(script_text, os.path.basename(self.targetFile))
            if emu_result is not None:
                report["emulation"]["script"] = emu_result

        vb_patterns = {
            "AutoExec": [
                r"\bAuto(?:Open|Close|Exec|Exit)\b",
                r"\bDocument_(?:Open|Close)\b",
                r"\bWorkbook_(?:Open|Close)\b"
            ],
            "Execution": [
                r"\bCreateObject\s*\(",
                r"\bGetObject\s*\(",
                r"\bWScript\.Shell\b",
                r"\bShell\s*\(",
                r"\bExec\s*\(",
                r"\bRun\s*\(",
                r"\bExecute(?:Global)?\b",
                r"\bEval\b"
            ],
            "Network": [
                r"\bMSXML2\.(?:XMLHTTP|ServerXMLHTTP)\b",
                r"\bWinHttp\.WinHttpRequest\b",
                r"\bURLDownloadToFile(?:A|W)?\b",
                r"\bADODB\.Stream\b",
                r"\bbitsadmin\b",
                r"\bcertutil\b"
            ],
            "Persistence": [
                r"\bRegWrite\b",
                r"\bCurrentVersion\\Run(?:Once)?\b",
                r"\b(?:HKCU|HKLM)\\",
                r"\bschtasks\b",
                r"\bwinmgmts\b",
                r"\bWin32_Process\b",
                r"\bStartup\b"
            ],
            "Obfuscation": [
                r"\bChrW?\s*\(",
                r"\bStrReverse\s*\(",
                r"\bSplit\s*\(",
                r"\bJoin\s*\(",
                r"\bReplace\s*\(",
                r"\bMid(?:B)?\s*\(",
                r"\bAscW?\s*\(",
                r"\bXor\b",
                r"\bFromBase64String\b",
                r"[A-Za-z0-9+/]{100,}={0,2}"
            ],
            "FileSystem": [
                r"\bScripting\.FileSystemObject\b",
                r"\bCreateTextFile\b",
                r"\bOpenTextFile\b",
                r"\bSaveToFile\b",
                r"\bWriteFile\b",
                r"\bCopyFile\b"
            ]
        }

        summary_table = Table(title="* VBScript/VBA Pattern Summary *", title_style="bold italic cyan", title_justify="center")
        summary_table.add_column("[bold green]Category", justify="center")
        summary_table.add_column("[bold green]Count", justify="center")

        for category, p_list in vb_patterns.items():
            hits = []
            seen = set()
            for pattern in p_list:
                for mt in re.finditer(pattern, script_text, re.IGNORECASE):
                    matched = mt.group(0).strip()
                    if matched and matched not in seen:
                        seen.add(matched)
                        hits.append(self._sanitize_text(matched))
            if hits:
                summary_table.add_row(f"[bold red]{category}", str(len(hits)))
                self._add_finding("VBScript", f"{category.lower()}={len(hits)}")
            else:
                summary_table.add_row(category, "0")
            report["script_analysis"]["categories"][category] = hits
            self._register_section(f"vbscript_{category.lower()}_hits", hits)

        print(summary_table)

        # Print per-category matched values for categories with hits.
        for cat, hits in report["script_analysis"]["categories"].items():
            if not hits:
                continue
            det_table = Table(
                title=f"* {cat} Matches *",
                title_style="bold italic cyan", title_justify="center"
            )
            det_table.add_column("[bold green]Matched Value", justify="left")
            for h in hits[:50]:
                det_table.add_row(h)
            print(det_table)

        # Common COM object and command extraction.
        create_obj = []
        for mt in re.finditer(r'CreateObject\s*\(\s*"([^"]+)"\s*\)', script_text, re.IGNORECASE):
            val = self._sanitize_text(mt.group(1))
            if val not in create_obj:
                create_obj.append(val)
        report["script_analysis"]["createobject_values"] = create_obj
        if create_obj:
            obj_table = Table(title="* CreateObject Values *", title_style="bold italic cyan", title_justify="center")
            obj_table.add_column("[bold green]ProgID", justify="center")
            for obj in create_obj:
                obj_table.add_row(obj)
            print(obj_table)

        shell_cmds = []
        cmd_patterns = [
            r'(?:WScript\.Shell\s*\.\s*Run|WScript\.Shell\s*\.\s*Exec)\s*\(\s*"([^"]+)"',
            r'\bShell\s*\(\s*"([^"]+)"'
        ]
        for cp in cmd_patterns:
            for mt in re.finditer(cp, script_text, re.IGNORECASE):
                cmd = self._sanitize_text(mt.group(1).strip())
                if cmd and cmd not in shell_cmds:
                    shell_cmds.append(cmd)
        report["script_analysis"]["shell_commands"] = shell_cmds
        if shell_cmds:
            cmd_table = Table(title="* Potential Shell Commands *", title_style="bold italic cyan", title_justify="center")
            cmd_table.add_column("[bold green]Command", justify="center")
            for cmd in shell_cmds:
                cmd_table.add_row(cmd)
                self._add_finding("VBScript", "shell_command")
            print(cmd_table)

        # Decode Base64 payloads for quick triage hints.
        # Minimum 8 groups of 4 chars (32 chars) to avoid false positives.
        # Try UTF-16-LE first (PowerShell -EncodedCommand uses it), then UTF-8.
        decoded_hints = []
        b64_candidates = re.findall(
            r"(?:[A-Za-z0-9+/]{4}){8,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?",
            script_text
        )
        for candidate in b64_candidates[:60]:
            # Hex hashes are also syntactically valid base64. Decoding them
            # as UTF-16 produces printable but meaningless glyphs.
            if re.fullmatch(r"[0-9A-Fa-f]+", candidate) and len(candidate) % 2 == 0:
                continue
            decoded = None
            for encoding in ("utf-16-le", "utf-8", "latin-1"):
                try:
                    raw = base64.b64decode(candidate + "==")
                    text = raw.decode(encoding, errors="ignore")
                    text = text.strip()
                    if len(text) < 8:
                        continue
                    printable_ratio = sum(
                        ch in "\r\n\t" or 32 <= ord(ch) <= 126 for ch in text
                    ) / max(len(text), 1)
                    if printable_ratio < 0.65:
                        continue
                    decoded = text
                    break
                except Exception:
                    continue
            if not decoded:
                continue
            hint, truncated = self._sanitize_and_truncate(decoded, 200)
            if hint and hint not in decoded_hints:
                decoded_hints.append(hint)
            if truncated:
                self._add_finding("VBScript", "decoded_payload_truncated")
            if len(decoded_hints) >= 20:
                break
        report["script_analysis"]["decoded_payload_hints"] = decoded_hints
        self._register_section("vbscript_decoded_payload_hint_count", len(decoded_hints))
        if decoded_hints:
            dec_table = Table(title="* Decoded Payload Hints *", title_style="bold italic cyan", title_justify="center")
            dec_table.add_column("[bold green]Snippet", justify="center")
            for hint in decoded_hints:
                dec_table.add_row(hint)
            print(dec_table)

        # URL extraction
        print(f"\n{infoS} Looking for embedded URL values...")
        url_hits = self._extract_normalized_urls(script_text)
        if url_hits:
            url_table = Table(title="* Extracted URLs *", title_style="bold italic cyan", title_justify="center")
            url_table.add_column("[bold green]URL", justify="center")
            for url in url_hits:
                url_table.add_row(url)
                self._append_unique("extracted_urls", url)
            print(url_table)
            self._add_finding("VBScript", f"url_count={len(url_hits)}")
        else:
            print(f"{errorS} There is no URL value found!")

        # Perform Yara scan
        print(f"\n{infoS} Performing YARA rule matching...")
        yara_rule_scanner(self.rule_path, self.targetFile, report)

# Execution area
try:
    docObj = DocumentAnalyzer(targetFile)
    ext = docObj.CheckExt()
    report["document_type"] = ext
    if ext == "docscan" or ext == "archive_type_doc":
        docObj.BasicInfoGa()
    elif ext == "pdfscan":
        docObj.PDFAnalysis()
    elif ext == "onenote":
        docObj.OneNoteAnalysis()
    elif ext in ("html", "javascript", "hta"):
        print(f"{errorS} HTML, JavaScript, and HTA files are not supported by [bold green]--docs[white]. Use [bold green]--analyze[white] instead.")
    elif ext == "rtf":
        docObj.RTFAnalysis()
    elif ext == "vbscript":
        docObj.VBScriptAnalysis()
    elif ext == "unknown":
        print(f"{errorS} Analysis technique is not implemented for now. Please send the file to the developer for further analysis.")
    else:
        print(f"{errorS} File format is not supported.")
    docObj.analyze_decrypted_output()
    if get_argv(2) == "True":
        save_report("document", report)
except Exception as exc:
    err_exit(f"{errorS} An error occured while analyzing that file. Details: {exc}")
