#!/usr/bin/python3

import re
import os
import sys
import json
import base64
import subprocess
import configparser
import urllib.parse
from bs4 import BeautifulSoup
from analysis.multiple.multi import chk_wlist, perform_strings, yara_rule_scanner, calc_hashes
from utils.helpers import err_exit, get_argv, save_report

# Native JavaScript behavior emulator.  It abstractly interprets common
# browser/WSH/Node malware APIs and never executes the sample in a JS runtime.
# Keep this optional so static analysis remains available in partial installs.
try:
    from js_emulator import emulate_javascript
except Exception:
    emulate_javascript = None

try:
    from rich import print
    from rich.markup import escape as _esc
    from rich.table import Table
except:
    err_exit("Error: >rich< module not found.")

try:
    import yara
except:
    err_exit("Error: >yara< module not found.")

# Legends
infoS = f"[bold cyan][[bold red]*[bold cyan]][white]"
errorS = f"[bold cyan][[bold red]![bold cyan]][white]"
URL_REGEX = r"https?://[^\s'\"<>()]+"
URL_PATTERN = re.compile(URL_REGEX)
# Matches js_emulator.MAX_SOURCE_CHARS (20M chars): UTF-16 samples need
# 2 bytes/char, so this must be at least 2x that to avoid truncating the
# raw read before the decoder even sees the tail of a large UTF-16 sample.
MAX_SCRIPT_FILE_BYTES = 48 * 1024 * 1024

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

# Report — document schema (matches document_analyzer.py so save_report("document",...) works)
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
    "emulation": {
        "enabled": False,
        "javascript": []
    }
}


class HTMLScriptAnalyzer:
    def __init__(self, targetFile):
        self.targetFile = targetFile
        self.rule_path = conf["Rule_PATH"]["rulepath"]
        self._findings_seen = set()
        report["filename"] = self.targetFile
        calc_hashes(self.targetFile, report)
        report["all_strings"] = len(allstr.split("\n"))
        self.base64_pattern = r'(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{4})'
        with open(f"{sc0pe_path}{path_seperator}Systems{path_seperator}Multiple{path_seperator}malicious_html_codes.json", "r") as fp:
            self.mal_code = json.load(fp)

    # ── Utility helpers ──────────────────────────────────────────────────────

    def _append_unique(self, key, value):
        if value and value not in report[key]:
            report[key].append(value)

    def _add_finding(self, category, value):
        finding_key = f"{category}:{value}"
        if value and finding_key not in self._findings_seen:
            self._findings_seen.add(finding_key)
            report["categorized_findings"] += 1

    def _register_section(self, key, value):
        report["sections"][key] = value

    def _sanitize_text(self, value):
        return "".join(ch if ch.isprintable() else f"\\x{ord(ch):02x}" for ch in str(value))

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
    def _is_short_symbolic_string(text):
        if len(text) > 6:
            return False
        symbol_chars = [")", "(", "[", "]", "+", "-", "<", ">", "*", "!"]
        return any(symbol in text for symbol in symbol_chars)

    def output_writer(self, out_file, mode, buffer):
        # Carved names are derived from attacker-controlled content lengths.
        # Use exclusive creation so an existing file or symlink is never
        # followed or silently overwritten.
        requested = os.path.basename(str(out_file))
        stem, suffix = os.path.splitext(requested)
        actual = requested
        fd = None
        for index in range(1000):
            if index:
                actual = f"{stem}-{index}{suffix}"
            try:
                flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
                fd = os.open(actual, flags, 0o600)
                break
            except FileExistsError:
                continue
        if fd is None:
            raise OSError(f"Could not allocate a unique output name for {requested}")
        if "b" in mode:
            with os.fdopen(fd, "wb") as ff:
                ff.write(buffer)
        else:
            with os.fdopen(fd, "w", encoding="utf-8", errors="ignore") as ff:
                ff.write(buffer)
        print(f"{infoS} Data saved as: [bold yellow]{_esc(actual)}[white]")
        self._append_unique("extracted_files", actual)
        return actual

    def _read_target_bytes(self):
        try:
            with open(self.targetFile, "rb") as source_file:
                data = source_file.read(MAX_SCRIPT_FILE_BYTES + 1)
        except OSError:
            return b""
        if len(data) > MAX_SCRIPT_FILE_BYTES:
            try:
                original_size = os.path.getsize(self.targetFile)
            except OSError:
                original_size = len(data)
            report["sections"]["script_input_truncated"] = {
                "limit_bytes": MAX_SCRIPT_FILE_BYTES,
                "original_size_bytes": original_size,
            }
            return data[:MAX_SCRIPT_FILE_BYTES]
        return data

    def _decode_script_bytes(self, script_bytes):
        # Plain `.decode("utf-8", errors="ignore")` silently mangles any
        # UTF-16 .js/.hta file (common -- many WSH droppers are saved as
        # UTF-16LE) into mostly-empty text: every ASCII byte is followed by
        # a null byte, and "ignore" just drops most of it. That breaks both
        # the static pattern analysis (every category shows 0 hits despite
        # YARA matching the same UTF-16-encoded strings) and emulation
        # (0 steps / empty program). Mirrors document_analyzer.py's fix for
        # the same issue in .vbs files.
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

    def _read_target_text(self):
        return self._decode_script_bytes(self._read_target_bytes())

    # ── Sandboxed JavaScript behavior emulation ─────────────────────────────

    def _run_javascript_emulation(self, source, origin):
        if emulate_javascript is None or not source or not source.strip():
            return None

        # js_emulator._bounded_timeout() already permits up to 30s; large,
        # deliberately padded samples (junk-character-stuffed source well
        # past the old 8M-char cap) can need close to that just to reach
        # their first network/process call, so use the full budget.
        timeout_seconds = 30
        print(f"\n{infoS} Emulating [bold green]{_esc(self._sanitize_text(origin))}[white] "
              f"(isolated, in-memory, up to {timeout_seconds}s)...")
        try:
            result = emulate_javascript(source, origin=origin, timeout_seconds=timeout_seconds)
        except Exception as exc:
            print(f"{errorS} JavaScript emulation failed: {_esc(str(exc))}")
            return None

        report["emulation"]["enabled"] = True
        report["emulation"]["javascript"].append(result)
        for finding in result.get("findings", []):
            self._add_finding("JavaScript Emulation", finding.get("rule_id", "finding"))
        for request in result.get("network_requests", []):
            normalized = self._normalize_url(str(request.get("url", "")))
            if normalized and chk_wlist(normalized):
                self._append_unique("extracted_urls", normalized)

        try:
            self._display_javascript_emulation(result)
        except Exception as exc:
            print(f"{errorS} JavaScript emulation completed but rendering failed: {_esc(str(exc))}")
        return result

    def _display_javascript_emulation(self, result):
        print(f"[dim]>>> Emulation finished ({result.get('elapsed_seconds', 0)}s, "
              f"{result.get('step_count', 0):,} steps, engine: "
              f"{_esc(result.get('engine', 'unknown'))})[white]")
        for finding in result.get("findings", []):
            severity = finding.get("severity", "info").upper()
            color = {
                "HIGH": "bold red", "MEDIUM": "bold yellow", "LOW": "bold blue",
                "INFO": "white",
            }.get(severity, "white")
            print(f"  [{color}][{severity}][white] {_esc(finding.get('title', ''))}")

        events = result.get("ioc_events", [])
        print(f"\n[bold cyan]JavaScript behavior trace[white]  ({len(events)} events)")
        if not events:
            print("  [dim](no behavior observed through a modeled JavaScript API)[white]")
        else:
            display_limit = 250
            for index, event in enumerate(events[:display_limit], 1):
                category = event.get("category", "event")
                details = []
                for key, value in event.items():
                    if key in ("category", "ts") or value in (None, ""):
                        continue
                    safe_value, _truncated = self._sanitize_and_truncate(value, 1024)
                    details.append(f"{key}={safe_value}")
                detail_text, _detail_truncated = self._sanitize_and_truncate(", ".join(details), 4096)
                detail_text = _esc(detail_text)
                print(f"  [dim]{index:>4} t+{event.get('ts', 0):6.3f}s[white] "
                      f"[bold magenta]{_esc(category):<20}[white] {detail_text}")
            if len(events) > display_limit:
                print(f"  [dim]... {len(events) - display_limit} additional events are available in the JSON report.[white]")

        network_events = [
            event for event in events
            if event.get("category") in (
                "network_request", "network_send", "network_download_capability",
                "network_c2_capability", "network_indicator"
            )
        ]
        print("\n[bold cyan]Network activity[white]")
        if not network_events:
            incomplete_payloads = [
                event for event in events
                if event.get("category") == "embedded_payload_truncated"
            ]
            if incomplete_payloads:
                print("  [bold yellow]unresolved[white] exact downstream network activity could not be "
                      "recovered because an embedded executable is incomplete")
                for event in incomplete_payloads:
                    print(f"  [dim]payload_sha256={_esc(event.get('payload_sha256', 'unknown'))}, "
                          f"recovered_size={_esc(event.get('recovered_size', 'unknown'))}, "
                          f"declared_size={_esc(event.get('declared_size', 'unknown'))}[white]")
            else:
                print("  [dim]none observed at the JavaScript/embedded-payload layer[white]")
        else:
            for event in network_events:
                details = []
                for key, value in event.items():
                    if key in ("category", "ts") or value in (None, ""):
                        continue
                    safe_value, _truncated = self._sanitize_and_truncate(value, 1024)
                    details.append(f"{key}={safe_value}")
                print(f"  [bold yellow]{_esc(event.get('category', 'network'))}[white] "
                      f"{_esc(', '.join(details))}")

    def _emulate_inline_javascript(self, html_text, origin_label):
        if not html_text.strip():
            return None
        soup = BeautifulSoup(html_text, "html.parser")
        blocks = []
        for tag in soup.find_all("script"):
            language = str(tag.get("language") or tag.get("type") or "").lower()
            if "vbscript" in language or tag.get("src"):
                continue
            body = tag.string if tag.string is not None else tag.get_text()
            if body and body.strip():
                blocks.append(body)

        # Browser malware frequently hides the only executable statements in
        # onload/onclick attributes or javascript: URLs rather than <script>.
        for tag in soup.find_all(True):
            for attribute, value in tag.attrs.items():
                if isinstance(value, list):
                    value = " ".join(str(item) for item in value)
                value = str(value)
                if str(attribute).lower().startswith("on") and value.strip():
                    blocks.append(value)
                elif value.lower().startswith("javascript:"):
                    blocks.append(value[len("javascript:"):])

        if not blocks:
            return None
        combined = "\n;\n".join(blocks)
        self._register_section("inline_javascript_blocks", len(blocks))
        return self._run_javascript_emulation(combined, origin_label)

    # ── Shared analysis helpers ───────────────────────────────────────────────

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

    def html_detect_malicious_code(self, given_buffer):
        # Check for malicious code patterns
        print(f"\n{infoS} Performing detection of the malicious code patterns...")
        mind = 0
        for mc in self.mal_code:
            mtc = re.findall(mc, given_buffer, re.IGNORECASE)
            if mtc != []:
                mind += 1
                self.mal_code[mc]["count"] = len(mtc)
        if mind != 0:
            att_types = []
            mal_table = Table()
            mal_table.add_column("[bold green]Pattern", justify="center")
            mal_table.add_column("[bold green]Description", justify="center")
            for mc in self.mal_code:
                if self.mal_code[mc]["count"] != 0:
                    mal_table.add_row(str(mc), self.mal_code[mc]["description"])
                    self._add_finding("HTML", f"{mc}:{self.mal_code[mc]['count']}")

                    # Parsing attack keywords
                    if self.mal_code[mc]["type"] not in att_types:
                        att_types.append(self.mal_code[mc]["type"])
            print(mal_table)
            print(f"{infoS} Keywords for this sample: [bold red]{att_types}[white]")
            self._register_section("html_attack_keywords", att_types)
        else:
            print(f"{errorS} There is no pattern found!")

    # ── HTML-specific helpers ─────────────────────────────────────────────────

    def chk_b64(self, given_buffer):
        keywords_to_check = [r"function", r"_0x", r"parseInt", r"script", r"var", r"document", r"src", r"atob", r"eval"]
        decc = []
        for cod in re.findall(self.base64_pattern, given_buffer):
            try:
                decoded_text = base64.b64decode(cod).decode()
            except:
                continue

            if self._is_short_symbolic_string(decoded_text):
                continue

            key_count = 0
            for key in keywords_to_check:
                km = re.findall(key, decoded_text)
                if km != []:
                    key_count += 1

            # If we have target patterns and the decoded payload is very large, save it as file.
            if key_count != 0 and len(decoded_text) >= 150:
                print(f"\n{infoS} Warning length of the decoded data is bigger than as we expected!")
                self.output_writer(
                    out_file=f"qu1cksc0pe_decoded_javascript-{len(decoded_text)}.js",
                    mode="w",
                    buffer=decoded_text
                )
                continue
            decc.append(decoded_text)

        return decc if decc != [] else None

    def html_dump_javascript(self, soup_obj):
        # Dump javascript
        print(f"\n{infoS} Checking for Javascript...")
        javscr = soup_obj.find_all("script")
        if javscr != []:
            print(f"{infoS} Found [bold red]{len(javscr)}[white]. If there is a potential malicious one we will extract it...")
            self._add_finding("HTML", f"javascript_tag_count={len(javscr)}")
            for jv in javscr:
                jav_buf = jv.getText().replace("<script>", "").replace("</script>", "")
                # We need only malicious codes!
                mal_ind = 0
                for mcode in self.mal_code:
                    mtc = re.findall(mcode, jav_buf)
                    if mtc != []:
                        mal_ind += 1

                if mal_ind != 0 and len(jav_buf) > 0:
                    self.output_writer(out_file=f"qu1cksc0pe_carved_javascript-{len(jav_buf)}.js", mode="w", buffer=jav_buf)
        else:
            print(f"{errorS} There is no Javascript found!")

    def html_check_input_points(self, soup_obj):
        # Check for input points
        print(f"\n{infoS} Checking for input points...")
        inputz = soup_obj.find_all("input")
        if inputz != []:
            inp_table = Table()
            inp_table.add_column("[bold green]ID", justify="center")
            inp_table.add_column("[bold green]Name", justify="center")
            inp_table.add_column("[bold green]Type", justify="center")
            inp_table.add_column("[bold green]Value", justify="center")
            for inp in inputz:
                input_template = {
                    "id": None,
                    "name": None,
                    "type": None,
                    "value": None
                }
                try:
                    # Check for values
                    for key in input_template:
                        input_template[key] = inp.get(key)

                    inp_table.add_row(str(input_template["id"]), str(input_template["name"]), str(input_template["type"]), str(input_template["value"]))
                except:
                    continue
            print(inp_table)
        else:
            print(f"{errorS} There is no input point found!")

    def html_check_iframe_tag(self, soup_obj):
        # Check for iframe tag
        print(f"\n{infoS} Checking for iframe presence...")
        ifr = soup_obj.find_all("iframe")
        if ifr != []:
            ifr_table = Table()
            ifr_table.add_column("[bold green]Source", justify="center")
            for ii in ifr:
                ifr_template = {
                    "src": None
                }
                try:
                    #Check values
                    for key in ifr_template:
                        ifr_template[key] = ii.get(key)

                    ifr_table.add_row(str(ifr_template["src"]))
                except:
                    continue
            print(ifr_table)
        else:
            print(f"{errorS} There is no iframe presence!")

    def html_check_suspicious_files(self, given_buffer):
        # Check suspicious files
        susp_file_pattern = [r'\b\w+\.exe\b', r'\b\w+\.ps1\b', r'\b\w+\.hta\b', r'\b\w+\.bat\b', r'\b\w+\.zip\b', r'\b\w+\.rar\b']
        print(f"\n{infoS} Checking for suspicious filename patterns...")
        indicator = 0
        for sus in susp_file_pattern:
            smt = re.findall(sus, given_buffer)
            if smt != []:
                indicator += 1
                for pat in smt:
                    print(f"[bold magenta]>>>[white] {pat}")
                    self._add_finding("HTML", f"suspicious_file:{pat}")

        if indicator == 0:
            print(f"{errorS} There is no suspicious pattern found!")

    def html_check_powershell_codes(self, given_buffer):
        pow_code = [r"AppData", r"Get-Random", r"New-Object", r"System.Random", r"Start-BitsTransfer", r"Remove-Item", r"New-ItemProperty"]
        powe_table = Table()
        powe_table.add_column("[bold green]Pattern", justify="center")
        powe_table.add_column("[bold green]Occurence", justify="center")
        pind = 0
        for co in pow_code:
            mtch = re.findall(co, given_buffer, re.IGNORECASE)
            if mtch != []:
                pind += 1
                powe_table.add_row(co, str(len(mtch)))
                self._add_finding("HTML", f"powershell_pattern:{co}")
        if pind != 0:
            print(f"\n{infoS} Looks like we found powershell code patterns!")
            print(powe_table)

    # ── File type detection ───────────────────────────────────────────────────

    def CheckExt(self):
        doc_type = subprocess.run(["file", self.targetFile], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        decoded_doc_type = doc_type.stdout.decode()
        lower_file = self.targetFile.lower()
        report["file_magic"] = decoded_doc_type.strip()
        if lower_file.endswith(".js"):
            return "javascript"
        if lower_file.endswith(".hta"):
            return "hta"
        if lower_file.endswith((".html", ".htm")) or "HTML document" in decoded_doc_type:
            return "html"
        return "unknown"

    # ── Main analyzers ────────────────────────────────────────────────────────

    def HTMLanalysis(self):
        print(f"{infoS} Performing HTML analysis...")
        soup_analysis = BeautifulSoup(allstr, "html.parser")
        raw_html = self._read_target_text() or allstr

        # Check for malicious code patterns
        self.html_detect_malicious_code(given_buffer=allstr)

        # Fetch url values
        self.html_fetch_urls(given_buffer=allstr)

        # Dump javascript
        self.html_dump_javascript(soup_obj=soup_analysis)

        # Execute no attacker code: inline blocks and event handlers are
        # abstractly interpreted against fake browser/WSH/Node APIs.
        self._emulate_inline_javascript(raw_html, f"{os.path.basename(self.targetFile)}:inline-js")

        # Check for input points
        self.html_check_input_points(soup_obj=soup_analysis)

        # Check for iframe presence
        self.html_check_iframe_tag(soup_obj=soup_analysis)

        # Check for powershell patterns
        self.html_check_powershell_codes(given_buffer=allstr)

        # Print possible base64 decoded values
        print(f"\n{infoS} Extracting possible decoded [bold green]BASE64[white] values...")
        decodd = self.chk_b64(given_buffer=allstr)
        if decodd:
            for dd in decodd:
                print(f"[bold magenta]>>>[white] {dd}")
            self._add_finding("HTML", f"decoded_base64={len(decodd)}")
        else:
            print(f"{errorS} There is no potential encoded BASE64 value found!")

        # Check suspicious files
        self.html_check_suspicious_files(given_buffer=allstr)

        # Check for unescape pattern
        if self.mal_code["unescape"]["count"] != 0:
            print(f"\n{infoS} Looks like we have a obfuscated data (via [bold green]unescape[white])")
            print(f"{infoS} Performing extraction...")
            un_dat = re.findall(r"unescape\('([^']+)'", allstr)
            if un_dat != []:
                for escape in un_dat:
                    deobf = urllib.parse.unquote(escape)
                    self.output_writer(out_file=f"qu1cksc0pe_decoded_unescape-{len(deobf)}.bin", mode="w", buffer=deobf)

                    # After extracting the data also we need to scan it!
                    print(f"\n{infoS} Performing analysis against [bold yellow]qu1cksc0pe_decoded_unescape-{len(deobf)}.bin[white]")
                    if "html" in deobf:
                        new_soup = BeautifulSoup(deobf, "html.parser")
                        self.html_check_input_points(soup_obj=new_soup)
                        self.html_check_iframe_tag(soup_obj=new_soup)
                        self.html_detect_malicious_code(given_buffer=deobf)
                        self.html_check_suspicious_files(given_buffer=deobf)

    def JSAnalysis(self):
        print(f"{infoS} Performing JavaScript static analysis...")
        script_bytes = self._read_target_bytes()
        if not script_bytes and not os.path.isfile(self.targetFile):
            err_exit(f"{errorS} Could not read target script.")

        script_text = self._decode_script_bytes(script_bytes)
        if script_text.strip() == "":
            script_text = allstr

        report["script_analysis"]["language"] = "JavaScript"

        js_patterns = {
            "Execution": [
                r"\beval\s*\(",
                r"\bnew\s+Function\s*\(",
                r"\bsetTimeout\s*\(",
                r"\bsetInterval\s*\(",
            ],
            "Obfuscation": [
                r"\b_0x[0-9a-fA-F]+\b",
                r"\bString\.fromCharCode\s*\(",
                r"\bunescape\s*\(",
                r"\batob\s*\(",
                r"\bbtoa\s*\(",
                r"[A-Za-z0-9+/]{100,}={0,2}",
            ],
            "Network": [
                r"\bXMLHttpRequest\b",
                r"\bfetch\s*\(",
                r"\bWebSocket\s*\(",
                r"\bActiveXObject\s*\(",
                r"\bWScript\.Shell\b",
            ],
            "Shell/Execution": [
                r"\brequire\s*\(\s*['\"]child_process['\"]",
                r"\bexecSync\s*\(",
                r"\bspawnSync\s*\(",
                r"\bprocess\.env\b",
            ],
            "FileSystem": [
                r"\brequire\s*\(\s*['\"]fs['\"]",
                r"\bfs\.write(?:File)?(?:Sync)?\s*\(",
                r"\bfs\.read(?:File)?(?:Sync)?\s*\(",
                r"\bScripting\.FileSystemObject\b",
            ],
            "Persistence": [
                r"\bWScript\.Shell\b.{0,60}RegWrite\b",
                r"\bschtasks\b",
                r"CurrentVersion\\\\Run\b",
            ],
        }

        summary_table = Table(title="* JavaScript Pattern Summary *", title_style="bold italic cyan", title_justify="center")
        summary_table.add_column("[bold green]Category", justify="center")
        summary_table.add_column("[bold green]Count", justify="center")

        for category, p_list in js_patterns.items():
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
                self._add_finding("JavaScript", f"{category.lower()}={len(hits)}")
            else:
                summary_table.add_row(category, "0")
            report["script_analysis"]["categories"][category] = hits
            self._register_section(f"js_{category.lower()}_hits", hits)

        print(summary_table)

        # Reuse malicious HTML/JS pattern database (eval, atob, XMLHttpRequest, WScript.Shell, etc.)
        self.html_detect_malicious_code(given_buffer=script_text)

        # Base64 decode hints
        decoded_hints = []
        b64_candidates = re.findall(r"(?:[A-Za-z0-9+/]{4}){30,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?", script_text)
        for candidate in b64_candidates[:30]:
            try:
                decoded = base64.b64decode(candidate).decode("utf-8", errors="ignore")
            except Exception:
                continue
            decoded = decoded.strip()
            if len(decoded) < 20:
                continue
            printable_ratio = sum(ch.isprintable() for ch in decoded) / max(len(decoded), 1)
            if printable_ratio < 0.80:
                continue
            hint, truncated = self._sanitize_and_truncate(decoded, 200)
            if hint and hint not in decoded_hints:
                decoded_hints.append(hint)
            if truncated:
                self._add_finding("JavaScript", "decoded_payload_truncated")
            if len(decoded_hints) >= 15:
                break
        report["script_analysis"]["decoded_payload_hints"] = decoded_hints
        self._register_section("js_decoded_payload_hint_count", len(decoded_hints))
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
            self._add_finding("JavaScript", f"url_count={len(url_hits)}")
        else:
            print(f"{errorS} There is no URL value found!")

        # Automatic, side-effect-free behavior emulation runs in addition to
        # the complete static scan above.
        self._run_javascript_emulation(script_text, os.path.basename(self.targetFile))

        # Perform Yara scan
        print(f"\n{infoS} Performing YARA rule matching...")
        yara_rule_scanner(self.rule_path, self.targetFile, report)

    def HTAAnalysis(self):
        print(f"{infoS} Performing HTA (HTML Application) analysis...")
        hta_bytes = self._read_target_bytes()
        if not hta_bytes and not os.path.isfile(self.targetFile):
            err_exit(f"{errorS} Could not read target file.")

        hta_text = self._decode_script_bytes(hta_bytes)
        soup = BeautifulSoup(hta_text, "html.parser")

        # HTA application metadata
        hta_tag = soup.find("hta:application")
        if hta_tag:
            print(f"\n{infoS} HTA application metadata found:")
            hta_meta = {}
            for attr in ["applicationname", "singleinstance", "windowstate", "navigable", "icon", "border", "borderstyle"]:
                val = hta_tag.get(attr)
                if val:
                    print(f"[bold magenta]>>>[white] {attr}: [bold green]{val}")
                    hta_meta[attr] = val
            self._register_section("hta_application_meta", hta_meta)
        else:
            print(f"\n{infoS} No [bold yellow]<HTA:APPLICATION>[white] tag found.")

        # Determine scripting language from script tags
        script_lang = "JScript"
        for tag in soup.find_all("script"):
            lang_attr = (tag.get("language") or "").lower()
            if "vbscript" in lang_attr:
                script_lang = "VBScript"
                break
        print(f"{infoS} Detected script language: [bold green]{script_lang}")
        self._register_section("hta_script_language", script_lang)
        report["script_analysis"]["language"] = f"HTA/{script_lang}"

        # HTML analysis components
        self.html_detect_malicious_code(given_buffer=hta_text)
        self.html_fetch_urls(given_buffer=hta_text)
        self.html_dump_javascript(soup_obj=soup)
        self.html_check_iframe_tag(soup_obj=soup)
        self.html_check_powershell_codes(given_buffer=hta_text)
        self.html_check_suspicious_files(given_buffer=hta_text)

        # Extract and scan inline script block content
        script_blocks = []
        for tag in soup.find_all("script"):
            block = tag.get_text()
            if block.strip():
                script_blocks.append(block)
        combined_scripts = "\n".join(script_blocks)

        if combined_scripts.strip():
            print(f"\n{infoS} Scanning [bold green]{len(script_blocks)}[white] inline script block(s)...")
            if script_lang == "VBScript":
                vb_patterns = {
                    "Execution": [
                        r"\bCreateObject\s*\(", r"\bWScript\.Shell\b", r"\bShell\s*\(", r"\bExec\s*\(", r"\bRun\s*\("
                    ],
                    "Network": [
                        r"\bMSXML2\.(?:XMLHTTP|ServerXMLHTTP)\b", r"\bWinHttp\.WinHttpRequest\b",
                        r"\bURLDownloadToFile(?:A|W)?\b", r"\bADODB\.Stream\b"
                    ],
                    "Obfuscation": [
                        r"\bChrW?\s*\(", r"\bStrReverse\s*\(", r"\bFromBase64String\b",
                        r"[A-Za-z0-9+/]{100,}={0,2}"
                    ],
                    "Persistence": [
                        r"\bRegWrite\b", r"\bCurrentVersion\\Run(?:Once)?\b", r"\bschtasks\b"
                    ],
                }
            else:
                vb_patterns = {
                    "Execution": [
                        r"\beval\s*\(", r"\bnew\s+Function\s*\(", r"\bActiveXObject\s*\(", r"\bWScript\.Shell\b"
                    ],
                    "Network": [
                        r"\bXMLHttpRequest\b", r"\bfetch\s*\(", r"\bWebSocket\s*\("
                    ],
                    "Obfuscation": [
                        r"\b_0x[0-9a-fA-F]+\b", r"\bString\.fromCharCode\s*\(", r"\batob\s*\(",
                        r"[A-Za-z0-9+/]{100,}={0,2}"
                    ],
                    "Persistence": [
                        r"\bschtasks\b", r"CurrentVersion\\\\Run\b"
                    ],
                }

            script_table = Table(title="* Script Block Pattern Summary *", title_style="bold italic cyan", title_justify="center")
            script_table.add_column("[bold green]Category", justify="center")
            script_table.add_column("[bold green]Count", justify="center")
            for category, p_list in vb_patterns.items():
                hits = []
                seen = set()
                for pattern in p_list:
                    for mt in re.finditer(pattern, combined_scripts, re.IGNORECASE):
                        matched = mt.group(0).strip()
                        if matched and matched not in seen:
                            seen.add(matched)
                            hits.append(self._sanitize_text(matched))
                if hits:
                    script_table.add_row(f"[bold red]{category}", str(len(hits)))
                    self._add_finding("HTA", f"{category.lower()}={len(hits)}")
                else:
                    script_table.add_row(category, "0")
                report["script_analysis"]["categories"][category] = hits
            print(script_table)

        if script_lang != "VBScript" and combined_scripts.strip():
            self._run_javascript_emulation(
                combined_scripts,
                f"{os.path.basename(self.targetFile)}:inline-js",
            )

        # Base64 decode hints from full HTA text
        decoded_hints = []
        b64_candidates = re.findall(r"(?:[A-Za-z0-9+/]{4}){30,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?", hta_text)
        for candidate in b64_candidates[:30]:
            try:
                decoded = base64.b64decode(candidate).decode("utf-8", errors="ignore")
            except Exception:
                continue
            decoded = decoded.strip()
            if len(decoded) < 20:
                continue
            printable_ratio = sum(ch.isprintable() for ch in decoded) / max(len(decoded), 1)
            if printable_ratio < 0.80:
                continue
            hint, truncated = self._sanitize_and_truncate(decoded, 200)
            if hint and hint not in decoded_hints:
                decoded_hints.append(hint)
            if len(decoded_hints) >= 15:
                break
        report["script_analysis"]["decoded_payload_hints"] = decoded_hints
        if decoded_hints:
            dec_table = Table(title="* Decoded Payload Hints *", title_style="bold italic cyan", title_justify="center")
            dec_table.add_column("[bold green]Snippet", justify="center")
            for hint in decoded_hints:
                dec_table.add_row(hint)
            print(dec_table)

        # Perform Yara scan
        print(f"\n{infoS} Performing YARA rule matching...")
        yara_rule_scanner(self.rule_path, self.targetFile, report)


# Execution area
try:
    scriptObj = HTMLScriptAnalyzer(targetFile)
    ext = scriptObj.CheckExt()
    report["document_type"] = ext
    if ext == "html":
        scriptObj.HTMLanalysis()
    elif ext == "javascript":
        scriptObj.JSAnalysis()
    elif ext == "hta":
        scriptObj.HTAAnalysis()
    elif ext == "unknown":
        print(f"{errorS} File type not recognized as HTML, JavaScript, or HTA.")
    if get_argv(2) == "True":
        save_report("document", report)
except Exception as exc:
    err_exit(f"{errorS} An error occured while analyzing that file. Details: {exc}")
