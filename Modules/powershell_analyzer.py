#!/usr/bin/python3
	
import re
import io
import sys
import json
import zlib
import gzip
import base64
import binascii
import subprocess
import warnings
import os
import hashlib
import tempfile
	
from utils.helpers import err_exit, get_argv, save_report

# Native PowerShell behavior emulator.  It abstractly interprets common
# malicious PowerShell idioms (download cradles, obfuscation, process/
# registry/file operations, Invoke-Expression chains) and never hands
# attacker-controlled source to a real PowerShell/pwsh interpreter or a
# command shell. Keep this optional so static analysis remains available in
# partial installs.
try:
    from powershell_emulator import (emulate_powershell, MAX_TIMEOUT_SECONDS, MAX_SOURCE_CHARS,
                                    MAX_EMBEDDED_PAYLOAD_BYTES, MAX_EXPORTED_PAYLOAD_BYTES, mark_source_truncated)
    _emulator_import_error = None
except Exception as exc:
    emulate_powershell = None
    _emulator_import_error = str(exc)

try:
    from rich import print
    from rich.markup import escape as _esc
    from rich.table import Table
except:
    err_exit("Error: >rich< module not found.")

# Legends
infoS = f"[bold cyan][[bold red]*[bold cyan]][white]"
errorS = f"[bold cyan][[bold red]![bold cyan]][white]"
	
# Gathering Qu1cksc0pe path variable
try:
    sc0pe_path = open(os.path.join(os.path.expanduser("~"), ".qu1cksc0pe_path"), "r").read().strip()
except Exception:
    # Allow running module directly without the path cache.
    sc0pe_path = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))

# Configurating strings parameter and make compatability
path_seperator = "/"
strings_param = "--all"
if sys.platform == "darwin":
    strings_param = "-a"
elif sys.platform == "win32":
    strings_param = "-a"
    path_seperator = "\\"

# Load patterns
powershell_code_patterns = json.load(open(f"{sc0pe_path}{path_seperator}Systems{path_seperator}Windows{path_seperator}powershell_code_patterns.json"))

warnings.filterwarnings("ignore")

class PowerShellAnalyzer:
    def __init__(self, target_file):
        self.target_file = target_file
        self.target_buffer_normal = subprocess.run(["strings", strings_param, self.target_file], stderr=subprocess.PIPE, stdout=subprocess.PIPE)
        if sys.platform != "win32":
            self.target_buffer_16bit = subprocess.run(["strings", strings_param, "-e", "l", self.target_file], stderr=subprocess.PIPE, stdout=subprocess.PIPE)
            self.all_strings = self.target_buffer_16bit.stdout.decode().split("\n")+self.target_buffer_normal.stdout.decode().split("\n")
        else:
            self.all_strings = self.target_buffer_normal.stdout.decode().split("\n")
        # Computed once and reused everywhere below instead of each method
        # (some in nested loops) separately re-running ``str(self.all_strings)``
        # -- a large sample's extracted-strings list can be tens of
        # thousands of entries, and Python's list-repr conversion is not
        # free at that size when it happens repeatedly.
        self._all_strings_text = str(self.all_strings)
        # NOTE: Avoid inline flag blocks like `(?i)` mid-pattern; use re.IGNORECASE in calls instead.
        self.pattern_b64 = [
                            r"\[sYsteM\.coNvert\]::FROmbaSe64StRiNG\(\s*[\'\"]([^'\"]*)[\'\"]\s*\)|\[System\.Convert\]::FromBase64String\(\s*'([A-Za-z0-9+/=]+)'\s*\)",
                            r"[A-Za-z0-9+/=]{40,}"
                        ]
        self.pattern_ascii = r'\[Byte\[\]\]\((\d+(?:,\d+)*)\)'
        self.pattern_hex = r'\[System\.Convert\]::fromHEXString\(\'([0-9a-fA-F]+)\'\)'

        # JSON report object (used when qu1cksc0pe runs with --report/--ai).
        self.report = {
            "filename": self.target_file,
            "file_type": "POWERSHELL",
            "hash_md5": "",
            "hash_sha1": "",
            "hash_sha256": "",
            "matched_patterns": {},
            "extracted_paths": [],
            "possible_executions": [],
            "payloads": {
                "xor_key": "",
                "xor_detected": False,
                "decoded_files": [],
                "non_xored_detected": False,
                "non_xored_files": [],
                "normal_base64_decoded_files": [],
                "decoded_base64_values_file": "",
                "decoded_base64_values_count": 0,
            },
            "errors": [],
            "extracted_urls": [],
            "extracted_domains": [],
            "extracted_ips": [],
            "large_variable_blobs": [],
            "emulation": {
                "enabled": False,
                "result": None,
            },
        }
        self.decoded_b64_entries = []
        self._decoded_b64_seen = set()
        self._calc_hashes_into_report()
        self._write_temp_txt()

    def _calc_hashes_into_report(self):
        try:
            md5 = hashlib.md5()
            sha1 = hashlib.sha1()
            sha256 = hashlib.sha256()
            with open(self.target_file, "rb") as f:
                for chunk in iter(lambda: f.read(8192), b""):
                    md5.update(chunk)
                    sha1.update(chunk)
                    sha256.update(chunk)
            self.report["hash_md5"] = md5.hexdigest()
            self.report["hash_sha1"] = sha1.hexdigest()
            self.report["hash_sha256"] = sha256.hexdigest()
        except Exception:
            pass

    def _write_temp_txt(self):
        """
        smart_analyzer.py enriches LLM context by reading ./temp.txt.
        PowerShell analysis previously didn't create it, so --ai had less evidence.
        """
        try:
            if str(os.environ.get("SC0PE_POWERSHELL_WRITE_TEMP_TXT", "1")).strip() == "0":
                return
        except Exception:
            pass

        try:
            # Prefer the strings output (already collected). Keep it simple and ASCII-safe.
            data = "\n".join([s for s in (self.all_strings or []) if isinstance(s, str)])
            temp_txt_path = os.environ.get("SC0PE_TEMP_TXT_PATH", "temp.txt")
            with open(temp_txt_path, "w", encoding="utf-8", errors="ignore") as f:
                f.write(data)
        except Exception:
            # Best-effort only.
            pass

    def _extract_b64_from_match(self, m):
        # re.findall with alternation returns tuples; pick the first non-empty group.
        if isinstance(m, tuple):
            for it in m:
                if it:
                    return str(it)
            return ""
        return str(m or "")

    def save_data_into_file(self, output_file, data):
        with open(output_file, "wb") as ff:
            ff.write(data)
        print(f"{infoS} Decoded payload saved into: [bold green]{output_file}[white]")
        try:
            self.report["payloads"]["decoded_files"].append(output_file)
        except Exception:
            pass

    def _record_decoded_b64_text(self, decoded_text, output_file=""):
        text = str(decoded_text or "").replace("\x00", "").strip()
        if len(text) < 10:
            return
        # A large sample (a big embedded hex/base64 payload split by
        # `strings` into tens of thousands of individual line-matches, seen
        # on a real 3.8MB RemcosRAT sample) can call this tens of thousands
        # of times. The previous ``entry not in self.decoded_b64_entries``
        # duplicate check re-scanned the whole (ever-growing) list on every
        # call -- O(n^2), ~76s on that sample -- while a set keyed the same
        # way is O(1) average per check.
        key = (str(output_file or ""), text)
        if key in self._decoded_b64_seen:
            return
        self._decoded_b64_seen.add(key)
        self.decoded_b64_entries.append({"output_file": key[0], "decoded_text": text})

    def _maybe_record_bytes_as_text(self, blob, output_file=""):
        try:
            raw = bytes(blob)
        except Exception:
            return
        try:
            text = raw.decode("utf-8", errors="ignore").replace("\x00", "").strip()
        except Exception:
            text = ""
        # Prefer readable text; if not readable, keep a hex representation so decoded value is still preserved.
        if len(text) < 10:
            hex_text = raw.hex()
            if hex_text:
                self._record_decoded_b64_text(decoded_text=f"[non-printable-bytes-hex]\n{hex_text}", output_file=output_file)
            return
        printable_ratio = sum(ch.isprintable() for ch in text) / max(len(text), 1)
        if printable_ratio >= 0.85:
            self._record_decoded_b64_text(decoded_text=text, output_file=output_file)
            return
        hex_text = raw.hex()
        if hex_text:
            self._record_decoded_b64_text(decoded_text=f"[non-printable-bytes-hex]\n{hex_text}", output_file=output_file)

    def write_decoded_b64_list_file(self):
        if not self.decoded_b64_entries:
            return

        out_name = "qu1cksc0pe_decoded_b64_values.txt"
        try:
            with open(out_name, "w", encoding="utf-8", errors="ignore") as ff:
                for idx, entry in enumerate(self.decoded_b64_entries, 1):
                    ff.write(f"[{idx}] output_file: {entry['output_file'] or '-'}\n")
                    ff.write(entry["decoded_text"])
                    if not entry["decoded_text"].endswith("\n"):
                        ff.write("\n")
                    ff.write("-" * 70 + "\n")
            print(f"{infoS} Decoded BASE64 values list saved into: [bold green]{out_name}[white]")
            self.report["payloads"]["decoded_base64_values_file"] = out_name
            self.report["payloads"]["decoded_base64_values_count"] = len(self.decoded_b64_entries)
            self.report["payloads"]["normal_base64_decoded_files"] = [out_name]
        except Exception as exc:
            self.report["errors"].append(f"decoded_base64_values_write_error: {exc}")
		
    def scan_code_patterns(self):
        print(f"{infoS} Performing pattern scan...")
        self.report["matched_patterns"] = {}
        for pat in powershell_code_patterns:
            pat_table = Table()
            pat_table.add_column(f"Extracted patterns about [bold green]{pat}[white]", justify="center")
            found = []
            for code in powershell_code_patterns[pat]["patterns"]:
                matchh = re.findall(code, self._all_strings_text, re.IGNORECASE)
                if matchh != []:
                    pat_table.add_row(code)
                    found.append(code)
            if found:
                print(pat_table)
                self.report["matched_patterns"][pat] = found
	
    def check_executions(self):
        print(f"\n{infoS} Performing detection of possible executions...")
        exec_patterns = [
            r"regsvr32\s+C://[\w/.:-]+\.dll",
            r"regsvr32\s+C:\\[\w/.:-]+\.dll",
            r'(start\s+\w+\.exe)',
            r'CMD\s+/C\s+powershell\b.*',
            r'powershell\s+-exec\s+bypass\s+-c',
            r'(Start-Process\s+\"[^\"]+\.exe\")',
            r'(?:IEX|Invoke-Expression)\s*\(',
            r'&\s*\(\s*\$\w+',
            r'&\s*\$\w+',
            r'Invoke-Command\b',
            r'WMIC\s+process\s+call\s+create',
            r'mshta(?:\.exe)?\s+',
            r'(?:c|w)script(?:\.exe)?\s+',
            r'rundll32(?:\.exe)?\s+',
            r'msiexec(?:\.exe)?\s+/[iq]',
            r'bitsadmin\s+/transfer',
            r'certutil\s+-decode',
            r'(?:New-Object|\.)\s*Net\.WebClient',
            r'(?:DownloadFile|DownloadString|DownloadData)\s*\(',
        ]
        swc = 0
        exec_table = Table()
        exec_table.add_column(f"Extracted patterns about [bold green]Execution[white]", justify="center")
        for expat in exec_patterns:
            matchs = re.findall(expat, self._all_strings_text, re.IGNORECASE)
            if matchs != []:
                for mm in matchs:
                    exec_table.add_row(mm)
                    try:
                        self.report["possible_executions"].append(mm)
                    except Exception:
                        pass
                    swc += 1
        if swc != 0:
            print(exec_table)
        else:
            print(f"{errorS} There is no pattern about execution!\n")

    def extract_path_values(self):
        print(f"\n{infoS} Performing extraction of path values...")
        # List repr doubles backslashes, turning regex escapes into false
        # UNC candidates. Use the original strings instead.
        paths = self._extract_windows_paths("\n".join(self.all_strings))
        path_table = Table()
        path_table.add_column("Extracted [bold green]PATH[white] values", justify="center")
        for path in paths:
            path_table.add_row(_esc(path))
            if path not in self.report["extracted_paths"]:
                self.report["extracted_paths"].append(path)
        if paths:
            print(path_table)
        else:
            print(f"{errorS} There is no pattern about path values...\n")

    @staticmethod
    def _extract_windows_paths(text):
        path_patterns = [
            r"'([A-Z]:\\[^']+)'",           # single-quoted drive paths
            r'"([A-Z]:\\[^"]+)"',           # double-quoted drive paths
            r"'(\\\\[^']+)'",               # single-quoted UNC paths
            r'"(\\\\[^"]+)"',               # double-quoted UNC paths
            r'(\$env:\w+\\[^\s\'">\]]+)',   # environment variable paths
        ]
        paths = []
        seen = set()
        for path_regex in path_patterns:
            for path in re.findall(path_regex, text, re.IGNORECASE):
                if any(char in path for char in "\r\n|<>"):
                    continue
                if path.startswith("\\\\") and not re.fullmatch(r'\\\\[^\\/:*?"<>|\s`]+\\[^\\/:*?"<>|`]+(?:\\[^\r\n|<>]*)?', path):
                    continue
                if path in seen:
                    continue
                seen.add(path)
                paths.append(path)
        return paths

    # ------------------------------------ XORED Payload detection and extratcion
    def check_for_xor_key(self):
        text = self._all_strings_text
        # Literal integer key: -bxor 0x1F or -bxor 31
        for pattern in (r'-bxor\s+(0x[0-9a-fA-F]+)', r'-bxor\s+(\d+)'):
            m = re.findall(pattern, text, re.IGNORECASE)
            if m:
                val = m[0]
                return str(int(val, 16)) if val.startswith(("0x", "0X")) else val
        # Variable key: -bxor $keyVar  → return variable name for reporting
        mv = re.findall(r'-bxor\s+(\$\w+)', text, re.IGNORECASE)
        if mv:
            return mv[0]   # e.g. "$key" — caller receives a string, won't cast to int
        return None

    def find_payloads_xored(self):
        print(f"\n{infoS} Performing [bold green]XOR\'ed[white] payload detection...")
        # First we need to check Bytearrays (Metasploit, CobaltStrike)
        if self.check_for_xor_key() is not None:
            print(f"{infoS} Looks like we have a possible [bold green]XOR\'ed[white] payload. Attempting to detect its type...")
            try:
                self.report["payloads"]["xor_detected"] = True
                self.report["payloads"]["xor_key"] = str(self.check_for_xor_key() or "")
            except Exception:
                pass
            self.detect_and_carve_base64_payloads_xored()
            self.detect_and_carve_ascii_number_payloads_xored()
            self.detect_and_carve_hex_values_payloads_xored()
        else:
            print(f"{errorS} There is no pattern about XOR\'ed payloads!\n")

    def xor_decrypt_and_save(self, payload_type, payload, xor_key):
        try:
            xor_int = int(xor_key) & 0xFF
        except (ValueError, TypeError):
            print(f"{errorS} XOR key [bold yellow]{xor_key}[white] is a variable — cannot decrypt statically.\n")
            return
        if payload_type == "base64":
            byte_arr = bytearray(base64.b64decode(payload))
            for byt in range(len(byte_arr)):
                byte_arr[byt] = byte_arr[byt] ^ xor_int
            self._maybe_record_bytes_as_text(blob=byte_arr, output_file="base64_xored_payload")
            print(f"{infoS} Decoded BASE64 payload added to [bold green]qu1cksc0pe_decoded_b64_values.txt[white] list queue")
        elif payload_type == "ascii":
            temp_array = []
            for num in payload:
                temp_array.append(int(num))
            byte_arr = bytearray(temp_array)
            for byt in range(len(byte_arr)):
                byte_arr[byt] = byte_arr[byt] ^ xor_int
            self.save_data_into_file(output_file="qu1cksc0pe_decoded_ascii_numbers_payload.bin", data=byte_arr)
        elif payload_type == "hex":
            byte_arr = bytearray(binascii.unhexlify(payload))
            for byt in range(len(byte_arr)):
                byte_arr[byt] = byte_arr[byt] ^ xor_int
            self.save_data_into_file(output_file="qu1cksc0pe_decoded_hex_values_payload.bin", data=byte_arr)

    def detect_and_carve_base64_payloads_xored(self):
        print(f"\n{infoS} Searching for: [bold green]BASE64 Encoded[white] payloads...")
        b64matches = re.findall(self.pattern_b64[0], self._all_strings_text, re.IGNORECASE)
        if b64matches != []:
            print(f"{infoS} We have a [bold green]BASE64[white] encoded payload. Performing decode and extract...")
            print(f"{infoS} Checking for XOR key...")
            xor_key = self.check_for_xor_key()
            if xor_key is not None:
                print(f"{infoS} XOR Key: [bold green]{xor_key}[white]")
                payload = self._extract_b64_from_match(b64matches[0])
                if payload:
                    self.xor_decrypt_and_save(payload_type="base64", payload=payload, xor_key=xor_key)
            else:
                print(f"{errorS} Couldn\'t find XOR key!\n")
        else:
            print(f"{errorS} There is no pattern about BASE64 encoded payloads!\n")

    def detect_and_carve_ascii_number_payloads_xored(self):
        print(f"\n{infoS} Searching for: [bold green]ASCII Numbers[white]...")
        asciinum = re.findall(self.pattern_ascii, self._all_strings_text, re.IGNORECASE)
        if asciinum != []:
            print(f"{infoS} We have an array of [bold green]ASCII Numbers[white]. Performing decode and extract...")
            print(f"{infoS} Checking for XOR key...")
            xor_key = self.check_for_xor_key()
            if xor_key is not None:
                print(f"{infoS} XOR Key: [bold green]{xor_key}[white]")
                self.xor_decrypt_and_save(payload_type="ascii", payload=asciinum[0].split(","), xor_key=xor_key)
            else:
                print(f"{errorS} Couldn\'t find XOR key!\n")
        else:
            print(f"{errorS} There is no pattern about ASCII Numbers!\n")

    def detect_and_carve_hex_values_payloads_xored(self):
        print(f"\n{infoS} Searching for: [bold green]HEX Values[white]...")
        hexval = re.findall(self.pattern_hex, self._all_strings_text, re.IGNORECASE)
        if hexval != []:
            print(f"{infoS} We have an array of [bold green]HEX Values[white]. Performing decode and extract...")
            print(f"{infoS} Checking for XOR key...")
            xor_key = self.check_for_xor_key()
            if xor_key is not None:
                print(f"{infoS} XOR Key: [bold green]{xor_key}[white]")
                self.xor_decrypt_and_save(payload_type="hex", payload=hexval[0], xor_key=xor_key)
            else:
                print(f"{errorS} Couldn\'t find XOR key!\n")
        else:
            print(f"{errorS} There is no pattern about HEX Values!\n")

    # ------------------------------------ non-XORED payload detection and extraction
    def check_for_non_xored_payloads_presence(self):
        print(f"{infoS} Performing [bold green]non-XOR\'ed[white] payload detection...")
        try:
            b64_payload = re.findall(self.pattern_b64[0], self._all_strings_text, re.IGNORECASE)
        except re.error as e:
            self.report["errors"].append(f"regex_error_base64_pattern: {e}")
            b64_payload = []
        ascii_payload = re.findall(self.pattern_ascii, self._all_strings_text, re.IGNORECASE)
        hex_payload = re.findall(self.pattern_hex, self._all_strings_text, re.IGNORECASE)
        pe_payload = re.findall(r"4d5a90", self._all_strings_text, re.IGNORECASE)
        if b64_payload != [] or ascii_payload != [] or hex_payload != [] or pe_payload != []:
            if self.check_for_xor_key() is None:
                print(f"{infoS} Looks like we have a possible [bold green]non-XOR\'ed[white] payload. Attempting to detect its type...")
                try:
                    self.report["payloads"]["non_xored_detected"] = True
                except Exception:
                    pass
                self.detect_and_carve_b64_non_xored()
                self.detect_and_carve_pe_executable_non_xored()
            else:
                print(f"{errorS} Couldn\'t detect XOR key!\n")
        else:
            print(f"{errorS} There is no pattern about non-XOR\'ed payloads!\n")

    def detect_and_carve_b64_non_xored(self):
        # This method is for: frombase64 type payloads
        print(f"\n{infoS} Searching for: [bold green]BASE64 Encoded[white] payloads...")
        b64matches = re.findall(self.pattern_b64[0], self._all_strings_text, re.IGNORECASE)
        if b64matches != []:
            payload = self._extract_b64_from_match(b64matches[0])
            if not payload:
                return
            b64_data = base64.b64decode(payload)
            print(f"{infoS} We have a [bold green]BASE64[white] encoded payload. Performing decode and extract...")
            print(f"{infoS} Checking for compressed data presence...")
            deflatestream = re.findall(r'Io\.CoMpRESSiOn\.defLaTEstReam', self._all_strings_text, re.IGNORECASE)
            gzipstream = re.findall(r"IO\.Compression\.GZipStream", self._all_strings_text, re.IGNORECASE)
            if deflatestream != []:
                print(f"{infoS} Deflatestream data found! Attempting to decompress...")
                decompress_obj = zlib.decompressobj(-zlib.MAX_WBITS)
                decompressed_data = decompress_obj.decompress(b64_data)
                output = io.BytesIO(decompressed_data).read().decode('ascii')
                self._record_decoded_b64_text(decoded_text=output, output_file="base64_non_xored_deflate")
                print(f"{infoS} Decoded BASE64 payload added to [bold green]qu1cksc0pe_decoded_b64_values.txt[white] list queue")
            elif gzipstream != []:
                print(f"{infoS} Gzip data found! Attempting to decompress...")
                decompressed_data = gzip.decompress(b64_data)
                self._maybe_record_bytes_as_text(blob=decompressed_data, output_file="base64_non_xored_gzip")
                print(f"{infoS} Decoded BASE64 payload added to [bold green]qu1cksc0pe_decoded_b64_values.txt[white] list queue")
            else:
                print(f"{infoS} There is no compression. Extracting payload anyway...")
                self._maybe_record_bytes_as_text(blob=b64_data, output_file="base64_non_xored_raw")
                print(f"{infoS} Decoded BASE64 payload added to [bold green]qu1cksc0pe_decoded_b64_values.txt[white] list queue")
        else:
            print(f"{errorS} There is no pattern about BASE64 encoded payloads!\n")
	
    def check_only_legit_base64(self):
        print(f"\n{infoS} Searching for: [bold green]Normal BASE64[white] patterns...")
        b64_match = re.findall(self.pattern_b64[1], self._all_strings_text, re.IGNORECASE)
        if b64_match:
            print(f"{infoS} We have a [bold green]BASE64[white] encoded payload. Performing decode and extract...")
            for enc in b64_match:
                try:
                    decbf = base64.b64decode(enc)
                    self._maybe_record_bytes_as_text(blob=decbf, output_file="base64_normal_match")
                except:
                    continue
            print(f"{infoS} Decoded BASE64 payload values queued for [bold green]qu1cksc0pe_decoded_b64_values.txt[white]")
        else:
            print(f"{errorS} There is no pattern about BASE64 encoded payloads!\n")

    def detect_and_carve_pe_executable_non_xored(self):
        print(f"\n{infoS} Searching for: [bold green]PE Executable[white] patterns...")
        pe_match = re.findall(r"4d5a90", self._all_strings_text, re.IGNORECASE)
        if pe_match != []:
            print(f"{infoS} Looks like we have possible [bold green]{len(pe_match)}[white] patterns. Attempting to extraction...")
            counter = 0
            for pat in self.all_strings:
                if "4D5A90" in pat and "=" in pat:
                    sanitized = self.buffer_sanitizer(executable_buffer=pat.split("=")[1])
                    out_name = f"qu1cksc0pe_extracted_pe_{counter}.exe"
                    self.save_data_into_file(output_file=out_name, data=binascii.unhexlify(sanitized))
                    try:
                        self.report["payloads"]["non_xored_files"].append(out_name)
                    except Exception:
                        pass
                    counter += 1
        else:
            print(f"{errorS} There is no possible PE executable pattern found!\n")

    def extract_network_iocs(self):
        """Extract URLs and IP addresses from the script."""
        print(f"\n{infoS} Performing network IOC extraction...")
        text = self._all_strings_text
        found = False

        urls = list(dict.fromkeys(re.findall(r'https?://[^\s\'"<>\]]+', text, re.IGNORECASE)))
        # Download cradles also accept a bare hostname. Keep that hostname
        # as a domain IOC without inventing an HTTP/HTTPS scheme.
        domains = list(dict.fromkeys(re.findall(
            r"\b(?:irm|iwr|Invoke-RestMethod|Invoke-WebRequest)\s+(?:-Uri\s+)?['\"]?"
            r"((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63})"
            r"(?=[:/\s|'\"\]])", text, re.IGNORECASE)))
        self.report["extracted_domains"] = domains[:50]
        if domains:
            domain_table = Table()
            domain_table.add_column("Extracted domain values", justify="left")
            for domain in domains[:50]:
                domain_table.add_row(domain)
            print(domain_table)
            found = True
        if urls:
            url_table = Table()
            url_table.add_column("Extracted [bold green]URL[white] values", justify="left")
            for u in urls[:50]:
                url_table.add_row(u)
            print(url_table)
            self.report["extracted_urls"] = urls[:50]
            found = True

        ips = list(dict.fromkeys(re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', text)))
        # filter obviously non-IP version strings (0.0.0.0 is still valid)
        ips = [ip for ip in ips if all(0 <= int(o) <= 255 for o in ip.split("."))]
        if ips:
            ip_table = Table()
            ip_table.add_column("Extracted [bold green]IP[white] values", justify="center")
            for ip in ips[:50]:
                ip_table.add_row(ip)
            print(ip_table)
            self.report["extracted_ips"] = ips[:50]
            found = True

        if not found:
            print(f"{errorS} There are no network IOCs found!\n")

    def detect_large_variable_blobs(self):
        """Detect variables holding large Base64-like blobs (e.g. encrypted payloads)."""
        print(f"\n{infoS} Performing large variable blob detection...")
        # Read source directly for multi-line variable assignments
        try:
            with open(self.target_file, "r", encoding="utf-8", errors="ignore") as fh:
                source = fh.read()
        except Exception:
            source = self._all_strings_text

        pattern = r'\$(\w+)\s*=\s*["\']([A-Za-z0-9+/=]{200,})["\']'
        blobs = re.findall(pattern, source)
        if not blobs:
            print(f"{errorS} There are no large variable blobs found!\n")
            return

        blob_table = Table()
        blob_table.add_column("[bold green]Variable[white]", justify="center")
        blob_table.add_column("[bold green]Length[white]", justify="center")
        blob_table.add_column("[bold green]Preview (first 60 chars)[white]", justify="left")
        report_blobs = []
        for var_name, blob in blobs[:20]:
            blob_table.add_row(f"${var_name}", str(len(blob)), blob[:60] + "...")
            report_blobs.append({"variable": f"${var_name}", "length": len(blob), "preview": blob[:60]})
        print(blob_table)
        self.report["large_variable_blobs"] = report_blobs

    def buffer_sanitizer(self, executable_buffer):
        # Unwanted characters
        unwanted = ['@', '\t', '\n', " ", "\'"]
        for uc in unwanted:
            if uc in executable_buffer:
                executable_buffer = executable_buffer.replace(uc, "")

        return executable_buffer

    # ── Sandboxed PowerShell behavior emulation ─────────────────────────

    def _decode_script_bytes(self, script_bytes):
        # A plain ``.decode("utf-8", errors="ignore")`` silently mangles a
        # UTF-16 .ps1 (common -- many WSH/scheduled-task droppers save
        # PowerShell as UTF-16LE) into mostly-empty text: every ASCII byte
        # is followed by a null byte, and "ignore" just drops most of it.
        # Mirrors the same fix in document_analyzer.py/html_script_analyzer.py.
        if script_bytes[:2] == b"\xff\xfe":
            return script_bytes[2:].decode("utf-16-le", errors="ignore")
        if script_bytes[:2] == b"\xfe\xff":
            return script_bytes[2:].decode("utf-16-be", errors="ignore")
        if script_bytes[:3] == b"\xef\xbb\xbf":
            return script_bytes[3:].decode("utf-8", errors="ignore")
        if script_bytes and (script_bytes.count(b"\x00") / len(script_bytes)) > 0.25:
            try:
                return script_bytes.decode("utf-16-le")
            except UnicodeDecodeError:
                pass
        try:
            return script_bytes.decode("utf-8")
        except UnicodeDecodeError:
            return script_bytes.decode("latin-1", errors="ignore")

    def _dump_emulated_payloads(self, result):
        output_dir = None
        total = 0
        for payload in result.get("embedded_payloads", []):
            encoded = payload.pop("_data_b64", None)
            if encoded is None:
                continue
            try:
                digest = payload.get("sha256", "")
                payload_type = payload.get("type")
                if payload_type not in ("PE", "Shellcode", "binary") or not re.fullmatch(r"[0-9a-f]{64}", digest):
                    raise ValueError("invalid payload metadata")
                if not isinstance(encoded, str) or len(encoded) > 4 * ((MAX_EMBEDDED_PAYLOAD_BYTES + 2) // 3):
                    raise ValueError("payload export size exceeded")
                raw = base64.b64decode(encoded, validate=True)
                if (not raw or (payload_type == "PE" and not raw.startswith(b"MZ"))
                        or len(raw) != payload.get("size") or hashlib.sha256(raw).hexdigest() != digest):
                    raise ValueError("payload integrity check failed")
                if total + len(raw) > MAX_EXPORTED_PAYLOAD_BYTES:
                    raise ValueError("total payload export size exceeded")
                if output_dir is None:
                    root = os.path.abspath("sc0pe_reports")
                    os.makedirs(root, exist_ok=True)
                    output_dir = tempfile.mkdtemp(prefix="powershell_payloads_", dir=root)
                # Fresh private directory and hash-only names: no sample
                # path is ever used as a host write destination.
                suffix = {"PE": ".pe.bin", "Shellcode": ".shellcode.bin", "binary": ".bin"}[payload_type]
                destination = os.path.join(output_dir, digest + suffix)
                fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                with os.fdopen(fd, "wb") as stream:
                    stream.write(raw)
                total += len(raw)
                payload["dump_path"] = destination
                payload["dump_status"] = "saved"
            except (OSError, ValueError, TypeError) as exc:
                payload["dump_status"] = "failed"
                self.report["errors"].append(f"payload_dump_error: {exc}")
        if output_dir:
            print(f"{infoS} Embedded payloads saved as data into: [bold green]{_esc(output_dir)}[white]")

    def run_emulation(self):
        if emulate_powershell is None:
            self.report["errors"].append(f"emulation_unavailable: {_emulator_import_error}")
            return None
        try:
            with open(self.target_file, "rb") as fh:
                script_bytes = fh.read(MAX_SOURCE_CHARS * 4 + 1)
        except OSError as exc:
            self.report["errors"].append(f"emulation_read_error: {exc}")
            return None
        source = self._decode_script_bytes(script_bytes)
        if not source.strip():
            return None

        timeout_seconds = MAX_TIMEOUT_SECONDS
        print(f"\n{infoS} Emulating [bold green]{_esc(self.target_file)}[white] "
              f"(isolated, in-memory, up to {timeout_seconds}s)...")
        try:
            result = emulate_powershell(source, origin=self.target_file, timeout_seconds=timeout_seconds,
                                       include_payload_data=True)
        except Exception as exc:
            self.report["errors"].append(f"emulation_error: {exc}")
            print(f"{errorS} PowerShell emulation failed: {_esc(str(exc))}")
            return None

        result["source_truncated"] = bool(result.get("source_truncated") or len(script_bytes) > MAX_SOURCE_CHARS * 4)
        if result["source_truncated"]:
            mark_source_truncated(result)
        self._dump_emulated_payloads(result)
        self.report["emulation"]["enabled"] = True
        self.report["emulation"]["result"] = result
        for request in result.get("network_requests", []):
            url = str(request.get("url", ""))
            if url and "<unknown" not in url and "<truncated>" not in url and url not in self.report["extracted_urls"]:
                self.report["extracted_urls"].append(url)

        recovered_paths = []
        for event in result.get("ioc_events", []):
            for field in ("path", "args", "command"):
                value = event.get(field)
                if not isinstance(value, str) or "<unknown" in value:
                    continue
                # Include bare path arguments as well as quoted paths
                # within modeled commands; retain their dynamic origin.
                candidates = self._extract_windows_paths(value)
                if field == "path" or (field == "args" and re.fullmatch(r'[A-Za-z]:\\[^",<>|\r\n]*\.(?:exe|dll|ps1)', value, re.IGNORECASE)):
                    candidates += self._extract_windows_paths('"' + value + '"')
                for path in candidates:
                    if path not in recovered_paths:
                        recovered_paths.append(path)
                    paths = self.report.setdefault("extracted_paths", [])
                    if path not in paths:
                        paths.append(path)
        result["recovered_paths"] = recovered_paths

        try:
            self._display_emulation(result)
        except Exception as exc:
            print(f"{errorS} PowerShell emulation completed but rendering failed: {_esc(str(exc))}")
        return result

    def _display_emulation(self, result):
        status = "Emulation ended with partial results" if result.get("analysis_status") == "partial" else "Bounded emulation finished"
        print(f"[dim]>>> {status} ({result.get('elapsed_seconds', 0)}s, "
              f"{result.get('step_count', 0):,} steps, engine: "
              f"{_esc(result.get('engine', 'unknown'))})[white]")
        if "unresolved_dynamic_code" in result.get("incomplete_reasons", []):
            native_payload = any(e.get("reason") == "native-code-not-emulated" and e.get("payload_available")
                                 for e in result.get("ioc_events", []))
            if native_payload:
                print("[bold yellow]Native payload bytes were recovered. Machine-code execution is not modeled; "
                      "any recovered configuration is static evidence. See unresolved events for remaining gaps.[white]")
            else:
                print("[bold yellow]Some dynamic invocations could not be fully analyzed: their inputs or native "
                      "behavior are unresolved. See the unresolved events below.[white]")
        if result.get("analysis_semantics") == "heuristic-path-exploration":
            print("[dim]Behavior trace includes speculative paths; it does not establish runtime reachability.[white]")
        if any(e.get('category') == 'static_payload_recovery' for e in result.get('ioc_events', [])):
            print("[bold yellow]PE data was recovered statically using the assumptions listed below. "
                  "Recovered bytes do not resolve the original dynamic invocation or prove execution.[white]")
        for finding in result.get("findings", []):
            severity = finding.get("severity", "info").upper()
            color = {
                "HIGH": "bold red", "MEDIUM": "bold yellow", "LOW": "bold blue",
                "INFO": "white",
            }.get(severity, "white")
            print(f"  [{color}][{severity}][white] {_esc(finding.get('title', ''))}")

        events = result.get("ioc_events", [])
        print(f"\n[bold cyan]PowerShell behavior trace[white]  ({len(events)} events)")
        if not events:
            print("  [dim](no behavior observed through a modeled PowerShell/.NET API)[white]")
        else:
            display_limit = 250
            for index, event in enumerate(events[:display_limit], 1):
                category = event.get("category", "event")
                details = []
                for key, value in event.items():
                    if key in ("category", "ts") or value in (None, ""):
                        continue
                    text = str(value)
                    if len(text) > 1024:
                        text = text[:1024] + "...<truncated>"
                    details.append(f"{key}={text}")
                detail_text = _esc(", ".join(details))[:4096]
                print(f"  [dim]{index:>4} t+{event.get('ts', 0):6.3f}s[white] "
                      f"[bold magenta]{_esc(category):<20}[white] {detail_text}")
            if len(events) > display_limit:
                print(f"  [dim]... {len(events) - display_limit} additional events are available in the JSON report.[white]")

        payloads = result.get("embedded_payloads", [])
        if payloads:
            payload_table = Table(title="Embedded payloads (data only; not executed)")
            for heading in ("Type", "Bytes", "SHA-256", "Source", "Dump"):
                payload_table.add_column(heading)
            for payload in payloads[:50]:
                payload_table.add_row(str(payload.get("type", "")), str(payload.get("size", "")),
                                      _esc(str(payload.get("sha256", ""))), _esc(str(payload.get("source", ""))),
                                      _esc(str(payload.get("dump_status", "not requested"))))
            print(payload_table)
            for payload in payloads[:50]:
                if payload.get("dump_path"):
                    print(f"  [bold green]Dump:[white] {_esc(payload['dump_path'])}")

        if result.get("recovered_paths"):
            path_table = Table(title="Paths recovered during emulation")
            path_table.add_column("Path")
            for path in result["recovered_paths"]:
                path_table.add_row(_esc(path))
            print(path_table)

        network_events = [event for event in events if event.get("category") in ("network_request", "network_send")]
        print("\n[bold cyan]Network activity[white]")
        if not network_events:
            print("  [dim]No requests resolved through modeled APIs; this does not exclude network behavior in unresolved code.[white]")
        else:
            print("  [dim]Requests are modeled only; network responses are not fetched.[white]")
            for event in network_events:
                details = []
                for key, value in event.items():
                    if key in ("category", "ts") or value in (None, ""):
                        continue
                    details.append(f"{key}={value}")
                print(f"  [bold yellow]{_esc(event.get('category', 'network'))}[white] {_esc(', '.join(details))}")

        configs = result.get("embedded_network_configs", [])
        if configs:
            print("\n[bold cyan]Embedded network configuration (static evidence; no requests sent)[white]")
            for config in configs:
                print(f"  {_esc(str(config.get('method', '')))} {_esc(str(config.get('url', '')))}")


def main():
    if len(sys.argv) < 2:
        err_exit("Usage: powershell_analyzer.py <file> [save_report=True|False]")

    target_pwsh = sys.argv[1]
    pwsh_analyzer = PowerShellAnalyzer(target_pwsh)
    for stage in (
        pwsh_analyzer.scan_code_patterns,
        pwsh_analyzer.extract_path_values,
        pwsh_analyzer.check_executions,
        pwsh_analyzer.extract_network_iocs,
        pwsh_analyzer.detect_large_variable_blobs,
        pwsh_analyzer.find_payloads_xored,
        pwsh_analyzer.check_for_non_xored_payloads_presence,
        pwsh_analyzer.check_only_legit_base64,
        pwsh_analyzer.run_emulation,
    ):
        try:
            stage()
        except Exception as exc:
            # A failed static decoder must not skip behavioral emulation.
            pwsh_analyzer.report["errors"].append(f"{stage.__name__}: {exc}")
            print(f"{errorS} PowerShell analysis error ({stage.__name__}): {_esc(str(exc))}")

    # Aggregate decoded BASE64 text values into a single list file.
    pwsh_analyzer.write_decoded_b64_list_file()

    if get_argv(2) == "True":
        save_report("powershell", pwsh_analyzer.report)


if __name__ == "__main__":
    main()
