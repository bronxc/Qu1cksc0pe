import sys
import re
import hashlib
import subprocess
import yara
import os
import atexit
import stat
import tempfile
import threading
from rich import print
from rich.table import Table
from rich.markup import escape

# Compatibility
path_seperator = "/"
strings_param = "-a"
_MAX_STRINGS_OUTPUT_BYTES = 16 * 1024 * 1024
_STRINGS_TIMEOUT_SECONDS = 60
_owned_strings_path = None
if sys.platform == "win32":
    path_seperator = "\\"

# Gathering Qu1cksc0pe path variable
try:
    sc0pe_path = open(os.path.join(os.path.expanduser("~"), ".qu1cksc0pe_path"), "r").read().strip()
except Exception:
    # Allow running modules directly without the path cache.
    sc0pe_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))

# Get whitelist domains for "chk_wlist" method
whitelist_domains = open(f"{sc0pe_path}{path_seperator}Systems{path_seperator}Multiple{path_seperator}whitelist_domains.txt", "r").read().split("\n")

# WHITELIST DOMAIN SCANNER
def chk_wlist(target_string):
    for pat in whitelist_domains:
        matched = re.findall(pat, target_string)
        if matched:
            return False # Whitelist found
    return True

# HASH CALCULATOR
def calc_hashes(filename, report_object):
    hashmd5 = hashlib.md5()
    hashsha1 = hashlib.sha1()
    hashsha256 = hashlib.sha256()
    try:
        with open(filename, "rb") as ff:
            for chunk in iter(lambda: ff.read(4096), b""):
                hashmd5.update(chunk)
        ff.close()
        with open(filename, "rb") as ff:
            for chunk in iter(lambda: ff.read(4096), b""):
                hashsha1.update(chunk)
        ff.close()
        with open(filename, "rb") as ff:
            for chunk in iter(lambda: ff.read(4096), b""):
                hashsha256.update(chunk)
        ff.close()
    except: # TODO: more specific; also: handle/raise!
        pass

    # OUTPUT
    print(f"[bold red]>>>>[white] MD5: [bold green]{hashmd5.hexdigest()}")
    print(f"[bold red]>>>>[white] SHA1: [bold green]{hashsha1.hexdigest()}")
    print(f"[bold red]>>>>[white] SHA256: [bold green]{hashsha256.hexdigest()}")
    report_object["hash_md5"] = hashmd5.hexdigest()
    report_object["hash_sha1"] = hashsha1.hexdigest()
    report_object["hash_sha256"] = hashsha256.hexdigest()

def _cleanup_owned_strings_file():
    if _owned_strings_path:
        try:
            os.unlink(_owned_strings_path)
        except OSError:
            pass


def _strings_output_path():
    """Return a private per-analysis path shared through the environment."""
    global _owned_strings_path
    configured = os.environ.get("SC0PE_TEMP_TXT_PATH", "").strip()
    if configured:
        return os.path.abspath(os.path.expanduser(configured))
    fd, output_path = tempfile.mkstemp(prefix="qu1cksc0pe-strings-", suffix=".txt")
    os.close(fd)
    try:
        os.chmod(output_path, 0o600)
    except OSError:
        pass
    _owned_strings_path = output_path
    os.environ["SC0PE_TEMP_TXT_PATH"] = output_path
    return output_path


def _secure_strings_file(output_path):
    """Open the strings output without following a pre-existing symlink."""
    flags = os.O_RDWR | os.O_CREAT | os.O_TRUNC
    flags |= getattr(os, "O_BINARY", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(output_path, flags, 0o600)
    if not stat.S_ISREG(os.fstat(fd).st_mode):
        os.close(fd)
        raise OSError("strings output path is not a regular file")
    try:
        os.chmod(output_path, 0o600)
    except OSError:
        pass
    return os.fdopen(fd, "w+b")


def _run_strings_bounded(command, output_file, remaining_bytes):
    """Stream a strings process into the output without exceeding its cap."""
    if remaining_bytes <= 0:
        return True
    try:
        process = subprocess.Popen(
            command,
            stderr=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stdin=subprocess.DEVNULL,
        )
    except OSError:
        return False

    state = {"written": 0, "capped": False}

    def pump_stdout():
        try:
            while process.stdout is not None:
                chunk = process.stdout.read(64 * 1024)
                if not chunk:
                    break
                allowed = min(len(chunk), remaining_bytes - state["written"])
                if allowed > 0:
                    output_file.write(chunk[:allowed])
                    state["written"] += allowed
                if state["written"] >= remaining_bytes:
                    state["capped"] = True
                    try:
                        process.terminate()
                    except OSError:
                        pass
                    break
        finally:
            if process.stdout is not None:
                process.stdout.close()

    reader = threading.Thread(target=pump_stdout, name="qu1cksc0pe-strings-reader", daemon=True)
    reader.start()
    try:
        process.wait(timeout=_STRINGS_TIMEOUT_SECONDS)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()
    reader.join(timeout=5)
    if reader.is_alive():
        try:
            process.kill()
        except OSError:
            pass
        reader.join(timeout=1)
    return state["capped"]


# PERFORM STRINGS
def perform_strings(filename):
    """Extract bounded strings without invoking a command shell."""
    output_path = _strings_output_path()
    commands = [["strings", strings_param, str(filename)]]
    if sys.platform != "win32":
        commands.append(["strings", strings_param, "-e", "l", str(filename)])

    try:
        with _secure_strings_file(output_path) as output_file:
            for command in commands:
                remaining = _MAX_STRINGS_OUTPUT_BYTES - output_file.tell()
                capped = _run_strings_bounded(command, output_file, remaining)
                output_file.flush()
                if capped or output_file.tell() >= _MAX_STRINGS_OUTPUT_BYTES:
                    output_file.truncate(_MAX_STRINGS_OUTPUT_BYTES)
                    break
            output_file.flush()
            output_file.seek(0)
            raw = output_file.read(_MAX_STRINGS_OUTPUT_BYTES)
    except OSError:
        return []
    return raw.decode("utf-8", errors="ignore").split("\n")


atexit.register(_cleanup_owned_strings_file)

# YARA RULE CACHE (rule_dir -> list[(rule_file, yara.Rules)])
_YARA_RULE_CACHE = {}
_YARA_RULE_CACHE_ERR = {}
_YARA_MATCH_TIMEOUT_SECONDS = 2

def _resolve_rule_dir(rulepath):
    cleaned = str(rulepath or "").strip().strip('"').strip("'")
    cleaned = os.path.expandvars(os.path.expanduser(cleaned))
    if cleaned and os.path.isdir(cleaned):
        return os.path.abspath(cleaned)
    # Backwards-compat: treat as sc0pe_path-relative even if it starts with "/".
    rel = cleaned.lstrip("/\\")
    candidate = os.path.join(sc0pe_path, rel)
    if os.path.isdir(candidate):
        return os.path.abspath(candidate)
    return ""

def _load_yara_rules(rule_dir):
    if rule_dir in _YARA_RULE_CACHE:
        return _YARA_RULE_CACHE[rule_dir]

    compiled = []
    err = ""
    try:
        files = sorted(os.listdir(rule_dir))
    except Exception as e:
        err = f"rule_dir_unreadable: {e}"
        _YARA_RULE_CACHE[rule_dir] = []
        _YARA_RULE_CACHE_ERR[rule_dir] = err
        return []

    failed = 0
    for rf in files:
        if not rf.lower().endswith((".yara", ".yar")):
            continue
        full = os.path.join(rule_dir, rf)
        try:
            compiled.append((rf, yara.compile(filepath=full)))
        except Exception:
            failed += 1
            continue

    if not compiled:
        err = "no_rules_compiled"
        if failed:
            err = f"no_rules_compiled_failed={failed}"

    _YARA_RULE_CACHE[rule_dir] = compiled
    _YARA_RULE_CACHE_ERR[rule_dir] = err
    return compiled

# YARA SCANNER
def yara_rule_scanner(
    rulepath,
    filename,
    report_object,
    quiet_nomatch=False,
    header_label="",
    quiet_errors=False,
    detailed_key=None,
    print_matches=True,
    print_nomatch=True,
):
    """
    Shared YARA scanner with rule caching.

    Backwards-compatible args:
      yara_rule_scanner(rulepath, filename, report_object)

    Optional args:
      quiet_nomatch: suppress per-file "no match" message
      header_label: printed before matches (useful to label targets)
      quiet_errors: suppress rule-load errors. Match timeouts are always
                    reported because silently skipping a rule can create a
                    false-negative impression.
      detailed_key: report key for detailed per-target matches (default: None)

    Returns True if any rule matched; False otherwise.
    """
    yara_match_indicator = 0
    report_object.setdefault("matched_rules", [])
    report_object.setdefault("yara_scan_warnings", [])
    if detailed_key:
        report_object.setdefault(detailed_key, [])

    rule_dir = _resolve_rule_dir(rulepath)
    if not rule_dir:
        if not quiet_errors:
            print(f"[bold white on red]YARA rule directory could not be resolved for: {rulepath}")
        return False

    compiled_rules = _load_yara_rules(rule_dir)
    if not compiled_rules:
        if not quiet_errors:
            err = _YARA_RULE_CACHE_ERR.get(rule_dir, "")
            print(f"[bold white on red]No YARA rules could be loaded from: {rule_dir} ({err})")
        return False

    # This array for holding and parsing easily matched rules
    yara_matches = []
    timed_out_rule_files = []
    for rule_file, rules in compiled_rules:
        try:
            # A single pathological regex-heavy rule used to hold the whole
            # document scan for minutes on multi-megabyte script samples.
            # YARA enforces this deadline internally, so it also interrupts
            # native matching work that a Python-side timer cannot preempt.
            tempmatch = rules.match(filename, timeout=_YARA_MATCH_TIMEOUT_SECONDS)
        except yara.TimeoutError:
            warning = {
                "type": "match_timeout",
                "target": str(filename),
                "rule_file": str(rule_file),
                "timeout_seconds": _YARA_MATCH_TIMEOUT_SECONDS,
            }
            if warning not in report_object["yara_scan_warnings"]:
                report_object["yara_scan_warnings"].append(warning)
            timed_out_rule_files.append(str(rule_file))
            continue
        except Exception:
            continue
        if tempmatch:
            for matched in tempmatch:
                if matched.strings:
                    yara_matches.append(matched)

    if timed_out_rule_files:
        shown = ", ".join(escape(name) for name in timed_out_rule_files[:5])
        remaining = len(timed_out_rule_files) - 5
        if remaining > 0:
            shown += f", ... (+{remaining} more)"
        print(
            f"[bold yellow]YARA scan warning:[white] "
            f"{len(timed_out_rule_files)} rule file(s) exceeded the "
            f"{_YARA_MATCH_TIMEOUT_SECONDS}s match limit while scanning "
            f"[bold cyan]{escape(str(filename))}[white]: {shown}"
        )

    # Printing area
    if yara_matches != []:
        yara_match_indicator += 1
        for rul in yara_matches:
            report_object["matched_rules"].append({str(rul): []})
            detailed = {
                "target": filename,
                "rule": str(rul),
                "strings": []
            }
            if print_matches:
                yaraTable = Table()
                if header_label:
                    print(f"[bold magenta]>>>>[white] {header_label}[white]")
                    header_label = ""  # Print once.
                print(f">>> Rule name: [i][bold magenta]{rul}[/i]")
                yaraTable.add_column("Offset", style="bold green", justify="center")
                yaraTable.add_column("Matched String/Byte", style="bold green", justify="center")
            for matched_pattern in rul.strings:
                if print_matches:
                    yaraTable.add_row(f"{hex(matched_pattern.instances[0].offset)}", f"{str(matched_pattern.instances[0].matched_data)}")
                try:
                    s = {"offset": hex(matched_pattern.instances[0].offset), "matched_pattern": matched_pattern.instances[0].matched_data.decode("ascii")}
                except:
                    s = {"offset": hex(matched_pattern.instances[0].offset), "matched_pattern": str(matched_pattern.instances[0].matched_data)}
                report_object["matched_rules"][-1][str(rul)].append(s)
                detailed["strings"].append(s)
            if detailed_key:
                report_object[detailed_key].append(detailed)
            if print_matches:
                print(yaraTable)
                print(" ")

    if yara_match_indicator == 0:
        if (not quiet_nomatch) and print_nomatch:
            print(f"[bold white on red]There is no rules matched for {filename}")
        return False
    return True
