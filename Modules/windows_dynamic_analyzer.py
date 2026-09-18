import re
import os
import sys
import json
import psutil
import asyncio
import warnings
import argparse
import time
import math
import queue
import signal
import subprocess
import ipaddress
from dynamic_memory import MemoryScanSession
from windows_injection import InjectionMonitor, INJECTION_APIS, inspect_process_image
from pathlib import Path
from urllib.parse import urlsplit
from rich.markup import escape
from utils.helpers import err_exit
from utils.helpers import update_table
from windows_process_reader import WindowsProcessReader

try:
    from rich import print, box
    from rich.table import Table
    from rich.live import Live
    from rich.layout import Layout
    from rich.panel import Panel
except Exception:
    err_exit("Error: >rich< module not found.")

from datetime import datetime

try:
    import pymem
except Exception:
    err_exit("Error: >pymem< module not found.")

try:
    from windows_api_hooker import WindowsAPIHooker
except Exception:
    err_exit("Error: >windows_api_hooker< could not be loaded.")

try:
    from colorama import Fore, Style
except Exception:
    err_exit("Error: >colorama< module not found.")

# Colors
red    = Fore.LIGHTRED_EX
cyan   = Fore.LIGHTCYAN_EX
yellow = Fore.LIGHTYELLOW_EX
green  = Fore.LIGHTGREEN_EX
white  = Style.RESET_ALL

# Legends
errorS = f"[bold cyan][[bold red]![bold cyan]][white]"
infoS  = f"[bold cyan][[bold red]*[bold cyan]][white]"
infoC  = f"{cyan}[{red}*{cyan}]{white}"

# Sc0pe path
try:
    sc0pe_path = open(os.path.join(os.path.expanduser("~"), ".qu1cksc0pe_path"), "r").read().strip()
except Exception:
    sc0pe_path = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))

# Compatibility
path_seperator = "/"
if sys.platform == "win32":
    path_seperator = "\\"

# Ignore warnings
warnings.filterwarnings("ignore")

# API-entry observations, kept separately from observed TCP connections.
_NETWORK_APIS = frozenset((
    'connect', 'WSAConnect', 'send', 'recv', 'sendto', 'WSASend', 'WSARecv', 'getaddrinfo',
    'InternetOpen', 'InternetOpenA', 'InternetOpenW', 'InternetConnectA', 'InternetConnectW',
    'InternetOpenUrlA', 'InternetOpenUrlW', 'HttpOpenRequestA', 'HttpOpenRequestW',
    'InternetRead', 'InternetReadFile', 'WinHttpOpen', 'WinHttpConnect',
    'WinHttpOpenRequest', 'WinHttpSendRequest', 'WinHttpReadData',
))

# Processes commonly abused by malware (LOLBins + shells)
_SUSPICIOUS_PROCESSES = {
    "cmd.exe", "powershell.exe", "powershell_ise.exe", "pwsh.exe",
    "rundll32.exe", "regsvr32.exe", "mshta.exe",
    "wscript.exe", "cscript.exe",
    "msbuild.exe", "installutil.exe", "regasm.exe", "regsvcs.exe",
    "certutil.exe", "bitsadmin.exe",
    "schtasks.exe", "at.exe",
    "wmic.exe", "wmiprvse.exe",
    "cmstp.exe", "control.exe",
    "odbcconf.exe", "pcalua.exe",
    "forfiles.exe", "bash.exe",
    "msiexec.exe",
    "net.exe", "net1.exe",
    "sc.exe", "bcdedit.exe",
    "vssadmin.exe", "wbadmin.exe",
    "nltest.exe", "whoami.exe",
    "curl.exe", "wget.exe",
}

# Compiled regex patterns
_URL_RE     = re.compile(r"https?://[a-zA-Z0-9./@?=_%:&#+\-\[\]~!$'()*,;]{8,}")
_IP_RE      = re.compile(r"(?<![\w.])(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?![\w.])")
# Bound each component and reject suffixes of oversized tokens. Unbounded
# searches on long packed/base64 strings can monopolize the event-loop thread.
_EMAIL_RE   = re.compile(r"(?<![a-zA-Z0-9._%+\-])[a-zA-Z0-9._%+\-]{1,64}@[a-zA-Z0-9.\-]{2,253}\.[a-zA-Z]{2,63}(?![a-zA-Z0-9.\-])")
_TG_TOKEN   = re.compile(r"\b(\d{8,12}:[A-Za-z0-9_-]{35})\b")
_TG_CHATID  = re.compile(r"chat_id=(-?\d{5,15})")
_DISCORD_WH = re.compile(r"https://discord(?:app)?\.com/api/webhooks/\d{17,20}/[A-Za-z0-9_-]{60,80}")
_DISCORD_TK = re.compile(r"[MNO][A-Za-z0-9_-]{23}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27}")
_REG_RE     = re.compile(
    r"(?:HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER|HKEY_CLASSES_ROOT|HKLM|HKCU|HKCR)"
    r"\\[\\A-Za-z0-9_\\ ]{5,80}", re.IGNORECASE
)
_ENC_CMD    = re.compile(r"(?:-[Ee]ncodedCommand|-[Ee]nc?)\s+([A-Za-z0-9+/=]{20,})", re.IGNORECASE)

# Some Windows handle-name queries can deadlock inside psutil. Keep them out
# of the analyzer process: a cancelled executor thread cannot be safely killed.
_OPEN_FILES_PROBE = """
import json, psutil, sys
p = psutil.Process(int(sys.argv[1]))
if p.create_time() != float(sys.argv[2]):
    raise SystemExit('pid_reused')
print(json.dumps([f.path for f in p.open_files()][:4096]))
"""


async def _query_open_files(pid, birth, timeout=3.0):
    spawning = asyncio.create_task(asyncio.create_subprocess_exec(
        sys.executable, '-c', _OPEN_FILES_PROBE, str(pid), str(birth),
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        creationflags=subprocess.CREATE_NO_WINDOW))
    worker = None
    try:
        worker = await asyncio.shield(spawning)
        output, error = await asyncio.wait_for(worker.communicate(), timeout)
        if worker.returncode:
            raise OSError(error.decode('utf-8', errors='replace')[-300:])
        return json.loads(output)
    finally:
        # Cancellation during pipe setup must also reap the newly spawned child.
        if worker is None:
            worker = await spawning
        if worker.returncode is None:
            try:
                worker.kill()
            except ProcessLookupError:
                pass
            await worker.communicate()


class WindowsDynamicAnalyzer:
    def __init__(self, target_pid, output_dir=".", dump_interval=10.0, *, memory_scan=True,
                 yara_paths=None, dump_suspicious=True, memory_dumps=True, injection_detection=True):
        self.target_pid       = target_pid
        self.output_dir = Path(output_dir).resolve()
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.report_path = self.output_dir / f"sc0pe_process-{target_pid}.json"
        self._stop = asyncio.Event()
        self._hookers = {}
        self._retired_hookers = []
        self._dump_directories = {target_pid: self.output_dir}
        self._pending_dumps = {}
        self.dump_interval = dump_interval
        self._last_dump_time = {}
        self.memory_dumps_enabled = memory_dumps
        self._api_queue = queue.Queue(maxsize=4096)
        self._dropped_callbacks = 0
        self._injection = InjectionMonitor() if injection_detection else None
        self._injection_queue = queue.Queue(maxsize=1024)
        self._injection_dropped = 0
        self._network_api_index = {}
        self.target_processes = []
        self.dumped_files     = []
        self.logged_things    = []
        self._dump_mtimes     = {}   # pid -> last mtime, avoids re-reading unchanged dumps

        with open(f"{sc0pe_path}{path_seperator}Systems{path_seperator}Multiple{path_seperator}whitelist_domains.txt", "r") as f:
            self.whitelist_domains = f.read().split("\n")

        with open(f"{sc0pe_path}{path_seperator}Systems{path_seperator}Windows{path_seperator}windows_api_trace_list.txt", "r") as f:
            self.target_api_list = f.read().split("\n")
        if self._injection:
            self.target_api_list = list(dict.fromkeys(self.target_api_list+sorted(INJECTION_APIS)))

        self.proc_handler = psutil.Process(self.target_pid)
        self._processes = {target_pid: self.proc_handler}
        self._process_births = {target_pid: self.proc_handler.create_time()}
        self._process_exited_at = {}
        self.target_processes.append(self.target_pid)

        self._hooker = None   # kept alive so hooks remain active
        self._memory_scan = MemoryScanSession(
            yara_paths if yara_paths is not None else [Path(sc0pe_path) / 'Systems' / 'Windows' / 'YaraRules_Windows'],
            self.output_dir, dump_suspicious=dump_suspicious,
        ) if memory_scan else None

        self.report = {
            "analysis": {"pid": target_pid, "started_at": datetime.now().astimezone().isoformat(),
                         "status": "running", "stop_reason": None,
                         "limitations": ["Polling can miss short-lived processes, files and connections.",
                                         "API tracing requires 64-bit Python and supports x64 and WOW64/x86 targets.",
                                         "Memory capture is bounded to 50 MiB per process."]},
            "errors": [],
            "features": {"memory_scan":memory_scan,"memory_dumps":memory_dumps,
                         "dump_suspicious":dump_suspicious,"injection_detection":injection_detection},
            "injection_detection": self._injection.report if self._injection else {'status':'disabled'},
            "memory_dumps": {},
            "memory_errors": {},
            "api_events": [],
            "api_events_truncated": 0,
            "api_callbacks_dropped": 0,
            "network_api_observations": [],
            "network_api_observations_dropped": 0,
            "network_api_observation_limit": 1000,
            "memory_scan": self._memory_scan.report if self._memory_scan else {"status": "disabled"},
            "process_hook_info": {},
            "process_history": [],
            "network_connections": [],
            "api_calls":           [],
            "commandline_args":    {},
            "process_ids":         {},
            "open_files":          {},
            "open_file_status":    {},
            "loaded_modules":      {},
            "extracted_urls":      {},
            "hook_info": {
                "hooked": [],
                "failed": [],
            },
            "interesting_findings": {
                "telegram_bot_token": [],
                "telegram_chat_id":   [],
                "discord_webhook":    [],
                "discord_token":      [],
                "email":              [],
                "email_password":     [],
                "ip_addresses":       [],
                "registry_keys":      [],
                "encoded_commands":   [],
            },
        }
        self.report['process_ids'][target_pid] = {
            'name': self.proc_handler.name(), 'parent_pid': self.proc_handler.ppid(),
            'created_at': self._process_births[target_pid], 'childs': [],
        }

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _is_valid_url(self, url: str) -> bool:
        if len(url) < 13 or url in {"http://", "https://"}:
            return False
        try:
            host = (urlsplit(url).hostname or "").lower().rstrip(".")
        except ValueError:
            return False
        if not host:
            return False
        return not any(host == wl.strip().lower().rstrip(".") or
                       host.endswith("." + wl.strip().lower().rstrip("."))
                       for wl in self.whitelist_domains if wl.strip())

    def _extract_strings_from_raw(self, raw: bytes):
        """Return (ascii_strings, wide_strings) extracted from a raw byte buffer."""
        ascii_strs = [m.decode(errors="ignore")
                      for m in re.findall(rb"[^\x00-\x1F\x7F-\xFF]{4,}", raw)]
        wide_raw   = re.findall(rb"(?:[\x20-\x7E]\x00){4,}", raw)
        wide_strs  = [s.replace(b"\x00", b"").decode(errors="ignore") for s in wide_raw]
        return ascii_strs, wide_strs

    def _search(self, pattern: re.Pattern, strings: list) -> list:
        """Apply a compiled pattern across a list of strings; return unique matches."""
        seen, results = set(), []
        for s in strings:
            for m in pattern.findall(s):
                val = m if isinstance(m, str) else (m[0] if isinstance(m, tuple) else str(m))
                if val and val not in seen:
                    seen.add(val)
                    results.append(val)
        return results

    def _add_finding(self, key: str, values: list):
        """Add unique values to an interesting_findings category."""
        bucket = self.report["interesting_findings"][key]
        for v in values:
            if v not in bucket:
                bucket.append(v)

    # ------------------------------------------------------------------
    # Async coroutines
    # ------------------------------------------------------------------

    def _generation_report(self, pid, birth):
        if self._process_births.get(pid) == birth:
            return self.report
        return next(entry for entry in self.report['process_history']
                    if entry['pid'] == pid and entry['created_at'] == birth)

    def _archive_process(self, pid, new_birth):
        birth = self._process_births[pid]
        history = {'pid': pid, 'created_at': birth}
        for section in ('process_ids', 'process_hook_info', 'commandline_args', 'open_files',
                        'open_file_status', 'loaded_modules', 'extracted_urls', 'memory_dumps', 'memory_errors'):
            value = self.report[section].pop(pid, None)
            history[section] = {pid: value} if value is not None else {}
        self.report['process_history'].append(history)
        hooker = self._hookers.pop(pid, None)
        if hooker:
            self._retired_hookers.append((pid, birth, hooker))
        if self._injection:
            history['image'] = self._injection.report['images'].pop(str(pid), None)
        self._last_dump_time.pop(pid, None)
        self._dump_mtimes.pop(pid, None)
        self._process_exited_at.pop(pid, None)
        self._dump_directories[pid] = self.output_dir / 'process_generations' / f'{pid}_{int(new_birth * 10000000)}'

    def _discover_processes(self):
        # Windows keeps a child's parent PID after the parent exits. Calling
        # children() on only living parents loses these descendants entirely.
        snapshot = {}
        for pid in psutil.pids():
            try:
                process = psutil.Process(pid)  # fresh identity, no process_iter cache
                info = process.as_dict(attrs=['pid', 'ppid', 'name', 'create_time'])
                if info['create_time'] is not None:
                    snapshot[pid] = (process, info)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        observed_at = time.time()
        for pid, birth in self._process_births.items():
            current = snapshot.get(pid)
            if ((current is not None and current[1]['create_time'] != birth)
                    or not self._processes[pid].is_running()):
                self._process_exited_at.setdefault(pid, observed_at)
        pending = {pid: item for pid, item in snapshot.items()
                   if self._process_births.get(pid) != item[1]['create_time']}
        changed = True
        while changed:
            changed = False
            for pid, (process, info) in list(pending.items()):
                parent_pid = info['ppid']
                parent_birth = self._process_births.get(parent_pid)
                if parent_birth is None or info['create_time'] < parent_birth:
                    continue
                current_parent = snapshot.get(parent_pid)
                if current_parent and current_parent[1]['create_time'] != parent_birth:
                    continue  # the parent PID now belongs to a different process
                exit_observed = self._process_exited_at.get(parent_pid)
                if exit_observed is not None and info['create_time'] > exit_observed:
                    continue
                if pid in self._processes:
                    self._archive_process(pid, info['create_time'])
                self._processes[pid] = process
                self._process_births[pid] = info['create_time']
                if pid not in self.target_processes:
                    self.target_processes.append(pid)
                self._dump_directories.setdefault(pid, self.output_dir)
                self.report['process_ids'][pid] = {
                    'name': info['name'] or str(pid), 'parent_pid': parent_pid,
                    'created_at': info['create_time'], 'childs': [],
                }
                children = self.report['process_ids'][parent_pid]['childs']
                if pid not in children:
                    children.append(pid)
                del pending[pid]
                changed = True

    async def gather_processes(self, table_object):
        displayed = set()
        while True:
            self._discover_processes()
            for pid, info in self.report['process_ids'].items():
                identity = (pid, self._process_births[pid])
                if identity not in displayed:
                    update_table(table_object, 8, escape(info['name']), str(pid))
                    displayed.add(identity)
            await asyncio.sleep(0.5)

    async def enumerate_network_connections(self, table_object):
        while True:
            for pid_n in list(self.target_processes):
                try:
                    proc_net = self._processes[pid_n]
                    if not proc_net.is_running():
                        continue
                    for conn in proc_net.net_connections():
                        if conn.raddr:
                            conn_str = (f"{proc_net.pid}|{proc_net.name()}|"
                                        f"{conn.raddr.ip}:{conn.raddr.port}|{conn.status}")
                            if conn_str not in self.report["network_connections"]:
                                update_table(table_object, 15, *conn_str.split("|"))
                                self.report["network_connections"].append(conn_str)
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            await asyncio.sleep(0.5)

    async def check_alive_process(self):
        while True:
            for tp in list(self.target_processes):
                if not self._processes[tp].is_running():
                    self.target_processes.remove(tp)
            if not self.target_processes:
                # One final snapshot before stopping closes the race where the
                # parent exits just after spawning a child between polls.
                self._discover_processes()
                self.target_processes[:] = [pid for pid in self.target_processes
                                             if self._processes[pid].is_running()]
            if not self.target_processes:
                self.report["analysis"]["stop_reason"] = "process_tree_exited"
                self._stop.set()
                return
            await asyncio.sleep(0.5)

    async def parse_cmdline_arguments(self):
        while True:
            for tpcmd in list(self.target_processes):
                try:
                    if tpcmd not in self.report["commandline_args"]:
                        cmd_tp = self._processes[tpcmd]
                        if not cmd_tp.is_running():
                            continue
                        cmdline = cmd_tp.cmdline()
                        if len(cmdline) > 1:
                            self.report["commandline_args"][tpcmd] = cmdline[1:]
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            await asyncio.sleep(1)

    async def get_loaded_modules(self):
        def modules_for_pid(pid):
            mem = pymem.Pymem()
            try:
                mem.open_process_from_id(pid)
                return [mod.name for mod in mem.list_modules()]
            finally:
                if mem.process_handle:
                    mem.close_process()
        while True:
            for proc_pid in list(self.target_processes):
                try:
                    if not self._processes[proc_pid].is_running():
                        continue
                    birth = self._process_births[proc_pid]
                    modules = await asyncio.to_thread(modules_for_pid, proc_pid)
                    if self._process_births.get(proc_pid) == birth and self._processes[proc_pid].is_running():
                        self.report["loaded_modules"][proc_pid] = modules
                except Exception:
                    continue
            await asyncio.sleep(2)

    def _record_dump(self, pid, birth, reader, state):
        report = self._generation_report(pid, birth)
        path = Path(reader.output_dir) / f'qu1cksc0pe_memory_dump_{pid}.bin'
        if state:
            captures = report['memory_dumps'].get(pid, {}).get('captures', 0) + 1
            report['memory_dumps'][pid] = {'path': str(path.relative_to(self.output_dir)),
                'bytes': path.stat().st_size, 'captures': captures, 'captured_at': time.time(), 'created_at': birth}
            report['memory_errors'].pop(pid, None)
        else:
            report['memory_errors'][pid] = reader.last_error or 'Memory capture failed'

    async def memory_dumper(self, table_obj):
        loop = asyncio.get_running_loop()
        while True:
            try:
                for t_p in list(self.target_processes):
                    if not self._processes[t_p].is_running():
                        continue
                    birth = self._process_births[t_p]
                    identity = (t_p, birth)
                    dump_name = f"qu1cksc0pe_memory_dump_{t_p}.bin"
                    if time.monotonic() - self._last_dump_time.get(t_p, -float('inf')) < self.dump_interval:
                        continue
                    destination = self._dump_directories[t_p]
                    destination.mkdir(parents=True, exist_ok=True)
                    w_p_r = WindowsProcessReader(t_p, destination, expected_birth=birth)
                    try:
                        future = loop.run_in_executor(None, w_p_r.dump_memory)
                        self._pending_dumps[identity] = (w_p_r, future)
                        state = await asyncio.shield(future)
                    except Exception:
                        state = False
                    self._record_dump(t_p, birth, w_p_r, state)
                    if state and self._process_births.get(t_p) == birth:
                        if dump_name not in self.dumped_files:
                            self.dumped_files.append(dump_name)
                        self._last_dump_time[t_p] = time.monotonic()
                        try:
                            size = os.path.getsize(destination / dump_name)
                        except (OSError, KeyboardInterrupt):
                            size = 0
                        update_table(table_obj, 8, str(t_p), dump_name, str(size))
                    self._pending_dumps.pop(identity, None)
            except (Exception, KeyboardInterrupt):
                pass
            await asyncio.sleep(1.5)

    def _load_and_extract(self, dump_path):
        """Read dump file and extract strings — runs in thread executor."""
        with open(dump_path, "rb") as fh:
            raw = fh.read()
        return self._extract_strings_from_raw(raw)

    async def extract_url_and_interesting_from_memory(self, table_object, once=False):
        loop = asyncio.get_running_loop()
        while True:
            for tpu in list(self.report["memory_dumps"]):
                birth = self._process_births[tpu]
                dump_path = self.output_dir / self.report['memory_dumps'][tpu]['path']
                if not os.path.exists(dump_path):
                    continue

                # Skip re-processing if the dump file hasn't changed
                try:
                    mtime = os.path.getmtime(dump_path)
                except OSError:
                    continue
                if self._dump_mtimes.get(tpu) == mtime:
                    continue

                # File read + regex string extraction run in a thread so they
                # don't block the event loop (50 MB file + re.findall is slow)
                try:
                    ascii_strs, wide_strs = await loop.run_in_executor(
                        None, self._load_and_extract, dump_path
                    )
                except OSError:
                    continue

                if self._process_births.get(tpu) != birth:
                    continue
                all_strs = ascii_strs + wide_strs
                fi       = self.report["interesting_findings"]

                # Telegram bot token
                self._add_finding("telegram_bot_token",
                    [t.replace("bot", "") if t.startswith("bot") else t
                     for t in self._search(_TG_TOKEN, all_strs)])

                # Telegram chat_id
                self._add_finding("telegram_chat_id", self._search(_TG_CHATID, all_strs))

                # Discord webhook URL
                self._add_finding("discord_webhook", self._search(_DISCORD_WH, all_strs))

                # Discord bot token
                self._add_finding("discord_token", self._search(_DISCORD_TK, all_strs))

                # String adjacency does not establish a credential relationship.
                # Keep the legacy email_password field empty for report compatibility.
                for mail in self._search(_EMAIL_RE, all_strs):
                    if mail not in fi["email"]:
                        fi["email"].append(mail)


                # Non-loopback, non-private, non-version-like IP addresses
                def _is_ioc_ip(ip):
                    try:
                        candidate = ipaddress.ip_address(ip)
                        if not candidate.is_global or candidate.is_multicast:
                            return False
                    except ValueError:
                        return False
                    if ip.startswith(("127.", "0.", "169.254.", "255.", "10.", "192.168.")):
                        return False
                    try:
                        parts = [int(o) for o in ip.split(".")]
                        if parts[0] == 172 and 16 <= parts[1] <= 31:
                            return False
                        # All octets small → version string (e.g. 1.2.3.4)
                        if max(parts) < 20:
                            return False
                        # Last octet 0 → network/subnet address (e.g. 145.0.0.0, 77.1.0.0)
                        if parts[3] == 0:
                            return False
                        # Second octet 0 → version string or subnet (e.g. 21.0.2.14)
                        if parts[1] == 0:
                            return False
                        # Last three octets identical → placeholder (e.g. 37.7.7.7)
                        if parts[1] == parts[2] == parts[3]:
                            return False
                        # Low first + low second octet → version string (e.g. 14.5.201.12)
                        if parts[0] < 20 and parts[1] < 10:
                            return False
                    except (ValueError, IndexError):
                        return False
                    return True
                self._add_finding("ip_addresses", [
                    ip for ip in self._search(_IP_RE, all_strs) if _is_ioc_ip(ip)
                ])

                # Registry keys
                self._add_finding("registry_keys", self._search(_REG_RE, all_strs))

                # PowerShell encoded commands
                self._add_finding("encoded_commands", self._search(_ENC_CMD, all_strs))

                # URLs
                seen_urls = set(self.report["extracted_urls"].get(tpu, []))
                tpu_urls  = list(seen_urls)
                for s in all_strs:
                    for url in _URL_RE.findall(s):
                        if url not in seen_urls and self._is_valid_url(url):
                            update_table(table_object, 13, url)
                            tpu_urls.append(url)
                            seen_urls.add(url)
                self.report["extracted_urls"][tpu] = tpu_urls
                self._dump_mtimes[tpu] = mtime

            if once:
                return
            await asyncio.sleep(2)

    def _monitor_handler(self, data_type, table_object, description):
        for item in self.report["interesting_findings"].get(data_type, []):
            if item not in self.logged_things:
                update_table(table_object, 12, description, str(item))
                self.logged_things.append(item)

    async def interesting_findings_monitor(self, table_object):
        _LABELS = {
            "telegram_bot_token": "Telegram Bot Token",
            "telegram_chat_id":   "Telegram Chat ID",
            "discord_webhook":    "Discord Webhook",
            "discord_token":      "Discord Bot Token",
            "email":              "E-Mail Address",
            "ip_addresses":       "Embedded IP",
            "registry_keys":      "Registry Key",
            "encoded_commands":   "Encoded PS Command",
        }
        while True:
            for key, label in _LABELS.items():
                self._monitor_handler(data_type=key, table_object=table_object, description=label)
            await asyncio.sleep(1)

    async def _attach_one(self, pid, on_api_call_cb, birth=None):
        birth = self._process_births[pid] if birth is None else birth
        for old_pid, _, previous in self._retired_hookers:
            if old_pid == pid and not await asyncio.to_thread(previous.stop):
                self.report['errors'].append({'component': 'hooker', 'pid': pid,
                    'error': 'Previous process debugger has not stopped; new attachment deferred'})
                return
        if self._process_births.get(pid) != birth or not self._processes[pid].is_running():
            return

        def save_status(status):
            status['created_at'] = birth
            self._generation_report(pid, birth)['process_hook_info'][pid] = status
            if pid == self.target_pid and self._process_births.get(pid) == birth:
                self.report['hook_info'] = status

        def _threadsafe_cb(api_name, args_str):
            try:
                self._api_queue.put_nowait((api_name, args_str, pid, birth, time.time()))
            except queue.Full:
                self._dropped_callbacks += 1

        def _injection_cb(event):
            event['source_created_at'] = birth
            try:
                self._injection_queue.put_nowait(event)
            except queue.Full:
                self._injection_dropped += 1

        hooker = WindowsAPIHooker(
            pid,
            [a for a in self.target_api_list if a.strip()],
            _threadsafe_cb,
            event_callback=_injection_cb if self._injection else None,
            expected_birth=birth,
        )
        try:
            # start() only allocates resources; DebugActiveProcess runs inside the thread
            hooker.start()
        except Exception as exc:
            status = {
                "hooked": [],
                "architecture": hooker.architecture,
                "failed": [{"api": "attach", "reason": str(exc)}],
            }
            save_status(status)
            return

        self._hookers[pid] = hooker
        if pid == self.target_pid:
            self._hooker = hooker

        # Continuously sync hook status from the background debug thread.
        # Wait for the thread to actually start (attach_error might be set early).
        await asyncio.sleep(0.5)

        while hooker._running and self._process_births.get(pid) == birth:
            status = {
                "hooked": list(hooker.hooked),
                "architecture": hooker.architecture,
                "failed": list(hooker.failed),
                "loop_error": hooker.loop_error or "",
                "attach_error": hooker.attach_error or "",
                "ready": hooker.ready,
                "phase": hooker.phase, "api_call_count": hooker.api_call_count,
                "debug_event_count": hooker.debug_event_count,
            }
            save_status(status)
            await asyncio.sleep(2)

        # Final sync after debug loop exits
        status = {
            "hooked": list(hooker.hooked),
            "architecture": hooker.architecture,
            "failed": list(hooker.failed),
            "loop_error": hooker.loop_error or "",
            "attach_error": hooker.attach_error or "",
            "ready": hooker.ready,
            "phase": hooker.phase, "api_call_count": hooker.api_call_count,
        }
        save_status(status)

    async def attach_process_with_hooker(self, on_api_call_cb):
        tasks = {}
        try:
            while True:
                for pid in list(self.target_processes):
                    identity = (pid, self._process_births[pid])
                    if identity not in tasks:
                        tasks[identity] = asyncio.create_task(self._attach_one(pid, on_api_call_cb, identity[1]))
                await asyncio.sleep(0.25)
        finally:
            for task in tasks.values():
                task.cancel()
            await asyncio.gather(*tasks.values(), return_exceptions=True)

    async def consume_api_calls(self, callback):
        while True:
            for _ in range(256):
                try:
                    self._deliver_api_call(callback, self._api_queue.get_nowait())
                except queue.Empty:
                    break
            self.report['api_callbacks_dropped'] = self._dropped_callbacks
            self._drain_injection_events()
            await asyncio.sleep(.02)

    def _deliver_api_call(self, callback, event):
        self.record_api_call(*event)
        if callback and callback != self.record_api_call:
            callback(*event[:3])

    def _drain_injection_events(self):
        if self._injection:
            while not self._injection_queue.empty():
                self._injection.observe(self._injection_queue.get_nowait())
            self._injection.report['callback_events_dropped'] = self._injection_dropped

    async def inspect_process_images(self):
        while True:
            for pid in list(self.target_processes):
                if self._processes[pid].is_running():
                    birth = self._process_births[pid]
                    result = await asyncio.to_thread(inspect_process_image,pid,birth)
                    if self._process_births.get(pid) == birth:
                        self._injection.observe_image(result)
                    else:
                        self._generation_report(pid, birth)['image'] = result
            await asyncio.sleep(2)

    async def get_open_files(self):
        while True:
            for tprc in list(self.target_processes):
                birth = self._process_births[tprc]
                try:
                    opfl = self._processes[tprc]
                    if not opfl.is_running():
                        continue
                    files = await _query_open_files(tprc, birth)
                    if self._process_births.get(tprc) != birth:
                        continue
                    self.report["open_files"][tprc] = files
                    self.report['open_file_status'][tprc] = {'status':'observed','time':time.time()}
                except asyncio.TimeoutError:
                    self._generation_report(tprc, birth)['open_file_status'][tprc] = {'status':'unavailable','reason':'query_timeout','time':time.time()}
                except Exception as exc:
                    self._generation_report(tprc, birth)['open_file_status'][tprc] = {'status':'unavailable','reason':str(exc),'time':time.time()}
            await asyncio.sleep(1.5)

    async def create_log_file(self):
        while True:
            self.save_report()
            await asyncio.sleep(1)

    def save_report(self):
        temporary = self.report_path.with_suffix(".json.tmp")
        with temporary.open("w", encoding="utf-8") as report_file:
            json.dump(self.report, report_file, indent=4, ensure_ascii=False)
        os.replace(temporary, self.report_path)

    def record_api_call(self, api_name, args_str, pid, created_at=None, observed_at=None):
        observed_at = time.time() if observed_at is None else observed_at
        created_at = self._process_births.get(pid) if created_at is None else created_at
        if api_name in _NETWORK_APIS:
            key = (pid, created_at, api_name, args_str)
            observation = self._network_api_index.get(key)
            if observation is not None:
                observation['count'] += 1
                observation['last_seen'] = observed_at
            elif len(self._network_api_index) < self.report['network_api_observation_limit']:
                observation = {'pid': pid, 'created_at': created_at, 'api': api_name, 'arguments': args_str,
                               'first_seen': observed_at, 'last_seen': observed_at,
                               'count': 1, 'evidence': 'api_entry', 'outcome': 'unknown'}
                self._network_api_index[key] = observation
                self.report['network_api_observations'].append(observation)
            else:
                self.report['network_api_observations_dropped'] += 1
        if len(self.report['api_events']) >= 20000:
            # Evict a batch to retain later activity without O(n) work per call.
            del self.report['api_events'][:1000]
            del self.report['api_calls'][:1000]
            self.report['api_events_truncated'] += 1000
        self.report["api_calls"].append((api_name, args_str))
        self.report["api_events"].append({"pid": pid, "created_at": created_at, "api": api_name,
                                          "arguments": args_str, "time": observed_at})

    async def run(self, tables=None, on_api_call=None, extra_tasks=(), duration=None):
        if tables is None:
            tables = {}
            for name, columns in (("processes", 2), ("network", 4), ("dumps", 3),
                                  ("urls", 1), ("findings", 2)):
                tables[name] = Table(*[str(n) for n in range(columns)])
        callback = on_api_call
        coroutines = [self.gather_processes(tables["processes"]), self.check_alive_process(),
                      self.enumerate_network_connections(tables["network"]),
                      self.parse_cmdline_arguments(),
                      self.create_log_file(), self.get_loaded_modules(),
                      self.extract_url_and_interesting_from_memory(tables["urls"]),
                      self.interesting_findings_monitor(tables["findings"]),
                      self.attach_process_with_hooker(callback), self.get_open_files(), *extra_tasks]
        coroutines.append(self.consume_api_calls(callback))
        if self._injection:
            coroutines.append(self.inspect_process_images())
        if self.memory_dumps_enabled:
            coroutines.append(self.memory_dumper(tables['dumps']))
        if self._memory_scan:
            coroutines.append(self._memory_scan.run(lambda: [(pid, self._process_births[pid])
                for pid in self.target_processes if self._processes[pid].is_running()]))

        async def guarded(coroutine):
            try:
                await coroutine
            except Exception as exc:
                self.report["errors"].append({"component": coroutine.cr_code.co_name,
                                              "error": f"{type(exc).__name__}: {exc}"})
                self.report["analysis"]["stop_reason"] = "collector_failed"
                self._stop.set()

        tasks = [asyncio.create_task(guarded(c)) for c in coroutines]
        try:
            await asyncio.wait_for(self._stop.wait(), timeout=duration)
        except asyncio.TimeoutError:
            self.report["analysis"]["stop_reason"] = "duration_elapsed"
        except asyncio.CancelledError:
            self.report["analysis"]["stop_reason"] = "interrupted"
            raise
        finally:
            # Cancel discovery before taking the final hooker inventory so no
            # child debugger can start during shutdown.
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
            hookers = [(pid, self._process_births[pid], h) for pid, h in self._hookers.items()] + self._retired_hookers
            stopped_results = await asyncio.gather(*(asyncio.to_thread(h.stop) for _, _, h in hookers))
            for (pid, birth, hooker), stopped in zip(hookers, stopped_results):
                status = {
                    "created_at": birth,
                    "hooked": list(hooker.hooked), "failed": list(hooker.failed),
                    "architecture": hooker.architecture,
                    "injection_event_errors": list(hooker.event_errors),
                    "attach_error": hooker.attach_error or "", "loop_error": hooker.loop_error or "",
                    "ready": hooker.ready, "stopped": stopped,
                    "exceptions": list(hooker.exceptions), "exit_code": hooker.exit_code,
                    "phase": hooker.phase, "api_call_count": hooker.api_call_count,
                }
                self._generation_report(pid, birth)['process_hook_info'][pid] = status
                if pid == self.target_pid and self._process_births[pid] == birth:
                    self.report["hook_info"] = status
                if not stopped:
                    self.report["errors"].append({"component": "hooker", "pid": pid,
                                                  "error": "Debugger shutdown timed out"})
            while not self._api_queue.empty():
                self._deliver_api_call(callback, self._api_queue.get_nowait())
            self.report['api_callbacks_dropped'] = self._dropped_callbacks
            self._drain_injection_events()
            if self._injection:
                self._injection.report['status'] = 'stopped'
            for (pid, birth), (reader, future) in self._pending_dumps.items():
                try:
                    self._record_dump(pid, birth, reader, await future)
                except Exception as exc:
                    self.report["errors"].append({"component": "memory_dumper", "pid": pid, "error": str(exc)})
            await self.extract_url_and_interesting_from_memory(tables["urls"], once=True)
            missing_tracer = any(info.get("attach_error") or info.get('loop_error') or
                                 any(f.get("api") == "attach" for f in info.get("failed", []))
                                 for generation in [self.report, *self.report['process_history']]
                                 for info in generation['process_hook_info'].values())
            self.report["analysis"]["status"] = "partial" if self.report["errors"] or missing_tracer else "finished"
            self.report["analysis"]["finished_at"] = datetime.now().astimezone().isoformat()
            self.save_report()


def main_app(target_pid, output_dir=".", duration=None, headless=False, dump_interval=10.0, **kwargs):
    start_time     = datetime.now()
    wda            = WindowsDynamicAnalyzer(target_pid, output_dir, dump_interval, **kwargs)
    if headless:
        _run_with_interrupt(wda, wda.run(duration=duration))
        return
    program_layout = Layout(name="RootLayout")

    # Root: fixed header strip + main body
    program_layout.split_column(
        Layout(name="Header", size=3),
        Layout(name="Main"),
    )
    # Main body: left (ratio 3) + right (ratio 2)
    program_layout["Main"].split_row(
        Layout(name="Left",  ratio=3),
        Layout(name="Right", ratio=2),
    )
    # Left: network on top (ratio 2) + api/url row below (ratio 3)
    program_layout["Left"].split_column(
        Layout(name="network", ratio=2),
        Layout(name="api_row", ratio=3),
    )
    program_layout["api_row"].split_row(
        Layout(name="api"),
        Layout(name="urls"),
    )
    # Right: process/dump row (ratio 1) + findings (ratio 2)
    program_layout["Right"].split_column(
        Layout(name="proc_row", ratio=1),
        Layout(name="findings", ratio=2),
    )
    program_layout["proc_row"].split_row(
        Layout(name="processes"),
        Layout(name="dumps"),
    )
    finding_panels = [Layout(name='legacy_findings')]
    if wda._memory_scan:
        finding_panels.append(Layout(name='live_memory'))
    if wda._injection:
        finding_panels.append(Layout(name='injection'))
    program_layout['findings'].split_column(*finding_panels)

    # Network connections table
    conn_table = Table(show_header=True, header_style="bold green",
                       box=box.SIMPLE_HEAD, expand=True)
    conn_table.add_column("PID",        justify="right",  style="cyan",   no_wrap=True, width=7)
    conn_table.add_column("Process",    justify="left",   style="white",  no_wrap=True)
    conn_table.add_column("Connection", justify="left",   style="yellow", no_wrap=True)
    conn_table.add_column("Status",     justify="center", style="green",  no_wrap=True, width=14)

    # Process tree table
    proc_info_table = Table(show_header=True, header_style="bold yellow",
                            box=box.SIMPLE_HEAD, expand=True)
    proc_info_table.add_column("Process Name", justify="left",  style="white")
    proc_info_table.add_column("PID",          justify="right", style="cyan", no_wrap=True, width=7)

    # Windows API calls table
    win_api_ct = Table(show_header=True, header_style="bold red",
                       box=box.SIMPLE_HEAD, expand=True)
    win_api_ct.add_column("API / Function", justify="left", style="bold white", no_wrap=True)
    win_api_ct.add_column("Arguments",      justify="left", style="yellow")

    # Extracted URLs table
    ex_url_mem = Table(show_header=True, header_style="bold blue",
                       box=box.SIMPLE_HEAD, expand=True)
    ex_url_mem.add_column("Extracted URL", justify="left", style="bright_blue")

    # Memory dumps table
    mem_dumpy = Table(show_header=True, header_style="bold magenta",
                      box=box.SIMPLE_HEAD, expand=True)
    mem_dumpy.add_column("PID",       justify="right", style="cyan",    no_wrap=True, width=7)
    mem_dumpy.add_column("File Name", justify="left",  style="white",   no_wrap=True)
    mem_dumpy.add_column("Size (B)",  justify="right", style="magenta", no_wrap=True, width=10)

    # Interesting findings table
    ifds = Table(show_header=True, header_style="bold cyan",
                 box=box.SIMPLE_HEAD, expand=True)
    ifds.add_column("Type",  justify="left", style="bold cyan",   no_wrap=True)
    ifds.add_column("Value", justify="left", style="bold yellow")

    # Assign panels to layout nodes
    program_layout["Header"].update(Panel("", border_style="bold blue"))
    program_layout["network"].update(
        Panel(conn_table, border_style="bold green", title="Network Connection Tracer")
    )
    program_layout["api"].update(
        Panel(win_api_ct, border_style="bold red", title="Windows API Tracer")
    )
    program_layout["urls"].update(
        Panel(ex_url_mem, border_style="bold blue", title="Memory URL Candidates")
    )
    program_layout["processes"].update(
        Panel(proc_info_table, border_style="bold yellow", title="Process Tree")
    )
    program_layout["dumps"].update(
        Panel(mem_dumpy, border_style="bold magenta", title="Memory Dumps")
    )
    program_layout["legacy_findings"].update(
        Panel(ifds, border_style="bold cyan", title="Interesting Findings")
    )

    # API hook callback — drained from the bounded queue on the UI event loop.
    async def update_injection_panel():
        while True:
            report = wda._injection.report
            table = Table('Type','Target PID','Evidence',expand=True)
            observed = sum(i['status']=='observed' for i in report['images'].values())
            table.add_row('Collection','',f"{observed}/{len(report['images'])} images checked | {len(report['events'])} API observations")
            for finding in report['findings'][-6:]:
                table.add_row(finding['kind'],str(finding['target_pid']),
                              f"source: {finding['source_pid']} | 0x{finding['address']:X}")
            program_layout['injection'].update(Panel(table,title=f"Injection / Hollowing: {report['status']} | {len(report['findings'])} candidates"))
            await asyncio.sleep(1)
    def on_api_call(api_name, args_str, pid):
        update_table(win_api_ct, 13, escape(api_name), escape(args_str))

    # Status coroutine — live-updates the API Tracer panel title every 2 seconds
    async def update_hook_status():
        while True:
            await asyncio.sleep(2)
            fi         = wda.report.get("hook_info", {})
            hooked     = len(fi.get("hooked", []))
            failed     = fi.get("failed", [])
            loop_err   = fi.get("loop_error", "")
            ready = fi.get('ready', False)
            calls = sum(i.get('api_call_count', 0) for i in wda.report['process_hook_info'].values())

            # attach_error is either in hook_info["failed"] or directly on the hooker object
            attach_err = next(
                (f["reason"] for f in failed if f.get("api") == "attach"), None
            )
            if not attach_err and wda._hooker and wda._hooker.attach_error:
                attach_err = wda._hooker.attach_error
            write_fail = sum(1 for f in failed if "write_failed" in f.get("reason", ""))
            not_found  = sum(1 for f in failed if f.get("reason") == "export_not_found")

            if attach_err:
                title = f"[bold red]Windows API Tracer[/] [dim red]({attach_err[:70]})[/]"
            elif loop_err:
                title = f"[bold red]Windows API Tracer[/] [dim red](loop error: {loop_err[:60]})[/]"
            elif ready and hooked:
                extra = ""
                if write_fail:
                    extra = f", {write_fail} write failures"
                if not_found:
                    extra += f", {not_found} not found"
                title = f"[bold red]Windows API Tracer[/] [dim green]({hooked} root hooks, {calls} tree calls{extra})[/]"
            elif wda._hooker is not None:
                title = "[bold red]Windows API Tracer[/] [dim yellow](attaching...)[/]"
            else:
                title = "[bold red]Windows API Tracer[/] [dim](waiting for attach)[/]"

            program_layout["api"].update(
                Panel(win_api_ct, border_style="bold red", title=title)
            )

    # Header coroutine — updates PID, process name, status and uptime every second
    async def update_header():
        while True:
            elapsed = datetime.now() - start_time
            h, rem  = divmod(int(elapsed.total_seconds()), 3600)
            m, s    = divmod(rem, 60)
            try:
                proc    = wda.proc_handler
                if not proc.is_running():
                    raise psutil.NoSuchProcess(wda.target_pid)
                pname   = proc.name()
                pstatus = "[bold green]● RUNNING[/]"
            except psutil.NoSuchProcess:
                pname   = "N/A"
                pstatus = "[bold red]● TERMINATED[/]"
            g = Table.grid(expand=True)
            g.add_column(justify="left",   ratio=1)
            g.add_column(justify="center", ratio=1)
            g.add_column(justify="right",  ratio=1)
            g.add_row(
                f"  [bold cyan]PID[/]: [white]{wda.target_pid}[/]  "
                f"[bold cyan]Process[/]: [white]{pname}[/]  {pstatus}",
                "[bold red]Qu1cksc0pe[/] [bold white]Windows Dynamic Analyzer[/]",
                f"[bold cyan]Monitored[/]: [white]{len(wda.target_processes)}[/]  "
                f"[bold cyan]Uptime[/]: [white]{h:02d}:{m:02d}:{s:02d}[/]  ",
            )
            program_layout["Header"].update(Panel(g, border_style="bold blue"))
            await asyncio.sleep(1)

    with Live(program_layout, refresh_per_second=1.8):
        memory_ui = (wda._memory_scan.update_panel(program_layout['live_memory']),) if wda._memory_scan else ()
        _run_with_interrupt(wda, wda.run(
            tables={"processes": proc_info_table, "network": conn_table, "dumps": mem_dumpy,
                    "urls": ex_url_mem, "findings": ifds},
            on_api_call=on_api_call, extra_tasks=(update_header(), update_hook_status(), *memory_ui,
                *((update_injection_panel(),) if wda._injection else ())),
            duration=duration,
        ))


def _run_with_interrupt(analyzer, coroutine):
    async def run():
        loop = asyncio.get_running_loop()
        signals = [signal.SIGINT, signal.SIGBREAK] if hasattr(signal, 'SIGBREAK') else [signal.SIGINT]
        previous = {sig: signal.getsignal(sig) for sig in signals}
        def stop(signum, frame):
            analyzer.report['analysis']['stop_reason'] = 'interrupted'
            loop.call_soon_threadsafe(analyzer._stop.set)
        for sig in signals:
            signal.signal(sig, stop)
        try:
            await coroutine
        finally:
            for sig, handler in previous.items():
                signal.signal(sig, handler)
    asyncio.run(run())


if __name__ == "__main__":
    try:
        parser = argparse.ArgumentParser(description="Monitor an existing Windows process")
        parser.add_argument("--pid", type=int, help="Target process ID")
        parser.add_argument("--name", help="Wait for this exact executable name")
        parser.add_argument("--duration", type=float, help="Maximum analysis duration in seconds")
        parser.add_argument("--output-dir", default=".", help="Directory for reports and memory dumps")
        parser.add_argument("--headless", action="store_true", help="Collect without the live terminal UI")
        parser.add_argument("--dump-interval", type=float, default=10.0, help="Seconds between memory snapshots (default: 10)")
        parser.add_argument('--memory-yara', action='append', help='YARA file/directory for live scanning (repeatable; defaults to bundled Windows rules)')
        parser.add_argument('--dump-suspicious', action=argparse.BooleanOptionalAction, default=True,
                            help='Save bounded YARA-matched/RWX memory windows (default: enabled)')
        parser.add_argument('--injection-detection', action=argparse.BooleanOptionalAction, default=True,
                            help='Correlate remote memory operations and inspect process images (default: enabled)')
        parser.add_argument('--no-memory-scan', action='store_true', help='Disable live YARA/IOC scanning')
        parser.add_argument('--no-memory-dumps', action='store_true', help='Disable full snapshots; live memory scanning can still run')
        options = parser.parse_args()
        if options.pid is not None and options.name:
            parser.error("Choose either --pid or --name")
        if options.duration is not None and (options.duration <= 0 or not math.isfinite(options.duration)):
            parser.error("--duration must be a positive finite number")
        if options.pid is not None and options.pid <= 0:
            parser.error("--pid must be positive")
        if options.dump_interval <= 0 or not math.isfinite(options.dump_interval):
            parser.error("--dump-interval must be a positive finite number")
        target_pid_or_name = str(options.pid) if options.pid is not None else options.name
        if target_pid_or_name is None:
            if options.headless:
                parser.error("--headless requires --pid or --name")
            target_pid_or_name = input(f"{infoC} Enter target PID or Process Name: ").strip()

        if target_pid_or_name.isnumeric():
            target_pid = int(target_pid_or_name)
        else:
            # Strip path separators — only keep the filename
            if path_seperator in target_pid_or_name:
                target_pid_or_name = target_pid_or_name.split(path_seperator)[-1]

            print(f"\n{infoS} Target acquired! Now you need to [bold blink green]execute the target file![white]")
            target_pid = None
            while True:
                for pr in psutil.process_iter(["name"]):
                    if (pr.info["name"] or "").casefold() == target_pid_or_name.casefold():
                        target_pid = int(pr.pid)
                        break
                if target_pid:
                    break
                time.sleep(0.1)

        print(f"\n{infoS} Monitoring PID: [bold green]{target_pid}[white]. ([bold blink yellow]Ctrl+C to stop![white])")
        destination = Path(options.output_dir).resolve() / f"sc0pe_process-{target_pid}.json"
        print(f"{infoS} Report: [bold green]{escape(str(destination))}[white]")
        main_app(target_pid, options.output_dir, options.duration, options.headless, options.dump_interval,
                 memory_scan=not options.no_memory_scan, yara_paths=options.memory_yara,
                 dump_suspicious=options.dump_suspicious, memory_dumps=not options.no_memory_dumps,
                 injection_detection=options.injection_detection)
    except KeyboardInterrupt:
        err_exit(f"{errorS} Keyboard interrupt detected...")
    except Exception as exc:
        err_exit(f"{errorS} {escape(type(exc).__name__ + ': ' + str(exc))}")
