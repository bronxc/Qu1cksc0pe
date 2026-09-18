"""Bounded live-memory YARA/IOC scanning shared by Windows and Linux monitors.

Results describe observed bytes, never successful network or filesystem actions.
Large regions use overlapping windows; whole-region YARA semantics are not
guaranteed for regions larger than a window. No target code is executed here.
"""
import asyncio
from dataclasses import dataclass
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import threading
import time
from urllib.parse import urlsplit


@dataclass(frozen=True)
class Region:
    address: int
    size: int
    protection: str
    kind: str = ""


class WindowsMemory:
    def __init__(self, pid, created_at=None):
        from windows_process_reader import WindowsProcessReader
        self.reader = WindowsProcessReader(pid, expected_birth=created_at)
        self.handle = self.reader.get_process_handle()
        if not self.handle:
            raise PermissionError(f"Cannot open PID {pid} for memory reading")

    def regions(self):
        import ctypes
        address = 0
        while True:
            mbi = self.reader.query_memory(self.handle, ctypes.c_void_p(address))
            if not mbi:
                break
            end = int(mbi.BaseAddress or 0) + mbi.RegionSize
            if end <= address:
                break
            flags = mbi.Protect & 0xff
            if mbi.State == 0x1000 and not mbi.Protect & 0x100 and flags in (2, 4, 8, 0x20, 0x40, 0x80):
                permissions = 'r' + ('w' if flags in (4, 8, 0x40, 0x80) else '-') + ('x' if flags >= 0x20 else '-')
                yield Region(address, end - address, permissions,
                             {0x20000: 'private', 0x40000: 'mapped', 0x1000000: 'image'}.get(mbi.Type, 'unknown'))
            address = end

    def read(self, address, size):
        import ctypes
        return self.reader.read_memory(self.handle, ctypes.c_void_p(address), size) or b''

    def close(self):
        from windows_process_reader import kernel32
        kernel32.CloseHandle(self.handle)


class LinuxMemory:
    def __init__(self, pid, created_at=None):
        import psutil
        self.pid = int(pid)
        self.proc_fd = self.fd = None
        try:
            if created_at is not None and psutil.Process(self.pid).create_time() != created_at:
                raise ProcessLookupError(f'PID {pid} was reused')
            # Pin /proc to this process instance. A later PID reuse must not
            # pair a new process's maps with the old process's memory handle.
            self.proc_fd = os.open(f'/proc/{self.pid}', os.O_RDONLY | os.O_DIRECTORY)
            self.fd = os.open('mem', os.O_RDONLY, dir_fd=self.proc_fd)
            if created_at is not None and psutil.Process(self.pid).create_time() != created_at:
                raise ProcessLookupError(f'PID {pid} was reused while opening memory')
        except BaseException:
            self.close()
            raise

    def regions(self):
        maps_fd = os.open('maps', os.O_RDONLY, dir_fd=self.proc_fd)
        with os.fdopen(maps_fd, encoding='utf-8', errors='replace') as maps:
            for line in maps:
                fields = line.split(maxsplit=5)
                if len(fields) < 5 or not fields[1].startswith('r'):
                    continue
                start, end = (int(n, 16) for n in fields[0].split('-'))
                yield Region(start, end - start, fields[1][:3],
                             'mapped' if len(fields) > 5 and fields[5].startswith('/') else 'private')

    def read(self, address, size):
        try:
            return os.pread(self.fd, size, address)
        except OSError:
            return b''

    def close(self):
        for name in ('fd', 'proc_fd'):
            fd = getattr(self, name)
            if fd is not None:
                os.close(fd)
                setattr(self, name, None)


_URL = re.compile(r'https?://[^\s<>"\x00-\x20]{4,2048}', re.I)
_IP = re.compile(r'(?<![\w.])(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?![\w.])')
_DOMAIN = re.compile(r'(?<![\w@.-])(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}(?![\w.-])', re.I)
_TLDS = set('com net org info biz io co me dev app online site xyz top ru cn uk de fr tr us cc su pw club live shop cloud pro tech world space win work store click link mobi ai gov edu'.split())
_ASCII = re.compile(rb'[\x20-\x7e]{4,}')
_WIDE = re.compile(rb'(?:[\x20-\x7e]\x00){4,}')


def extract_iocs(data, base, limit=256):
    """Return candidate strings with exact virtual addresses, including UTF-16LE."""
    found, seen = [], set()
    for pattern, encoding, stride in ((_ASCII, 'ascii', 1), (_WIDE, 'utf-16le', 2)):
        for raw in pattern.finditer(data):
            text = raw.group().decode(encoding)
            for kind, regex in (('url', _URL), ('ip', _IP), ('domain', _DOMAIN)):
                for match in regex.finditer(text):
                    value = match.group().rstrip('.,;!)]}')
                    if kind == 'ip':
                        try:
                            ip = ipaddress.ip_address(value)
                            if not ip.is_global or ip.is_multicast:
                                continue
                        except ValueError:
                            continue
                    elif kind == 'url':
                        try:
                            if not urlsplit(value).hostname:
                                continue
                        except ValueError:
                            continue
                    elif value.rsplit('.', 1)[-1].lower() not in _TLDS:
                        continue
                    key = (kind, value)
                    if key in seen:
                        continue
                    seen.add(key)
                    found.append({'kind': kind, 'value': value,
                                  'address': base + raw.start() + match.start() * stride,
                                  'encoding': encoding})
                    if len(found) >= limit:
                        return found
    return found


class MemoryScanner:
    WINDOW = 1024 * 1024
    OVERLAP = 4096

    def __init__(self, rule_paths=(), output_dir='.', *, max_bytes=32 * 1024 * 1024,
                 max_seconds=2.0, dump_suspicious=False, backend=None):
        self.rule_paths = [Path(p) for p in rule_paths]
        self.output_dir = Path(output_dir)
        self.max_bytes, self.max_seconds = max_bytes, max_seconds
        self.dump_suspicious = dump_suspicious
        self.backend = backend or (WindowsMemory if os.name == 'nt' else LinuxMemory)
        self.stop = threading.Event()
        self.rules = None
        self.rule_errors = []
        self.rule_count = 0
        self.rule_sources = {}
        self.context_sources = {}
        self.context_rules = {}
        self.prepared = False
        self.cursors = {}
        self.exported = set()
        self.export_bytes = 0
        self.max_export_bytes = 16 * 1024 * 1024

    def prepare(self):
        if self.prepared:
            return
        self.prepared = True
        project_root = Path(__file__).resolve().parents[1]
        policy_path = project_root / 'Systems' / 'YaraSources' / 'memory_policy.json'
        if policy_path.is_file():
            try:
                policy = json.loads(policy_path.read_text(encoding='utf-8'))
                self.context_sources = {str((project_root / path).resolve()): reason
                                        for path, reason in policy['context_rule_files'].items()}
                self.context_rules = {str((project_root / path).resolve()): rules
                                      for path, rules in policy.get('context_rules', {}).items()}
            except (OSError, ValueError, KeyError, TypeError) as exc:
                self.rule_errors.append({'file': str(policy_path), 'error': f'Memory policy: {exc}'})
        try:
            import yara
        except ImportError:
            self.rule_errors.append({'error': 'yara-python is unavailable; IOC scanning remains enabled'})
            return
        paths = []
        for path in self.rule_paths:
            if path.is_file():
                paths.append(path)
            elif path.is_dir():
                paths.extend(p for p in sorted(path.rglob('*')) if p.suffix.lower() in ('.yar', '.yara'))
            else:
                self.rule_errors.append({'file': str(path), 'error': 'Rule path does not exist'})
        valid = {}
        for i, path in enumerate(dict.fromkeys(paths)):
            if self.stop.is_set():
                return
            try:
                yara.compile(filepath=str(path))
                valid[f'rulefile_{i}'] = str(path)
            except Exception as exc:
                self.rule_errors.append({'file': str(path), 'error': str(exc)})
        if valid:
            try:
                self.rules = yara.compile(filepaths=valid)
                self.rule_count = len(valid)
                self.rule_sources = valid
            except Exception as exc:
                self.rule_errors.append({'error': f'Rule compilation failed: {exc}'})

    def context_reason(self, source, rule):
        if not source:
            return None
        resolved = str(Path(source).resolve())
        return self.context_sources.get(resolved) or self.context_rules.get(resolved, {}).get(rule)

    def scan(self, pid, created_at=None):
        self.prepare()
        started = time.monotonic()
        identity = (pid, created_at) if created_at is not None else pid
        result = {'pid': pid, 'created_at': created_at, 'time': time.time(), 'bytes_scanned': 0, 'windows_scanned': 0,
                  'unreadable_windows': 0, 'overlap_bytes_read': 0, 'matches': [], 'context_matches': [], 'iocs': [], 'suspicious_regions': [],
                  'exports': [], 'errors': [], 'status': 'complete', 'next_address': 0,
                  'coverage': {'enumerated_regions': 0, 'enumerated_bytes': 0,
                               'yara_bytes_scanned': 0, 'yara_failed_windows': 0,
                               'read_complete': False, 'yara_complete': False}}
        memory = None
        try:
            memory = self.backend(pid, created_at) if self.backend in (WindowsMemory, LinuxMemory) else self.backend(pid)
            regions = list(memory.regions())
            result['coverage']['enumerated_regions'] = len(regions)
            result['coverage']['enumerated_bytes'] = sum(r.size for r in regions)
            cursor = self.cursors.get(identity, 0)
            # Resume across passes rather than scanning only the first 32 MiB.
            ordered = [r for r in regions if r.address + r.size > cursor] + [r for r in regions if r.address + r.size <= cursor]
            for region in ordered:
                position = cursor if region.address <= cursor < region.address + region.size else region.address
                tail = b''
                if position > region.address:
                    # Re-read the prefix: carrying old bytes between passes can
                    # combine stale content with a newly unpacked allocation.
                    prefix_size = min(self.OVERLAP, position - region.address)
                    prefix = memory.read(position - prefix_size, prefix_size)
                    result['overlap_bytes_read'] += len(prefix)
                    if len(prefix) == prefix_size:
                        tail = prefix
                if 'w' in region.protection and 'x' in region.protection:
                    result['suspicious_regions'].append({'address': region.address, 'size': region.size,
                                                         'protection': region.protection, 'kind': region.kind,
                                                         'reason': 'writable_executable'})
                while position < region.address + region.size:
                    if self.stop.is_set() or time.monotonic() - started >= self.max_seconds or result['bytes_scanned'] >= self.max_bytes:
                        result['status'] = 'cancelled' if self.stop.is_set() else 'budget_exhausted'
                        result['next_address'] = position
                        return result
                    size = min(self.WINDOW, region.address + region.size - position, self.max_bytes - result['bytes_scanned'])
                    data = memory.read(position, size)
                    if not data:
                        result['unreadable_windows'] += 1
                        position += min(4096, size)
                        tail = b''
                        continue
                    block, base = tail + data, position - len(tail)
                    result['bytes_scanned'] += len(data)
                    result['windows_scanned'] += 1
                    if len(result['iocs']) < 1024:
                        result['iocs'].extend(extract_iocs(block, base, min(256, 1024-len(result['iocs']))))
                    matches = []
                    if self.rules:
                        try:
                            matches = self.rules.match(data=block, timeout=1)
                            # Count new bytes only; overlap does not increase coverage.
                            result['coverage']['yara_bytes_scanned'] += len(data)
                        except Exception as exc:
                            result['coverage']['yara_failed_windows'] += 1
                            if len(result['errors']) < 32:
                                result['errors'].append({'address': base, 'error': str(exc)})
                    detection_hit = False
                    for match in matches:
                        source = self.rule_sources.get(match.namespace)
                        reason = self.context_reason(source, match.rule)
                        destination = 'context_matches' if reason else 'matches'
                        detection_hit |= not bool(reason)
                        if len(result[destination]) >= 256:
                            continue
                        strings = []
                        for string in match.strings:
                            for instance in string.instances:
                                if len(strings) < 32:
                                    strings.append({'identifier': string.identifier, 'address': base + instance.offset,
                                                    'length': instance.matched_length})
                        result[destination].append({'rule': match.rule, 'namespace': match.namespace,
                                                  'source': source, 'meta': dict(match.meta),
                                                  'classification': 'context' if reason else 'candidate',
                                                  'context_reason': reason,
                                                  'tags': list(match.tags), 'address': base,
                                                  'region_address': region.address, 'region_size': region.size,
                                                  'window_size': len(block), 'strings': strings})
                    if self.dump_suspicious and (detection_hit or ('w' in region.protection and 'x' in region.protection)):
                        digest = hashlib.sha256(block).hexdigest()
                        key = (identity, base, digest)
                        if key not in self.exported and self.export_bytes + len(block) <= self.max_export_bytes:
                            folder = self.output_dir / 'memory_regions'
                            folder.mkdir(parents=True, exist_ok=True)
                            filename = folder / f'{pid}_{base:x}_{digest[:16]}.bin'
                            filename.write_bytes(block)
                            self.exported.add(key)
                            self.export_bytes += len(block)
                            result['exports'].append({'path': str(filename), 'address': base, 'bytes': len(block),
                                                      'sha256': digest, 'region_address': region.address,
                                                      'region_size': region.size, 'complete_region': base == region.address and len(block) == region.size})
                    tail = block[-self.OVERLAP:]
                    position += len(data)
                cursor = 0
            return result
        except (OSError, ValueError) as exc:
            result['status'] = 'error'
            result['errors'].append({'error': f'{type(exc).__name__}: {exc}'})
            return result
        finally:
            coverage = result['coverage']
            coverage['read_complete'] = bool(
                coverage['enumerated_bytes'] > 0 and result['status'] == 'complete'
                and not result['unreadable_windows']
                and result['bytes_scanned'] == coverage['enumerated_bytes'])
            coverage['yara_complete'] = bool(
                coverage['read_complete'] and self.rules and not self.rule_errors
                and not coverage['yara_failed_windows']
                and coverage['yara_bytes_scanned'] == coverage['enumerated_bytes'])
            self.cursors[identity] = result['next_address']
            result['duration_seconds'] = time.monotonic() - started
            if memory:
                memory.close()


class MemoryScanSession:
    """One background reader, bounded retained findings, JSON-safe event-loop merges."""
    def __init__(self, rule_paths, output_dir='.', **kwargs):
        self.scanner = MemoryScanner(rule_paths, output_dir, **kwargs)
        self.pending = None
        self.seen = set()
        self.finding_limits = {'yara_matches': 1000, 'context_matches': 500, 'iocs': 3000, 'suspicious_regions': 500, 'exports': 500}
        self.report = {'status': 'starting', 'rule_files': 0, 'rule_errors': [], 'processes': {}, 'process_history': [],
                       'yara_matches': [], 'context_matches': [], 'iocs': [], 'suspicious_regions': [], 'exports': [],
                       'truncated_findings': 0,
                       'limits': {'bytes_per_pass': self.scanner.max_bytes, 'seconds_per_pass': self.scanner.max_seconds,
                                  'window_bytes': self.scanner.WINDOW, 'overlap_bytes': self.scanner.OVERLAP,
                                  'max_export_bytes': self.scanner.max_export_bytes, 'retained_findings': self.finding_limits,
                                  'matches_per_pass': 256, 'context_matches_per_pass': 256, 'iocs_per_pass': 1024}}

    def merge(self, result):
        previous = self.report['processes'].get(str(result['pid']))
        if previous and previous.get('created_at') != result.get('created_at'):
            self.report['process_history'].append(previous)
        self.report['processes'][str(result['pid'])] = {k: v for k, v in result.items() if k not in ('matches', 'context_matches', 'iocs', 'suspicious_regions', 'exports')}
        for source, dest in (('matches', 'yara_matches'), ('context_matches', 'context_matches'), ('iocs', 'iocs'), ('suspicious_regions', 'suspicious_regions'), ('exports', 'exports')):
            for value in result.get(source, []):
                key = (dest, result['pid'], result.get('created_at'), value.get('rule'), value.get('namespace'), value.get('kind'), value.get('value'), value.get('address'), value.get('sha256'))
                if key in self.seen:
                    continue
                # Common IOC strings must not crowd out later YARA evidence.
                if len(self.report[dest]) >= self.finding_limits[dest]:
                    self.report['truncated_findings'] += 1
                    continue
                self.seen.add(key)
                self.report[dest].append(dict(value, pid=result['pid'], created_at=result.get('created_at'), first_seen=result['time']))

    async def run(self, get_pids, interval=10.0):
        try:
            self.pending = asyncio.create_task(asyncio.to_thread(self.scanner.prepare))
            await asyncio.shield(self.pending)
            self.pending = None
            self.report.update(status='running', rule_files=self.scanner.rule_count, rule_errors=self.scanner.rule_errors)
            while True:
                for identity in list(get_pids()):
                    pid, birth = identity if isinstance(identity, tuple) else (identity, None)
                    self.pending = asyncio.create_task(asyncio.to_thread(self.scanner.scan, pid, birth))
                    result = await asyncio.shield(self.pending)
                    self.pending = None
                    self.merge(result)
                    await asyncio.sleep(0)
                await asyncio.sleep(interval)
        finally:
            self.scanner.stop.set()
            if self.pending:
                result = await self.pending
                if isinstance(result, dict):
                    self.merge(result)
                self.pending = None
            self.report.update(status='stopped', rule_files=self.scanner.rule_count, rule_errors=self.scanner.rule_errors)

    async def update_panel(self, node):
        """Display memory evidence separately from observed process activity."""
        from rich.table import Table
        from rich.panel import Panel
        from rich.text import Text
        while True:
            table = Table('Type / PID', 'Live memory evidence', expand=True)
            processes = list(self.report['processes'].values())
            fully_read = sum(p.get('coverage', {}).get('read_complete', False) for p in processes)
            fully_scanned = sum(p.get('coverage', {}).get('yara_complete', False) for p in processes)
            table.add_row('Coverage',
                          f'Last pass: {fully_read}/{len(processes)} PIDs fully read; '
                          f'YARA completed all windows for {fully_scanned}/{len(processes)}')
            for match in self.report['yara_matches'][-5:]:
                table.add_row(Text(f"Candidate / {match['pid']}"),
                              Text(f"{match['rule']} @ 0x{match['address']:x}"))
            for match in self.report['context_matches'][-3:]:
                table.add_row(Text(f"Context / {match['pid']}"), Text(match['rule']))
            for ioc in self.report['iocs'][-4:]:
                table.add_row(Text(f"{ioc['kind']} / {ioc['pid']}"), Text(ioc['value']))
            errors = len(self.report['rule_errors']) + sum(len(p['errors']) for p in self.report['processes'].values())
            title = f"Live Memory: {self.report['status']} | {self.report['rule_files']} files | {len(self.report['yara_matches'])} candidates | {len(self.report['context_matches'])} context | {errors} errors"
            node.update(Panel(table, title=Text(title), border_style='cyan'))
            await asyncio.sleep(1)
