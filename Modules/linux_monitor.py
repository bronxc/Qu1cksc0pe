"""Linux process-tree monitoring with explicit coverage and owned-task cleanup."""
import asyncio
from collections import Counter
import ipaddress
import json
import math
import os
from pathlib import Path
import re
import shutil
import signal
import time

import psutil

from dynamic_memory import MemoryScanSession
from linux_trace import TraceParser, STRACE_FILTER, LTRACE_FILTER, behavior_observations


class LinuxDynamicAnalyzer:
    MAX_EVENTS = 20000
    MAX_FINDINGS = 2000
    MAX_PROCESSES = 256

    def __init__(self, target_pid, *, memory_scan=True, yara_paths=None,
                 dump_suspicious=True, output_dir='.', tracer='auto', interval=1.0):
        if tracer not in ('auto', 'strace', 'ltrace', 'none'):
            raise ValueError('Unsupported tracer')
        if not math.isfinite(interval) or interval < 0.1:
            raise ValueError('Polling interval must be finite and at least 0.1 seconds')
        self.target_pid = int(target_pid)
        if self.target_pid == os.getpid():
            raise ValueError('The analyzer cannot trace itself')
        self.proc_handler = psutil.Process(self.target_pid)
        self.root_birth = self.proc_handler.create_time()
        self.processes = {self.target_pid: self.proc_handler}
        self.births = {self.target_pid: self.root_birth}
        self.output_dir = Path(output_dir).resolve()
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.report_path = self.output_dir / f'sc0pe_process-{self.target_pid}.json'
        self.interval = interval
        self.tracer_choice = tracer
        self.tracer = None
        self.stop = asyncio.Event()
        self._tasks = []
        self._seen = set()
        self._counts = Counter()
        self._started = time.monotonic()
        self._parser = None
        rule_root = Path(__file__).resolve().parents[1] / 'Systems/Linux/YaraRules_Linux'
        self.memory_scan = MemoryScanSession(
            yara_paths if yara_paths is not None else [rule_root],
            output_dir=self.output_dir, dump_suspicious=dump_suspicious,
        ) if memory_scan else None
        self.report = {
            'schema_version': 2, 'platform': 'linux', 'pid': self.target_pid,
            'created_at': self.root_birth, 'started_at': time.time(), 'status': 'starting',
            'features': {'syscall_trace': tracer != 'none', 'memory_scan': memory_scan,
                         'suspicious_memory_exports': bool(memory_scan and dump_suspicious),
                         'process_tree': True, 'network_connections': True, 'open_files': True,
                         'behavior_observations': True},
            'process_ids': [], 'processes': {}, 'process_history': [],
            'network_connections': [], 'network_observations': [], 'open_files': {},
            'commandline_args': {}, 'syscalls': {}, 'trace_events': [],
            'recent_trace_events': [],
            'behavior_observations': [], 'errors': [], 'truncated': {},
            'tracer_info': {'tool': None, 'status': 'disabled' if tracer == 'none' else 'starting',
                            'traced_pid': self.target_pid, 'requested_pids': [], 'errors': []},
            'memory_scan': self.memory_scan.report if self.memory_scan else {'status': 'disabled'},
            'interesting_findings': {name: [] for name in (
                'executed_commands', 'loaded_libraries', 'accessed_files', 'environment_variables',
                'resolved_hostnames', 'ip_addresses', 'urls', 'bitcoin_addresses',
                'ethereum_addresses', 'anti_analysis')},
        }

    @property
    def target_processes(self):
        return [pid for pid, _ in self.identities()]

    def identities(self):
        found = []
        for pid, process in list(self.processes.items()):
            try:
                if process.is_running() and process.status() != psutil.STATUS_ZOMBIE:
                    found.append((pid, self.births[pid]))
            except psutil.Error:
                continue
        return found

    def _error(self, collector, error, pid=None):
        item = {'collector': collector, 'pid': pid, 'error': str(error)}
        if item not in self.report['errors'] and len(self.report['errors']) < 200:
            self.report['errors'].append(item)

    def _append(self, key, value, limit=None):
        rows = self.report[key]
        limit = self.MAX_FINDINGS if limit is None else limit
        if len(rows) >= limit:
            self.report['truncated'][key] = self.report['truncated'].get(key, 0) + 1
            return False
        rows.append(value)
        return True

    def _unique(self, key, value):
        token = (key, json.dumps(value, sort_keys=True))
        if token not in self._seen and self._append(key, value):
            self._seen.add(token)

    def discover(self):
        # Continue following known children even after the original parent exits.
        candidates = list(self.processes.values())
        for process in list(candidates):
            try:
                if process.is_running():
                    candidates.extend(process.children(recursive=True))
            except psutil.NoSuchProcess:
                pass
            except psutil.AccessDenied as exc:
                self._error('process_tree', exc, process.pid)
        for pid, process in list(self.processes.items()):
            try:
                alive = process.is_running() and process.status() != psutil.STATUS_ZOMBIE
            except psutil.NoSuchProcess:
                alive = False
            except psutil.AccessDenied:
                alive = True
            if not alive:
                previous = self.report['processes'].pop(str(pid), {'pid': pid, 'created_at': self.births[pid]})
                previous.update(status='exited', ended_at=time.time(),
                    commandline=self.report['commandline_args'].pop(str(pid), []),
                    open_files=self.report['open_files'].pop(str(pid), []))
                self._append('process_history', previous)
                self.processes.pop(pid, None)
                self.births.pop(pid, None)
        for process in candidates:
            try:
                if process.pid == os.getpid() or (self.tracer and process.pid == self.tracer.pid):
                    continue
                if not process.is_running() or process.status() == psutil.STATUS_ZOMBIE:
                    continue
                pid, birth = process.pid, process.create_time()
                if self.births.get(pid) == birth and str(pid) in self.report['processes']:
                    continue
                if pid not in self.processes and len(self.processes) >= self.MAX_PROCESSES:
                    self.report['truncated']['processes'] = self.report['truncated'].get('processes', 0) + 1
                    continue
                if pid in self.births and self.births[pid] != birth:
                    previous = self.report['processes'].pop(str(pid), {})
                    previous['ended_at'] = time.time()
                    self._append('process_history', previous)
                    self.report['open_files'].pop(str(pid), None)
                    self.report['commandline_args'].pop(str(pid), None)
                self.processes[pid], self.births[pid] = process, birth
                info = {'pid': pid, 'created_at': birth, 'name': process.name(),
                        'ppid': process.ppid(), 'status': process.status(), 'first_seen': time.time()}
                self.report['processes'][str(pid)] = info
                self._append('process_ids', {'pid': pid, 'name': info['name'], 'created_at': birth})
            except psutil.NoSuchProcess:
                continue
            except psutil.AccessDenied as exc:
                self._error('process_tree', exc, process.pid)

    @staticmethod
    def _snapshot(process):
        result = {'pid': process.pid, 'errors': []}
        if not process.is_running():
            return result
        for key, reader in (('commandline', process.cmdline), ('open_files', process.open_files),
                            ('connections', lambda: process.net_connections(kind='inet'))):
            try:
                result[key] = reader()
            except psutil.NoSuchProcess:
                break
            except (psutil.AccessDenied, OSError) as exc:
                result['errors'].append((key, str(exc)))
        if not process.is_running():
            return {'pid': process.pid, 'errors': []}
        return result

    async def _poll(self):
        while not self.stop.is_set():
            self.discover()
            active = self.identities()
            if not active:
                self.report['stop_reason'] = 'process_tree_exited'
                self.stop.set()
                return
            active_ids = {pid for pid, _ in active}
            for pid, info in self.report['processes'].items():
                info['status'] = 'running' if int(pid) in active_ids else 'exited'
            for pid, birth in active:
                snapshot = await asyncio.to_thread(self._snapshot, self.processes[pid])
                if self.births.get(pid) != birth:
                    continue
                for key, error in snapshot['errors']:
                    self._error(key, error, pid)
                if 'commandline' in snapshot:
                    self.report['commandline_args'][str(pid)] = snapshot['commandline']
                if 'open_files' in snapshot:
                    self.report['open_files'][str(pid)] = sorted({f.path for f in snapshot['open_files'] if f.path})[:1000]
                for connection in snapshot.get('connections', []):
                    def address(value):
                        return {'ip': value.ip, 'port': value.port} if value else None
                    item = {'pid': pid, 'created_at': birth, 'family': int(connection.family),
                            'type': int(connection.type), 'local': address(connection.laddr),
                            'remote': address(connection.raddr), 'status': connection.status}
                    self._unique('network_observations', item)
                    remote = item['remote']
                    if remote:
                        self._unique('network_connections', f"{pid}|{self.report['processes'][str(pid)]['name']}|{remote['ip']}:{remote['port']}|{connection.status}")
            await asyncio.sleep(self.interval)

    def _record_event(self, event):
        tid = event['tid']
        try:
            status = Path(f'/proc/{tid}/status').read_text()
            pid = int(re.search(r'^Tgid:\s+(\d+)', status, re.M).group(1))
            process = psutil.Process(pid)
            birth = process.create_time()
            if birth <= event['time']:
                event['pid'] = pid
                event['created_at'] = birth
        except (OSError, psutil.Error, AttributeError):
            pass
        event['identity_verified'] = 'created_at' in event
        self._counts[event['call']] += 1
        self._append('trace_events', event, self.MAX_EVENTS)
        recent = self.report['recent_trace_events']
        recent.append(event)
        del recent[:-32]
        values = self.report['syscalls'].setdefault(event['call'], [])
        if event['arguments'] not in values and len(values) < 100:
            values.append(event['arguments'])
        for observation in behavior_observations(event):
            self._unique('behavior_observations', observation)
        # Failed calls remain in the event stream; they did not perform the action.
        if event['success'] is not True or not event['arguments_complete']:
            return
        findings = self.report['interesting_findings']
        call = event['call']
        key = None
        if call in ('execve', 'execveat'):
            key = 'executed_commands'
        elif call in ('open', 'openat', 'openat2', 'creat', 'unlink', 'unlinkat', 'rename', 'renameat', 'renameat2', 'mkdir', 'mkdirat'):
            key = 'accessed_files'
        if key and event['strings']:
            value = event['strings'][0]
            if value not in findings[key] and len(findings[key]) < 500:
                findings[key].append(value)
        for value in re.findall(r'https?://[^\s<>"\\]+', event['arguments']):
            if value not in findings['urls'] and len(findings['urls']) < 500:
                findings['urls'].append(value)
        for value in re.findall(r'(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])', event['arguments']):
            try:
                ipaddress.ip_address(value)
            except ValueError:
                continue
            if value not in findings['ip_addresses'] and len(findings['ip_addresses']) < 500:
                findings['ip_addresses'].append(value)

    async def _trace(self):
        info = self.report['tracer_info']
        if self.tracer_choice == 'none':
            return
        tool = self.tracer_choice
        if tool == 'auto':
            tool = 'strace' if shutil.which('strace') else 'ltrace'
        if not shutil.which(tool):
            info.update(status='unavailable', tool=tool)
            self._error('tracer', f'{tool} executable not found')
            return
        self.discover()
        identities = self.identities()
        pids = [pid for pid, _ in identities]
        if not pids:
            info.update(status='target_exited', tool=tool)
            return
        # -f follows future forks; explicit -p also covers pre-existing children.
        cmd = [tool, '-f', '-ttt', '-s', '512']
        if tool == 'strace':
            cmd += ['-T', '-yy', '-e', f'trace={STRACE_FILTER}']
        else:
            cmd += ['-e', LTRACE_FILTER]
        for pid in pids:
            cmd += ['-p', str(pid)]
        info.update(tool=tool, status='starting', requested_pids=pids)
        self._parser = TraceParser(self.target_pid, tool)
        try:
            spawn = asyncio.create_task(asyncio.create_subprocess_exec(*cmd, stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.PIPE, limit=65536, start_new_session=True,
                env=dict(os.environ, LC_ALL='C')))
            try:
                self.tracer = await asyncio.shield(spawn)
            except asyncio.CancelledError:
                self.tracer = await spawn
                raise
            info['tracer_pid'] = self.tracer.pid
            async for raw in self._parser.lines(self.tracer.stderr):
                line = raw.decode('utf-8', errors='replace').strip()
                if line.startswith(f'{tool}:'):
                    if 'attached' in line:
                        info['status'] = 'active'
                    elif 'detached' not in line:
                        if len(info['errors']) < 30:
                            info['errors'].append(line)
                        self._error('tracer', line)
                    continue
                event = self._parser.feed(line)
                if event:
                    info['status'] = 'active'
                    self._record_event(event)
            code = await self.tracer.wait()
            info['exit_code'] = code
            if code and not self.stop.is_set():
                info['status'] = 'error'
                self._error('tracer', f'{tool} exited with status {code}')
            elif not self.stop.is_set() and self.identities():
                info['status'] = 'ended_early'
                self._error('tracer', 'Tracing ended while monitored processes remain alive')
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            info['status'] = 'error'
            self._error('tracer', exc)
        finally:
            # If parsing was cancelled or failed, keep draining stderr so a
            # full pipe cannot prevent subprocess.wait() from completing.
            async def drain():
                while await self.tracer.stderr.read(65536):
                    pass
            drainer = asyncio.create_task(drain()) if self.tracer else None
            try:
                await self._detach()
            finally:
                if drainer:
                    try:
                        await asyncio.wait_for(drainer, 2)
                    except asyncio.TimeoutError:
                        self._error('tracer', 'Tracer output did not close after detach')
            if info['status'] not in ('error', 'unavailable', 'ended_early'):
                info['status'] = 'stopped'
            info['unmatched_returns'] = self._parser.unmatched_returns
            info['dropped_lines'] = self._parser.dropped
            info['unfinished_calls'] = len(self._parser.pending)
            if self._parser.dropped:
                self._error('tracer', f'{self._parser.dropped} trace records exceeded parser limits')

    async def _detach(self):
        tracer = self.tracer
        if tracer and tracer.returncode is None:
            try:
                # Signal only the tracer, never the target's process group.
                tracer.send_signal(signal.SIGINT)
                await asyncio.wait_for(tracer.wait(), timeout=3)
            except asyncio.TimeoutError:
                tracer.kill()
                await tracer.wait()
                self._error('tracer', 'Graceful detach timed out; tracer terminated')
            except ProcessLookupError:
                pass
        if tracer:
            self.report['tracer_info']['exit_code'] = tracer.returncode

    def save(self):
        self.report['uptime_seconds'] = round(time.monotonic() - self._started, 3)
        self.report['syscall_counts'] = dict(self._counts)
        temporary = self.report_path.with_suffix('.json.tmp')
        with temporary.open('w', encoding='utf-8') as handle:
            json.dump(self.report, handle, indent=2)
            handle.flush()
            os.fsync(handle.fileno())
        temporary.replace(self.report_path)

    async def run(self, duration=None, refresh=None):
        if duration is not None and (not math.isfinite(duration) or duration <= 0):
            raise ValueError('Duration must be positive and finite')
        self.report['status'] = 'running'
        try:
            self.discover()
            self._tasks = [asyncio.create_task(self._poll()), asyncio.create_task(self._trace())]
            if self.memory_scan:
                self._tasks.append(asyncio.create_task(self.memory_scan.run(self.identities)))
            while not self.stop.is_set():
                for task in self._tasks:
                    if task.done() and not task.cancelled() and task.exception():
                        raise task.exception()
                if duration is not None and time.monotonic() - self._started >= duration:
                    self.report['stop_reason'] = 'duration_elapsed'
                    break
                if refresh:
                    refresh(self.report)
                self.save()
                await asyncio.sleep(0.25)
        except asyncio.CancelledError:
            self.report['stop_reason'] = 'interrupted'
            raise
        except Exception as exc:
            self._error('monitor', exc)
            raise
        finally:
            self.stop.set()
            if self.memory_scan:
                self.memory_scan.scanner.stop.set()
            # Keep the reader alive while strace drains and detaches.
            await self._detach()
            for task in self._tasks:
                task.cancel()
            await asyncio.gather(*self._tasks, return_exceptions=True)
            memory = self.report['memory_scan']
            partial = bool(self.report['errors'] or self.report['truncated'] or memory.get('rule_errors'))
            partial |= any(p.get('status') not in ('complete',) for p in memory.get('processes', {}).values())
            self.report.update(status='partial' if partial else 'complete', ended_at=time.time())
            self.save()
