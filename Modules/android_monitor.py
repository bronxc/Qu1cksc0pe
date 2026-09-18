"""Android process monitoring with owned ADB/Frida resources and bounded reports."""
from collections import Counter
import hashlib
import json
import lzma
import math
import os
from pathlib import Path
import queue
import re
import shlex
import subprocess
import tempfile
import threading
import time
import urllib.request

from android_adb import ADB, ADBError, validate_package
from android_archive import validate_apk_size
from android_apk_info import apk_info
from android_rpc import DISPATCHER, request


ABI = {'armeabi': 'arm', 'armeabi-v7a': 'arm', 'arm64-v8a': 'arm64', 'x86': 'x86', 'x86_64': 'x86_64'}


def load_agent(hooks=True):
    path = Path(__file__).resolve().parents[1] / 'Systems/Android/FridaScripts/sc0pe_android_enumeration.js'
    script = path.read_text(encoding='utf-8-sig')
    bridge_error = None
    bridge = ''
    try:
        import frida_tools
        source = (Path(frida_tools.__file__).parent / 'bridges/java.js').read_text(encoding='utf-8')
        # frida-tools ships an already bundled factory named `bridge`.
        bridge = 'if (typeof Java === "undefined") { (function () {\n' + source + '\nglobalThis.Java = bridge;\n})(); }\n'
    except (ImportError, OSError) as error:
        bridge_error = f'Java bridge is unavailable: {error}; install current frida-tools for Frida 17+'
    return 'globalThis.SC0PE_OPTIONS = ' + json.dumps({'hooks': hooks}) + ';\n' + bridge + script + DISPATCHER, bridge_error


def download_server(version, arch, directory):
    if not re.fullmatch(r'\d+\.\d+\.\d+(?:[.-][A-Za-z0-9]+)*', version) or arch not in ABI.values():
        raise ValueError('Invalid Frida version or architecture')
    filename = f'frida-server-{version}-android-{arch}.xz'
    request = urllib.request.Request(f'https://api.github.com/repos/frida/frida/releases/tags/{version}',
                                     headers={'User-Agent': 'Qu1cksc0pe'})
    with urllib.request.urlopen(request, timeout=20) as response:
        release = json.loads(response.read(4 * 1024 * 1024))
    asset = next((item for item in release.get('assets', []) if item.get('name') == filename), None)
    if not asset or asset['size'] > 64 * 1024 * 1024:
        raise ValueError('Matching Frida release asset is missing or oversized')
    url = f'https://github.com/frida/frida/releases/download/{version}/{filename}'
    archive = Path(directory) / filename
    digest = hashlib.sha256()
    total = 0
    with urllib.request.urlopen(url, timeout=30) as response, archive.open('xb') as output:
        while True:
            block = response.read(1024 * 1024)
            if not block:
                break
            total += len(block)
            if total > 64 * 1024 * 1024:
                raise ValueError('Frida download exceeds limit')
            digest.update(block)
            output.write(block)
    checksum = digest.hexdigest()
    expected = asset.get('digest')
    if expected and expected != 'sha256:' + checksum:
        raise ValueError('Frida release checksum mismatch')
    target = Path(directory) / filename[:-3]
    total = 0
    with lzma.open(archive) as source, target.open('xb') as output:
        while True:
            block = source.read(1024 * 1024)
            if not block:
                break
            total += len(block)
            if total > 128 * 1024 * 1024:
                raise ValueError('Frida binary exceeds limit')
            output.write(block)
    return target, {'url': url, 'sha256': checksum, 'publisher_digest_verified': bool(expected)}


class AndroidDynamicAnalyzer:
    MAX_PROCESSES = 16

    def __init__(self, package=None, *, apk=None, adb=None, serial=None, output_dir='sc0pe_reports/android-dynamic',
                 hooks=True, memory=True, files=True, logcat=True, launch=True, dump=True,
                 rule_paths=None, server_path=None, interval=1.0):
        if not math.isfinite(interval) or interval < 0.1:
            raise ValueError('Polling interval must be finite and at least 0.1 seconds')
        self.package = validate_package(package) if package else None
        self.apk = str(Path(apk).expanduser().resolve()) if apk else None
        self.adb = adb or ADB(serial=serial)
        self.adb.serial = serial or self.adb.serial
        parent = Path(output_dir).expanduser().resolve()
        parent.mkdir(parents=True, exist_ok=True)
        self.output_dir = Path(tempfile.mkdtemp(prefix='analysis-', dir=str(parent)))
        self.report_path = self.output_dir / 'report.json'
        self.features = {'hooks': hooks, 'memory_scan': memory, 'files': files, 'logcat': logcat,
                         'process_tree': True, 'suspicious_memory_exports': bool(memory and dump)}
        self.launch = launch
        self.dump = dump
        self.server_path = server_path
        self.interval = interval
        self.rule_paths = rule_paths or [Path(__file__).resolve().parents[1] / 'Systems/Android/YaraRules']
        self.stop = threading.Event()
        self.stop_reason = None
        self.closing = False
        self.events = queue.Queue(maxsize=4096)
        self.dropped_messages = 0
        self.entries = {}
        self.attach_sequence = 0
        self.logs = {}
        self.file_state = {}
        self.device = None
        self.frida = None
        self.active_call = None
        self.remote_address = None
        self.owned_server = None
        self.spawned_pid = None
        self.metadata = {}
        self.memory = None
        self.agent = None
        self.counts = Counter()
        self.started = time.monotonic()
        self.report = {'schema_version': 2, 'platform': 'android', 'package': self.package,
                       'device': self.adb.serial, 'status': 'starting', 'started_at': time.time(),
                       'features': self.features, 'processes': {}, 'process_history': [],
                       'api_events': [], 'recent_api_events': [], 'api_counts': {}, 'network_events': [],
                       'module_events': [], 'logcat': [],
                       'file_inventory': [], 'file_changes': [], 'errors': [], 'truncated': {},
                       'frida': {'status': 'starting' if hooks or memory or files else 'disabled'},
                       'memory_scan': {'status': 'starting' if memory else 'disabled'},
                       'file_status': 'starting' if files else 'disabled',
                       'logcat_status': 'starting' if logcat else 'disabled',
                       'coverage': {'process_selection': 'Package name, colon subprocesses and their descendants; custom unrelated process names may be omitted.',
                                    'file_scope': 'Application data directory; metadata and bounded hashes, not complete file contents.'},
                       'malware_verdict': None}

    def request_stop(self, reason='interrupt'):
        self.stop_reason = self.stop_reason or reason
        self.stop.set()
        if self.active_call:
            self.active_call.cancel()

    def _error(self, collector, error, **context):
        item = dict(collector=collector, error=str(error)[:1500], **context)
        if item not in self.report['errors'] and len(self.report['errors']) < 200:
            self.report['errors'].append(item)

    def _append(self, key, value, maximum=2000):
        if len(self.report[key]) >= maximum:
            self.report['truncated'][key] = self.report['truncated'].get(key, 0) + 1
            return
        self.report[key].append(value)

    def _call(self, function, *args, timeout=5, **kwargs):
        if self.stop.is_set() and not self.closing:
            raise RuntimeError('Analysis was stopped')
        cancellable = self.frida.Cancellable()
        timer = threading.Timer(timeout, cancellable.cancel)
        timer.daemon = True
        self.active_call = cancellable
        timer.start()
        try:
            with cancellable:
                return function(*args, **kwargs)
        finally:
            timer.cancel()
            self.active_call = None

    def _rpc(self, entry, method, *args, timeout=5):
        return request(entry['script'], method, args, timeout=timeout,
                       stop=None if self.closing else self.stop, post=self._call)

    def _enqueue(self, identity, message, data=None):
        try:
            self.events.put_nowait((identity, message))
        except queue.Full:
            self.dropped_messages += 1

    def _metadata(self):
        if not self.apk:
            try:
                _, output, _ = self.adb.shell(['pm', 'path', self.package])
                paths = [line[8:] for line in output.splitlines() if line.startswith('package:')]
                path = next((p for p in paths if p.endswith('/base.apk')), paths[0] if paths else None)
                if path:
                    _, size, _ = self.adb.shell(['stat', '-c', '%s', path])
                    if not size.isdigit() or int(size) > 256 * 1024 * 1024:
                        raise ValueError('Installed base APK size unavailable or exceeds 256 MiB')
                    destination = self.output_dir / 'base.apk'
                    self.adb.run('pull', path, str(destination), timeout=60)
                    self.apk = str(destination)
                    self.report['coverage']['apk_metadata'] = 'base APK only; split APK content is not included'
            except Exception as error:
                self._error('apk_metadata', error)
        if self.apk:
            try:
                validate_apk_size(self.apk)
                from androguard.core.bytecodes.apk import APK
                from analysis.multiple.android_yara import apk_metadata
                parsed = APK(self.apk)
                identity = apk_info(self.apk, parsed)
                self.report['coverage']['apk_identity'] = identity
                if identity.get('package') != self.package:
                    raise ValueError('APK package differs from the selected package')
                self.metadata, errors = apk_metadata(parsed)
                for error in errors:
                    self._error('apk_metadata', error)
            except Exception as error:
                self._error('apk_metadata', error)

    def _connect_frida(self):
        import frida
        self.frida = frida
        port = self.adb.forward()
        self.remote_address = f'127.0.0.1:{port}'
        manager = frida.get_device_manager()
        self.device = self._call(manager.add_remote_device, self.remote_address)
        try:
            self._call(self.device.enumerate_processes)
            self.report['frida'].update(status='connected', server='existing', client_version=frida.__version__)
            return
        except Exception:
            pass
        if self.stop.is_set():
            raise RuntimeError('Analysis stopped during Frida connection')
        if not self.adb.root_mode:
            raise ADBError('A reachable Frida server or root access is required for hooks, memory and files')
        _, abi, _ = self.adb.shell(['getprop', 'ro.product.cpu.abi'])
        arch = ABI.get(abi)
        if not arch:
            raise ADBError('Unsupported Android ABI: ' + abi)
        remote = f'/data/local/tmp/qu1cksc0pe-frida-{frida.__version__}-{arch}'
        code, version, _ = self.adb.shell([remote, '--version'], root=True, check=False)
        if code != 0 or version != frida.__version__:
            if self.server_path:
                local = Path(self.server_path).expanduser().resolve(strict=True)
                provenance = {'source': 'provided', 'path': str(local)}
            else:
                local, provenance = download_server(frida.__version__, arch, self.output_dir)
            self.adb.run('push', str(local), remote, timeout=60)
            self.adb.shell(['chmod', '755', remote], root=True)
            _, version, _ = self.adb.shell([remote, '--version'], root=True)
            if version != frida.__version__:
                raise ADBError('Frida server version does not match the Python client')
            self.report['frida']['download'] = provenance
        log = remote + '.log'
        command = f'nohup {shlex.quote(remote)} -l 127.0.0.1:27042 >{shlex.quote(log)} 2>&1 </dev/null & echo $!'
        _, pid, _ = self.adb.shell(['sh', '-c', command], root=True)
        if not pid.isdigit():
            raise ADBError('Frida server did not return its PID')
        self.owned_server = (int(pid), self.adb.identity(int(pid)))
        deadline = time.monotonic() + 20
        last_error = None
        while not self.stop.is_set() and time.monotonic() < deadline:
            try:
                self._call(self.device.enumerate_processes)
                self.report['frida'].update(status='connected', server='started', server_pid=int(pid),
                                             client_version=frida.__version__, abi=abi)
                return
            except Exception as error:
                last_error = error
                self.stop.wait(0.5)
        raise ADBError(f'Frida server failed to become ready: {last_error}')

    def prepare(self):
        self.adb.select()
        self.report['device'] = self.adb.serial
        if self.apk:
            validate_apk_size(self.apk)
            identity = apk_info(self.apk)
            self.report['coverage']['apk_identity'] = identity
            package = validate_package(identity.get('package'))
            if self.package and self.package != package:
                raise ValueError('Selected package differs from APK manifest')
            self.package = package
            self.report['package'] = package
            _, device_abi, _ = self.adb.shell(['getprop', 'ro.product.cpu.abilist'])
            if not device_abi:
                _, device_abi, _ = self.adb.shell(['getprop', 'ro.product.cpu.abi'])
            device_abis = device_abi.split(',')
            self.report['compatibility'] = {'apk_native_abis': identity['native_abis'],
                'device_abis': device_abis, 'native_abi_match':
                bool(set(device_abis) & set(identity['native_abis'])) if identity['native_abis'] else None,
                'installation': 'pending'}
            self.adb.install(self.apk)
            self.report['compatibility']['installation'] = 'installed'
        if not self.package:
            raise ValueError('Select an installed package or provide an APK')
        self.report['package'] = self.package
        code, output, _ = self.adb.shell(['pm', 'path', self.package], check=False)
        if code or not output.startswith('package:'):
            raise ADBError('Selected package is not installed')
        try:
            self.adb.probe_root()
        except ADBError as error:
            self._error('root_probe', error)
        self._metadata()
        if self.stop.is_set():
            return
        if self.features['hooks'] or self.features['memory_scan'] or self.features['files']:
            try:
                self._connect_frida()
                self.agent, warning = load_agent(self.features['hooks'])
                if warning:
                    self._error('java_bridge', warning)
                if self.features['memory_scan']:
                    from android_memory import AndroidMemoryScanner
                    self.memory = AndroidMemoryScanner(self.rule_paths, self.output_dir,
                                                       metadata=self.metadata, export=self.dump)
                    self.memory.prepare()
                    self.report['memory_scan'] = self.memory.report
            except Exception as error:
                self._error('frida', error)
                self.report['frida']['status'] = 'unavailable'
                self.device = None
                if self.features['memory_scan']:
                    self.report['memory_scan']['status'] = 'unavailable'
                if self.features['files']:
                    self.report['file_status'] = 'unavailable'
        if self.launch and not self.stop.is_set() and not self.adb.processes(self.package):
            if self.device:
                try:
                    self.spawned_pid = self._call(self.device.spawn, self.package, timeout=30)
                    birth = self.adb.identity(self.spawned_pid)
                    self._attach({'pid': self.spawned_pid, 'ppid': None, 'name': self.package}, birth)
                finally:
                    if self.spawned_pid:
                        # A stop request must still allow an owned spawn to resume.
                        try:
                            self.closing = True
                            self._call(self.device.resume, self.spawned_pid)
                            self.spawned_pid = None
                        finally:
                            self.closing = False
            else:
                self.adb.shell(['monkey', '-p', self.package, '-c', 'android.intent.category.LAUNCHER', '1'], timeout=15)
        self.report['status'] = 'monitoring'

    def _attach(self, process, birth):
        pid = process['pid']
        identity = f'{pid}:{birth}'
        self.attach_sequence += 1
        generation = self.attach_sequence
        entry = dict(process, birth=birth, identity=identity, session=None, script=None,
                     attach_generation=generation)
        self.entries[pid] = entry
        view = dict(process, identity=identity, status='observed', first_seen=time.time(), hooks={},
                    attach_generation=generation)
        self.report['processes'][str(pid)] = view
        if self.device:
            try:
                session = self._call(self.device.attach, pid)
                entry['session'] = session
                def on_detached(reason, crash):
                    self._enqueue(identity, {'type': 'detached', 'reason': reason,
                                             'attach_generation': generation,
                                             'crash': str(crash)[:1500] if crash else None})
                session.on('detached', on_detached)
                script = self._call(session.create_script, self.agent)
                entry['script'] = script
                def on_message(message, data):
                    payload = message.get('payload')
                    if isinstance(payload, dict) and payload.get('type') == 'sc0pe-reply':
                        return
                    self._enqueue(identity, message, data)
                script.on('message', on_message)
                self._call(script.load, timeout=15)
                if self.adb.identity(pid) != birth or self._rpc(entry, 'identity')['pid'] != pid:
                    raise RuntimeError('PID identity changed during attach')
                view['status'] = 'attached'
            except Exception as error:
                view['status'] = 'attach_error'
                self._error('attach', error, pid=pid)
                self._detach_script(entry)
                entry['next_retry'] = time.monotonic() + 5
        if self.features['logcat']:
            self._start_log(entry)

    def _start_log(self, entry):
        pid, identity = entry['pid'], entry['identity']
        try:
            process = subprocess.Popen(self.adb.argv('logcat', f'--pid={pid}', '-v', 'epoch', '-T', '1'),
                                       stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            def reader():
                while True:
                    line = process.stdout.readline(16385)
                    if not line:
                        break
                    if len(line) > 16384:
                        while line and not line.endswith(b'\n'):
                            line = process.stdout.readline(16385)
                        self._enqueue(identity, {'type': 'log_truncated'})
                        continue
                    self._enqueue(identity, {'type': 'log', 'line': line.decode('utf-8', 'replace').rstrip()})
            thread = threading.Thread(target=reader, daemon=True, name=f'android-logcat-{pid}')
            self.logs[pid] = (process, thread)
            thread.start()
            self.report['logcat_status'] = 'running'
        except OSError as error:
            self._error('logcat', error, pid=pid)
            self.report['logcat_status'] = 'error'

    def _detach_script(self, entry):
        script, session = entry.get('script'), entry.get('session')
        if session and session.is_detached:
            entry['script'] = entry['session'] = None
            return
        if script:
            try:
                self._rpc(entry, 'stop', timeout=2)
            except Exception:
                pass
            try:
                self._call(script.unload, timeout=3)
            except Exception as error:
                self._error('script_unload', error, pid=entry['pid'])
        if session:
            try:
                self._call(session.detach, timeout=3)
            except Exception as error:
                self._error('detach', error, pid=entry['pid'])
        entry['script'] = entry['session'] = None

    def _retire(self, pid, reason):
        entry = self.entries.pop(pid, None)
        if entry:
            self._detach_script(entry)
        if pid in self.logs:
            process, thread = self.logs.pop(pid)
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=2)
            thread.join(timeout=2)
            process.stdout.close()
        view = self.report['processes'].pop(str(pid), None)
        if view:
            view.update(status='retired', reason=reason, last_seen=time.time())
            self._append('process_history', view, 256)
        if entry and self.memory:
            self.memory.cursors.pop(entry['identity'], None)

    def _drain(self):
        for _ in range(4096):
            try:
                identity, message = self.events.get_nowait()
            except queue.Empty:
                break
            if not isinstance(identity, str) or not isinstance(message, dict):
                self._error('agent_message', 'Invalid callback payload')
                continue
            if message.get('type') == 'send':
                message = message.get('payload', {})
            if not isinstance(message, dict):
                self._error('agent_message', 'Invalid agent payload')
                continue
            kind = message.get('type')
            pid = int(identity.split(':')[0])
            view = self.report['processes'].get(str(pid))
            current = view and view['identity'] == identity
            if kind == 'batch':
                if current:
                    view['agent_calls'] = message.get('calls', 0)
                    view['agent_dropped'] = message.get('dropped', 0)
                for event in message.get('events', [])[:256]:
                    if not isinstance(event, dict) or event.get('pid') != pid:
                        continue
                    event['process_identity'] = identity
                    if event.get('type') == 'module':
                        self._append('module_events', event, 2000)
                        continue
                    if event.get('type') != 'api':
                        continue
                    self.counts[event.get('api', 'unknown')] += 1
                    self._append('api_events', event, 20000)
                    if event.get('api') == 'connect' and event.get('layer') == 'native':
                        self._append('network_events', dict(event, observation='connection_attempt'), 2000)
                    self.report['recent_api_events'].append(event)
                    self.report['recent_api_events'] = self.report['recent_api_events'][-24:]
            elif kind == 'hooks' and current:
                view['hooks'] = message.get('hooks', {})
            elif kind == 'error':
                self._error('agent', message.get('description', message), pid=pid)
            elif (kind == 'detached' and current and
                  message.get('attach_generation') == view.get('attach_generation')):
                view['status'] = 'detached'
                view['detach_reason'] = message.get('reason')
            elif kind == 'log':
                line = message.get('line', '')
                fields = line.split(None, 5)
                # Defend against unsupported --pid options and mixed log buffers.
                if len(fields) >= 5 and fields[1].isdigit() and int(fields[1]) == pid:
                    self._append('logcat', {'process_identity': identity, 'pid': pid, 'line': line}, 5000)
                elif line and not line.startswith('---------'):
                    self._error('logcat_output', line, pid=pid)
            elif kind == 'log_truncated':
                self.report['truncated']['logcat_lines'] = self.report['truncated'].get('logcat_lines', 0) + 1
        self.report['api_counts'] = dict(self.counts)
        self.report['truncated']['message_queue'] = self.dropped_messages

    def _files(self, entry):
        result = self._rpc(entry, 'files')
        self.report['file_status'] = result.get('status', 'partial')
        self.report['file_inventory'] = result.get('files', [])[:256]
        current = {item['path']: item for item in self.report['file_inventory']}
        for name, item in current.items():
            if self.file_state.get(name) != item:
                self._append('file_changes', dict(item, change='created' if name not in self.file_state else 'modified',
                    observed_at=time.time(), process_identity=entry['identity']))
        if result.get('enumeration_complete', result.get('status') == 'complete'):
            for name in self.file_state.keys() - current.keys():
                self._append('file_changes', {'path': name, 'change': 'deleted', 'observed_at': time.time()})
            self.file_state = current
        else:
            self.file_state.update(current)

    def poll(self):
        known = []
        for pid, entry in list(self.entries.items()):
            try:
                if self.adb.identity(pid) != entry['birth']:
                    self._retire(pid, 'pid_reused')
                elif self.report['processes'][str(pid)]['status'] == 'detached':
                    self._retire(pid, 'frida_detached')
                elif self.device and not entry.get('script') and time.monotonic() >= entry.get('next_retry', 0):
                    self._retire(pid, 'retry_attach')
                else:
                    known.append(pid)
            except ADBError:
                self._retire(pid, 'exited_or_inaccessible')
        rows = self.adb.processes(self.package, known)
        if len(rows) > self.MAX_PROCESSES:
            self.report['truncated']['processes'] = len(rows) - self.MAX_PROCESSES
        for process in rows[:self.MAX_PROCESSES]:
            if process['pid'] not in self.entries:
                try:
                    self._attach(process, self.adb.identity(process['pid']))
                except Exception as error:
                    self._error('process_discovery', error, pid=process['pid'])
        for pid, (process, _) in self.logs.items():
            if process.poll() is not None and not self.stop.is_set():
                self.report['logcat_status'] = 'partial'
                self._error('logcat', f'Collector exited {process.returncode}', pid=pid)
        self._drain()

    def save(self):
        self.report['uptime_seconds'] = round(time.monotonic() - self.started, 2)
        temporary = self.output_dir / '.report.json.tmp'
        with temporary.open('w', encoding='utf-8') as output:
            json.dump(self.report, output, indent=2)
        os.replace(temporary, self.report_path)

    def run(self, *, duration=None, update=None):
        if duration is not None and (not math.isfinite(duration) or duration <= 0):
            raise ValueError('Duration must be a positive finite number')
        next_files = next_memory = 0
        rotation = 0
        try:
            self.prepare()
            self.started = time.monotonic()
            while not self.stop.is_set():
                if duration is not None and time.monotonic() - self.started >= duration:
                    self.request_stop('duration')
                    break
                try:
                    self.poll()
                    self.report['status'] = 'monitoring' if self.entries else 'waiting_for_process'
                    entries = [entry for entry in self.entries.values() if entry.get('script')]
                    now = time.monotonic()
                    if entries and self.features['files'] and now >= next_files:
                        try:
                            self._files(entries[0])
                        except Exception as error:
                            self.report['file_status'] = 'unavailable'
                            self._error('files', error, pid=entries[0]['pid'])
                        next_files = now + 5
                    if entries and self.memory and now >= next_memory and not self.stop.is_set():
                        entry = entries[rotation % len(entries)]
                        rotation += 1
                        self.memory.scan(entry['identity'], lambda method, *args: self._rpc(entry, method, *args), self.stop)
                        next_memory = time.monotonic() + 2
                except Exception as error:
                    self.report['status'] = 'disconnected_or_partial'
                    self._error('poll', error)
                self._drain()
                self.save()
                if update:
                    update(self.report)
                self.stop.wait(self.interval)
        except KeyboardInterrupt:
            self.request_stop('interrupt')
        except Exception as error:
            self._error('prepare', error)
            if self.report.get('compatibility', {}).get('installation') == 'pending':
                self.report['compatibility']['installation'] = 'failed'
            if not self.stop.is_set():
                self.stop_reason = 'error'
        finally:
            self.close()
        return self.report

    def close(self):
        self.closing = True
        self.stop.set()
        for pid in list(self.entries):
            self._retire(pid, 'monitor_stopped')
        self._drain()
        if self.spawned_pid and self.device:
            try:
                self._call(self.device.resume, self.spawned_pid, timeout=3)
            except Exception as error:
                self._error('resume_on_shutdown', error)
        if self.owned_server:
            pid, birth = self.owned_server
            try:
                if self.adb.identity(pid) == birth:
                    self.adb.shell(['kill', '-TERM', str(pid)], root=True, timeout=3)
            except ADBError as error:
                self._error('server_cleanup', error)
            self.owned_server = None
        if self.remote_address and self.frida:
            try:
                self._call(self.frida.get_device_manager().remove_remote_device, self.remote_address, timeout=3)
            except Exception as error:
                self._error('frida_transport_cleanup', error)
        for error in self.adb.close():
            self._error('adb_forward_cleanup', error)
        self.report['status'] = 'error' if self.stop_reason == 'error' else 'stopped'
        self.report['stop_reason'] = self.stop_reason or 'closed'
        self.report['ended_at'] = time.time()
        if self.memory:
            self.memory.report['status'] = 'stopped'
        if self.report['logcat_status'] == 'running':
            self.report['logcat_status'] = 'stopped'
        self.save()
