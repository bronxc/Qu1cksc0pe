"""ADB transport with explicit device ownership and bounded command output."""
import configparser
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import tempfile


class ADBError(RuntimeError):
    pass


def resolve_adb(configured=None):
    if configured:
        candidate = str(Path(configured).expanduser())
        if Path(candidate).is_file():
            return candidate
        raise ADBError('Configured ADB executable does not exist')
    candidate = shutil.which('adb')
    if candidate:
        return candidate
    config = configparser.ConfigParser()
    config.read(Path(__file__).resolve().parents[1] / 'Systems/Windows/windows.conf', encoding='utf-8-sig')
    candidate = config.get('ADB_PATH', 'win_adb_path', fallback='').strip().strip('"')
    if candidate and Path(candidate).is_file():
        return candidate
    raise ADBError('ADB was not found; install Android platform-tools or pass --adb PATH')


def validate_package(package):
    if not re.fullmatch(r'[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)+', package or '', re.ASCII):
        raise ValueError('Expected a full Android package identifier')
    return package


class ADB:
    def __init__(self, executable=None, serial=None):
        self.executable = resolve_adb(executable)
        self.serial = serial
        self.root_mode = None
        self.forwards = set()

    def argv(self, *arguments, device=True):
        if device and not self.serial:
            raise ADBError('Select a device first')
        return [self.executable, *(['-s', self.serial] if device else []), *map(str, arguments)]

    def run(self, *arguments, timeout=8, device=True, check=True, limit=2 * 1024 * 1024):
        # Regular files prevent output-pipe deadlocks and bound retained memory.
        with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
            try:
                process = subprocess.run(self.argv(*arguments, device=device), stdout=stdout,
                                         stderr=stderr, timeout=timeout)
            except (OSError, subprocess.TimeoutExpired) as error:
                raise ADBError(f'ADB {arguments[0] if arguments else "command"}: {error}') from error
            stdout.seek(0)
            stderr.seek(0)
            output, errors = stdout.read(limit + 1), stderr.read(8192)
        if len(output) > limit:
            raise ADBError('ADB output exceeded the command limit')
        output = output.decode('utf-8', 'replace').strip()
        errors = errors.decode('utf-8', 'replace').strip()
        if check and process.returncode:
            raise ADBError(f'ADB exited {process.returncode}: {(errors or output)[:1000]}')
        return process.returncode, output, errors

    def shell(self, arguments, *, root=False, **kwargs):
        command = shlex.join([str(value) for value in arguments])
        if root and self.root_mode == 'su':
            command = 'su -c ' + shlex.quote(command)
        elif root and self.root_mode == 'su_zero':
            command = 'su 0 sh -c ' + shlex.quote(command)
        elif root and self.root_mode != 'adbd':
            raise ADBError('Root access is unavailable on the selected device')
        return self.run('shell', command, **kwargs)

    def devices(self):
        _, output, _ = self.run('devices', '-l', device=False)
        devices = []
        for line in output.splitlines():
            fields = line.split()
            if len(fields) >= 2 and fields[1] in ('device', 'offline', 'unauthorized', 'recovery', 'sideload', 'bootloader'):
                devices.append({'serial': fields[0], 'state': fields[1], 'details': ' '.join(fields[2:])})
        return devices

    def select(self, serial=None):
        devices = self.devices()
        serial = serial or self.serial
        ready = [item['serial'] for item in devices if item['state'] == 'device']
        if serial is None and len(ready) == 1:
            serial = ready[0]
        if serial not in ready:
            state = next((item['state'] for item in devices if item['serial'] == serial), 'not connected')
            raise ADBError(f'Device {serial or "selection"}: {state}; ready devices: {", ".join(ready) or "none"}')
        self.serial = serial
        return serial

    def probe_root(self):
        if self.shell(['id', '-u'])[1] == '0':
            self.root_mode = 'adbd'
        else:
            code, output, _ = self.shell(['su', '-c', 'id -u'], check=False, timeout=5)
            self.root_mode = 'su' if code == 0 and output == '0' else None
            if self.root_mode is None:
                code, output, _ = self.shell(['su', '0', 'id', '-u'], check=False, timeout=5)
                self.root_mode = 'su_zero' if code == 0 and output == '0' else None
        return self.root_mode

    def forward(self, remote_port=27042):
        _, port, _ = self.run('forward', 'tcp:0', f'tcp:{int(remote_port)}')
        if not port.isdigit() or not 1 <= int(port) <= 65535:
            raise ADBError('ADB did not return the allocated forwarding port')
        self.forwards.add(int(port))
        return int(port)

    def close(self):
        errors = []
        for port in list(self.forwards):
            try:
                self.run('forward', '--remove', f'tcp:{port}', timeout=3)
                self.forwards.discard(port)
            except ADBError as error:
                errors.append(str(error))
        return errors

    def install(self, filename):
        path = Path(filename).expanduser().resolve(strict=True)
        _, output, _ = self.run('install', '-r', str(path), timeout=120)
        if not any(line.strip() == 'Success' for line in output.splitlines()):
            raise ADBError('APK installation failed: ' + output[:1000])

    def packages(self):
        _, output, _ = self.shell(['pm', 'list', 'packages', '-3'])
        return sorted({line[8:] for line in output.splitlines() if line.startswith('package:')})

    def identity(self, pid):
        _, output, _ = self.shell(['cat', f'/proc/{int(pid)}/stat'], root=bool(self.root_mode), timeout=3)
        tail = output.rpartition(')')[2].split()
        if len(tail) < 20 or not tail[19].isdigit():
            raise ADBError('Process start time is unavailable')
        return tail[19]

    def processes(self, package, known_pids=()):
        validate_package(package)
        _, output, _ = self.shell(['ps', '-A', '-o', 'PID,PPID,ARGS'])
        rows = []
        for line in output.splitlines():
            fields = line.split(None, 2)
            if len(fields) != 3 or not fields[0].isdigit() or not fields[1].isdigit():
                continue
            name = fields[2].split()[0]
            rows.append({'pid': int(fields[0]), 'ppid': int(fields[1]), 'name': name})
        selected = {row['pid'] for row in rows if row['name'] == package or row['name'].startswith(package + ':')}
        # Existing descendants remain tracked when their parent exits; callers must
        # check each PID's birth token before passing it here.
        selected.update(set(known_pids) & {row['pid'] for row in rows})
        for _ in range(16):
            children = {row['pid'] for row in rows if row['ppid'] in selected}
            if children <= selected:
                break
            selected.update(children)
        return [row for row in rows if row['pid'] in selected]
