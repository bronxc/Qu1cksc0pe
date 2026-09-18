#!/usr/bin/env python3
"""Monitor an Android laboratory application through ADB and Frida."""
import argparse
import math
from pathlib import Path
import signal

from android_adb import ADB, ADBError
from android_monitor import AndroidDynamicAnalyzer


def positive(value):
    number = float(value)
    if not math.isfinite(number) or number <= 0:
        raise argparse.ArgumentTypeError('Expected a positive finite number')
    return number


def render(report):
    from rich.console import Group
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text
    processes = Table('PID', 'Process', 'State', 'Native / Java hooks', 'Calls')
    for row in report['processes'].values():
        hooks = row.get('hooks', {})
        processes.add_row(str(row['pid']), Text(row['name']), row['status'],
            f"{len(hooks.get('native', []))} / {len(hooks.get('java', []))}", str(row.get('agent_calls', 0)))
    calls = Table('PID', 'API / function', 'Arguments', 'Result')
    for row in report['recent_api_events'][-12:]:
        calls.add_row(str(row['pid']), Text(row.get('api', '')), Text(str(row.get('arguments', ''))[:140]),
                      'success' if row.get('success') else Text(str(row.get('error', row.get('result', 'unknown')))))
    logs = Table('PID', 'Recent logcat')
    for row in report['logcat'][-5:]:
        logs.add_row(str(row['pid']), Text(row['line'][:200]))
    files = Table('File', 'Change', 'Kind')
    for row in report['file_changes'][-5:]:
        files.add_row(Text(row['path']), row['change'], row.get('kind', ''))
    memory = report['memory_scan']
    status = (f"{report['status']} | Frida: {report['frida']['status']} | "
              f"Memory: {memory['status']}, {memory.get('rule_files', 0)} rule files, "
              f"{len(memory.get('matches', []))} candidates | Errors: {len(report['errors'])}")
    return Group(Panel(Text(f"{report['package']} on {report['device']}\n{status}")), processes, calls, files, logs)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('apk', nargs='?', help='APK to install and analyze')
    parser.add_argument('--package', help='Installed application package identifier')
    parser.add_argument('--device', help='Exact ADB device serial')
    parser.add_argument('--adb', help='ADB executable path')
    parser.add_argument('--list-devices', action='store_true')
    parser.add_argument('--headless', action='store_true')
    parser.add_argument('--duration', type=positive, help='Monitoring duration in seconds, excluding preparation')
    parser.add_argument('--interval', type=positive, default=1.0)
    parser.add_argument('--output-dir', default='sc0pe_reports/android-dynamic')
    parser.add_argument('--frida-server', help='Local server binary matching the device ABI and Python Frida version')
    parser.add_argument('--yara-path', action='append', help='Override default Android memory YARA sources')
    parser.add_argument('--no-launch', action='store_true', help='Wait for the application instead of launching it')
    parser.add_argument('--no-hooks', action='store_true')
    parser.add_argument('--no-memory-scan', action='store_true')
    parser.add_argument('--no-files', action='store_true')
    parser.add_argument('--no-logcat', action='store_true')
    parser.add_argument('--no-dump-suspicious', action='store_true')
    args = parser.parse_args(argv)
    from rich.console import Console
    console = Console()
    try:
        adb = ADB(args.adb, args.device)
        if args.list_devices:
            for device in adb.devices():
                console.print(f"{device['serial']}  {device['state']}  {device['details']}", markup=False)
            return 0
        if not args.headless:
            devices = adb.devices()
            ready = [item['serial'] for item in devices if item['state'] == 'device']
            if args.device is None and len(ready) > 1:
                console.print('Ready devices: ' + ', '.join(ready), markup=False)
                args.device = input('Select device serial: ').strip()
            adb.select(args.device)
            if not args.apk and not args.package:
                choice = input('Analyze [1] APK file or [2] installed package: ').strip()
                if choice == '1':
                    args.apk = input('APK path: ').strip().strip('"')
                elif choice == '2':
                    packages = adb.packages()
                    console.print('\n'.join(packages), markup=False)
                    args.package = input('Package identifier: ').strip()
                else:
                    raise ValueError('Select 1 or 2')
        if not args.apk and not args.package:
            parser.error('Provide an APK or --package for headless monitoring')
        analyzer = AndroidDynamicAnalyzer(args.package, apk=args.apk, adb=adb, serial=args.device,
            output_dir=args.output_dir, hooks=not args.no_hooks, memory=not args.no_memory_scan,
            files=not args.no_files, logcat=not args.no_logcat, launch=not args.no_launch,
            dump=not args.no_dump_suspicious, rule_paths=args.yara_path,
            server_path=args.frida_server, interval=args.interval)
    except (ADBError, OSError, ValueError) as error:
        console.print(f'Android preparation failed: {error}', markup=False)
        return 1
    console.print(f'Report: {analyzer.report_path}', markup=False)
    previous = {}
    for name in ('SIGINT', 'SIGTERM'):
        signum = getattr(signal, name, None)
        if signum is not None:
            previous[signum] = signal.signal(signum, lambda *_: analyzer.request_stop('interrupt'))
    try:
        if args.headless:
            report = analyzer.run(duration=args.duration)
        else:
            from rich.live import Live
            with Live(render(analyzer.report), console=console, refresh_per_second=2) as live:
                report = analyzer.run(duration=args.duration, update=lambda value: live.update(render(value)))
    finally:
        for signum, handler in previous.items():
            signal.signal(signum, handler)
    console.print(f"Analysis {report['status']}: {report.get('stop_reason', '')}. Report: {analyzer.report_path}", markup=False)
    for error in report['errors'][-5:]:
        console.print(f"{error['collector']}: {error['error']}", markup=False)
    return 1 if report['status'] == 'error' else 0


if __name__ == '__main__':
    raise SystemExit(main())
