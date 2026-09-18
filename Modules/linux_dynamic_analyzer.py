import re
import os
import sys
import json
import shutil
import psutil
import asyncio
import warnings
import argparse
from pathlib import Path
from dynamic_memory import MemoryScanSession
from linux_monitor import LinuxDynamicAnalyzer

try:
    from rich import print
    from rich.table import Table
    from rich.live import Live
    from rich.layout import Layout
    from rich.text import Text
    from rich.panel import Panel
except Exception:
    print("Error: >rich< module not found.")
    sys.exit(1)

try:
    from prompt_toolkit import prompt as pt_prompt
    from prompt_toolkit.completion import PathCompleter, WordCompleter
    _PATH_COMPLETER = PathCompleter(expanduser=True)
except Exception:
    pt_prompt       = None
    _PATH_COMPLETER = None
    WordCompleter   = None

try:
    from analysis.linux.linux_emulator import Linxcution
except Exception:
    try:
        from .analysis.linux.linux_emulator import Linxcution
    except Exception:
        Linxcution = None

try:
    import lief
except Exception:
    lief = None

# Legends
errorS = f"[bold cyan][[bold red]![bold cyan]][white]"
infoS  = f"[bold cyan][[bold red]*[bold cyan]][white]"

# Gathering Qu1cksc0pe path variable
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

# ── Helpers ────────────────────────────────────────────────────────────────

def _input_path(prompt_text):
    return _input_text(prompt_text, completer=_PATH_COMPLETER)


def _input_text(prompt_text, completer=None):
    if pt_prompt is not None and _PATH_COMPLETER is not None and sys.stdin and sys.stdin.isatty():
        try:
            if completer is not None:
                return pt_prompt(prompt_text, completer=completer, complete_while_typing=True)
            return pt_prompt(prompt_text)
        except Exception:
            pass
    return input(prompt_text)


def _build_menu_completer():
    if WordCompleter is None:
        return None
    return WordCompleter(
        ["1", "2", "binary", "emulation", "pid", "monitor"],
        ignore_case=True, sentence=True,
    )


def _build_pid_name_completer():
    if WordCompleter is None:
        return None
    candidates = set()
    try:
        for proc in psutil.process_iter(["pid", "name"]):
            pid  = proc.info.get("pid")
            name = str(proc.info.get("name") or "").strip()
            if pid:
                candidates.add(str(pid))
            if name:
                candidates.add(name)
    except Exception:
        pass
    return WordCompleter(sorted(candidates)[:500], ignore_case=True, sentence=True)


# ── Emulation helpers ──────────────────────────────────────────────────────

def _detect_machine_type(target_binary):
    if lief is None:
        print(f"{errorS} >lief< module not found. Cannot detect machine type for emulation.")
        return None
    try:
        parsed = lief.parse(target_binary)
        if not parsed:
            return None
        return str(parsed.header.machine_type).split(".")[-1]
    except Exception as exc:
        print(f"{errorS} Failed to parse target binary with LIEF: {exc}")
        return None


def run_binary_emulation_menu():
    if Linxcution is None:
        print(f"{errorS} Linux emulator module is not available.")
        return
    target_binary = _input_path(">>> Enter target binary path [TAB for autocomplete]: ").strip().strip("\"'")
    if not target_binary:
        print(f"{errorS} Empty path!")
        return
    target_binary = os.path.abspath(os.path.expanduser(target_binary))
    if not os.path.isfile(target_binary):
        print(f"{errorS} Target binary not found: [bold red]{target_binary}[white]")
        return

    machine_type = _detect_machine_type(target_binary)
    if not machine_type:
        print(f"{errorS} Could not determine machine type for emulation.")
        return

    try:
        linxc = Linxcution(target_binary, machine_type)
        linxc.perform_analysis()
    except Exception as exc:
        print(f"{errorS} Binary emulation failed: {exc}")


# ── PID resolution ─────────────────────────────────────────────────────────

def _parse_pid_input(raw):
    try:
        pid = int(str(raw).strip())
    except Exception:
        return None
    return pid if pid > 0 else None


def _normalize_process_name(raw_name):
    name = str(raw_name or "").strip().strip("\"'")
    if not name:
        return ""
    if path_seperator in name:
        name = name.split(path_seperator)[-1]
    return name.strip()


def _find_pid_by_process_name(target_name):
    name_l = str(target_name or "").strip().lower()
    if not name_l:
        return None

    exact = []
    for proc in psutil.process_iter(["pid", "name", "create_time"]):
        try:
            pname = str(proc.info.get("name") or "")
            if not pname:
                continue
            pl = pname.lower()
            entry = (proc.info.get("create_time") or 0, int(proc.info["pid"]))
            if pl == name_l:
                exact.append(entry)
        except Exception:
            continue

    if exact:
        exact.sort(reverse=True)
        return exact[0][1]
    return None


def _resolve_target_pid(value, wait_for_name=True, wait_seconds=45):
    pid = _parse_pid_input(value)
    if pid is not None:
        try:
            psutil.Process(pid)
            return pid
        except Exception:
            return None

    proc_name = _normalize_process_name(value)
    if not proc_name:
        return None

    found = _find_pid_by_process_name(proc_name)
    if found is not None:
        return found

    if not wait_for_name:
        return None

    print(f"{infoS} Target acquired! Now you need to [bold blink green]execute the target process[white].")
    import time
    for _ in range(max(1, int(wait_seconds))):
        found = _find_pid_by_process_name(proc_name)
        if found is not None:
            return found
        try:
            time.sleep(1)
        except Exception:
            break
    return None


# ── main_app ───────────────────────────────────────────────────────────────

def main_app(target_pid, *, headless=False, duration=None, **kwargs):
    lda = LinuxDynamicAnalyzer(target_pid, **kwargs)
    print(f"{infoS} Report: {lda.report_path}")

    def table(headers, rows):
        result = Table(*headers, expand=True)
        for row in rows:
            result.add_row(*(Text(str(value)) for value in row))
        return result

    layout = Layout()
    layout.split_column(Layout(name='status', size=3), Layout(name='top'), Layout(name='bottom'))
    layout['top'].split_row(Layout(name='processes'), Layout(name='network'), Layout(name='files'))
    layout['bottom'].split_row(Layout(name='calls', ratio=2), Layout(name='findings'))

    def refresh(report):
        tracer = report['tracer_info']
        layout['status'].update(Panel(Text(
            f"PID {lda.target_pid} | {report['status']} | "
            f"Tracer: {tracer['tool'] or '-'} / {tracer['status']} | "
            f"Calls: {sum(lda._counts.values())} | Errors: {len(report['errors'])}")))
        layout['processes'].update(Panel(table(['PID', 'Process', 'Status'],
            [(p['pid'], p['name'], p['status']) for p in list(report['processes'].values())[-12:]]), title='Process Tree'))
        def address(value):
            return f"{value['ip']}:{value['port']}" if value else '-'
        layout['network'].update(Panel(table(['PID', 'Local', 'Remote', 'State'],
            [(c['pid'], address(c['local']), address(c['remote']), c['status'])
             for c in report['network_observations'][-12:]]), title='Network Observations'))
        files = [(pid, path) for pid, paths in report['open_files'].items() for path in paths]
        layout['files'].update(Panel(table(['PID', 'Path'], files[-12:]), title='Open Files'))
        events = report.get('recent_trace_events', report['trace_events'])
        layout['calls'].update(Panel(table(['PID/TID', 'Call', 'Arguments', 'Result'],
            [(f"{e['pid']}/{e['tid']}", e['call'], e['arguments'][:100], e['return_value'][:50])
             for e in events[-14:]]), title='Syscall / API Tracer'))
        memory = report['memory_scan']
        rows = [(b['classification'], b['kind']) for b in report['behavior_observations'][-4:]]
        rows += [('YARA / '+str(m['pid']), m['rule']) for m in memory.get('yara_matches', [])[-4:]]
        rows += [('URL', u) for u in report['interesting_findings']['urls'][-3:]]
        rows += [('Error', e['collector']+': '+e['error']) for e in report['errors'][-2:]]
        title = f"Findings | Memory: {memory['status']} | {memory.get('rule_files', 0)} rule files"
        layout['findings'].update(Panel(table(['Type', 'Evidence'], rows), title=title))

    try:
        if headless:
            asyncio.run(lda.run(duration=duration))
        else:
            with Live(layout, refresh_per_second=2):
                asyncio.run(lda.run(duration=duration, refresh=refresh))
    except KeyboardInterrupt:
        print(f"\n{infoS} Monitoring stopped; tracers detached and report saved.")
    return lda.report


# ── Menus ──────────────────────────────────────────────────────────────────

def run_pid_monitoring_menu(**kwargs):
    raw_target = _input_text(
        ">>> Enter target PID or Process Name [TAB for autocomplete]: ",
        completer=_build_pid_name_completer(),
    ).strip()
    pid = _resolve_target_pid(raw_target, wait_for_name=True, wait_seconds=45)
    if pid is None:
        print(f"{errorS} PID/Process not found or is not accessible.")
        return

    print(f"\n{infoS} Monitoring PID: [bold green]{pid}[white]. ([bold blink yellow]Ctrl+C to stop![white])")
    main_app(pid, **kwargs)


def linux_dynamic_menu(**kwargs):
    print(f"\n{infoS} Linux Dynamic Analysis Menu")
    print("[bold cyan][[bold red]1[bold cyan]][white] Binary Emulation (run inside a VM)")
    print("[bold cyan][[bold red]2[bold cyan]][white] PID Monitoring")
    choice = _input_text(
        ">>> Select [1/2] [TAB for autocomplete]: ",
        completer=_build_menu_completer(),
    ).strip().lower()

    if choice in {"1", "binary", "emulation"}:
        run_binary_emulation_menu()
    elif choice in {"2", "pid", "monitor"}:
        run_pid_monitoring_menu(**kwargs)
    else:
        print(f"{errorS} Wrong option :(")


if __name__ == "__main__":
    try:
        parser = argparse.ArgumentParser(description='Linux dynamic analysis')
        parser.add_argument('target', nargs='?', help='PID or process name (otherwise show menu)')
        parser.add_argument('--memory-yara', action='append', help='YARA file/directory; repeat for multiple paths')
        parser.add_argument('--dump-suspicious', action='store_true', dest='dump_suspicious', default=True, help='Export bounded matching/RWX memory windows (default)')
        parser.add_argument('--no-dump-suspicious', action='store_false', dest='dump_suspicious', help='Disable memory exports')
        parser.add_argument('--headless', action='store_true', help='Monitor without the live terminal UI')
        parser.add_argument('--duration', type=float, help='Stop monitoring after this many seconds')
        parser.add_argument('--output-dir', default='.', help='Directory for reports and bounded memory exports')
        parser.add_argument('--tracer', choices=('auto','strace','ltrace','none'), default='auto')
        parser.add_argument('--interval', type=float, default=1.0, help='Process/network polling interval in seconds')
        parser.add_argument('--no-memory-scan', action='store_true', help='Disable live-memory YARA/IOC scanning')
        options = parser.parse_args()
        import math
        if sys.platform != 'linux':
            parser.error('Linux process monitoring requires Linux; run it inside your Linux VM')
        if options.duration is not None and (not math.isfinite(options.duration) or options.duration <= 0):
            parser.error('--duration must be positive and finite')
        if not math.isfinite(options.interval) or options.interval < 0.1:
            parser.error('--interval must be finite and at least 0.1 seconds')
        if options.headless and not options.target:
            parser.error('--headless requires a target PID or exact process name')
        kwargs = dict(memory_scan=not options.no_memory_scan, yara_paths=options.memory_yara,
                      dump_suspicious=options.dump_suspicious, headless=options.headless,
                      duration=options.duration, output_dir=options.output_dir,
                      tracer=options.tracer, interval=options.interval)
        if options.target:
            arg_pid = _resolve_target_pid(options.target, wait_for_name=False)
            if arg_pid is None:
                print(f"{errorS} PID/Process not found or is not accessible.")
                sys.exit(1)
            print(f"\n{infoS} Monitoring PID: [bold green]{arg_pid}[white]. ([bold blink yellow]Ctrl+C to stop![white])")
            main_app(arg_pid, **kwargs)
        else:
            linux_dynamic_menu(**kwargs)
    except KeyboardInterrupt:
        print(f"\n{infoS} Program terminated by user.")
        sys.exit(0)
    except Exception as exc:
        print(f"{errorS} Program terminated: {exc}")
        sys.exit(1)
