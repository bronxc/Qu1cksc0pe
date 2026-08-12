#!/usr/bin/python3

# module checking
try:
    import os
    import sys
    import subprocess
    import argparse
    import getpass
    import configparser
    import shutil
    import warnings
except Exception as e:
    print(f"Missing modules detected!: {e}")
    sys.exit(1)

# Check python version
if sys.version_info[0] == 2:
    print(f"{errorS} Looks like you are using Python 2. But we need Python 3!")
    sys.exit(1)

# When invoked via `sudo`, root's Python env lacks the original user's pip packages.
# Add that user's site-packages so all dependencies remain accessible.
_sudo_user = os.environ.get("SUDO_USER")
if _sudo_user and os.getuid() == 0:
    _pyver     = f"python{sys.version_info.major}.{sys.version_info.minor}"
    _user_home = os.path.expanduser(f"~{_sudo_user}")
    _user_site = os.path.join(_user_home, ".local", "lib", _pyver, "site-packages")
    if os.path.isdir(_user_site) and _user_site not in sys.path:
        sys.path.insert(0, _user_site)
    del _user_home, _user_site, _pyver
del _sudo_user

# Testing rich existence
try:
    from rich import print
except ModuleNotFoundError:
    print("Error: >rich< module not found. Run: pip3 install -r requirements.txt")
    sys.exit(1)

# Testing puremagic existence
try:
    import puremagic as pr
except ModuleNotFoundError:
    print("Error: >puremagic< module not found. Run: pip3 install -r requirements.txt")
    sys.exit(1)

try:
    from colorama import Fore, Style
except ModuleNotFoundError:
    print("Error: >colorama< module not found. Run: pip3 install -r requirements.txt")
    sys.exit(1)

# Colors
red = Fore.LIGHTRED_EX
cyan = Fore.LIGHTCYAN_EX
white = Style.RESET_ALL
green = Fore.LIGHTGREEN_EX

# Legends
infoC = f"{cyan}[{red}*{cyan}]{white}"
infoS = f"[bold cyan][[bold red]*[bold cyan]][white]"
foundS = f"[bold cyan][[bold red]+[bold cyan]][white]"
errorS = f"[bold cyan][[bold red]![bold cyan]][white]"

# Gathering username
username = getpass.getuser()

# Always use the same interpreter that is running this script so that
# all subprocesses inherit the active virtual environment.
py_binary = sys.executable

# Make Qu1cksc0pe work on Windows, Linux, OSX
homeD = os.path.expanduser("~")
path_seperator = "/"
if sys.platform == "win32":
    path_seperator = "\\"

# Path handler file: written to the user's home directory so it is
# always writable regardless of the current working directory.
_PH_FILE = os.path.join(os.path.expanduser("~"), ".qu1cksc0pe_path")

# Is Qu1cksc0pe installed??
if os.name != "nt":
    if os.path.exists("/usr/bin/qu1cksc0pe") == True and os.path.exists(f"/etc/qu1cksc0pe.conf") == True:
        # Parsing new path and write into handler
        sc0peConf = configparser.ConfigParser()
        sc0peConf.read(f"/etc/qu1cksc0pe.conf", encoding="utf-8-sig")
        sc0pe_path = str(sc0peConf["Qu1cksc0pe_PATH"]["sc0pe"])
        sys.path.append(sc0pe_path)
        with open(_PH_FILE, "w") as _ph:
            _ph.write(sc0pe_path)
    else:
        # Parsing current path and write into handler
        sc0pe_path = str(os.getcwd())
        with open(_PH_FILE, "w") as _ph:
            _ph.write(sc0pe_path)
else:
    sc0pe_path = str(os.getcwd())
    with open(_PH_FILE, "w") as _ph:
        _ph.write(sc0pe_path)

# Utility functions
from Modules.utils.helpers import err_exit

MODULE_PREFIX = f"{sc0pe_path}{path_seperator}Modules{path_seperator}"
def execute_module(target, path=MODULE_PREFIX, invoker=py_binary):
    if "python" in invoker or ".py" in target:
        # TODO in the future, raise a ValueError/OSError (and remove the additional code below)
        # instead of warning with a PendingDeprecationWarning
        DEV_NOTE = "[DEV NOTE]: when switching to import statements, remember to adjust any downstream imports! (e.g. `from .utils import err_exit` vs `from utils import err_exit`)"
        warnings.warn("Direct execution of Python files won't be supported much longer." + f" {DEV_NOTE}", PendingDeprecationWarning)
    parts  = target.split(" ", 1)
    script = parts[0]
    extra  = f" {parts[1]}" if len(parts) > 1 else ""
    inner_command = f'"{invoker}" "{path}{script}"{extra}'
    if sys.platform == "win32":
        # cmd.exe's `/c` only preserves quoting cleanly when the command string
        # contains exactly two quote characters; with more (invoker path quoted
        # *and* script path quoted, as below) it falls back to stripping just the
        # first and last quote, mangling everything in between. Wrapping the
        # whole command in one more outer quote pair is the standard workaround.
        # POSIX shells don't share this quirk -- an extra outer quote pair there
        # flips the quote-toggle parity for every char after it, turning the
        # separator spaces between args into literal quoted spaces and merging
        # the whole command into a single unresolvable word.
        os.system(f'"{inner_command}"')
    else:
        os.system(inner_command)

# Only the *stdio* MCP transport talks JSON-RPC over this process's own
# stdout, so only that mode requires suppressing the startup banner. Other
# transports (streamable-http, the default; sse) bind a port instead and
# never touch stdout as a protocol channel, so the banner is safe there.
# Mirrors Modules/mcp_server.py's own SC0PE_MCP_TRANSPORT default.
_mcp_requested = "--mcp" in sys.argv
_mcp_transport = os.environ.get("SC0PE_MCP_TRANSPORT", "streamable-http").strip().lower()
if not (_mcp_requested and _mcp_transport == "stdio"):
    import Modules.banners # show a banner
del _mcp_requested, _mcp_transport

# API keys manageable via --key_init (interactive menu) or --key_init
# --key_provider <id> (non-interactive, scriptable). Shared by the
# smart_analyzer.py cloud AI backends via matching filenames.
API_KEY_PROVIDERS = {
    "virustotal": {"label": "VirusTotal", "filename": "sc0pe_VT_apikey.txt"},
    "claude": {"label": "Claude (Anthropic)", "filename": "sc0pe_claude_apikey.txt"},
    "openai": {"label": "OpenAI", "filename": "sc0pe_openai_apikey.txt"},
    "deepseek": {"label": "DeepSeek", "filename": "sc0pe_deepseek_apikey.txt"},
    "kimi": {"label": "Kimi (Moonshot AI)", "filename": "sc0pe_kimi_apikey.txt"},
    "glm": {"label": "GLM (Zhipu AI)", "filename": "sc0pe_glm_apikey.txt"},
}

# Argument crating, parsing and handling
ARG_NAMES_TO_KWARG_OPTS = {
    "file": {"help": "Specify a file to scan or analyze."},
    "folder": {"help": "Specify a folder to scan or analyze."},
    "analyze": {"help": "Analyze target file.", "action": "store_true"},
    "archive": {"help": "Analyze archive files.", "action": "store_true"},
    "db_update": {"help": "Update malware hash database.", "action": "store_true"},
    "docs": {"help": "Analyze document files.", "action": "store_true"},
    "domain": {"help": "Extract URLs and IP addresses from file.", "action": "store_true"},
    "hashscan": {"help": "Scan target file's hash in local database.", "action": "store_true"},
    "install": {"help": "Install or Uninstall Qu1cksc0pe.", "action": "store_true"},
    "key_init": {"help": "Manage API keys (VirusTotal + AI providers). Shows an interactive menu; combine with --key_provider to skip it.", "action": "store_true"},
    "key_provider": {"help": "With --key_init, set this specific provider's key non-interactively (skips the menu).", "choices": list(API_KEY_PROVIDERS.keys()), "default": None},
    "lang": {"help": "Detect programming language.", "action": "store_true"},
    "packer": {"help": "Check if your file is packed with common packers.", "action": "store_true"},
    "resource": {"help": "Analyze resources in target file", "action": "store_true"},
    "report": {"help": "Export analysis reports into a file (JSON Format for now).", "action": "store_true"},
    "ai": {"help": "Analyze generated report using smart analyzer (requires --report; enabled automatically).", "action": "store_true"},
    "ai_provider": {"help": "AI backend for --ai: auto (Ollama, default, local/private), ollama, claude, openai, deepseek, kimi, or glm.", "choices": ["auto", "ollama", "claude", "openai", "deepseek", "kimi", "glm"], "default": None},
    "watch": {"help": "Perform dynamic analysis against Windows/Android files. (Linux will coming soon!!)", "action": "store_true"},
    "sigcheck": {"help": "Scan file signatures in target file.", "action": "store_true"},
    "vtFile": {"help": "Scan your file with VirusTotal API.", "action": "store_true"},
    "ui": {"help": "Launch Flask-based web interface.", "action": "store_true"},
    "mcp": {"help": "Launch MCP (Model Context Protocol) server for AI assistant integration.", "action": "store_true"}
}

parser = argparse.ArgumentParser()
for arg_name, cfg in ARG_NAMES_TO_KWARG_OPTS.items():
    cfg["required"] = cfg.get("required", False)
    parser.add_argument("--" + arg_name, **cfg)
args = parser.parse_args()

# If user requests AI analysis, we must have a report to analyze.
if getattr(args, "ai", False) and not getattr(args, "report", False):
    args.report = True

# Explicit --ai_provider overrides whatever SC0PE_AI_PROVIDER may already be
# set to; leave the environment untouched otherwise so a pre-set env var
# (e.g. for scripted/CI use) keeps working without passing the flag.
if getattr(args, "ai_provider", None):
    os.environ["SC0PE_AI_PROVIDER"] = args.ai_provider

def _latest_report_path():
    try:
        candidates = [f for f in os.listdir(".") if f.startswith("sc0pe_") and f.endswith("_report.json")]
    except Exception:
        return None
    if not candidates:
        return None
    candidates = [os.path.abspath(c) for c in candidates if os.path.exists(c)]
    if not candidates:
        return None
    return max(candidates, key=lambda p: os.path.getmtime(p))

def _maybe_run_ai(fast_mode=False):
    if not getattr(args, "ai", False):
        return
    report_path = _latest_report_path()
    if not report_path:
        print(f"{errorS} AI analysis requested but no report file found (expected sc0pe_*_report.json).")
        return
    if not fast_mode:
        execute_module(f"analysis/multiple/smart_analyzer.py \"{report_path}\"")
        return

    smart_analyzer_path = os.path.join(sc0pe_path, "Modules", "analysis", "multiple", "smart_analyzer.py")
    env = os.environ.copy()
    env.setdefault("SC0PE_AI_TOTAL_BUDGET", "45")
    env.setdefault("SC0PE_AI_OLLAMA_HTTP_TIMEOUT", "25")
    env.setdefault("SC0PE_AI_HTTP_PROBE_TIMEOUT", "8")
    env.setdefault("SC0PE_AI_OLLAMA_CLI_TIMEOUT", "35")
    env.setdefault("SC0PE_AI_OLLAMA_NUM_PREDICT", "280")
    env.setdefault("SC0PE_AI_OLLAMA_RETRY_NUM_PREDICT", "560")
    env.setdefault("SC0PE_AI_MAX_MODEL_CANDIDATES", "4")
    env.setdefault("SC0PE_AI_MAX_REPORT_CHARS", "65000")
    env.setdefault("SC0PE_AI_COMPACT_MAX_LIST_ITEMS", "24")
    env.setdefault("SC0PE_AI_TEMP_PARSE_MAX_LINES", "2500")
    env.setdefault("SC0PE_AI_TEMP_SAMPLE_LINES", "600")
    try:
        subprocess.run([sys.executable, smart_analyzer_path, report_path], env=env, check=False)
    except Exception:
        execute_module(f"analysis/multiple/smart_analyzer.py \"{report_path}\"")

def launch_web_ui():
    web_app_path = os.path.join(sc0pe_path, "Modules", "web_app.py")
    if not os.path.exists(web_app_path):
        err_exit(f"{errorS} UI entrypoint not found: {web_app_path}")
    print(f"{infoS} Launching [bold green]Qu1cksc0pe Web UI[white]...")
    try:
        ui_proc = subprocess.run([sys.executable, web_app_path], check=False)
    except KeyboardInterrupt:
        print("\n[bold white on red]Web UI terminated by user.\n")
        return
    if ui_proc.returncode != 0:
        err_exit(
            f"{errorS} Failed to launch Web UI. Make sure dependencies are installed "
            f"(e.g. [bold green]pip install -r requirements.txt[white]).",
            arg_override=ui_proc.returncode,
        )

def _save_api_key(prompt_label, filename):
    # Deliberately no try/except KeyboardInterrupt here: this is called both
    # standalone (--key_init --key_provider, where main()'s top-level handler
    # should catch Ctrl+C) and in a loop from _key_init_menu() (where that
    # loop's own handler should catch it so the menu actually exits instead
    # of silently swallowing the interrupt and looping back).
    apikey = str(input(f"{infoC} Enter your {prompt_label} API key: ")).strip()
    if not apikey:
        print(f"{errorS} No key entered; {prompt_label} API key was not saved.")
        return

    if not os.path.exists(f"{homeD}{path_seperator}sc0pe_Base"):
        os.system(f"mkdir {homeD}{path_seperator}sc0pe_Base")

    apifile = open(f"{homeD}{path_seperator}sc0pe_Base{path_seperator}{filename}", "w")
    apifile.write(apikey)
    print(f"{foundS} Your {prompt_label} API key saved.")

def _key_init_menu():
    items = list(API_KEY_PROVIDERS.items())
    try:
        while True:
            print("\n[bold cyan]>>> Qu1cksc0pe API Key Manager[white]")
            for idx, (_provider_id, meta) in enumerate(items, start=1):
                print(f"  [bold green]{idx}[white]) {meta['label']}")
            print("  [bold green]0[white]) Exit")
            choice = str(input(f"\n{infoC} Select an option: ")).strip()
            if choice in ("", "0"):
                break
            try:
                idx = int(choice)
                if idx < 1 or idx > len(items):
                    raise ValueError
                selected = items[idx - 1]
            except ValueError:
                print(f"{errorS} Invalid selection.")
                continue
            _provider_id, meta = selected
            _save_api_key(meta["label"], meta["filename"])
    except KeyboardInterrupt:
        print("\n[bold white on red]Program terminated by user.\n")

def launch_mcp_server():
    mcp_server_path = os.path.join(sc0pe_path, "Modules", "mcp_server.py")
    if not os.path.exists(mcp_server_path):
        err_exit(f"{errorS} MCP server entrypoint not found: {mcp_server_path}")
    # Once launched, the child owns stdout/stdin as the MCP JSON-RPC channel,
    # so nothing may be written to stdout from here on -- log to stderr instead.
    print(f"{infoS} Launching [bold green]Qu1cksc0pe MCP Server[white]...", file=sys.stderr)
    try:
        mcp_proc = subprocess.run([sys.executable, mcp_server_path], check=False)
    except KeyboardInterrupt:
        return
    if mcp_proc.returncode != 0:
        err_exit(
            f"{errorS} Failed to launch MCP server. Make sure dependencies are installed "
            f"(e.g. [bold green]pip install -r requirements.txt[white]).",
            arg_override=mcp_proc.returncode,
        )

# Basic analyzer function that handles single and multiple scans
def BasicAnalyzer(analyzeFile):
    print(f"{infoS} Analyzing: [bold green]{analyzeFile}[white]")
    fileType = str(pr.magic_file(analyzeFile))
    lower_ext = os.path.splitext(analyzeFile)[1].lower()
    # Windows Analysis
    if "Windows Executable" in fileType or ".msi" in fileType or ".dll" in fileType or ".exe" in fileType:
        print(f"{infoS} Target OS: [bold green]Windows[white]\n")
        if args.report:
            execute_module(f"windows_static_analyzer.py \"{analyzeFile}\" True True")
        else:
            execute_module(f"windows_static_analyzer.py \"{analyzeFile}\" False True")
        _maybe_run_ai()

    # Linux Analysis
    elif "ELF" in fileType:
        print(f"{infoS} Target OS: [bold green]Linux[white]\n")
        import Modules.linux_static_analyzer as lina
        lina.run(sc0pe_path, analyzeFile, emit_report=args.report)
        _maybe_run_ai()

    # MacOSX Analysis
    elif "Mach-O" in fileType or '\\xca\\xfe\\xba\\xbe' in fileType:
        print(f"{infoS} Target OS: [bold green]OSX[white]\n")
        if args.report:
            execute_module(f"apple_analyzer.py \"{analyzeFile}\" True")
        else:
            execute_module(f"apple_analyzer.py \"{analyzeFile}\" False")
        _maybe_run_ai()

    # Android Analysis
    elif ("PK" in fileType and "Java archive" in fileType) or "Dalvik (Android) executable" in fileType or lower_ext in (".apk", ".dex", ".jar"):
        print(f"{infoS} Target OS: [bold green]Android[white]")

        # Extension parsing
        file_name_trim = os.path.splitext(analyzeFile)

        # If given file is a JAR file then run JAR file analysis
        if file_name_trim[-1] == ".jar": # Extension based detection
            if args.report:
                execute_module(f"apkAnalyzer.py \"{analyzeFile}\" True JAR")
            else:
                execute_module(f"apkAnalyzer.py \"{analyzeFile}\" False JAR")
            _maybe_run_ai()
        elif "Dalvik (Android) executable" in fileType:
            if args.report:
                execute_module(f"apkAnalyzer.py \"{analyzeFile}\" True DEX")
            else:
                execute_module(f"apkAnalyzer.py \"{analyzeFile}\" False DEX")
            _maybe_run_ai()
        else:
            if args.report:
                execute_module(f"apkAnalyzer.py \"{analyzeFile}\" True APK")
            else:
                execute_module(f"apkAnalyzer.py \"{analyzeFile}\" False APK")
            _maybe_run_ai()
            if not args.report:
                # APP Security
                choice = str(input(f"\n{infoC} Do you want to check target app\'s security? This process will take a while.[Y/n]: "))
                if choice == "Y" or choice == "y":
                    execute_module(f"apkSecCheck.py")

    # Pcap analysis
    elif "pcap" in fileType or "capture file" in fileType or lower_ext in (".pcap", ".pcapng"):
        print(f"{infoS} Performing [bold green]PCAP[white] analysis...\n")
        if args.report:
            execute_module(f"pcap_analyzer.py \"{analyzeFile}\" True")
        else:
            execute_module(f"pcap_analyzer.py \"{analyzeFile}\" False")
        _maybe_run_ai()

    # Powershell analysis
    elif ".ps1" in analyzeFile:
        print(f"{infoS} Performing [bold green]Powershell Script[white] analysis...\n")
        if args.report:
            execute_module(f"powershell_analyzer.py \"{analyzeFile}\" True")
        else:
            execute_module(f"powershell_analyzer.py \"{analyzeFile}\" False")
        _maybe_run_ai()

    # VBScript/VBA family analysis
    elif lower_ext in (".vbs", ".vbe", ".vba", ".vb", ".bas", ".cls", ".frm"):
        print(f"{infoS} Performing [bold green]VBScript/VBA[white] analysis...\n")
        if args.report:
            execute_module(f"document_analyzer.py \"{analyzeFile}\" True")
        else:
            execute_module(f"document_analyzer.py \"{analyzeFile}\" False")
        _maybe_run_ai()

    # HTML analysis
    elif lower_ext in (".html", ".htm"):
        print(f"{infoS} Performing [bold green]HTML[white] analysis...\n")
        if args.report:
            execute_module(f"html_script_analyzer.py \"{analyzeFile}\" True")
        else:
            execute_module(f"html_script_analyzer.py \"{analyzeFile}\" False")
        _maybe_run_ai()

    # JavaScript analysis
    elif lower_ext == ".js":
        print(f"{infoS} Performing [bold green]JavaScript[white] analysis...\n")
        if args.report:
            execute_module(f"html_script_analyzer.py \"{analyzeFile}\" True")
        else:
            execute_module(f"html_script_analyzer.py \"{analyzeFile}\" False")
        _maybe_run_ai()

    # HTA (HTML Application) analysis
    elif lower_ext == ".hta":
        print(f"{infoS} Performing [bold green]HTA[white] analysis...\n")
        if args.report:
            execute_module(f"html_script_analyzer.py \"{analyzeFile}\" True")
        else:
            execute_module(f"html_script_analyzer.py \"{analyzeFile}\" False")
        _maybe_run_ai()

    # Windows Batch Script analysis
    elif lower_ext in (".bat", ".cmd"):
        print(f"{infoS} Performing [bold green]Batch Script[white] analysis...\n")
        if args.report:
            execute_module(f"batch_analyzer.py \"{analyzeFile}\" True")
        else:
            execute_module(f"batch_analyzer.py \"{analyzeFile}\" False")
        _maybe_run_ai()

    # Windows Shortcut (LNK) analysis
    elif lower_ext == ".lnk":
        print(f"{infoS} Performing [bold green]Windows Shortcut (LNK)[white] analysis...\n")
        if args.report:
            execute_module(f"lnk_analyzer.py \"{analyzeFile}\" True")
        else:
            execute_module(f"lnk_analyzer.py \"{analyzeFile}\" False")
        _maybe_run_ai()

    # Email file analysis
    elif "email message" in fileType or "message/rfc822" in fileType:
        print(f"{infoS} Performing [bold green]Email File[white] analysis...\n")
        if args.report:
            execute_module(f"email_analyzer.py \"{analyzeFile}\" True")
        else:
            execute_module(f"email_analyzer.py \"{analyzeFile}\" False")
        _maybe_run_ai()
    else:
        err_exit("\n[bold white on red]File type not supported. Make sure you are analyze executable files or document files.\n[bold]>>> If you want to scan document files try [bold green][i]--docs[/i] [white]argument.")

# Main function
def Qu1cksc0pe():
    # Launch Flask web UI and exit.
    if args.ui:
        launch_web_ui()
        return

    # Launch MCP server and exit.
    if args.mcp:
        launch_mcp_server()
        return


    # Getting all strings from the file if the target file exists.
    if args.file:
        if os.path.exists(args.file):
            # Before doing something we need to check file size
            file_size = os.path.getsize(args.file)
            if file_size < 52428800: # If given file smaller than 100MB
                if not shutil.which("strings"):
                    err_exit("[bold white on red][blink]strings[/blink] command not found. You need to install it.")
            else:
                print(f"{infoS} Whoa!! Looks like we have a large file here.")
                if args.analyze:
                    choice = str(input(f"\n{infoC} Do you want to analyze this file anyway [y/N]?: "))
                    if choice == "Y" or choice == "y":
                        BasicAnalyzer(analyzeFile=args.file)
                        sys.exit(0)

                if args.archive:
                    # Because why not!
                    print(f"{infoS} Analyzing: [bold green]{args.file}[white]")
                    if args.report:
                        execute_module(f"archiveAnalyzer.py \"{args.file}\" True")
                    else:
                        execute_module(f"archiveAnalyzer.py \"{args.file}\" False")
                    _maybe_run_ai(fast_mode=True)
                    sys.exit(0)

                # Check for embedded executables by default!
                if not args.sigcheck:
                    print(f"{infoS} Executing [bold green]SignatureAnalyzer[white] module...")
                    execute_module(f"sigChecker.py \"{args.file}\"")
                    sys.exit(0)
        else:
            err_exit("[bold white on red]Target file not found!\n")

    # Analyze the target file
    if args.analyze:
        # Handling --file argument
        if args.file is not None:
            BasicAnalyzer(analyzeFile=args.file)
        # Handling --folder argument
        if args.folder is not None:
            err_exit("[bold white on red][blink]--analyze[/blink] argument is not supported for folder analyzing!\n")

    # Analyze archive files
    if args.archive:
        # Handling --file argument
        if args.file is not None:
            print(f"{infoS} Analyzing: [bold green]{args.file}[white]")
            if args.report:
                execute_module(f"archiveAnalyzer.py \"{args.file}\" True")
            else:
                execute_module(f"archiveAnalyzer.py \"{args.file}\" False")
            _maybe_run_ai(fast_mode=True)
        # Handling --folder argument
        if args.folder is not None:
            err_exit("[bold white on red][blink]--docs[/blink] argument is not supported for folder analyzing!\n")

    # Analyze document files
    if args.docs:
        # Handling --file argument
        if args.file is not None:
            print(f"{infoS} Analyzing: [bold green]{args.file}[white]")
            if args.report:
                execute_module(f"document_analyzer.py \"{args.file}\" True")
            else:
                execute_module(f"document_analyzer.py \"{args.file}\" False")
            _maybe_run_ai()
        # Handling --folder argument
        if args.folder is not None:
            err_exit("[bold white on red][blink]--docs[/blink] argument is not supported for folder analyzing!\n")

    # Hash Scanning
    if args.hashscan:
        # Handling --file argument
        if args.file is not None:
            execute_module(f"hashScanner.py \"{args.file}\" --normal")
        # Handling --folder argument
        if args.folder is not None:
            execute_module(f"hashScanner.py {args.folder} --multiscan")

    # File signature scanner
    if args.sigcheck:
        # Handling --file argument
        if args.file is not None:
            execute_module(f"sigChecker.py \"{args.file}\"")
        # Handling --folder argument
        if args.folder is not None:
            err_exit("[bold white on red][blink]--sigcheck[/blink] argument is not supported for folder analyzing!\n")

    # Resource analyzer
    if args.resource:
        # Handling --file argument
        if args.file is not None:
            execute_module(f"resourceChecker.py \"{args.file}\"")
        # Handling --folder argument
        if args.folder is not None:
            err_exit("[bold white on red][blink]--resource[/blink] argument is not supported for folder analyzing!\n")

    # Language detection
    if args.lang:
        # Handling --file argument
        if args.file is not None:
            if args.report:
                execute_module(f"languageDetect.py \"{args.file}\" True {str(bool(args.ai))}")
            else:
                execute_module(f"languageDetect.py \"{args.file}\" False {str(bool(args.ai))}")
        # Handling --folder argument
        if args.folder is not None:
            err_exit("[bold white on red][blink]--lang[/blink] argument is not supported for folder analyzing!\n")

    # VT File scanner
    if args.vtFile:
        # Handling --file argument
        if args.file is not None:
            # if there is no key quit
            try:
                directory = f"{homeD}{path_seperator}sc0pe_Base{path_seperator}sc0pe_VT_apikey.txt"
                apik = open(directory, "r").read().split("\n")
            except:
                err_exit("[bold white on red]Use [blink]--key_init[/blink] to enter your key!\n")
            # if key is not valid quit
            if apik[0] == '' or apik[0] is None or len(apik[0]) != 64:
                err_exit("[bold]Please get your API key from -> [bold green][a]https://www.virustotal.com/[/a]\n")
            else:
                execute_module(f"VTwrapper.py {apik[0]} \"{args.file}\"")
        # Handling --folder argument
        if args.folder is not None:
            err_exit("[bold white on red]If you want to get banned from VirusTotal then do that :).\n")

    # packer detection
    if args.packer:
        # Handling --file argument
        if args.file is not None:
            if args.report:
                execute_module(f"packerAnalyzer.py --single \"{args.file}\" True {str(bool(args.ai))}")
            else:
                execute_module(f"packerAnalyzer.py --single \"{args.file}\" False {str(bool(args.ai))}")
        # Handling --folder argument
        if args.folder is not None:
            if args.report:
                execute_module(f"packerAnalyzer.py --multiscan {args.folder} True {str(bool(args.ai))}")
            else:
                execute_module(f"packerAnalyzer.py --multiscan {args.folder} False {str(bool(args.ai))}")

    # domain extraction
    if args.domain:
        # Handling --file argument
        if args.file is not None:
            if args.report:
                execute_module(f"domainCatcher.py \"{args.file}\" True")
            else:
                execute_module(f"domainCatcher.py \"{args.file}\" False")
        # Handling --folder argument
        if args.folder is not None:
            err_exit("[bold white on red][blink]--domain[/blink] argument is not supported for folder analyzing!\n")

    # Dynamic analysis
    if args.watch:
        execute_module(f"emulator.py")

    # Database update
    if args.db_update:
        execute_module(f"hashScanner.py --db_update")

    # Managing VirusTotal / AI provider API keys
    if args.key_init:
        if args.key_provider:
            meta = API_KEY_PROVIDERS[args.key_provider]
            _save_api_key(meta["label"], meta["filename"])
        else:
            _key_init_menu()

    # Install Qu1cksc0pe on your system!!
    if args.install:
        if sys.platform == "win32":
            err_exit(f"{errorS} This feature is not suitable for Windows systems for now!")

        execute_module(f'installer.sh "{sc0pe_path}" "{username}"', invoker="sudo bash")

def cleanup_junks():
    junkFiles = ["temp.txt", ".target-file.txt", ".target-folder.txt", "TargetAPK/", "TargetSource/"]
    for junk in junkFiles:
        if os.path.exists(junk):
            try: # assume simple file
                os.unlink(junk)
            except OSError: # try this for directories
                shutil.rmtree(junk)

def main():
    try:
        Qu1cksc0pe()
    except KeyboardInterrupt:
        print("\n[bold white on red]Program terminated by user.\n")
    finally: # ensure cleanup irrespective of errors
        cleanup_junks()


# This is the entrypoint when directly running
# this module as a standalone program
# (as opposed to it being imported/ran like a lib)
if __name__ == "__main__":
    main()
