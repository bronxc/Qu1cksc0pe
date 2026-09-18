#!/usr/bin/python3

import os
import sys
import shutil
import subprocess

from utils.helpers import err_exit, run_interactive_monitor

try:
    from rich import print
except:
    err_exit("Error: >rich< module not found.")

try:
    from prompt_toolkit import prompt
    from prompt_toolkit.completion import PathCompleter
    path_completer = PathCompleter()
except:
    err_exit("Error: >prompt_toolkit< module not found.")

try:
    from colorama import Fore, Style
except:
    err_exit("Error: >colorama< module not found.")

# Colors
red = Fore.LIGHTRED_EX
cyan = Fore.LIGHTCYAN_EX
white = Style.RESET_ALL

# Legends
errorS = f"[bold cyan][[bold red]![bold cyan]][white]"
infoS = f"[bold cyan][[bold red]*[bold cyan]][white]"
infoC = f"{cyan}[{red}*{cyan}]{white}"

# Use the same interpreter that launched this script so subprocesses
# inherit the active virtual environment.
py_binary = sys.executable

# Compatibility
path_seperator = "/"
if sys.platform == "win32":
    path_seperator = "\\"

# Gathering Qu1cksc0pe path variable
sc0pe_path = open(os.path.join(os.path.expanduser("~"), ".qu1cksc0pe_path"), "r").read().strip()

class DynamicAnalyzer:
    def __init__(self):
        pass

    def dynamic_analysis_main(self):
        # This area is for linux environment
        if sys.platform != "win32":
            print(f"\n{infoS} Dynamic Analysis Options")
            print(f"[bold cyan][[bold red]1[bold cyan]][white] Android")
            print(f"[bold cyan][[bold red]2[bold cyan]][white] Linux")
            tos = int(input("\n>>> Select: "))
            if tos == 1:
                print(f"\n{infoS} Target OS: [bold green]Android")
                run_interactive_monitor([py_binary, os.path.join(sc0pe_path, "Modules", "android_dynamic_analyzer.py")])
            elif tos == 2:
                print(f"\n{infoS} Target OS: [bold green]Linux")
                run_interactive_monitor([py_binary, os.path.join(sc0pe_path, "Modules", "linux_dynamic_analyzer.py")])
            else:
                err_exit(f"{errorS} Wrong option :(")

        # This area is for windows environment
        elif sys.platform == "win32":
            print(f"\n{infoS} Dynamic Analysis Options")
            print(f"[bold cyan][[bold red]1[bold cyan]][white] Android")
            print(f"[bold cyan][[bold red]2[bold cyan]][white] Windows")
            tos = int(input("\n>>> Select: "))
            if tos == 1:
                print(f"\n{infoS} Target OS: [bold green]Android")
                run_interactive_monitor([py_binary, os.path.join(sc0pe_path, "Modules", "android_dynamic_analyzer.py")])
            elif tos == 2:
                print(f"\n{infoS} Target OS: [bold green]Windows")
                run_interactive_monitor([py_binary, os.path.join(sc0pe_path, "Modules", "windows_dynamic_analyzer.py")])
            else:
                err_exit(f"{errorS} Wrong option :(")
        else:
            err_exit(f"{errorS} This platform is not suitable for dynamic analysis feature!!")

# Execute
emulator = DynamicAnalyzer()
try:
    print(f"{infoS} Performing Dynamic Analysis...")
    emulator.dynamic_analysis_main()
except KeyboardInterrupt:
    err_exit(f"{errorS} Keyboard interrupt detected...")
