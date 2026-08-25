"""Shared, in-memory-only state for one emulation run.

Nothing here ever touches the real filesystem, network, or registry --
that is the whole point of "fake API" emulation. Fake COM objects read and
write this state so a later ``FileExists`` call sees a file the script
wrote earlier, without any of it becoming a real side effect on the host
running the analysis.
"""

import posixpath
import time


class IOCSink:
    _TERMINAL_CATEGORIES = {"emulation_timeout", "emulation_error", "parse_error"}

    def __init__(self):
        self.events = []
        self.max_events = 20000

    def emit(self, category, **fields):
        # A noisy loop can legitimately fill the general IOC budget before
        # the wall-clock guard fires. Never lose the one terminal diagnostic
        # that explains why the run stopped; allowing at most one instance
        # of each terminal category keeps the overage strictly bounded.
        if len(self.events) >= self.max_events:
            if category not in self._TERMINAL_CATEGORIES:
                return
            if any(event.get("category") == category for event in self.events):
                return
        event = {"ts": time.time(), "category": category}
        event.update(fields)
        self.events.append(event)

    def __len__(self):
        return len(self.events)


class VirtualFile:
    __slots__ = ("path", "content", "is_binary", "created_ts")

    def __init__(self, path, content=b"", is_binary=False):
        self.path = path
        self.content = content
        self.is_binary = is_binary
        self.created_ts = time.time()


class Session:
    def __init__(self, config=None):
        self.ioc = IOCSink()
        self.config = config or {}
        self.vfs = {}
        self.registry = {}
        # Minimal Excel host state used by the fake Range/Cells object
        # model.  Keys are normalized ``<sheet>!<address>`` strings and
        # values are ordinary VBA values.  Keeping this on Session (rather
        # than on a transient Range object) means a later
        # ``Range("A1").Value`` read observes an earlier write to the same
        # cell, while remaining entirely in-memory like the VFS/registry.
        self.excel_cells = {}
        self.excel_sheet_names = []
        self.excel_active_sheet = "ActiveSheet"
        self.env_vars = {
            "TEMP": "C:\\Users\\User\\AppData\\Local\\Temp",
            "TMP": "C:\\Users\\User\\AppData\\Local\\Temp",
            "APPDATA": "C:\\Users\\User\\AppData\\Roaming",
            "LOCALAPPDATA": "C:\\Users\\User\\AppData\\Local",
            "PROGRAMDATA": "C:\\ProgramData",
            "USERPROFILE": "C:\\Users\\User",
            "WINDIR": "C:\\Windows",
            "COMPUTERNAME": "DESKTOP-SANDBOX",
            "USERNAME": "User",
        }
        self.output_log = []
        self.process_log = []
        self.err_number = 0
        self.err_description = ""
        # VBA's legacy Open/Put/Get/Close file I/O: filenum -> {"path",
        # "buffer": bytearray, "position": int}.
        self.file_handles = {}
        self._next_freefile = 1
        self.started_ts = time.time()
        self.step_count = 0
        # Wall-clock (max_seconds, caller-controlled) is the real,
        # meaningful resource boundary -- checked every tick (cheap), so it
        # reliably bounds real time regardless of step count. The step cap
        # is just a backstop against a truly runaway Python-level bug, not
        # something legitimate-but-heavy scripts should hit: a real sample
        # ran a custom bytecode-VM loop needing ~13M steps (~65s) to reach
        # its own Exit Do, and a previous 2M-step cap cut that off after
        # ~10s -- long before its time budget was actually used.
        self.max_steps = self.config.get("max_steps", 500_000_000)
        self.max_seconds = self.config.get("max_seconds", 20)

    def load_excel_cells(self, workbook_cells):
        """Load extractor output into normalized, case-insensitive state."""
        if not isinstance(workbook_cells, dict):
            return
        for sheet_name, cells in workbook_cells.items():
            if not isinstance(cells, dict):
                continue
            real_name = str(sheet_name)
            self.excel_sheet_names.append(real_name)
            for address, value in cells.items():
                key = f"{real_name.lower()}!{str(address).replace('$', '').lower()}"
                self.excel_cells[key] = value
        if self.excel_sheet_names:
            self.excel_active_sheet = self.excel_sheet_names[0]

    @staticmethod
    def norm_path(path):
        p = path.replace("\\", "/").strip()
        return posixpath.normpath(p).lower() if p else p

    def vfs_write(self, path, content, is_binary=False):
        self.vfs[self.norm_path(path)] = VirtualFile(path, content, is_binary)

    def vfs_read(self, path):
        f = self.vfs.get(self.norm_path(path))
        return f.content if f else None

    def vfs_exists(self, path):
        return self.norm_path(path) in self.vfs

    def vfs_delete(self, path):
        self.vfs.pop(self.norm_path(path), None)

    def tick(self):
        self.step_count += 1
        if self.step_count > self.max_steps:
            raise TimeoutError("Emulation step budget exceeded")
        # Checked every step, not just periodically: a single expensive
        # statement (e.g. exponential string-doubling via `s = s & s` in a
        # short loop) can blow the time budget in far fewer steps than any
        # periodic check would catch, and time.time() is cheap enough to
        # call every tick.
        if (time.time() - self.started_ts) > self.max_seconds:
            raise TimeoutError("Emulation wall-clock budget exceeded")
