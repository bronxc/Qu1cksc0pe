import ctypes
import json
import os
from ctypes import wintypes, byref

# Windows API constants
PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ = 0x0010

# Explicit pointer-sized prototypes are essential on 64-bit Windows. Keep a
# private WinDLL instance so importing another module cannot change our ABI.
kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
kernel32.OpenProcess.restype = wintypes.HANDLE
kernel32.ReadProcessMemory.argtypes = [wintypes.HANDLE, ctypes.c_void_p,
                                      ctypes.c_void_p, ctypes.c_size_t,
                                      ctypes.POINTER(ctypes.c_size_t)]
kernel32.ReadProcessMemory.restype = wintypes.BOOL
kernel32.VirtualQueryEx.argtypes = [wintypes.HANDLE, ctypes.c_void_p,
                                   ctypes.c_void_p, ctypes.c_size_t]
kernel32.VirtualQueryEx.restype = ctypes.c_size_t
kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
kernel32.CloseHandle.restype = wintypes.BOOL
kernel32.GetProcessTimes.argtypes = [wintypes.HANDLE, ctypes.c_void_p, ctypes.c_void_p,
                                    ctypes.c_void_p, ctypes.c_void_p]
kernel32.GetProcessTimes.restype = wintypes.BOOL

class MEMORY_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("BaseAddress", ctypes.c_void_p),
        ("AllocationBase", ctypes.c_void_p),
        ("AllocationProtect", wintypes.DWORD),
        ("RegionSize", ctypes.c_size_t),
        ("State", wintypes.DWORD),
        ("Protect", wintypes.DWORD),
        ("Type", wintypes.DWORD),
    ]

def filetime_to_unix(ticks):
    # Match psutil's integer epoch subtraction, double conversion, then division.
    # Changing the order loses precision and falsely rejects the same process.
    return float(ticks - 116444736000000000) / 10000000


class WindowsProcessReader:
    def __init__(self, target_pid, output_dir=".", *, expected_birth=None):
        self.target_pid = target_pid
        self.output_dir = output_dir
        self.last_error = None
        self.regions = []
        self.expected_birth = expected_birth

    def get_process_handle(self):
        # Get a handle to the process
        handle = kernel32.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, self.target_pid)
        if handle and self.expected_birth is not None:
            times = [ctypes.c_uint64() for _ in range(4)]
            if (not kernel32.GetProcessTimes(handle, *(byref(t) for t in times))
                    or filetime_to_unix(times[0].value) != self.expected_birth):
                kernel32.CloseHandle(handle)
                self.last_error = 'Process identity changed or creation time is inaccessible'
                return None
        return handle

    def read_memory(self, process_handle, address, size):
        # Read memory from the process
        buffer = ctypes.create_string_buffer(size)
        bytes_read = ctypes.c_size_t(0)
        kernel32.ReadProcessMemory(process_handle, address, buffer, size, byref(bytes_read))
        # ERROR_PARTIAL_COPY can still yield useful bytes; never write padding.
        return buffer.raw[:bytes_read.value] if bytes_read.value else None

    def query_memory(self, process_handle, address):
        # Query memory information of the process
        mbi = MEMORY_BASIC_INFORMATION()
        size = ctypes.sizeof(MEMORY_BASIC_INFORMATION)
        if kernel32.VirtualQueryEx(process_handle, address, byref(mbi), size) == 0:
            return None
        return mbi

    MAX_DUMP_BYTES = 50 * 1024 * 1024  # 50 MB cap — enough for IOC hunting
    READ_CHUNK_BYTES = 1024 * 1024

    def dump_memory(self):
        # Dump readable memory regions directly to file, capped at MAX_DUMP_BYTES
        process_handle = self.get_process_handle()
        if not process_handle:
            self.last_error = self.last_error or f"OpenProcess failed (error {ctypes.get_last_error()})"
            return False
        dump_name = os.path.join(self.output_dir, f"qu1cksc0pe_memory_dump_{self.target_pid}.bin")
        temporary = dump_name + ".tmp"
        self.regions = []
        try:
            address = 0
            written = 0
            with open(temporary, "wb") as dump_file:
                while written < self.MAX_DUMP_BYTES:
                    mbi = self.query_memory(process_handle, ctypes.c_void_p(address))
                    if not mbi:
                        break
                    region_end = int(mbi.BaseAddress or 0) + mbi.RegionSize
                    if region_end <= address:
                        break
                    # Include executable/readable and copy-on-write pages;
                    # exclude PAGE_GUARD and PAGE_NOACCESS without touching them.
                    if (mbi.State == 0x1000 and not mbi.Protect & 0x100
                            and mbi.Protect & 0xff in (0x02, 0x04, 0x08, 0x20, 0x40, 0x80)):
                        cursor = address
                        while cursor < region_end and written < self.MAX_DUMP_BYTES:
                            size = min(self.READ_CHUNK_BYTES, region_end - cursor,
                                       self.MAX_DUMP_BYTES - written)
                            data = self.read_memory(process_handle, ctypes.c_void_p(cursor), size)
                            if data:
                                self.regions.append({"address": cursor, "offset": written,
                                                     "size": len(data), "protect": mbi.Protect})
                                dump_file.write(data)
                                written += len(data)
                                cursor += len(data)
                            else:
                                # A page can become unreadable after the query.
                                cursor += min(4096, size)
                    address = region_end
            if not written:
                self.last_error = "No readable memory captured"
                return False
            os.replace(temporary, dump_name)
            with open(dump_name + ".json", "w", encoding="utf-8") as metadata:
                json.dump({"pid": self.target_pid, "bytes": written,
                           "limit_reached": written >= self.MAX_DUMP_BYTES,
                           "regions": self.regions}, metadata, indent=2)
            return True
        except Exception as exc:
            self.last_error = f"{type(exc).__name__}: {exc}"
            return False
        finally:
            kernel32.CloseHandle(process_handle)
            if os.path.exists(temporary):
                os.remove(temporary)
