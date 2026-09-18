"""Bounded parsing of strace/ltrace output, including interleaved returns."""
from collections import OrderedDict
import ast
import re
import time

# Categories avoid architecture-specific aliases such as send/recv on x86-64.
STRACE_FILTER = "%file,%network,%process,%memory,read,write,ptrace,prctl,process_vm_readv,process_vm_writev,memfd_create"
LTRACE_FILTER = "fopen+fopen64+freopen+opendir+system+popen+dlopen+getenv+setenv+putenv+gethostbyname+getaddrinfo+remove+execvp+execlp"
_PREFIX = re.compile(r"^(?:\[pid\s+(\d+)\]\s*|(\d+)\s+(?=\d+\.\d+|[A-Za-z_<+*-]))?")
_TIME = re.compile(r"^(\d{9,}\.\d+)\s+")
_CALL = re.compile(r"^(?:[\w.]+->)?([\w.]+)(?:@[\w.+-]+)?\((.*)$")
_RETURN = re.compile(r"^(.*)\)\s+=\s+(.*?)(?:\s+<(\d+\.\d+)>)?$")
_RESUME = re.compile(r"^<\.\.\. ([\w.]+) resumed>(.*)$")
_STRING = re.compile(r'"(?:\\.|[^"\\])*"')


def quoted_strings(arguments):
    result = []
    for match in _STRING.finditer(arguments):
        try:
            value = ast.literal_eval(match.group())
        except (ValueError, SyntaxError):
            value = match.group()[1:-1]
        result.append(value)
    return result


class TraceParser:
    MAX_LINE = 16384

    def __init__(self, root_pid, tool="strace"):
        self.root_pid = int(root_pid)
        self.tool = tool
        self.pending = OrderedDict()
        self.dropped = 0
        self.unmatched_returns = 0

    async def lines(self, reader):
        """Drain oversized lines without exceeding StreamReader's line limit."""
        buffered = bytearray()
        discarded = False
        while True:
            chunk = await reader.read(4096)
            if not chunk:
                break
            parts = chunk.split(b'\n')
            for index, part in enumerate(parts):
                if not discarded:
                    if len(buffered) + len(part) > self.MAX_LINE:
                        self.dropped += 1
                        buffered.clear()
                        discarded = True
                    else:
                        buffered.extend(part)
                if index < len(parts) - 1:
                    if not discarded:
                        yield bytes(buffered)
                    buffered.clear()
                    discarded = False
        if buffered and not discarded:
            yield bytes(buffered)

    def feed(self, line):
        if len(line) > self.MAX_LINE:
            self.dropped += 1
            return None
        line = line.strip()
        prefix = _PREFIX.match(line)
        tid = int(prefix.group(1) or prefix.group(2) or self.root_pid)
        line = line[prefix.end():]
        stamp = _TIME.match(line)
        timestamp = float(stamp.group(1)) if stamp else time.time()
        if stamp:
            line = line[stamp.end():]
        if line.startswith(("+++", "---")):
            if line.startswith("+++"):
                self.pending.pop(tid, None)
            return None
        resumed = _RESUME.match(line)
        incomplete = False
        if resumed:
            saved = self.pending.pop(tid, None)
            if saved and saved[0] == resumed.group(1):
                call, arguments, timestamp = saved
                line = f"{call}({arguments}{resumed.group(2)}"
            else:
                self.unmatched_returns += 1
                incomplete = True
                line = f"{resumed.group(1)}({resumed.group(2)}"
        call_match = _CALL.match(line)
        if not call_match:
            return None
        call, tail = call_match.groups()
        if tail.endswith("<unfinished ...>"):
            if tid in self.pending:
                self.dropped += 1
            self.pending[tid] = (call, tail[:-len("<unfinished ...>")], timestamp)
            if len(self.pending) > 2048:
                self.pending.popitem(last=False)
                self.dropped += 1
            return None
        returned = _RETURN.match(tail)
        if not returned:
            return None
        arguments, result, duration = returned.groups()
        errno = re.match(r"-1\s+([A-Z][A-Z0-9]+)\b", result)
        success = None
        if self.tool == "strace" and not result.startswith("?"):
            success = False if errno else True
        return {"tid": tid, "pid": tid, "time": timestamp, "tool": self.tool,
                "call": call, "arguments": arguments, "return_value": result,
                "success": success, "errno": errno.group(1) if errno else None,
                "duration_seconds": float(duration) if duration else None,
                "arguments_complete": not incomplete,
                "strings": quoted_strings(arguments)}


def behavior_observations(event):
    """Describe observed primitives without claiming malicious intent."""
    if (event["success"] is not True or not event["arguments_complete"]
            or not event.get("identity_verified", True)):
        return []
    call, args, result = event["call"], event["arguments"], event["return_value"]
    kind = None
    severity = "context"
    if call == "process_vm_writev" and re.match(r"[1-9]\d*\b", result):
        target = re.match(r"\s*(\d+)\s*,", args)
        if target and int(target.group(1)) != event["pid"]:
            kind, severity = "cross_process_memory_write", "candidate"
    elif call == "ptrace" and re.match(r"PTRACE_POKE(?:TEXT|DATA|USER)\b", args):
        kind, severity = "ptrace_memory_write", "candidate"
    elif call == "ptrace" and args.startswith("PTRACE_TRACEME"):
        kind = "trace_me_request"
    elif call == "memfd_create":
        kind = "anonymous_memory_file"
    elif call in ("execve", "execveat") and ("/memfd:" in args or "memfd:" in args):
        kind, severity = "memory_backed_execution", "candidate"
    elif call in ("mmap", "mmap2", "mprotect", "pkey_mprotect") and "PROT_WRITE" in args and "PROT_EXEC" in args:
        kind = "writable_executable_memory"
    if not kind:
        return []
    return [{"kind": kind, "classification": severity, "pid": event["pid"],
             "tid": event["tid"], "created_at": event.get("created_at"),
             "time": event["time"], "call": call, "arguments": args,
             "return_value": result, "malicious_intent_confirmed": False}]
