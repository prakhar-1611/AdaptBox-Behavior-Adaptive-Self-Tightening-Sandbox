"""Behavior monitor.

Streams syscalls / file / network / resource events from the sandboxed process
tree and aggregates them into one BehaviorWindow per scoring window.

Two backends share the same output:

* StraceMonitor  -- parses `strace -f -ttt` output. Simple, always available,
                    higher overhead. This is the default fallback.
* EbpfMonitor    -- (stub) attaches BCC programs to raw_syscalls tracepoints.
                    Lower overhead; filled in once BCC is confirmed on the VM.

The controller calls `collect_window()` once per window; the monitor returns the
events seen since the previous call, already summarised and merged with a fresh
cgroup resource sample.
"""

from __future__ import annotations

import logging
import re
import threading
import time
from collections import deque
from pathlib import Path

from .cgroups import Cgroup
from .config import (
    MonitorConfig, SENSITIVE_PATH_PATTERNS, SENSITIVE_PATH_PREFIXES,
    SENSITIVE_WRITE_PATTERNS, SENSITIVE_WRITE_PREFIXES, WRITE_IGNORE_PATTERNS,
)
from .events import BehaviorWindow, ResourceSample, SyscallEvent

log = logging.getLogger("adaptbox.monitor")

# System calls grouped by the danger they signal, counted per window by name.
PRIVESC_CALLS = frozenset({
    "setuid", "setgid", "setreuid", "setregid", "setresuid", "setresgid",
    "setfsuid", "setfsgid", "capset",
})
KMOD_CALLS = frozenset({"init_module", "finit_module", "delete_module"})
PTRACE_CALLS = frozenset({"ptrace", "process_vm_writev"})
MOUNT_CALLS = frozenset({"mount", "umount", "umount2", "chroot", "pivot_root"})
DELETE_CALLS = frozenset({"unlink", "unlinkat"})
# strace needs to be told to trace all of these (sandbox.build_command).
EXTRA_TRACED = (
    sorted(PRIVESC_CALLS | KMOD_CALLS | PTRACE_CALLS | MOUNT_CALLS | DELETE_CALLS)
)


def is_sensitive(path: str) -> bool:
    if any(path.startswith(p) for p in SENSITIVE_PATH_PREFIXES):
        return True
    return any(pat in path for pat in SENSITIVE_PATH_PATTERNS)


def is_sensitive_write(path: str) -> bool:
    if any(ig in path for ig in WRITE_IGNORE_PATTERNS):
        return False
    if any(path.startswith(p) for p in SENSITIVE_WRITE_PREFIXES):
        return True
    return any(pat in path for pat in SENSITIVE_WRITE_PATTERNS)


class BaseMonitor:
    """Common aggregation logic shared by both backends."""

    def __init__(self, cgroup: Cgroup, cfg: MonitorConfig):
        self.cgroup = cgroup
        self.cfg = cfg
        self._events: deque[SyscallEvent] = deque()
        self._lock = threading.Lock()
        self._prev_cpu = 0
        self._prev_mem = 0
        self._started = time.monotonic()

    # Backends push decoded events here.
    def _push(self, ev: SyscallEvent) -> None:
        with self._lock:
            self._events.append(ev)

    def collect_window(self) -> BehaviorWindow:
        """Drain buffered events and merge with a resource sample."""
        with self._lock:
            evs = list(self._events)
            self._events.clear()

        win = BehaviorWindow(ts=time.monotonic(), syscalls=evs)
        for ev in evs:
            win.syscall_counts[ev.name] = win.syscall_counts.get(ev.name, 0) + 1
            if ev.name in ("openat", "open") and ev.arg:
                if ev.write and is_sensitive_write(ev.arg):
                    win.sensitive_writes.append(ev.arg)
                elif not ev.write and is_sensitive(ev.arg):
                    win.sensitive_reads.append(ev.arg)
            elif ev.name == "connect" and ev.arg:
                win.outbound_connects.append(ev.arg)
            elif ev.name == "execve" and ev.arg:
                win.exec_calls.append(ev.arg)
            elif ev.name in ("clone", "clone3", "fork", "vfork"):
                win.fork_count += 1
            elif ev.name == "socket" and ev.arg == "raw":
                win.raw_socket = True
            elif ev.name in PRIVESC_CALLS and ev.arg == "root":
                win.privesc_count += 1
            elif ev.name in KMOD_CALLS:
                win.kmod_count += 1
            elif ev.name in PTRACE_CALLS:
                win.ptrace_count += 1
            elif ev.name in MOUNT_CALLS:
                win.mount_count += 1
            elif ev.name in DELETE_CALLS:
                win.delete_count += 1

        sample: ResourceSample = self.cgroup.sample()
        win.cpu_delta_usec = max(0, sample.cpu_usage_usec - self._prev_cpu)
        win.mem_delta_bytes = sample.memory_current_bytes - self._prev_mem
        win.mem_current_bytes = sample.memory_current_bytes
        win.pids_current = sample.pids_current
        self._prev_cpu = sample.cpu_usage_usec
        self._prev_mem = sample.memory_current_bytes
        return win

    def start(self) -> None:  # pragma: no cover - backend specific
        raise NotImplementedError

    def stop(self) -> None:  # pragma: no cover - backend specific
        pass


class StraceMonitor(BaseMonitor):
    """Reads an strace output file and decodes the lines we care about.

    Pull-based: each collect_window() reads whatever new bytes strace has
    written since the last call (tracking a byte offset, resetting on
    truncation). This avoids the race a background tail thread had with
    strace creating/truncating/buffering the file.
    """

    # Example line (strace -f -ttt):
    #   12345 1700000000.123456 openat(AT_FDCWD, "/etc/shadow", O_RDONLY) = 3
    # strace lines come in several shapes depending on version / -f:
    #   "1700000000.12 openat(AT_FDCWD, \"/etc/shadow\", O_RDONLY) = 3"   (bare)
    #   "10125 1700000000.12 openat(...) = 3"                              (-f pid)
    #   "[pid 10125] 1700000000.12 openat(...) = 3"                        (-f alt)
    # Both pid forms are optional; the epoch timestamp (has a dot) anchors it.
    LINE_RE = re.compile(
        r"^(?:\[pid\s+(?P<pid2>\d+)\]\s+)?"       # optional "[pid NNN] "
        r"(?:(?P<pid>\d+)\s+)?"                     # optional bare "NNN "
        r"(?P<ts>\d+\.\d+)\s+"                      # epoch timestamp (-ttt)
        r"(?P<name>\w+)\((?P<args>.*)\)\s*=\s*(?P<ret>-?\d+|\?).*$"
    )
    PATH_RE = re.compile(r'"((?:[^"\\]|\\.)*)"')
    # strace prints sin_port before sin_addr, and IPv6 uses inet_pton; match
    # each field independently so field order and address family don't matter.
    ADDR_RE = re.compile(r'inet_(?:addr|pton)\([^"]*"([0-9a-fA-F:.]+)"\)')
    PORT_RE = re.compile(r'sin6?_port=htons\((\d+)\)')
    INT_RE = re.compile(r'-?\d+')        # integer args, e.g. the uid in setuid(0)

    def __init__(self, cgroup: Cgroup, cfg: MonitorConfig, strace_out: Path):
        super().__init__(cgroup, cfg)
        self.path = Path(strace_out)
        self._offset = 0
        self._carry = ""   # partial trailing line between reads

    def start(self) -> None:
        self.path.touch(exist_ok=True)
        log.info("strace monitor reading %s", self.path)

    def stop(self) -> None:
        # Final drain so the last window's events aren't lost on exit.
        self._drain_file()

    def collect_window(self):  # type: ignore[override]
        self._drain_file()
        return super().collect_window()

    def _drain_file(self) -> None:
        """Parse any bytes written since the last read; handle truncation."""
        try:
            size = self.path.stat().st_size
        except OSError:
            return
        if size < self._offset:          # file was truncated/recreated
            self._offset = 0
            self._carry = ""
        if size == self._offset:
            return
        try:
            with self.path.open("r", errors="replace") as fh:
                fh.seek(self._offset)
                chunk = fh.read()
                self._offset = fh.tell()
        except OSError:
            return
        data = self._carry + chunk
        lines = data.split("\n")
        self._carry = lines.pop()        # last element is a partial line
        for line in lines:
            if line:
                self._parse(line)

    def _parse(self, line: str) -> None:
        m = self.LINE_RE.match(line)
        if not m:
            return
        name = m.group("name")
        args = m.group("args")
        try:
            ret = int(m.group("ret"))
        except ValueError:
            ret = None

        arg: str | None = None
        write = False
        if name in ("openat", "open"):
            paths = self.PATH_RE.findall(args)
            arg = paths[-1] if paths else None   # openat path is after the fd
            write = any(fl in args for fl in ("O_WRONLY", "O_RDWR", "O_CREAT", "O_APPEND", "O_TRUNC"))
        elif name == "execve":
            paths = self.PATH_RE.findall(args)
            arg = paths[0] if paths else None
        elif name == "connect":
            addr = self.ADDR_RE.search(args)
            port = self.PORT_RE.search(args)
            if addr:
                arg = f"{addr.group(1)}:{port.group(1) if port else '?'}"
        elif name == "socket":
            # SOCK_RAW / AF_PACKET => packet sniffing or spoofing
            if "SOCK_RAW" in args or "AF_PACKET" in args:
                arg = "raw"
        elif name in PRIVESC_CALLS:
            # Distinguish gaining root (uid/gid 0) from setpriv dropping to nobody:
            # only a 0 target is the danger signal.
            nums = self.INT_RE.findall(args)
            if "0" in nums:
                arg = "root"

        pid_str = m.group("pid") or m.group("pid2") or "0"
        self._push(SyscallEvent(
            ts=time.monotonic(), pid=int(pid_str),
            name=name, arg=arg, retval=ret, write=write,
        ))


class EbpfMonitor(BaseMonitor):
    """BCC-based backend. Stub: wired up once BCC is confirmed on the VM.

    Intended attach points:
      * tracepoint:raw_syscalls:sys_enter  (filter by cgroup id)
      * kprobe on tcp_connect / security_file_open for richer context
    Until implemented, start() raises so the factory falls back to strace.
    """

    def start(self) -> None:
        raise RuntimeError("eBPF backend not yet implemented; use strace backend")


def make_monitor(cgroup: Cgroup, cfg: MonitorConfig, strace_out: Path) -> BaseMonitor:
    """Pick a backend according to cfg.backend, with graceful fallback."""
    if cfg.backend in ("auto", "ebpf"):
        try:
            mon = EbpfMonitor(cgroup, cfg)
            mon.start()
            return mon
        except Exception as exc:  # noqa: BLE001 - fall back on any failure
            if cfg.backend == "ebpf":
                raise
            log.info("eBPF unavailable (%s); falling back to strace", exc)
    return StraceMonitor(cgroup, cfg, strace_out)
