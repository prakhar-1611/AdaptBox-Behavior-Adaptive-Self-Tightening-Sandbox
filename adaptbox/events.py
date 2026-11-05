"""Shared event types passed from the monitor to the rule engine and scorer.

Keeping these as small plain dataclasses means the strace and eBPF backends can
emit the same structure, and the rule engine / Isolation Forest never need to
know which backend produced an event.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class SyscallEvent:
    """A single observed system call from the sandboxed process tree."""

    ts: float                 # monotonic timestamp (seconds)
    pid: int
    name: str                 # e.g. "openat", "connect", "clone"
    # Best-effort decoded argument of interest, backend-dependent:
    #   openat   -> path string
    #   connect  -> "ip:port"
    #   execve   -> program path
    #   socket   -> "raw" when a raw/packet socket
    #   setuid.. -> "root" when the target uid/gid is 0
    arg: str | None = None
    retval: int | None = None
    write: bool = False       # openat/open opened for writing


@dataclass
class ResourceSample:
    """A point-in-time resource reading for the whole cgroup."""

    ts: float
    cpu_usage_usec: int        # cumulative, from cpu.stat
    memory_current_bytes: int  # from memory.current
    pids_current: int          # from pids.current


@dataclass
class BehaviorWindow:
    """Everything observed in one scoring window, handed to the scorers.

    Counts are per-window (reset each window); the resource fields are the
    latest absolute readings plus deltas since the previous window.
    """

    ts: float
    syscalls: list[SyscallEvent] = field(default_factory=list)

    # Derived counts, filled by the monitor before scoring.
    syscall_counts: dict[str, int] = field(default_factory=dict)
    sensitive_reads: list[str] = field(default_factory=list)
    sensitive_writes: list[str] = field(default_factory=list)   # system/persistence writes
    outbound_connects: list[str] = field(default_factory=list)
    exec_calls: list[str] = field(default_factory=list)
    fork_count: int = 0

    # Further OS-level danger signals, counted per window.
    privesc_count: int = 0        # setuid/etc targeting root
    kmod_count: int = 0           # (un)loading kernel modules
    ptrace_count: int = 0         # attaching to another process
    mount_count: int = 0          # mount/umount/chroot/pivot_root
    delete_count: int = 0         # unlink/unlinkat
    raw_socket: bool = False      # raw or packet socket opened

    # Resource deltas over the window.
    cpu_delta_usec: int = 0
    mem_current_bytes: int = 0
    mem_delta_bytes: int = 0
    pids_current: int = 0

    def feature_vector(self) -> list[float]:
        """Numeric features for the Isolation Forest scorer.

        Order is fixed; the scorer relies on it. Keep additions at the end.
        """
        return [
            float(sum(self.syscall_counts.values())),
            float(len(self.sensitive_reads)),
            float(len(self.outbound_connects)),
            float(len(self.exec_calls)),
            float(self.fork_count),
            float(self.cpu_delta_usec),
            float(self.mem_current_bytes),
            float(self.mem_delta_bytes),
            float(self.pids_current),
            # additions kept at the end so an older trained model still lines up
            float(len(self.sensitive_writes)),
            float(self.privesc_count),
            float(self.kmod_count),
            float(self.ptrace_count),
            float(self.mount_count),
            float(self.delete_count),
            float(self.raw_socket),
        ]


# Human-readable names matching the feature_vector() order, for logs/plots.
FEATURE_NAMES: tuple[str, ...] = (
    "total_syscalls",
    "sensitive_reads",
    "outbound_connects",
    "exec_calls",
    "fork_count",
    "cpu_delta_usec",
    "mem_current_bytes",
    "mem_delta_bytes",
    "pids_current",
    "sensitive_writes",
    "privesc_count",
    "kmod_count",
    "ptrace_count",
    "mount_count",
    "delete_count",
    "raw_socket",
)
