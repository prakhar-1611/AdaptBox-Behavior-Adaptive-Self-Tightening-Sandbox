"""cgroup v2 management for AdaptBox.

Creates a per-run child cgroup under /sys/fs/cgroup/adaptbox/<run-id>/, moves
the sandboxed process into it, reads live resource usage, lowers limits while
the process runs (stage 3), and kills the whole group via cgroup.kill (stage 4).

All writes are guarded so a dry run or a missing controller degrades to a
logged no-op rather than crashing the controller.
"""

from __future__ import annotations

import logging
import os
import time
from pathlib import Path

from .config import CGROUP_PARENT, CGROUP_ROOT, Limits
from .events import ResourceSample

log = logging.getLogger("adaptbox.cgroups")


class CgroupError(RuntimeError):
    pass


class Cgroup:
    """A single per-run cgroup v2 directory."""

    def __init__(self, run_id: str, limits: Limits, dry_run: bool = False):
        self.run_id = run_id
        self.limits = limits
        self.dry_run = dry_run
        self.parent = CGROUP_ROOT / CGROUP_PARENT
        self.path = self.parent / run_id
        self._created = False

    # -- lifecycle ---------------------------------------------------------

    def create(self) -> None:
        """Create the cgroup and enable controllers, applying loose limits."""
        if self.dry_run:
            log.info("[dry-run] would create cgroup %s", self.path)
            return
        self._ensure_parent_controllers()
        self.path.mkdir(parents=True, exist_ok=True)
        self._created = True
        self._apply_limits(
            cpu_percent=self.limits.cpu_max_percent,
            memory_mb=self.limits.memory_max_mb,
            pids=self.limits.pids_max,
        )
        log.info("created cgroup %s (loose profile)", self.path)

    def _ensure_parent_controllers(self) -> None:
        """Enable cpu, memory and pids controllers for children of the parent."""
        self.parent.mkdir(parents=True, exist_ok=True)
        subtree = self.parent / "cgroup.subtree_control"
        want = ("cpu", "memory", "pids")
        available = (CGROUP_ROOT / "cgroup.controllers").read_text().split()
        missing = [c for c in want if c not in available]
        if missing:
            raise CgroupError(
                f"cgroup v2 controllers not available: {missing}. "
                "Check `cat /sys/fs/cgroup/cgroup.controllers`."
            )
        try:
            subtree.write_text(" ".join(f"+{c}" for c in want))
        except OSError as exc:
            # Often already enabled; only fatal if a later write fails.
            log.debug("subtree_control write note: %s", exc)

    def add_process(self, pid: int) -> None:
        """Move a process (and its future children) into this cgroup."""
        if self.dry_run:
            log.info("[dry-run] would add pid %d to %s", pid, self.path)
            return
        self._write("cgroup.procs", str(pid))
        log.info("moved pid %d into cgroup %s", pid, self.path)

    # -- enforcement -------------------------------------------------------

    def tighten(self) -> None:
        """Stage 3: lower CPU, memory and pids limits on the live group."""
        if self.dry_run:
            log.info("[dry-run] would tighten cgroup limits")
            return
        self._apply_limits(
            cpu_percent=self.limits.cpu_tight_percent,
            memory_mb=self.limits.memory_tight_mb,
            pids=self.limits.pids_tight,
        )
        log.warning(
            "tightened cgroup: cpu=%d%% mem=%dMiB pids=%d",
            self.limits.cpu_tight_percent,
            self.limits.memory_tight_mb,
            self.limits.pids_tight,
        )

    def kill(self) -> None:
        """Stage 4: terminate every process in the group via cgroup.kill."""
        if self.dry_run:
            log.info("[dry-run] would kill cgroup %s", self.path)
            return
        try:
            self._write("cgroup.kill", "1")
            log.warning("killed cgroup %s", self.path)
        except OSError:
            # Older kernels lack cgroup.kill; fall back to SIGKILL per pid.
            self._kill_fallback()

    def _kill_fallback(self) -> None:
        for pid in self._read_pids():
            try:
                os.kill(pid, 9)
            except ProcessLookupError:
                pass
        log.warning("killed cgroup %s via per-pid SIGKILL fallback", self.path)

    # -- observation -------------------------------------------------------

    def sample(self) -> ResourceSample:
        """Read current CPU / memory / pids for the group."""
        if self.dry_run or not self._created:
            return ResourceSample(time.monotonic(), 0, 0, 0)
        return ResourceSample(
            ts=time.monotonic(),
            cpu_usage_usec=self._read_cpu_usec(),
            memory_current_bytes=self._read_int("memory.current"),
            pids_current=self._read_int("pids.current"),
        )

    def alive(self) -> bool:
        """True while the group still has processes."""
        if self.dry_run:
            return False
        return bool(self._read_pids())

    def destroy(self) -> None:
        """Remove the cgroup directory once empty."""
        if self.dry_run or not self._created:
            return
        try:
            self.path.rmdir()
            log.info("removed cgroup %s", self.path)
        except OSError as exc:
            log.debug("cgroup rmdir deferred (%s); processes may remain", exc)

    # -- low-level helpers -------------------------------------------------

    def _apply_limits(self, cpu_percent: int, memory_mb: int, pids: int) -> None:
        # cpu.max is "<quota> <period>"; quota = percent/100 * period.
        period = 100_000
        quota = int(period * cpu_percent / 100)
        self._write("cpu.max", f"{quota} {period}")
        self._write("memory.max", str(memory_mb * 1024 * 1024))
        self._write("pids.max", str(pids))
        # memory.max limits RAM only; swap has its own limit, unlimited by
        # default. Without this a memory hog pages out at the limit and keeps
        # running, and memory.current (RAM) stops growing, so its score fades.
        # With no swap, reaching memory.max invokes the OOM killer in the group.
        try:
            self._write("memory.swap.max", "0")
        except OSError as exc:      # kernel without swap accounting
            log.warning("could not disable swap for %s: %s", self.path, exc)

    def _write(self, fname: str, value: str) -> None:
        (self.path / fname).write_text(value)

    def _read_int(self, fname: str) -> int:
        try:
            return int((self.path / fname).read_text().strip())
        except (OSError, ValueError):
            return 0

    def oom_kills(self) -> int:
        """How many processes the kernel's OOM killer ended in this group."""
        if self.dry_run or not self._created:
            return 0
        try:
            for line in (self.path / "memory.events").read_text().splitlines():
                if line.startswith("oom_kill "):
                    return int(line.split()[1])
        except (OSError, ValueError):
            pass
        return 0

    def _read_cpu_usec(self) -> int:
        try:
            for line in (self.path / "cpu.stat").read_text().splitlines():
                if line.startswith("usage_usec"):
                    return int(line.split()[1])
        except OSError:
            pass
        return 0

    def _read_pids(self) -> list[int]:
        try:
            return [
                int(x) for x in (self.path / "cgroup.procs").read_text().split()
            ]
        except (OSError, ValueError):
            return []
