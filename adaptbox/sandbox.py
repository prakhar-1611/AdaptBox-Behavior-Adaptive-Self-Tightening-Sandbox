"""Isolation layer: launch the target under namespaces + cgroup, and enforce
the four graduated containment stages on the live process.

Design notes
------------
* Namespaces are created with `unshare` (util-linux), available on stock Kali,
  so no kernel rebuild is needed. We request PID, mount and (optionally) a
  network namespace plus UTS/IPC for a clean view.
* The child is placed in its per-run cgroup v2 group by the controller right
  after launch, so CPU/memory/pids caps and `cgroup.kill` act on the whole tree.
* Seccomp cannot be *added* to a running process from outside, so AdaptBox does
  NOT use seccomp for live tightening. Seccomp is used two ways instead:
    - an optional loose allow/deny filter installed at launch, and
    - the *generated* least-privilege policy emitted after the run (policy.py).
  Live tightening uses mechanisms that genuinely apply to a running process:
    - cut_network   -> drop the cgroup's packets with an nftables cgroupv2 rule
    - block_writes  -> remount the sandbox workdir read-only in its mount ns
    - cap_resources -> lower cpu.max / memory.max / pids.max (cgroups.py)
    - terminate     -> cgroup.kill (cgroups.py)

Each enforcement method degrades to a logged no-op when the backing tool is
missing or when running in dry-run mode, so the controller never crashes.
"""

from __future__ import annotations

import logging
import os
import shutil
import signal
import subprocess
import threading
import time
from pathlib import Path
from typing import Callable

from .config import RunConfig
from .cgroups import Cgroup

log = logging.getLogger("adaptbox.sandbox")


def _have(tool: str) -> bool:
    return shutil.which(tool) is not None


def _pump(stream, on_line: Callable[[str], None]) -> None:
    """Forward each line of the target's output until it closes."""
    for line in stream:
        try:
            on_line(line.rstrip("\n"))
        except Exception:  # noqa: BLE001 - a listener must not kill the pump
            pass


class Sandbox:
    """Owns the sandboxed process, its namespaces, and live enforcement."""

    def __init__(self, cfg: RunConfig, cgroup: Cgroup, run_id: str):
        self.cfg = cfg
        self.cgroup = cgroup
        self.run_id = run_id
        self.proc: subprocess.Popen | None = None
        self._net_cut = False
        self._writes_blocked = False
        self._nft_table = f"adaptbox_{run_id}"
        # Workdir is bind-mounted so it can be remounted read-only live.
        self._workdir = Path(cfg.workdir).resolve()

    # -- launch ------------------------------------------------------------

    def build_command(self, traced: bool = False, strace_out: str | None = None) -> list[str]:
        """Compose the unshare (+ optional strace) command for the target."""
        cmd: list[str] = []

        if _have("unshare") and not self.cfg.dry_run:
            cmd += ["unshare", "--fork", "--mount-proc"]
            if self.cfg.enable_pid_namespace:
                cmd += ["--pid"]
            if self.cfg.enable_mount_namespace:
                cmd += ["--mount"]
            if self.cfg.enable_net_namespace:
                # Start WITH connectivity on host net; stage 1 cuts it via nft.
                # (A private net ns with veth+NAT is a later enhancement.)
                pass
            cmd += ["--uts", "--ipc"]
        else:
            log.warning("unshare unavailable or dry-run: namespaces skipped")

        if traced and _have("strace"):
            # -f follows children; -ttt absolute timestamps; -e filters noise.
            from .monitor import EXTRA_TRACED
            base = ("openat,open,connect,execve,clone,clone3,fork,vfork,"
                    "mmap,brk,socket,sendto")
            cmd += [
                "strace", "-f", "-ttt", "-qq",
                "-e", "trace=" + base + "," + ",".join(EXTRA_TRACED),
            ]
            if strace_out:
                cmd += ["-o", strace_out]

        if self.cfg.run_as is not None and not self.cfg.dry_run:
            if not _have("setpriv"):
                # never run submitted code as root just because a tool is missing
                raise RuntimeError("setpriv (util-linux) is needed to drop privileges")
            # Drop to an unprivileged user under strace, so strace (root) can still
            # follow it; no_new_privs stops setuid binaries regaining root.
            uid = str(self.cfg.run_as)
            cmd += ["setpriv", f"--reuid={uid}", f"--regid={uid}",
                    "--clear-groups", "--no-new-privs", "--"]

        cmd += list(self.cfg.target)
        return cmd

    def launch(self, traced: bool = False, strace_out: str | None = None,
               on_output: Callable[[str], None] | None = None) -> int:
        """Start the target. Returns its PID. Does not wait.

        With on_output, the target's stdout/stderr is piped and each line is
        passed to it from a reader thread; otherwise output goes to the console.
        """
        cmd = self.build_command(traced=traced, strace_out=strace_out)
        log.info("launching: %s", " ".join(cmd))
        if self.cfg.dry_run:
            # Simulate a short-lived child so the loop logic can be exercised,
            # using the current interpreter so it runs on any platform.
            import sys
            self.proc = subprocess.Popen(
                [sys.executable, "-c", "import time; time.sleep(2)"]
            )
            return self.proc.pid

        # Unbuffered Python output, so each line arrives when it is printed.
        env = {**os.environ, "PYTHONUNBUFFERED": "1"}
        piped = on_output is not None

        # The child joins its cgroup itself, after fork and before exec, so
        # everything it starts (unshare -> strace -> the script) is born inside
        # it. Moving the PID in after launch raced with unshare's own forks: the
        # script escaped into the parent cgroup and ran with no limits at all.
        # If the write fails the launch fails, rather than running unconfined.
        procs = str(self.cgroup.path / "cgroup.procs")

        def enter_cgroup() -> None:
            with open(procs, "w") as fh:
                fh.write("0")           # "0" means the writing process itself

        # New session so we can signal the whole group as a backstop.
        self.proc = subprocess.Popen(
            cmd, cwd=str(self._workdir), start_new_session=True, env=env,
            preexec_fn=enter_cgroup,
            stdout=subprocess.PIPE if piped else None,
            stderr=subprocess.STDOUT if piped else None,
            text=piped, errors="replace" if piped else None,
        )
        if piped:
            threading.Thread(target=_pump, args=(self.proc.stdout, on_output),
                             daemon=True).start()
        return self.proc.pid

    # -- stage 1: network --------------------------------------------------

    # Each stage returns (ok, detail): whether the kernel accepted the change,
    # and one line saying what was done, for the run log and the dashboard.

    def cut_network(self) -> tuple[bool, str]:
        if self._net_cut:
            return True, "network already cut"
        self._net_cut = True
        if self.cfg.dry_run:
            return True, "[dry-run] nftables drop rule not installed"
        if not _have("nft"):
            log.error("nftables (nft) not found; cannot cut network live")
            return False, "nft not installed"
        cg_rel = CGROUP_REL(str(self.cgroup.path))
        # Drop all traffic originating from this run's cgroup.
        script = (
            f"add table inet {self._nft_table}; "
            f"add chain inet {self._nft_table} out "
            f"{{ type filter hook output priority 0; }}; "
            f"add rule inet {self._nft_table} out "
            f"socket cgroupv2 level 2 \"{cg_rel}\" drop"
        )
        rc = _run_nft(script)
        if rc == 0:
            log.warning("STAGE 1: network cut for %s", self.run_id)
            return True, f"nftables drops all packets from cgroup {cg_rel}"
        log.error("STAGE 1: nft rule failed (rc=%d)", rc)
        return False, f"nft rule failed (rc={rc})"

    # -- stage 2: writes ---------------------------------------------------

    def block_writes(self) -> tuple[bool, str]:
        if self._writes_blocked:
            return True, "writes already blocked"
        self._writes_blocked = True
        if self.cfg.dry_run:
            return True, "[dry-run] filesystem not remounted"
        pid = self.proc.pid if self.proc else None
        if not pid or not _have("nsenter"):
            log.error("cannot block writes: need nsenter and a live pid")
            return False, "nsenter missing or target gone"
        # Remount the filesystem holding the workdir read-only, inside the
        # sandbox's private mount namespace only (the host is untouched). The
        # whole mount is flipped, not a bind on the workdir, because the target's
        # cwd still points at the original mount and relative writes would slip
        # through. The kernel refuses (EBUSY) while a file on that mount is open
        # for writing, which is why the strace log lives on /dev/shm.
        ns = ["nsenter", "-t", str(pid), "-m", "--"]
        found = subprocess.run(
            ns + ["findmnt", "-n", "-o", "TARGET", "-T", str(self._workdir)],
            capture_output=True, text=True,
        )
        mnt = found.stdout.strip() or "/"
        res = subprocess.run(
            ns + ["mount", "-o", "remount,bind,ro", mnt],
            capture_output=True, text=True,
        )
        if res.returncode == 0:
            log.warning("STAGE 2: writes blocked (%s remounted ro in sandbox)", mnt)
            return True, f"{mnt} remounted read-only inside the sandbox"
        err = (res.stderr or "").strip().splitlines()
        log.error("STAGE 2: remount ro failed (rc=%d) %s", res.returncode, err[-1:] or "")
        return False, f"remount failed: {err[-1] if err else 'rc=' + str(res.returncode)}"

    # -- stage 3 & 4 are delegated to the cgroup ---------------------------

    def cap_resources(self) -> tuple[bool, str]:
        self.cgroup.tighten()
        lim = self.cfg.limits
        return True, (f"cpu.max {lim.cpu_tight_percent}%, memory.max "
                      f"{lim.memory_tight_mb} MiB, pids.max {lim.pids_tight}")

    def terminate(self) -> tuple[bool, str]:
        self.cgroup.kill()
        # Backstop: signal the process group in case cgroup.kill missed anything.
        if self.proc and not self.cfg.dry_run:
            try:
                os.killpg(os.getpgid(self.proc.pid), signal.SIGKILL)
            except (ProcessLookupError, PermissionError):
                pass
        return True, "cgroup.kill sent SIGKILL to every process in the group"

    # -- lifecycle ---------------------------------------------------------

    def poll(self) -> int | None:
        return self.proc.poll() if self.proc else None

    def wait(self, timeout: float | None = None) -> int | None:
        if not self.proc:
            return None
        try:
            return self.proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            return None

    def cleanup(self) -> None:
        """Remove any nftables table we installed; best-effort."""
        if self.cfg.dry_run:
            return
        if self._net_cut and _have("nft"):
            _run_nft(f"delete table inet {self._nft_table}")


# ---------------------------------------------------------------------------
# nftables helpers
# ---------------------------------------------------------------------------


def CGROUP_REL(abs_path: str) -> str:
    """Convert an absolute cgroup path to the form nft's cgroupv2 match wants
    (relative to the cgroup v2 root, no leading /sys/fs/cgroup)."""
    root = "/sys/fs/cgroup/"
    return abs_path[len(root):] if abs_path.startswith(root) else abs_path.lstrip("/")


def _run_nft(script: str) -> int:
    try:
        return subprocess.run(
            ["nft", "-f", "-"], input=script.encode(), capture_output=True
        ).returncode
    except FileNotFoundError:
        return 127
