"""Central configuration for AdaptBox.

All tunable knobs live here so the isolation layer, monitor, rule engine and
controller agree on thresholds, paths and limits. Values are deliberately
conservative defaults for a 4 GB / 2 vCPU Kali VM.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

# ---------------------------------------------------------------------------
# cgroup / resource limits applied at each containment stage
# ---------------------------------------------------------------------------

# The cgroup v2 mount point on a stock systemd system.
CGROUP_ROOT = Path("/sys/fs/cgroup")

# Name of the parent cgroup AdaptBox creates its per-run children under.
CGROUP_PARENT = "adaptbox"


@dataclass(frozen=True)
class Limits:
    """Resource limits for a run. 'loose' values are the starting profile."""

    # Starting (loose) limits.
    cpu_max_percent: int = 100          # 100% of one core
    memory_max_mb: int = 1024           # 1 GiB
    pids_max: int = 256

    # Tightened limits applied at containment stage 3.
    cpu_tight_percent: int = 10
    memory_tight_mb: int = 128
    pids_tight: int = 16


# ---------------------------------------------------------------------------
# Risk scoring
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Thresholds:
    """Risk-score cutoffs that trigger each containment stage.

    The score is a running value in [0, 1]. Benign code should stay well below
    STAGE_1. Each threshold must be strictly greater than the previous one.
    """

    stage_1_cut_network: float = 0.35
    stage_2_block_writes: float = 0.55
    stage_3_cap_resources: float = 0.75
    stage_4_terminate: float = 0.90

    def as_list(self) -> list[tuple[float, str]]:
        return [
            (self.stage_1_cut_network, "cut_network"),
            (self.stage_2_block_writes, "block_writes"),
            (self.stage_3_cap_resources, "cap_resources"),
            (self.stage_4_terminate, "terminate"),
        ]


# ---------------------------------------------------------------------------
# Paths treated as sensitive by the rule engine
# ---------------------------------------------------------------------------

SENSITIVE_PATH_PREFIXES: tuple[str, ...] = (
    "/etc/shadow",
    "/etc/sudoers",
    "/etc/gshadow",
    "/root/.ssh",
    "/proc/self/environ",
)

# Suffix / substring patterns that are sensitive wherever they appear.
SENSITIVE_PATH_PATTERNS: tuple[str, ...] = (
    ".ssh/id_",      # private keys
    ".aws/credentials",
    ".env",
    "/.netrc",
    "/.git-credentials",
)

# Paths that it is dangerous to WRITE to: system files, program directories and
# persistence locations (cron, systemd, login shells, SSH keys). A normal script
# never writes here; doing so is tampering, persistence or privilege escalation.
SENSITIVE_WRITE_PREFIXES: tuple[str, ...] = (
    "/etc/",
    "/boot/",
    "/bin/", "/sbin/",
    "/usr/bin/", "/usr/sbin/", "/usr/local/bin/", "/usr/local/sbin/",
    "/lib/systemd/", "/usr/lib/systemd/",
    "/var/spool/cron/",
    "/sys/",                     # kernel/device tunables
)
SENSITIVE_WRITE_PATTERNS: tuple[str, ...] = (
    ".ssh/authorized_keys",      # grant the attacker a login
    "/.bashrc", "/.bash_profile", "/.profile", "/.zshrc",   # run on next login
    "/.config/autostart/",       # run on next desktop login
    "crontab",                   # scheduled execution
)
# Never treat these writes as sensitive: the interpreter's own bytecode cache.
WRITE_IGNORE_PATTERNS: tuple[str, ...] = ("/__pycache__/", ".pyc")


# ---------------------------------------------------------------------------
# Monitor
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class MonitorConfig:
    """How behavior events are sampled."""

    backend: str = "auto"          # "auto" | "ebpf" | "strace"
    window_seconds: float = 1.0    # how often the controller re-scores
    # Carry factor for the leaky-accumulator score: each window the running
    # score is multiplied by this before the new window's signal is added.
    # ~0.6 keeps a lone benign event below stage 1 while letting sustained
    # malicious behavior climb to the stage-4 kill in a few windows.
    score_decay: float = 0.6


# ---------------------------------------------------------------------------
# Top-level run configuration
# ---------------------------------------------------------------------------


@dataclass
class RunConfig:
    target: list[str]                       # argv of the script to sandbox
    workdir: Path = Path.cwd()
    limits: Limits = field(default_factory=Limits)
    thresholds: Thresholds = field(default_factory=Thresholds)
    monitor: MonitorConfig = field(default_factory=MonitorConfig)

    # Isolation toggles. Network starts enabled and is revoked at stage 1.
    enable_net_namespace: bool = True
    enable_pid_namespace: bool = True
    enable_mount_namespace: bool = True

    # Where to write the generated least-privilege policy and run log.
    output_dir: Path = Path("runs")

    # Hard ceiling on wall-clock runtime regardless of score.
    timeout_seconds: float = 60.0

    # Run the target as this unprivileged uid/gid (setpriv, no new privileges)
    # instead of root. Used for code submitted through the dashboard, which is
    # truly untrusted; the bundled samples keep running as root.
    run_as: int | None = None

    # Dry run: build everything, log decisions, but don't actually enforce.
    dry_run: bool = False
