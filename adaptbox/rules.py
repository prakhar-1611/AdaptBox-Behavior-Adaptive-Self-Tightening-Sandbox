"""Rule-based risk contributions.

These are fast, explainable heuristics tied directly to the five threat classes
in the report. Each fired rule returns a weighted contribution and a human
reason string; the controller sums the contributions for the window, blends
them with the Isolation Forest anomaly score, and applies decay over time.

Scores are additive within a window and clamped to [0, 1] by the caller.
Rules are intentionally conservative so benign code contributes ~0.
"""

from __future__ import annotations

from dataclasses import dataclass

from .events import BehaviorWindow


@dataclass
class RuleHit:
    weight: float
    reason: str


# Per-event / per-window weights. Tuned so a single strong signal (e.g. reading
# /etc/shadow) lands near stage 1, and a combination escalates quickly.
W_SENSITIVE_READ = 0.40      # per sensitive file opened
W_OUTBOUND_CONNECT = 0.15    # per outbound connect attempt
W_MANY_CONNECTS = 0.35       # burst of connects in one window (port scan)
W_EXEC_SHELL = 0.45          # exec of a shell / interpreter
W_FORK_BURST = 0.40          # many forks in one window (fork bomb)
W_MEM_GROWTH = 0.35          # fast RSS growth (memory exhaustion)

# Further OS-level danger classes. These actions have essentially no benign use
# in an untrusted script, so their weights are high.
W_SENSITIVE_WRITE = 0.45     # per write to a system / persistence path
W_PRIVESC = 0.50             # trying to become root (setuid 0, capset)
W_KMOD = 0.60                # loading / unloading a kernel module
W_PTRACE = 0.40              # attaching to / injecting into another process
W_MOUNT = 0.50               # mount / chroot / pivot_root (fs or container escape)
W_RAW_SOCKET = 0.40          # raw / packet socket (sniffing or spoofing)
W_DELETE_BURST = 0.35        # mass file deletion (wiper / ransomware)

# Thresholds for burst/growth rules.
CONNECT_BURST = 10           # connects/window => scan-like
FORK_BURST = 20              # forks/window => fork-bomb-like
MEM_GROWTH_MB = 256          # +MiB/window => exhaustion-like
DELETE_BURST = 25            # deletes/window => wiper-like (benign cleanup is smaller)

SHELL_BINARIES = (
    "/bin/sh", "/bin/bash", "/bin/dash", "/usr/bin/sh", "/usr/bin/bash",
    "/bin/zsh", "/usr/bin/nc", "/bin/nc", "/usr/bin/ncat",
)


def evaluate(win: BehaviorWindow) -> list[RuleHit]:
    """Return every rule that fired for this window."""
    hits: list[RuleHit] = []

    # Threat: sensitive file reads.
    for path in win.sensitive_reads:
        hits.append(RuleHit(W_SENSITIVE_READ, f"sensitive read: {path}"))

    # Threat: reverse shell / exfiltration (exec of a shell or netcat).
    for prog in win.exec_calls:
        if any(prog == b or prog.endswith("/" + b.rsplit("/", 1)[-1]) for b in SHELL_BINARIES):
            hits.append(RuleHit(W_EXEC_SHELL, f"exec of shell/netcat: {prog}"))

    # Threat: network scan (burst of connects) vs ordinary single connect.
    n_conn = len(win.outbound_connects)
    if n_conn >= CONNECT_BURST:
        hits.append(RuleHit(W_MANY_CONNECTS, f"connect burst: {n_conn} in window"))
    else:
        for dst in win.outbound_connects:
            hits.append(RuleHit(W_OUTBOUND_CONNECT, f"outbound connect: {dst}"))

    # Threat: fork bomb.
    if win.fork_count >= FORK_BURST:
        hits.append(RuleHit(W_FORK_BURST, f"fork burst: {win.fork_count} in window"))

    # Threat: memory exhaustion.
    growth_mb = win.mem_delta_bytes / (1024 * 1024)
    if growth_mb >= MEM_GROWTH_MB:
        hits.append(RuleHit(W_MEM_GROWTH, f"fast memory growth: +{growth_mb:.0f} MiB"))

    # Threat: persistence / system tampering (writing to protected locations).
    for path in win.sensitive_writes:
        hits.append(RuleHit(W_SENSITIVE_WRITE, f"system write: {path}"))

    # Threat: privilege escalation (trying to become root).
    for _ in range(win.privesc_count):
        hits.append(RuleHit(W_PRIVESC, "privilege escalation: setuid to root"))

    # Threat: kernel tampering (loading a module).
    for _ in range(win.kmod_count):
        hits.append(RuleHit(W_KMOD, "kernel module load"))

    # Threat: process injection.
    for _ in range(win.ptrace_count):
        hits.append(RuleHit(W_PTRACE, "process injection: ptrace"))

    # Threat: filesystem / container escape.
    for _ in range(win.mount_count):
        hits.append(RuleHit(W_MOUNT, "filesystem escape: mount/chroot"))

    # Threat: packet sniffing or spoofing.
    if win.raw_socket:
        hits.append(RuleHit(W_RAW_SOCKET, "raw/packet socket opened"))

    # Threat: data destruction (mass delete).
    if win.delete_count >= DELETE_BURST:
        hits.append(RuleHit(W_DELETE_BURST, f"mass file deletion: {win.delete_count} in window"))

    return hits


def rule_score(win: BehaviorWindow) -> tuple[float, list[str]]:
    """Summed rule contribution for the window and the reasons that drove it."""
    hits = evaluate(win)
    total = sum(h.weight for h in hits)
    return total, [h.reason for h in hits]
