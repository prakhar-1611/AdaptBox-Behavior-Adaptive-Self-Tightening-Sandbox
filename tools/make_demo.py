"""Build web/demo-data.js: simulated recordings for the dashboard's offline mode.

    python3 tools/make_demo.py

When the dashboard cannot reach the engine it replays these instead. They are
not captured from a kernel: each sample's behaviour is scripted window by
window below (from what the sample does and what real runs on Kali showed), and
everything after that is computed by AdaptBox's own code: rules.evaluate, the
leaky-accumulator score, the thresholds, the stage mechanisms and the policy
builder. The dashboard labels them "simulated".
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from adaptbox.config import Limits, MonitorConfig, Thresholds  # noqa: E402
from adaptbox.controller import STAGES  # noqa: E402
from adaptbox.events import FEATURE_NAMES, BehaviorWindow  # noqa: E402
from adaptbox.policy import build_profile  # noqa: E402
from adaptbox.rules import evaluate  # noqa: E402
from adaptbox.server import list_samples, run_summary  # noqa: E402

WIN = 0.5
DECAY = MonitorConfig().score_decay
TH = [t for t, _ in Thresholds().as_list()]
LIM = Limits()
MB = 1024 * 1024

# Python's own start-up, seen in the first window of every run.
BOOT = {"execve": 1, "brk": 13, "mmap": 30, "openat": 43, "open": 1}


def w(syscalls=None, sensitive=(), connects=(), execs=(), forks=0, mem_mb=0.0, pids=1,
      writes=(), privesc=0, kmod=0, ptrace=0, mount=0, delete=0, raw=False):
    return {"syscalls": dict(syscalls or {}), "sensitive": list(sensitive),
            "connects": list(connects), "execs": list(execs), "forks": forks,
            "mem_mb": mem_mb, "pids": pids, "writes": list(writes), "privesc": privesc,
            "kmod": kmod, "ptrace": ptrace, "mount": mount, "delete": delete, "raw": raw}


def boot(**extra):
    s = dict(BOOT)
    for k, v in extra.items():
        s[k] = s.get(k, 0) + v
    return s


# Each sample: run id, per-window behaviour, the program's output as
# (t, line), its natural end (t, exit code) and, for runs a cgroup limit stops
# before AdaptBox does, the limit that stops them.
SCRIPTS = {
    "benign/compute.py": dict(
        run_id="3f1c0a92", started_at=1793088012.4,
        windows=[w(boot(openat=2), mem_mb=14)],
        output=[(0.31, "computed 17984 primes in 0.22s")],
        natural_end=(0.36, 0),
    ),
    "benign/file_tool.py": dict(
        run_id="5b07e4d1", started_at=1793088031.9,
        windows=[w(boot(openat=44), mem_mb=13)],
        output=[(0.12, "processed workspace: 4200 bytes across 20 files")],
        natural_end=(0.15, 0),
    ),
    "benign/single_fetch.py": dict(
        run_id="8c42d6f0", started_at=1793088048.2,
        windows=[w(boot(socket=1, connect=1), connects=["127.0.0.1:80"], mem_mb=12)],
        output=[(0.09, "single connect attempt finished: [Errno 111] Connection refused")],
        natural_end=(0.11, 0),
    ),
    "malicious/fork_storm.py": dict(
        run_id="a91e5c07", started_at=1793088103.6,
        windows=[w(boot(clone=212), forks=212, mem_mb=96, pids=212),
                 w({"clone": 256}, forks=256, mem_mb=40, pids=256),
                 w({"clone": 256}, forks=256, mem_mb=8, pids=256),
                 # stage 3 set pids.max to 16: children live 0.2 s, so ~40 fit a window
                 w({"clone": 41}, forks=41, mem_mb=-110, pids=16),
                 w({"clone": 38}, forks=38, mem_mb=0, pids=16)],
        output=[], natural_end=(5.02, 0),
    ),
    "malicious/mem_hog.py": dict(
        run_id="c2d7f318", started_at=1793088140.1,
        windows=[w(boot(mmap=9), mem_mb=448), w({"mmap": 8}, mem_mb=512)],
        output=[(0.05 + i * 0.066, f"allocated {64 * (i + 1)} MiB") for i in range(15)],
        limit_kill=(1.03, "memory.max (1024 MiB) reached: the kernel's OOM killer stopped it"),
    ),
    "malicious/net_scan.py": dict(
        run_id="d4a0b6e9", started_at=1793088171.8,
        windows=[w(boot(socket=1024, connect=1024),
                   connects=[f"127.0.0.1:{p}" for p in range(1, 1025)], mem_mb=12)],
        output=[(0.28, "attempted 1024 loopback connects")],
        natural_end=(0.31, 0),
    ),
    "malicious/read_secrets.py": dict(
        run_id="92a735bc", started_at=1793090316.0,
        windows=[w(boot(openat=5),
                   sensitive=["/etc/shadow", "/etc/sudoers", "/root/.ssh/id_rsa",
                              "/root/.aws/credentials", "/proc/self/environ"], mem_mb=12)],
        output=[(0.06, "READ /etc/shadow: 1448 bytes"), (0.06, "READ /etc/sudoers: 1714 bytes"),
                (0.07, "DENIED /root/.ssh/id_rsa: [Errno 2] No such file or directory: '/root/.ssh/id_rsa'"),
                (0.07, "DENIED /root/.aws/credentials: [Errno 2] No such file or directory: '/root/.aws/credentials'"),
                (0.07, "READ /proc/self/environ: 2373 bytes")],
        natural_end=(0.09, 0),
    ),
    "malicious/persistence.py": dict(
        run_id="b7e3f1a2", started_at=1793090420.0,
        windows=[w(boot(openat=3, setuid=1),
                   writes=["/root/.ssh/authorized_keys", "/etc/cron.d/adaptbox-fixture", "/root/.bashrc"],
                   privesc=1, mem_mb=12)],
        output=[(0.05, "DENIED ~/.ssh/authorized_keys: Permission denied"),
                (0.05, "DENIED /etc/cron.d/adaptbox-fixture: Permission denied"),
                (0.06, "DENIED ~/.bashrc: Permission denied"),
                (0.06, "setuid(0) denied: Operation not permitted")],
        natural_end=(0.08, 0),
    ),
    "malicious/shell_spawn.py": dict(
        run_id="e6b19f44", started_at=1793088204.3,
        windows=[w(boot(socket=1, connect=1, execve=1),
                   connects=["127.0.0.1:9999"], execs=["/bin/sh"], mem_mb=11)],
        output=[(0.05, "connect to 127.0.0.1:9999 failed (expected): [Errno 111] Connection refused"),
                (0.05, "exec /bin/sh with a harmless command (signature only)"),
                (0.07, "adaptbox-fixture-shell")],
        natural_end=(0.08, 0),
    ),
    "malicious/slow_escalation.py": dict(
        run_id="f05c8a3d", started_at=1793090588.7,
        windows=[w(boot(openat=1), sensitive=["/etc/shadow"], mem_mb=12),
                 w(), w(),
                 w(),
                 w({"socket": 4, "connect": 4, "openat": 1},
                   connects=[f"127.0.0.1:{p}" for p in (8080, 8081, 8082, 8083)]),
                 w(), w(),
                 w(),
                 w({"clone": 1, "execve": 1, "socket": 2, "connect": 2, "openat": 1},
                   execs=["/bin/sh"], connects=["127.0.0.1:9001", "127.0.0.1:9002"], pids=2),
                 w(), w(),
                 w(),
                 w({"openat": 2, "clone": 30}, sensitive=["/etc/sudoers", "/etc/shadow"],
                   forks=30, pids=16)],
        output=[(0.05, "phase 1: read /etc/shadow -> 1448 bytes"),
                (2.36, "phase 2: 4 loopback connects -> dropped, no reply, dropped, no reply, "
                       "dropped, no reply, dropped, no reply"),
                (2.36, "phase 2: write marker file -> written"),
                (4.38, "phase 3: shell exit 0; 2 connects -> dropped, no reply, dropped, no reply"),
                (4.38, "phase 3: write marker file -> Read-only file system"),
                (6.39, "phase 4: read /etc/sudoers -> 1714 bytes"),
                (6.39, "phase 4: read /etc/shadow -> 1448 bytes"),
                (6.41, "phase 4: forked 14 of 30 children"),
                (8.41, "finished without being stopped")],
        natural_end=(8.42, 0),
    ),
}


def mechanism(stage: int, run_id: str) -> str:
    return {
        1: f"nftables drops all packets from cgroup adaptbox/{run_id}",
        2: "/ remounted read-only inside the sandbox",
        3: (f"cpu.max {LIM.cpu_tight_percent}%, memory.max {LIM.memory_tight_mb} MiB, "
            f"pids.max {LIM.pids_tight}"),
        4: "cgroup.kill sent SIGKILL to every process in the group",
    }[stage]


def simulate(sample_id: str, spec: dict) -> dict:
    run_id = spec["run_id"]
    score, max_stage, mem = 0.0, 0, 0.0
    timeline, stage_log, observed = [], [], set()
    end_t, exit_code = spec.get("natural_end", (None, None))
    killed_at = None

    for i, beh in enumerate(spec["windows"]):
        t = round((i + 1) * WIN + 0.004 * (i + 1), 3)
        mem += beh["mem_mb"]
        win = BehaviorWindow(
            ts=t, syscall_counts=dict(beh["syscalls"]),
            sensitive_reads=beh["sensitive"], outbound_connects=beh["connects"],
            exec_calls=beh["execs"], fork_count=beh["forks"],
            sensitive_writes=beh["writes"], privesc_count=beh["privesc"],
            kmod_count=beh["kmod"], ptrace_count=beh["ptrace"],
            mount_count=beh["mount"], delete_count=beh["delete"], raw_socket=beh["raw"],
            cpu_delta_usec=int(sum(beh["syscalls"].values()) * 90),
            mem_current_bytes=int(max(mem, 0) * MB), mem_delta_bytes=int(beh["mem_mb"] * MB),
            pids_current=beh["pids"],
        )
        observed.update(win.syscall_counts)
        hits = evaluate(win)
        score = min(1.0, score * DECAY + min(1.0, sum(h.weight for h in hits)))
        stage = sum(score >= x for x in TH)
        for s in range(max_stage + 1, stage + 1):
            stage_log.append({"stage": s, "action": STAGES[s - 1], "t": t, "score": round(score, 3),
                              "ok": True, "detail": mechanism(s, run_id),
                              "cause": [h.reason for h in hits]})
        max_stage = max(max_stage, stage)
        timeline.append({
            "ts": t, "score": round(score, 3), "rule_contrib": round(sum(h.weight for h in hits), 3),
            "ml_contrib": 0.0, "reasons": [h.reason for h in hits], "stage": max_stage,
            "features": dict(zip(FEATURE_NAMES, win.feature_vector())),
            "syscalls": dict(win.syscall_counts),
            "hits": [{"weight": h.weight, "reason": h.reason} for h in hits],
        })
        if max_stage >= 4:
            killed_at = t
            break

    # The process ends at the earliest of: its own exit, a cgroup limit, or the
    # stage-4 kill. A kill that comes after the process already exited (a script
    # done before the first window) does not change its exit code.
    if "limit_kill" in spec and (killed_at is None or spec["limit_kill"][0] < killed_at):
        end_t, exit_code = spec["limit_kill"][0], -9
    elif killed_at is not None and (end_t is None or killed_at < end_t):
        end_t, exit_code = killed_at + 0.01, -9
    output = [{"t": round(t, 3), "line": line} for t, line in spec["output"] if t <= end_t]
    if "limit_kill" in spec and exit_code == -9 and end_t == spec["limit_kill"][0]:
        output.append({"t": end_t, "line": f"[adaptbox] {spec['limit_kill'][1]}"})
    # the controller notices the exit at its next window, so a run lasts at least one
    duration = max(end_t, timeline[-1]["ts"]) + 0.04

    result = {
        "run_id": run_id, "target": ["python3", f"{ROOT.name}/samples/{sample_id}"],
        "max_score": max((x["score"] for x in timeline), default=0.0),
        "max_stage": max_stage,
        "stage_times": {f"stage_{s['stage']}_{s['action']}": s["t"] for s in stage_log},
        "stage_log": stage_log, "exit_code": exit_code, "duration": round(duration, 3),
        "window_seconds": WIN, "thresholds": TH, "started_at": spec["started_at"],
        "timeline": timeline, "policy_path": f"runs/{run_id}/seccomp.json",
    }
    result["target"][1] = f"samples/{sample_id}"
    return {"result": result, "summary": run_summary(result),
            "policy": build_profile(observed), "output": output}


def main() -> None:
    samples = {s["id"]: s for s in list_samples()}
    runs = {sid: simulate(sid, spec) for sid, spec in SCRIPTS.items()}
    assert set(runs) == set(samples), f"scripts and samples differ: {set(runs) ^ set(samples)}"

    rows = []
    for sid, run in runs.items():
        r, s = run["result"], run["summary"]
        rows.append({
            "run_id": r["run_id"], "sample": s["sample"], "label": samples[sid]["class"],
            "max_score": round(r["max_score"], 2), "max_stage": r["max_stage"],
            "detected": r["max_stage"] >= 1,
            "time_to_containment_s": s["first_stage_t"], "duration_s": round(r["duration"], 2),
            "exit_code": r["exit_code"], "policy": r["policy_path"],
        })
    from eval.benchmark import summarise
    bench = {"rows": rows, "summary": summarise(rows), "finished_at": 1793090700.0}

    payload = {
        "note": "Simulated with AdaptBox's own scoring code; not captured from a kernel.",
        "info": {"engine": "simulated", "version": "0.1.0", "host": "recording",
                 "allow_runs": True, "busy": None, "window_seconds": WIN,
                 "thresholds": TH, "stages": STAGES},
        "samples": list(samples.values()),
        "runs": {r["result"]["run_id"]: r for r in runs.values()},
        "bySample": {sid: r["result"]["run_id"] for sid, r in runs.items()},
        "benchmark": bench,
    }
    out = ROOT / "web" / "demo-data.js"
    out.write_text("// Generated by tools/make_demo.py. Simulated, not captured from a kernel.\n"
                   "window.ADAPTBOX_DEMO = " + json.dumps(payload, separators=(",", ":")) + ";\n")
    for sid, r in runs.items():
        st = r["result"]["stage_log"]
        print(f"{sid:32s} max {r['result']['max_score']:.2f}  stage {r['result']['max_stage']}  "
              f"stages at {[s['t'] for s in st]}  exit {r['result']['exit_code']}")
    print(f"wrote {out}")


if __name__ == "__main__":
    main()
