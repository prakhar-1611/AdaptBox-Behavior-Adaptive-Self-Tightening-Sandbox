"""The adaptive control loop: run -> monitor -> score -> respond.

Each window the controller:
  1. collects a BehaviorWindow from the monitor,
  2. computes a rule score (rules.py) and, if available, an Isolation Forest
     anomaly score (scorer.py),
  3. blends them into a running risk score with decay, and
  4. applies the highest containment stage whose threshold the score crosses.

Stages only ever ratchet up (a sandbox tightens, never loosens), matching the
report's self-tightening model. A full timeline is recorded for evaluation
(damage-before-containment, time-to-stage, etc.) and written to the run dir.

An optional on_event callback receives each step as a plain dict ("start",
"window", "stage", "end") so the dashboard server can stream a run live.
"""

from __future__ import annotations

import json
import logging
import shutil
import time
import uuid
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Callable

from .cgroups import Cgroup
from .config import RunConfig
from .events import FEATURE_NAMES, BehaviorWindow
from .monitor import make_monitor
from .rules import evaluate
from .sandbox import Sandbox

log = logging.getLogger("adaptbox.controller")

# Stage ordering; index into this list is the stage number - 1.
STAGES = ["cut_network", "block_writes", "cap_resources", "terminate"]

# strace's log must not live on the filesystem that stage 2 remounts read-only
# (the kernel refuses while a file there is open for writing), so it is written
# to a RAM filesystem and copied into the run dir when the run ends.
SHM = Path("/dev/shm")


@dataclass
class WindowRecord:
    ts: float
    score: float
    rule_contrib: float
    ml_contrib: float
    reasons: list[str]
    stage: int                      # the stage actually enforced after this window
    features: dict[str, float]
    syscalls: dict[str, int] = field(default_factory=dict)
    hits: list[dict] = field(default_factory=list)   # [{weight, reason}] from rules.py


@dataclass
class StageRecord:
    stage: int
    action: str
    t: float
    score: float
    ok: bool
    detail: str                     # what the kernel was asked to do
    cause: list[str]                # the reasons in the window that crossed it


@dataclass
class RunResult:
    run_id: str
    target: list[str]
    max_score: float = 0.0
    max_stage: int = 0
    stage_times: dict[str, float] = field(default_factory=dict)  # stage -> t since start
    stage_log: list[StageRecord] = field(default_factory=list)
    exit_code: int | None = None
    duration: float = 0.0
    window_seconds: float = 1.0
    thresholds: list[float] = field(default_factory=list)
    started_at: float = 0.0         # wall clock, for listing runs
    timeline: list[WindowRecord] = field(default_factory=list)
    policy_path: str | None = None


class Controller:
    def __init__(self, cfg: RunConfig, scorer=None,
                 on_event: Callable[[dict], None] | None = None):
        self.cfg = cfg
        self.scorer = scorer  # optional object with .score(features)->[0,1]
        self.on_event = on_event
        self.run_id = uuid.uuid4().hex[:8]
        self.cgroup = Cgroup(self.run_id, cfg.limits, dry_run=cfg.dry_run)
        self.sandbox = Sandbox(cfg, self.cgroup, self.run_id)
        self.run_dir = Path(cfg.output_dir) / self.run_id
        self.score = 0.0
        self.max_stage = 0
        self.result = RunResult(
            run_id=self.run_id,
            target=list(cfg.target),
            window_seconds=cfg.monitor.window_seconds,
            thresholds=[t for t, _ in cfg.thresholds.as_list()],
            started_at=time.time(),
        )
        self._observed_syscalls: set[str] = set()
        self._last_reasons: list[str] = []
        self._last_rule = 0.0
        self._last_ml = 0.0
        self._last_hits: list[dict] = []
        self._output: list[dict] = []   # the target's printed lines, with t

    # -- public API --------------------------------------------------------

    def run(self) -> RunResult:
        self.run_dir.mkdir(parents=True, exist_ok=True)
        if SHM.is_dir() and not self.cfg.dry_run:
            strace_out = SHM / f"adaptbox-{self.run_id}.strace.log"
        else:
            strace_out = self.run_dir / "strace.log"
        start = self._start = time.monotonic()

        self.cgroup.create()
        monitor = make_monitor(self.cgroup, self.cfg.monitor, strace_out)

        # The target enters its cgroup before it execs (see Sandbox.launch).
        pid = self.sandbox.launch(
            traced=True, strace_out=str(strace_out),
            on_output=self._on_output if self.on_event else None,
        )

        log.info("run %s started (pid=%d) in cgroup %s", self.run_id, pid, self.cgroup.path)
        self._emit({
            "type": "start", "run_id": self.run_id, "target": self.result.target,
            "pid": pid, "window_seconds": self.result.window_seconds,
            "thresholds": self.result.thresholds, "stages": STAGES,
            "started_at": self.result.started_at,
        })
        try:
            self._loop(monitor, start)
            # Final drain: capture events written between the last tick and exit
            # so the policy and timeline cover the whole run. The target is gone
            # by now, so nothing is enforced on this window.
            final = monitor.collect_window()
            self._record_syscalls(final)
            self.score = self._update_score(final, self.cfg.monitor.score_decay)
            # A very short script can finish before the first scoring window, so
            # the loop exits before any stage was applied. If the final score
            # crosses a threshold, record the stage: the behaviour was detected,
            # even though enforcement is post-mortem (damage before containment).
            final_stage = self._stage_for_score(self.score)
            if final_stage > self.max_stage:
                still_alive = self.sandbox.poll() is None and self.cgroup.alive()
                self._apply_stage(final_stage, start, enforce=still_alive)
            self._log_window(final, start)
        finally:
            monitor.stop()
            self.result.exit_code = self.sandbox.wait(timeout=2)
            self.result.duration = time.monotonic() - start
            # Say so when the memory limit, not a stage, ended the process.
            oom = self.cgroup.oom_kills()
            if oom:
                mib = self.cfg.limits.memory_tight_mb if self.max_stage >= 3 else self.cfg.limits.memory_max_mb
                msg = (f"[adaptbox] memory.max ({mib} MiB) reached: the kernel's OOM killer "
                       f"ended {oom} process{'es' if oom > 1 else ''}")
                log.warning(msg)
                self._on_output(msg)
            self.sandbox.cleanup()
            self.cgroup.destroy()
            if strace_out.parent == SHM and strace_out.exists():
                shutil.move(str(strace_out), self.run_dir / "strace.log")
            self._finalize()
        return self.result

    # -- the loop ----------------------------------------------------------

    def _loop(self, monitor, start: float) -> None:
        window = self.cfg.monitor.window_seconds
        decay = self.cfg.monitor.score_decay

        while True:
            # Stop conditions: process gone, or hard timeout.
            if self.sandbox.poll() is not None and not self.cgroup.alive():
                log.info("target exited on its own")
                break
            if time.monotonic() - start > self.cfg.timeout_seconds:
                log.warning("hard timeout reached; terminating")
                self._last_reasons = [f"hard timeout after {self.cfg.timeout_seconds:.0f} s"]
                self._apply_stage(4, start)
                break

            time.sleep(window)
            win = monitor.collect_window()
            self._record_syscalls(win)

            self.score = self._update_score(win, decay)
            stage = self._stage_for_score(self.score)
            if stage > self.max_stage:
                self._apply_stage(stage, start)
            self._log_window(win, start)
            if self.max_stage >= 4:
                break

    # -- scoring -----------------------------------------------------------

    def _update_score(self, win: BehaviorWindow, decay: float) -> float:
        hits = evaluate(win)
        rscore = sum(h.weight for h in hits)
        reasons = [h.reason for h in hits]
        self._last_hits = [{"weight": h.weight, "reason": h.reason} for h in hits]
        mscore = 0.0
        if self.scorer is not None:
            try:
                mscore = float(self.scorer.score(win.feature_vector()))
            except Exception as exc:  # noqa: BLE001
                log.debug("scorer error: %s", exc)

        # Blend: rules dominate (explainable), ML adds anomaly sensitivity.
        instant = min(1.0, rscore + 0.5 * mscore)
        # Leaky accumulator: carry a decayed fraction of the previous score and
        # add this window's signal. Sustained malicious behavior ratchets toward
        # the stage-4 kill, while a lone benign event fades below stage 1.
        # (With decay~0.6: benign single-connect steady state ~0.34 < 0.35;
        #  an attack at ~0.40/window climbs past 0.90 in a few windows.)
        blended = self.score * decay + instant
        self._last_reasons = reasons
        self._last_rule = rscore
        self._last_ml = mscore
        return min(1.0, blended)

    def _stage_for_score(self, score: float) -> int:
        stage = 0
        for i, (threshold, _name) in enumerate(self.cfg.thresholds.as_list(), start=1):
            if score >= threshold:
                stage = i
        return stage

    # -- enforcement -------------------------------------------------------

    def _apply_stage(self, stage: int, start: float, enforce: bool = True) -> None:
        for s in range(self.max_stage + 1, stage + 1):
            action = STAGES[s - 1]
            t = time.monotonic() - start
            log.warning("APPLY stage %d: %s (score=%.2f%s)", s, action, self.score,
                        "" if enforce else ", post-mortem")
            if enforce:
                ok, detail = getattr(self.sandbox, action)()
            else:
                # The script finished before this stage could lock. It was still
                # detected; the live action is moot on a process that has exited.
                ok, detail = False, "score crossed after the process had already exited"
            self.result.stage_times.setdefault(f"stage_{s}_{action}", t)
            rec = StageRecord(stage=s, action=action, t=round(t, 3),
                              score=round(self.score, 3), ok=ok, detail=detail,
                              cause=list(self._last_reasons))
            self.result.stage_log.append(rec)
            self._emit({"type": "stage", "run_id": self.run_id, **asdict(rec)})
        self.max_stage = max(self.max_stage, stage)
        self.result.max_stage = self.max_stage

    # -- bookkeeping -------------------------------------------------------

    def _record_syscalls(self, win: BehaviorWindow) -> None:
        self._observed_syscalls.update(win.syscall_counts.keys())

    def _log_window(self, win: BehaviorWindow, start: float) -> None:
        feats = dict(zip(FEATURE_NAMES, win.feature_vector()))
        rec = WindowRecord(
            ts=round(time.monotonic() - start, 3),
            score=round(self.score, 3),
            rule_contrib=round(self._last_rule, 3),
            ml_contrib=round(self._last_ml, 3),
            reasons=list(self._last_reasons),
            stage=self.max_stage,
            features=feats,
            syscalls=dict(win.syscall_counts),
            hits=list(self._last_hits),
        )
        self.result.timeline.append(rec)
        self.result.max_score = max(self.result.max_score, self.score)
        self._emit({"type": "window", "run_id": self.run_id, **asdict(rec)})
        if rec.reasons:
            log.info("t=%.1fs score=%.2f stage=%d :: %s",
                     rec.ts, self.score, self.max_stage, "; ".join(rec.reasons))

    def _on_output(self, line: str) -> None:
        rec = {"t": round(time.monotonic() - self._start, 3), "line": line}
        self._output.append(rec)
        self._emit({"type": "output", "run_id": self.run_id, **rec})

    def _emit(self, event: dict) -> None:
        if self.on_event is None:
            return
        try:
            self.on_event(event)
        except Exception as exc:  # noqa: BLE001 - a UI must never break a run
            log.debug("event listener error: %s", exc)

    def _finalize(self) -> None:
        # Generate the least-privilege policy from observed syscalls, then write
        # the run result as JSON for the evaluation harness and the dashboard.
        try:
            from .policy import generate_policy
            path = generate_policy(self._observed_syscalls, self.run_dir)
            self.result.policy_path = str(path)
            log.info("least-privilege policy written to %s", path)
        except ImportError:
            log.debug("policy module not present yet; skipping policy generation")

        (self.run_dir / "result.json").write_text(json.dumps(asdict(self.result), indent=2))
        if self._output:
            (self.run_dir / "output.json").write_text(json.dumps(self._output, indent=1))
        log.info("run %s finished: max_score=%.2f max_stage=%d exit=%s (%.1fs)",
                 self.run_id, self.result.max_score, self.result.max_stage,
                 self.result.exit_code, self.result.duration)
        self._emit({
            "type": "end", "run_id": self.run_id, "max_score": self.result.max_score,
            "max_stage": self.result.max_stage, "exit_code": self.result.exit_code,
            "duration": round(self.result.duration, 3),
            "policy_path": self.result.policy_path,
        })
