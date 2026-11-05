"""Evaluation harness.

Runs every benign and malicious sample under AdaptBox and summarises the metrics
the report calls for:

  * detection rate        -- malicious samples that reached stage >= 1
  * containment stage     -- highest stage each sample reached
  * time-to-containment   -- t of the first applied stage
  * false-positive rate   -- benign samples that reached stage >= 1
  * per-run overhead       -- wall-clock duration (vs a baseline later)

Usage (inside the Kali VM, as root for real enforcement):

    sudo python3 -m eval.benchmark
    python3 -m eval.benchmark --dry-run      # logic check, unprivileged

Results are printed as a table and written to eval/results/summary.{json,md}.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from adaptbox.config import Limits, MonitorConfig, RunConfig, Thresholds
from adaptbox.controller import Controller
from adaptbox.scorer import load_default_scorer

ROOT = Path(__file__).resolve().parent.parent
BENIGN_DIR = ROOT / "samples" / "benign"
MALICIOUS_DIR = ROOT / "samples" / "malicious"
RESULTS_DIR = Path(__file__).resolve().parent / "results"


def _samples(d: Path) -> list[Path]:
    return sorted(d.glob("*.py"))


def run_one(script: Path, label: str, args) -> dict:
    cfg = RunConfig(
        target=["python3", str(script)],
        limits=Limits(),
        thresholds=Thresholds(),
        monitor=MonitorConfig(backend=args.backend, window_seconds=args.window),
        output_dir=RESULTS_DIR / "runs",
        timeout_seconds=args.timeout,
        dry_run=args.dry_run,
    )
    scorer = None if args.no_ml else load_default_scorer()
    res = Controller(cfg, scorer=scorer).run()
    return row_from_result(script, label, res)


def row_from_result(script: Path, label: str, res) -> dict:
    """One benchmark row from a finished run (shared with the dashboard server)."""
    first_stage_t = min(res.stage_times.values()) if res.stage_times else None
    return {
        "run_id": res.run_id,
        "sample": script.name,
        "label": label,                         # "benign" | "malicious"
        "max_score": round(res.max_score, 2),
        "max_stage": res.max_stage,
        "detected": res.max_stage >= 1,
        "time_to_containment_s": round(first_stage_t, 2) if first_stage_t else None,
        "duration_s": round(res.duration, 2),
        "exit_code": res.exit_code,
        "policy": res.policy_path,
    }


def summarise(rows: list[dict]) -> dict:
    mal = [r for r in rows if r["label"] == "malicious"]
    ben = [r for r in rows if r["label"] == "benign"]
    detected = [r for r in mal if r["detected"]]
    false_pos = [r for r in ben if r["detected"]]
    return {
        "malicious_total": len(mal),
        "malicious_detected": len(detected),
        "detection_rate": round(len(detected) / len(mal), 2) if mal else None,
        "benign_total": len(ben),
        "false_positives": len(false_pos),
        "false_positive_rate": round(len(false_pos) / len(ben), 2) if ben else None,
        "avg_time_to_containment_s": round(
            sum(r["time_to_containment_s"] or 0 for r in detected) / len(detected), 2
        ) if detected else None,
    }


def to_markdown(rows: list[dict], summary: dict) -> str:
    lines = ["# AdaptBox evaluation\n", "| sample | class | score | stage | detected | t-contain | dur |",
             "|---|---|---|---|---|---|---|"]
    for r in rows:
        lines.append(
            f"| {r['sample']} | {r['label']} | {r['max_score']} | {r['max_stage']} "
            f"| {'yes' if r['detected'] else 'no'} | {r['time_to_containment_s']} "
            f"| {r['duration_s']}s |"
        )
    lines += [
        "\n## Summary\n",
        f"- detection rate: **{summary['detection_rate']}** "
        f"({summary['malicious_detected']}/{summary['malicious_total']})",
        f"- false-positive rate: **{summary['false_positive_rate']}** "
        f"({summary['false_positives']}/{summary['benign_total']})",
        f"- avg time-to-containment: **{summary['avg_time_to_containment_s']}s**",
    ]
    return "\n".join(lines) + "\n"


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--backend", choices=["auto", "ebpf", "strace"], default="auto")
    ap.add_argument("--timeout", type=float, default=30.0)
    ap.add_argument("--window", type=float, default=1.0)
    ap.add_argument("--no-ml", action="store_true")
    args = ap.parse_args(argv)

    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    rows: list[dict] = []
    for s in _samples(BENIGN_DIR):
        print(f"\n--- benign: {s.name} ---")
        rows.append(run_one(s, "benign", args))
    for s in _samples(MALICIOUS_DIR):
        print(f"\n--- malicious: {s.name} ---")
        rows.append(run_one(s, "malicious", args))

    summary = summarise(rows)
    (RESULTS_DIR / "summary.json").write_text(
        json.dumps({"rows": rows, "summary": summary}, indent=2))
    md = to_markdown(rows, summary)
    (RESULTS_DIR / "summary.md").write_text(md)
    print("\n" + md)
    print(f"written to {RESULTS_DIR}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
