"""Command-line entry point.

    sudo python3 -m adaptbox.cli run samples/benign/compute.py
    sudo python3 -m adaptbox.cli run --dry-run samples/malicious/read_secrets.py
    sudo python3 -m adaptbox.cli run -- python3 -c 'print(1)'

Root is required for real runs (cgroup, namespace, nft, nsenter). Use --dry-run
to exercise the control loop without enforcing, which works unprivileged.
"""

from __future__ import annotations

import argparse
import logging
import os
import sys
from pathlib import Path

from .config import Limits, MonitorConfig, RunConfig, Thresholds
from .controller import Controller


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="adaptbox", description=__doc__)
    sub = p.add_subparsers(dest="cmd", required=True)

    r = sub.add_parser("run", help="sandbox and run a target script/command")
    r.add_argument("target", nargs=argparse.REMAINDER,
                   help="script or command to run (use -- to pass flags)")
    r.add_argument("--dry-run", action="store_true",
                   help="log decisions without enforcing (works unprivileged)")
    r.add_argument("--backend", choices=["auto", "ebpf", "strace"], default="auto")
    r.add_argument("--timeout", type=float, default=60.0)
    r.add_argument("--window", type=float, default=1.0,
                   help="seconds between re-scores")
    r.add_argument("--no-ml", action="store_true",
                   help="disable the Isolation Forest scorer, rules only")
    r.add_argument("--output-dir", default="runs")
    r.add_argument("-v", "--verbose", action="store_true")
    return p


def _load_scorer(enabled: bool):
    if not enabled:
        return None
    try:
        from .scorer import load_default_scorer
        return load_default_scorer()
    except Exception as exc:  # noqa: BLE001
        logging.getLogger("adaptbox").info(
            "ML scorer unavailable (%s); running rules-only", exc)
        return None


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )
    log = logging.getLogger("adaptbox")

    target = [t for t in args.target if t != "--"]
    if not target:
        log.error("no target given")
        return 2
    # If it's a .py file, run it with python3.
    if len(target) == 1 and target[0].endswith(".py"):
        target = ["python3", target[0]]

    if not args.dry_run and os.geteuid() != 0:
        log.error("real runs need root; re-run with sudo, or pass --dry-run")
        return 1

    cfg = RunConfig(
        target=target,
        limits=Limits(),
        thresholds=Thresholds(),
        monitor=MonitorConfig(backend=args.backend, window_seconds=args.window),
        output_dir=Path(args.output_dir),
        timeout_seconds=args.timeout,
        dry_run=args.dry_run,
    )

    scorer = _load_scorer(enabled=not args.no_ml)
    result = Controller(cfg, scorer=scorer).run()

    print(f"\n=== AdaptBox run {result.run_id} ===")
    print(f"target       : {' '.join(result.target)}")
    print(f"max score    : {result.max_score:.2f}")
    print(f"max stage    : {result.max_stage} "
          f"({'contained' if result.max_stage else 'ran free'})")
    for name, t in result.stage_times.items():
        print(f"  {name:28s} at t={t:.2f}s")
    print(f"exit code    : {result.exit_code}")
    print(f"duration     : {result.duration:.1f}s")
    if result.policy_path:
        print(f"policy       : {result.policy_path}")
    print(f"details      : {cfg.output_dir}/{result.run_id}/result.json")
    return 0


if __name__ == "__main__":
    sys.exit(main())
