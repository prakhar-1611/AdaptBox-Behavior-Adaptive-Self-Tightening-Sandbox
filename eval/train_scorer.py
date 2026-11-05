"""Train the Isolation Forest scorer from benign run timelines.

Collects per-window feature vectors from the result.json files produced by
benign runs, fits the model (scorer.train), and saves it to the default path so
load_default_scorer() picks it up on the next run.

Usage (after running benign samples at least once to produce result.json files):

    python3 -m eval.train_scorer runs/            # dir of run folders
    python3 -m eval.train_scorer eval/results/runs/
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from adaptbox.events import FEATURE_NAMES
from adaptbox.scorer import train


def collect_features(runs_dir: Path) -> list[list[float]]:
    rows: list[list[float]] = []
    for result in runs_dir.glob("*/result.json"):
        data = json.loads(result.read_text())
        for win in data.get("timeline", []):
            feats = win.get("features", {})
            rows.append([float(feats.get(name, 0.0)) for name in FEATURE_NAMES])
    return rows


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("runs_dir", help="directory containing <run-id>/result.json")
    ap.add_argument("--contamination", type=float, default=0.02)
    args = ap.parse_args(argv)

    rows = collect_features(Path(args.runs_dir))
    print(f"collected {len(rows)} benign feature windows")
    scorer = train(rows, contamination=args.contamination)
    path = scorer.save()
    print(f"model saved to {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
