"""Train the Isolation Forest so the ML anomaly score goes live.

    sudo python3 tools/train_model.py            # 8 runs of each benign sample
    sudo python3 tools/train_model.py 12         # more runs = more training data

It runs the benign samples a number of times, collects the per-window feature
vectors they produce, fits the Isolation Forest on them, and saves the model to
adaptbox/models/iforest.joblib. From then on the engine loads it automatically
and the risk score includes the ML anomaly term (rules + 0.5 x anomaly).

Needs root (real cgroup/strace runs) and scikit-learn. The model is one file:
delete it to go back to rules-only (see the printed note at the end).
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from adaptbox.config import Limits, MonitorConfig, RunConfig, Thresholds  # noqa: E402
from adaptbox.controller import Controller  # noqa: E402
from adaptbox.events import FEATURE_NAMES  # noqa: E402
from adaptbox.scorer import train  # noqa: E402

BENIGN_DIR = ROOT / "samples" / "benign"


def main() -> int:
    repeats = int(sys.argv[1]) if len(sys.argv) > 1 else 8
    samples = sorted(BENIGN_DIR.glob("*.py"))
    if not samples:
        print("no benign samples found"); return 1

    print(f"collecting behaviour from {len(samples)} benign samples x {repeats} runs ...")
    rows: list[list[float]] = []
    for script in samples:
        for i in range(repeats):
            cfg = RunConfig(
                target=["python3", str(script)], workdir=ROOT,
                limits=Limits(), thresholds=Thresholds(),
                monitor=MonitorConfig(backend="auto", window_seconds=0.5),
                output_dir=ROOT / "runs", timeout_seconds=20,
            )
            res = Controller(cfg).run()           # no scorer during collection
            for w in res.timeline:
                rows.append([float(w.features.get(n, 0.0)) for n in FEATURE_NAMES])
        print(f"  {script.name}: total {len(rows)} windows so far")

    if len(rows) < 10:
        print(f"only {len(rows)} windows collected; need at least 10. Try a higher repeat count.")
        return 1

    print(f"\ntraining Isolation Forest on {len(rows)} benign windows ...")
    scorer = train(rows)
    path = scorer.save()
    print(f"saved model to {path}")

    # Sanity check: benign should score LOW, obvious malware HIGH.
    benign_scores = [scorer.score(r) for r in rows]
    bmax = max(benign_scores); bmean = sum(benign_scores) / len(benign_scores)
    # a clearly malicious window (sensitive reads + forks + connects)
    mal = [0.0] * len(FEATURE_NAMES)
    idx = {n: k for k, n in enumerate(FEATURE_NAMES)}
    mal[idx["sensitive_reads"]] = 5; mal[idx["fork_count"]] = 50
    mal[idx["outbound_connects"]] = 30; mal[idx["total_syscalls"]] = 2000
    mscore = scorer.score(mal)
    print(f"\nsanity check:")
    print(f"  benign windows  anomaly: mean {bmean:.2f}, max {bmax:.2f}  (want low)")
    print(f"  malicious window anomaly: {mscore:.2f}  (want high)")
    if bmax > 0.6:
        print("  WARNING: some benign windows score high. If the benchmark then shows")
        print("           benign false positives, delete the model (command below).")
    print("\nThe ML is now live. Restart the server to load it:")
    print("  sudo pkill -f adaptbox.server ; cd ~/adaptbox && sudo -v && \\")
    print("  sudo nohup python3 -m adaptbox.server > /tmp/adaptbox.log 2>&1 &")
    print("\nTo turn the ML back off at any time (revert to rules-only):")
    print(f"  rm {path}  ; then restart the server")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
