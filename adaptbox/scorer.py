"""Isolation Forest anomaly scorer.

The rule engine is precise but only knows the behaviors we anticipated. The
Isolation Forest adds unsupervised sensitivity: trained on feature vectors from
*benign* runs, it flags windows that look unlike normal behavior, even patterns
no rule covers. Its output is mapped to [0, 1] (0 = looks normal, 1 = strongly
anomalous) and blended into the running score by the controller.

Training data is the per-window feature vectors (events.FEATURE_NAMES order)
collected from benign sample runs. See eval/train_scorer.py.

sklearn is imported lazily so a machine without it (or without a trained model)
simply runs rules-only; load_default_scorer() returns None in that case and the
controller degrades gracefully.
"""

from __future__ import annotations

import logging
from pathlib import Path

log = logging.getLogger("adaptbox.scorer")

DEFAULT_MODEL_PATH = Path(__file__).with_name("models") / "iforest.joblib"


class IForestScorer:
    """Wraps a fitted IsolationForest and maps its output to [0, 1]."""

    def __init__(self, model, lo: float, hi: float):
        self._model = model
        # Calibration bounds on decision_function over benign training data,
        # used to normalise anomaly scores into [0, 1].
        self._lo = lo
        self._hi = hi

    def score(self, features: list[float]) -> float:
        import numpy as np  # lazy

        # decision_function: higher = more normal. Negate so higher = anomalous.
        raw = -float(self._model.decision_function(np.array([features]))[0])
        span = (self._hi - self._lo) or 1.0
        norm = (raw - self._lo) / span
        return max(0.0, min(1.0, norm))

    # -- persistence -------------------------------------------------------

    def save(self, path: Path = DEFAULT_MODEL_PATH) -> Path:
        import joblib  # lazy
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump({"model": self._model, "lo": self._lo, "hi": self._hi}, path)
        return path

    @classmethod
    def load(cls, path: Path = DEFAULT_MODEL_PATH) -> "IForestScorer":
        import joblib  # lazy
        blob = joblib.load(Path(path))
        return cls(blob["model"], blob["lo"], blob["hi"])


def train(feature_rows: list[list[float]], contamination: float = 0.02) -> IForestScorer:
    """Fit an IsolationForest on benign feature vectors and calibrate bounds."""
    import numpy as np  # lazy
    from sklearn.ensemble import IsolationForest  # lazy

    X = np.array(feature_rows, dtype=float)
    if X.ndim != 2 or len(X) < 10:
        raise ValueError("need at least 10 benign feature rows to train")

    model = IsolationForest(
        n_estimators=200, contamination=contamination, random_state=0
    )
    model.fit(X)

    # Calibrate the [0,1] mapping from the benign spread, NOT from min..max:
    # using the max would map the single most-unusual benign window to 1.0 and
    # let it false-positive. Instead 70% of benign maps to ~0, and the scale is
    # set well above the benign range, so only behaviour beyond benign scores high.
    raw = -model.decision_function(X)
    lo = float(np.percentile(raw, 70))
    span = max(float(np.percentile(raw, 99)) - lo, 1e-6)
    hi = lo + 4.0 * span
    log.info("trained IsolationForest on %d rows; calib [%.3f, %.3f]", len(X), lo, hi)
    return IForestScorer(model, lo, hi)


def load_default_scorer() -> IForestScorer | None:
    """Load the shipped model if present; else None (controller runs rules-only)."""
    if DEFAULT_MODEL_PATH.exists():
        try:
            return IForestScorer.load()
        except Exception as exc:  # noqa: BLE001
            log.warning("failed to load scorer model: %s", exc)
    return None
