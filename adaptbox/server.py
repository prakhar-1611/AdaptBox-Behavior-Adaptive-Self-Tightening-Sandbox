"""Dashboard server: serves the web UI and streams AdaptBox runs live.

    sudo python3 -m adaptbox.server                 # on Kali, real runs
    python3 -m adaptbox.server --no-runs            # anywhere: saved runs only

Then open http://localhost:8765 (from Windows, through a VirtualBox port
forward of host 8765 -> guest 8765).

Standard library only. The browser can start runs, but only of the scripts in
samples/, chosen by exact name: the server runs as root and never accepts a
command or a path from the network.

API
  GET  /api/info              engine status, thresholds, whether runs are allowed
  GET  /api/samples           the sample scripts, with their class and description
  GET  /api/runs              saved runs, newest first (summary rows)
  GET  /api/runs/<id>         one run: result, policy, the target's output
  POST /api/runs              {"sample": "malicious/read_secrets.py"} -> starts a run
  GET  /api/benchmark         the last benchmark summary (404 if none yet)
  POST /api/benchmark         runs every sample in turn, streaming each one
  GET  /api/stream            Server-Sent Events: start, window, stage, output, end,
                              bench_start, bench_row, bench_end, busy
"""

from __future__ import annotations

import argparse
import ast
import json
import logging
import os
import queue
import re
import shutil
import sys
import tempfile
import threading
import time
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

from . import __version__
from .config import Limits, MonitorConfig, RunConfig, Thresholds
from .controller import STAGES, Controller

log = logging.getLogger("adaptbox.server")

ROOT = Path(__file__).resolve().parent.parent
WEB = ROOT / "web"
SAMPLES = ROOT / "samples"
RUNS = ROOT / "runs"
BENCH = ROOT / "eval" / "results" / "summary.json"
RUN_ID = re.compile(r"^[0-9a-f]{8}$")

# The dashboard scores twice a second so each stage is seen as it happens.
WINDOW_SECONDS = 0.5
TIMEOUT_SECONDS = 30.0

# Code submitted through the dashboard ("Test your own code").
CUSTOM_PREFIX = "adaptbox-custom-"
CUSTOM_MAX_BYTES = 200_000
CUSTOM_NAME = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.-]{0,63}\.(py|sh)$")
NOBODY = 65534          # uid/gid of nobody/nogroup on Debian and Kali

MIME = {
    ".html": "text/html; charset=utf-8", ".css": "text/css; charset=utf-8",
    ".js": "text/javascript; charset=utf-8", ".json": "application/json",
    ".svg": "image/svg+xml", ".png": "image/png", ".ico": "image/x-icon",
    ".woff2": "font/woff2",
}


# ---------------------------------------------------------------------------
# Event hub: fan one stream of events out to every connected browser
# ---------------------------------------------------------------------------


class Hub:
    def __init__(self) -> None:
        self._clients: set[queue.Queue] = set()
        self._lock = threading.Lock()
        # Events of the run in progress, so a browser that connects mid-run
        # (or reloads) catches up instead of seeing half a chart.
        self._current: list[dict] = []

    def subscribe(self) -> queue.Queue:
        q: queue.Queue = queue.Queue(maxsize=2000)
        with self._lock:
            self._clients.add(q)
            for ev in self._current:
                q.put_nowait(ev)
        return q

    def unsubscribe(self, q: queue.Queue) -> None:
        with self._lock:
            self._clients.discard(q)

    def publish(self, event: dict) -> None:
        with self._lock:
            if event.get("type") == "start":
                self._current = []
            if event.get("type") in ("start", "window", "stage", "output"):
                self._current.append(event)
            elif event.get("type") == "end":
                self._current = []
            for q in list(self._clients):
                try:
                    q.put_nowait(event)
                except queue.Full:       # a stalled tab; drop it
                    self._clients.discard(q)


# ---------------------------------------------------------------------------
# Samples, runs, benchmark
# ---------------------------------------------------------------------------


def list_samples() -> list[dict]:
    try:
        catalog = json.loads((SAMPLES / "catalog.json").read_text())
    except (OSError, ValueError):
        catalog = {}
    out = []
    for cls in ("benign", "malicious"):
        for path in sorted((SAMPLES / cls).glob("*.py")):
            try:
                doc = ast.get_docstring(ast.parse(path.read_text())) or ""
            except (SyntaxError, OSError):
                doc = ""
            first = doc.strip().splitlines()[0] if doc.strip() else ""
            # "Threat class: network scan." -> "network scan"
            kind = re.sub(r"^(Threat class|Benign):\s*", "", first).rstrip(".")
            sid = f"{cls}/{path.name}"
            info = catalog.get(sid, {})
            out.append({"id": sid, "name": path.name, "class": cls, "kind": kind,
                        "why": info.get("why", ""), "does": info.get("does", ""),
                        "expect": info.get("expect", "")})
    return out


def sample_label(target: list[str]) -> tuple[str, str]:
    """(class, file name) for a run's target argv."""
    path = Path(target[-1]) if target else Path("")
    folder = path.parent.name
    if folder.startswith(CUSTOM_PREFIX):
        return "custom", path.name
    return (folder if folder in ("benign", "malicious") else "other"), path.name


def run_summary(result: dict) -> dict:
    cls, name = sample_label(result.get("target", []))
    stages = result.get("stage_log") or []
    return {
        "run_id": result["run_id"], "sample": name, "class": cls,
        "started_at": result.get("started_at"),
        "max_score": result.get("max_score", 0.0),
        "max_stage": result.get("max_stage", 0),
        "first_stage_t": stages[0]["t"] if stages else None,
        "duration": result.get("duration", 0.0),
        "exit_code": result.get("exit_code"),
    }


def list_runs() -> list[dict]:
    rows = []
    for f in RUNS.glob("*/result.json"):
        try:
            rows.append(run_summary(json.loads(f.read_text())))
        except (OSError, ValueError, KeyError):
            continue
    rows.sort(key=lambda r: r.get("started_at") or 0, reverse=True)
    return rows


def load_run(run_id: str) -> dict | None:
    d = RUNS / run_id
    try:
        result = json.loads((d / "result.json").read_text())
    except (OSError, ValueError):
        return None
    out = {"result": result, "summary": run_summary(result), "policy": None, "output": [], "code": None}
    for key, name in (("policy", "seccomp.json"), ("output", "output.json")):
        try:
            out[key] = json.loads((d / name).read_text())
        except (OSError, ValueError):
            pass
    try:                                    # what was submitted, for custom runs
        out["code"] = (d / "submitted.txt").read_text(errors="replace")
    except OSError:
        pass
    return out


class Runner:
    """Runs one thing at a time: a single sample, or the whole benchmark."""

    def __init__(self, hub: Hub, allow_runs: bool):
        self.hub = hub
        self.allow_runs = allow_runs
        self._lock = threading.Lock()
        self.busy: str | None = None    # "run:<sample>" or "benchmark"

    def _config(self, sample: dict) -> RunConfig:
        return RunConfig(
            target=["python3", str(SAMPLES / sample["id"])],
            workdir=ROOT,
            limits=Limits(), thresholds=Thresholds(),
            monitor=MonitorConfig(backend="auto", window_seconds=WINDOW_SECONDS),
            output_dir=RUNS, timeout_seconds=TIMEOUT_SECONDS,
        )

    def _scorer(self):
        try:
            from .scorer import load_default_scorer
            return load_default_scorer()
        except Exception:  # noqa: BLE001 - rules-only is a valid mode
            return None

    def _claim(self, what: str) -> bool:
        with self._lock:
            if self.busy:
                return False
            self.busy = what
        self.hub.publish({"type": "busy", "busy": what})
        return True

    def _release(self) -> None:
        with self._lock:
            self.busy = None
        self.hub.publish({"type": "busy", "busy": None})

    def start_sample(self, sample: dict) -> str | None:
        if not self._claim(f"run:{sample['id']}"):
            return None
        ctl = Controller(self._config(sample), scorer=self._scorer(), on_event=self._tag(sample))
        threading.Thread(target=self._run_one, args=(ctl,), daemon=True).start()
        return ctl.run_id

    def _tag(self, sample: dict):
        def emit(ev: dict) -> None:
            ev.setdefault("sample", sample["id"])
            ev.setdefault("class", sample["class"])
            self.hub.publish(ev)
        return emit

    def _run_one(self, ctl: Controller, scratch: Path | None = None) -> None:
        try:
            ctl.run()
        except Exception as exc:  # noqa: BLE001
            log.exception("run failed")
            self.hub.publish({"type": "error", "run_id": ctl.run_id, "message": str(exc)})
        finally:
            if scratch is not None:
                shutil.rmtree(scratch, ignore_errors=True)
            self._release()

    def start_custom(self, filename: str, code: str) -> str | None:
        """Run code pasted or uploaded in the dashboard. It is truly untrusted, so
        on top of everything a sample gets it runs as nobody (no new privileges),
        in a throwaway folder in /tmp that is deleted afterwards."""
        if not self._claim(f"run:custom/{filename}"):
            return None
        try:
            scratch = Path(tempfile.mkdtemp(prefix=CUSTOM_PREFIX))
            script = scratch / filename
            script.write_text(code)
            os.chmod(script, 0o644)
            os.chown(scratch, NOBODY, NOBODY)        # its only writable folder
            interp = "python3" if filename.endswith(".py") else "/bin/sh"
            cfg = RunConfig(
                target=[interp, str(script)], workdir=scratch,
                limits=Limits(), thresholds=Thresholds(),
                monitor=MonitorConfig(backend="auto", window_seconds=WINDOW_SECONDS),
                output_dir=RUNS, timeout_seconds=TIMEOUT_SECONDS, run_as=NOBODY,
            )
            tag = {"id": f"custom/{filename}", "class": "custom"}
            ctl = Controller(cfg, scorer=self._scorer(), on_event=self._tag(tag))
            ctl.run_dir.mkdir(parents=True, exist_ok=True)
            (ctl.run_dir / "submitted.txt").write_text(code)
        except Exception:
            self._release()
            raise
        threading.Thread(target=self._run_one, args=(ctl, scratch), daemon=True).start()
        return ctl.run_id

    def start_benchmark(self) -> bool:
        if not self._claim("benchmark"):
            return False
        threading.Thread(target=self._bench, daemon=True).start()
        return True

    def _bench(self) -> None:
        sys.path.insert(0, str(ROOT))
        from eval.benchmark import row_from_result, summarise, to_markdown
        samples = list_samples()
        self.hub.publish({"type": "bench_start", "samples": [s["id"] for s in samples]})
        rows: list[dict] = []
        try:
            for s in samples:
                ctl = Controller(self._config(s), scorer=self._scorer(), on_event=self._tag(s))
                res = ctl.run()
                row = row_from_result(SAMPLES / s["id"], s["class"], res)
                rows.append(row)
                self.hub.publish({"type": "bench_row", "row": row})
                time.sleep(0.5)       # a beat between runs, so each is seen
            summary = summarise(rows)
            BENCH.parent.mkdir(parents=True, exist_ok=True)
            BENCH.write_text(json.dumps({"rows": rows, "summary": summary,
                                         "finished_at": time.time()}, indent=2))
            (BENCH.parent / "summary.md").write_text(to_markdown(rows, summary))
            self.hub.publish({"type": "bench_end", "summary": summary})
        except Exception as exc:  # noqa: BLE001
            log.exception("benchmark failed")
            self.hub.publish({"type": "error", "message": f"benchmark stopped: {exc}"})
        finally:
            self._release()


# ---------------------------------------------------------------------------
# HTTP
# ---------------------------------------------------------------------------


def make_handler(hub: Hub, runner: Runner):
    class Handler(BaseHTTPRequestHandler):
        server_version = f"AdaptBox/{__version__}"

        def log_message(self, fmt, *args):  # quieter console
            log.debug("%s - %s", self.address_string(), fmt % args)

        # -- helpers -------------------------------------------------------

        def _cors(self) -> None:
            # The UI may also be opened from a file on Windows and talk to the
            # engine through the port forward; everything here is local.
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Access-Control-Allow-Headers", "Content-Type")
            self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")

        def _json(self, payload, status=HTTPStatus.OK) -> None:
            body = json.dumps(payload).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self._cors()
            self.end_headers()
            self.wfile.write(body)

        def _error(self, status, message) -> None:
            self._json({"error": message}, status)

        def _body(self) -> dict:
            n = int(self.headers.get("Content-Length") or 0)
            if n <= 0 or n > CUSTOM_MAX_BYTES * 2:   # JSON escaping can double code
                return {}
            try:
                return json.loads(self.rfile.read(n))
            except ValueError:
                return {}

        # -- routes --------------------------------------------------------

        def do_OPTIONS(self):
            self.send_response(HTTPStatus.NO_CONTENT)
            self._cors()
            self.end_headers()

        def do_GET(self):
            path = urlparse(self.path).path
            if path == "/api/info":
                return self._json({
                    "engine": "live", "version": __version__,
                    "host": os.uname().nodename if hasattr(os, "uname") else "",
                    "allow_runs": runner.allow_runs, "busy": runner.busy,
                    "window_seconds": WINDOW_SECONDS,
                    "thresholds": [t for t, _ in Thresholds().as_list()],
                    "stages": STAGES,
                })
            if path == "/api/samples":
                return self._json(list_samples())
            if path == "/api/runs":
                return self._json(list_runs())
            if path.startswith("/api/runs/"):
                run_id = path.rsplit("/", 1)[-1]
                run = load_run(run_id) if RUN_ID.match(run_id) else None
                return self._json(run) if run else self._error(HTTPStatus.NOT_FOUND, "no such run")
            if path == "/api/benchmark":
                try:
                    return self._json(json.loads(BENCH.read_text()))
                except (OSError, ValueError):
                    return self._error(HTTPStatus.NOT_FOUND, "no benchmark yet")
            if path == "/api/stream":
                return self._stream()
            return self._static(path)

        def do_POST(self):
            path = urlparse(self.path).path
            if path in ("/api/runs", "/api/benchmark") and not runner.allow_runs:
                return self._error(HTTPStatus.FORBIDDEN,
                                   "runs are off: start the server as root on Linux")
            if path == "/api/runs":
                body = self._body()
                if "code" in body:                          # "Test your own code"
                    code, name = body.get("code"), str(body.get("filename") or "")
                    if not isinstance(code, str) or not code.strip():
                        return self._error(HTTPStatus.BAD_REQUEST, "no code given")
                    if len(code.encode()) > CUSTOM_MAX_BYTES:
                        return self._error(HTTPStatus.BAD_REQUEST, "code is over 200 KB")
                    if not CUSTOM_NAME.match(name):
                        return self._error(HTTPStatus.BAD_REQUEST,
                                           "file name must end in .py or .sh and use only letters, digits, _ . -")
                    run_id = runner.start_custom(name, code)
                    if run_id is None:
                        return self._error(HTTPStatus.CONFLICT, f"busy: {runner.busy}")
                    return self._json({"run_id": run_id}, HTTPStatus.ACCEPTED)
                want = body.get("sample")
                sample = next((s for s in list_samples() if s["id"] == want), None)
                if sample is None:
                    return self._error(HTTPStatus.BAD_REQUEST, "unknown sample")
                run_id = runner.start_sample(sample)
                if run_id is None:
                    return self._error(HTTPStatus.CONFLICT, f"busy: {runner.busy}")
                return self._json({"run_id": run_id}, HTTPStatus.ACCEPTED)
            if path == "/api/benchmark":
                if not runner.start_benchmark():
                    return self._error(HTTPStatus.CONFLICT, f"busy: {runner.busy}")
                return self._json({"started": True}, HTTPStatus.ACCEPTED)
            return self._error(HTTPStatus.NOT_FOUND, "no such endpoint")

        def _stream(self):
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Connection", "keep-alive")
            self._cors()
            self.end_headers()
            q = hub.subscribe()
            try:
                self.wfile.write(b"retry: 2000\n\n")
                self.wfile.flush()
                while True:
                    try:
                        ev = q.get(timeout=15)
                        data = f"data: {json.dumps(ev)}\n\n"
                    except queue.Empty:
                        data = ": keep-alive\n\n"
                    self.wfile.write(data.encode())
                    self.wfile.flush()
            except (BrokenPipeError, ConnectionResetError, OSError):
                pass
            finally:
                hub.unsubscribe(q)

        def _static(self, path: str):
            rel = "index.html" if path in ("", "/") else path.lstrip("/")
            target = (WEB / rel).resolve()
            if WEB.resolve() not in target.parents and target != WEB.resolve() / "index.html":
                return self._error(HTTPStatus.NOT_FOUND, "not found")
            if not target.is_file():
                return self._error(HTTPStatus.NOT_FOUND, "not found")
            body = target.read_bytes()
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", MIME.get(target.suffix, "application/octet-stream"))
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)

    return Handler


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="adaptbox.server", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--host", default="0.0.0.0")
    ap.add_argument("--port", type=int, default=8765)
    ap.add_argument("--no-runs", action="store_true",
                    help="serve the UI and saved runs only; never start a run")
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args(argv)
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
                        datefmt="%H:%M:%S")

    is_root = hasattr(os, "geteuid") and os.geteuid() == 0
    allow_runs = is_root and not args.no_runs
    if not allow_runs and not args.no_runs:
        log.warning("not running as root on Linux: runs are off, saved runs only")

    hub = Hub()
    runner = Runner(hub, allow_runs)
    RUNS.mkdir(parents=True, exist_ok=True)
    httpd = ThreadingHTTPServer((args.host, args.port), make_handler(hub, runner))
    httpd.daemon_threads = True
    print(f"\nAdaptBox dashboard on http://localhost:{args.port}  "
          f"(runs {'on' if allow_runs else 'off'})  Ctrl+C to stop\n")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
