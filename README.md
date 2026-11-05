# AdaptBox

A behavior-adaptive, self-tightening OS-level sandbox for untrusted (e.g. AI-generated) code.

AdaptBox runs an untrusted script under a **loose** profile inside Linux namespaces and
its own cgroup, watches what it does at runtime, converts that behavior into a live
**risk score**, and **tightens confinement in stages** as the score rises:

1. revoke network access
2. block file writes
3. cap CPU and memory
4. terminate the process

Benign code never crosses the thresholds and runs normally. After each run AdaptBox
emits a minimal least-privilege seccomp policy for that class of code.

> Platform: Linux (developed for Kali), stock kernel, no kernel rebuild. Python tooling.

## Status

Early scaffold. Build order (something runnable at each step):

- [x] Project structure
- [x] Isolation layer (`sandbox.py`) — namespaces + cgroups v2 + seccomp
- [x] Monitor (`monitor.py`) — strace backend first, eBPF/BCC backend next
- [x] Rule-based risk score (`rules.py`)
- [x] Graduated controller (`controller.py`) — network → writes → CPU/mem → kill
- [x] Sample scripts (`samples/`) — benign + the 5 threat classes
- [x] Isolation Forest scorer (`scorer.py`) + training helper (`eval/train_scorer.py`)
- [x] Policy generator (`policy.py`) — OCI seccomp allow-list
- [x] Evaluation harness (`eval/benchmark.py`) — detection / FP / time-to-contain
- [x] Web dashboard (`adaptbox/server.py` + `web/`) — live score, the stage ratchet, replay, benchmark
- [ ] eBPF/BCC monitor backend (currently strace; eBPF is a stub)
- [ ] Baseline comparison runs vs Docker default / static seccomp

## Layout

```
adaptbox/        core package
  sandbox.py     launches target under namespaces + cgroup; the 4 live stages
  monitor.py     reads strace output into per-window behaviour summaries
  rules.py       rule-based risk contributions
  scorer.py      Isolation Forest anomaly score
  controller.py  the run→monitor→score→respond loop; emits events for the UI
  policy.py      least-privilege seccomp policy generation
  server.py      dashboard server: web UI + live event stream (stdlib only)
  cli.py         command-line entry point
web/             the dashboard (plain HTML/CSS/JS, no build step)
samples/
  benign/        harmless scripts that must run uncontained
  malicious/     the threat classes, each self-limited & loopback-only
eval/            benchmark harness, scorer training
tools/           make_demo.py (offline recordings), parse_check.py (strace debug)
```

## Dashboard

The engine runs in Kali; the dashboard opens in a browser on Windows.

**1. On Kali** (from the project folder):

```bash
sudo python3 -m adaptbox.server
```

**2. One-time VirtualBox port forward**, so Windows can reach it:
Settings → Network → Adapter 1 (NAT) → Advanced → Port Forwarding → **+**

| Name | Protocol | Host IP | Host Port | Guest IP | Guest Port |
|---|---|---|---|---|---|
| adaptbox | TCP | 127.0.0.1 | 8765 | *(blank)* | 8765 |

**3. On Windows**, open **http://localhost:8765**.

Screens: **Live** (run a sample, watch the score and the four-stage ratchet lock),
**Test your own code** (paste a Python/shell script and have AdaptBox judge it),
**Runs** (every saved run, replayable, with its generated seccomp policy),
**Benchmark** (all samples, detection and false positives),
**How it works** (the loop, following one system call).

Code submitted through **Test your own code** is treated as fully untrusted: it
runs as the unprivileged `nobody` user (via `setpriv`, no new privileges), in a
throwaway `/tmp` folder deleted after the run, under the same cgroup limits and
timeout as the samples. Only `.py`/`.sh`, up to 200 KB. This needs `setpriv`
(util-linux, already installed in setup) and the `nobody` user (present by
default on Kali).

If the engine can't be reached, the dashboard says so and replays **simulated
recordings** instead (built by `tools/make_demo.py` with AdaptBox's own scoring
code, not captured from a kernel). Add `?engine=demo` to the URL to force them.

## Quick start (inside the Kali VM)

```bash
# one-time setup — see SETUP.md
sudo python3 -m adaptbox.cli run samples/benign/compute.py
sudo python3 -m adaptbox.cli run samples/malicious/read_secrets.py
```

Root is required for cgroup, namespace and seccomp operations.

## Threats detected

The rule engine (`adaptbox/rules.py`) flags these OS-level danger classes, each
tied to a system-call signal, tuned so ordinary code never trips them:

secret-file read · write to a system/persistence path (`/etc`, cron, systemd,
login files, `authorized_keys`) · privilege escalation (`setuid` to root) ·
kernel-module load · filesystem/container escape (`mount`, `chroot`, `pivot_root`) ·
process injection (`ptrace`) · shell spawn · raw/packet socket · outbound
connect · port scan · fork bomb · memory exhaustion · mass file deletion.
An Isolation Forest adds anomaly sensitivity on top.

## Safety

The scripts under `samples/malicious/` are **contained test fixtures** for evaluating
AdaptBox's detection and containment. They are intentionally harmless: network samples
target loopback or a dummy address only, the fork and memory samples are self-capped,
and all are meant to be run inside a disposable VM with a snapshot taken first.
