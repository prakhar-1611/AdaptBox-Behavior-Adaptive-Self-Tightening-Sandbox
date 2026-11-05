"""Debug: parse a saved strace.log offline and report what AdaptBox would see.

    python3 tools/parse_check.py runs/<run-id>/strace.log

Isolates parser correctness from the live-collection path.
"""
import sys
from adaptbox.cgroups import Cgroup
from adaptbox.config import Limits, MonitorConfig
from adaptbox.monitor import StraceMonitor

path = sys.argv[1]
m = StraceMonitor(Cgroup("dbg", Limits(), dry_run=True), MonitorConfig(), path)

total = matched = 0
with open(path, errors="replace") as fh:
    for line in fh:
        total += 1
        if m.LINE_RE.match(line):
            matched += 1
            m._parse(line.rstrip("\n"))

w = m.collect_window()
print(f"total lines     : {total}")
print(f"matched lines   : {matched}")
print(f"syscall counts  : {dict(list(w.syscall_counts.items())[:12])}")
print(f"sensitive reads : {w.sensitive_reads}")
print(f"outbound conn.  : {w.outbound_connects}")
print(f"exec calls      : {w.exec_calls}")
print(f"fork count      : {w.fork_count}")
if matched == 0 and total:
    print("\n!! parser matched nothing — first non-empty line was:")
    for line in open(path, errors="replace"):
        if line.strip():
            print("   ", repr(line[:120]))
            break
