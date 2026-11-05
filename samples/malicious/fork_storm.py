"""Threat class: fork bomb.

TEST FIXTURE — self-capped. A real fork bomb spawns processes without limit; to
keep the fixture safe to run even if containment were off, this one stops after
a hard cap on total children and a wall-clock limit. The burst of clone/fork in
a short window is the signal AdaptBox detects, and the cgroup pids.max is what
actually contains it.

Run only inside a disposable VM.
"""

import os
import time

MAX_CHILDREN = 2000         # hard safety cap
TIME_LIMIT_S = 5.0          # hard safety cap


def main() -> None:
    start = time.time()
    spawned = 0
    while spawned < MAX_CHILDREN and (time.time() - start) < TIME_LIMIT_S:
        try:
            pid = os.fork()
        except OSError:
            # pids.max reached — this is AdaptBox containing us.
            break
        if pid == 0:
            # Child: sleep briefly, then exit so we don't truly exhaust the host.
            time.sleep(0.2)
            os._exit(0)
        spawned += 1
    print(f"parent spawned {spawned} children (cap {MAX_CHILDREN})")


if __name__ == "__main__":
    main()
