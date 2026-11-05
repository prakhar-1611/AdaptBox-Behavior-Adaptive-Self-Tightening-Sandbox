"""Threat class: staged intrusion (escalates over several seconds).

TEST FIXTURE — harmless. Every other fixture does its one bad thing at once, so
AdaptBox jumps straight to a high stage. This one behaves the way a real
intrusion often does, a little worse every couple of seconds, so each
containment stage can be watched locking in on a process that is still running:

  phase 1  reads one secret file            -> expected stage 1 (network cut)
  phase 2  tries a few loopback connects     -> expected stage 2 (writes blocked)
  phase 3  spawns a shell and connects again -> expected stage 3 (CPU/memory capped)
  phase 4  reads secrets and bursts forks    -> expected stage 4 (killed)

It prints what each phase managed to do, so the effect of the previous stage is
visible (connects time out after the network cut, the write fails after the
remount, forks hit pids.max after the cap). Loopback only; forks are capped and
exit immediately. Run only inside a disposable VM.
"""

import os
import select
import socket
import subprocess
import time

GAP_S = 2.0                 # time between phases, so each stage is seen apart


def connect_burst(ports: list[int]) -> str:
    """Start every connect at once (non-blocking) so they land in one scoring
    window, then wait briefly to see what happened to them."""
    socks = []
    for port in ports:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setblocking(False)
        s.connect_ex(("127.0.0.1", port))
        socks.append(s)
    _, done, _ = select.select([], socks, [], 0.3)
    outcomes = []
    for s in socks:
        if s in done:
            err = s.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
            outcomes.append("connected" if err == 0 else os.strerror(err).lower())
        else:
            outcomes.append("dropped, no reply")
        s.close()
    return ", ".join(outcomes)


def try_write(name: str) -> str:
    try:
        with open(name, "w") as fh:
            fh.write("staged intrusion marker\n")
        return "written"
    except OSError as exc:
        return exc.strerror or str(exc)


def read_secret(path: str) -> str:
    try:
        with open(path, "rb") as fh:
            return f"{len(fh.read())} bytes"
    except OSError as exc:
        return exc.strerror or str(exc)


def main() -> None:
    print("phase 1: read /etc/shadow ->", read_secret("/etc/shadow"), flush=True)
    time.sleep(GAP_S)

    print("phase 2: 4 loopback connects ->", connect_burst([8080, 8081, 8082, 8083]), flush=True)
    print("phase 2: write marker file ->", try_write("escalation_marker.txt"), flush=True)
    time.sleep(GAP_S)

    shell = subprocess.run(["/bin/sh", "-c", "true"]).returncode
    print(f"phase 3: shell exit {shell}; 2 connects ->", connect_burst([9001, 9002]), flush=True)
    print("phase 3: write marker file ->", try_write("escalation_marker.txt"), flush=True)
    time.sleep(GAP_S)

    print("phase 4: read /etc/sudoers ->", read_secret("/etc/sudoers"), flush=True)
    print("phase 4: read /etc/shadow ->", read_secret("/etc/shadow"), flush=True)
    forked = 0
    for _ in range(30):
        try:
            pid = os.fork()
        except OSError:
            break               # pids.max reached
        if pid == 0:
            os._exit(0)
        forked += 1
    print(f"phase 4: forked {forked} of 30 children", flush=True)
    time.sleep(GAP_S)
    print("finished without being stopped", flush=True)


if __name__ == "__main__":
    main()
