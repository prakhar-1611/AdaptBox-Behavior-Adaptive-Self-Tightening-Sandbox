"""Threat class: reverse shell / exfiltration (behavioral signature only).

TEST FIXTURE — harmless by construction. A real reverse shell connects out and
wires a shell's stdin/stdout to the socket. To exercise AdaptBox's detector
WITHOUT creating a usable backdoor, this fixture only reproduces the observable
OS-level *signature* of that behavior:

  * one outbound connect() to loopback (127.0.0.1), and
  * an execve() of /bin/sh

but the shell runs a fixed harmless command and is NOT connected to the socket,
so there is no interactive channel and nothing is exfiltrated. This is enough
for the rule engine (exec-of-shell + outbound connect) to raise the score and
for the controller to stage containment.

Run only inside a disposable VM.
"""

import os
import socket

HOST = "127.0.0.1"          # loopback only
PORT = 9999                 # typically no listener; connect may be refused


def main() -> None:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(1.0)
    try:
        s.connect((HOST, PORT))
        print(f"connected to {HOST}:{PORT}")
    except OSError as exc:
        print(f"connect to {HOST}:{PORT} failed (expected): {exc}")
    finally:
        s.close()

    # Reproduce the execve(/bin/sh) signal with a harmless, non-interactive
    # command. Deliberately NOT duping the socket onto the shell's fds.
    print("exec /bin/sh with a harmless command (signature only)")
    os.execv("/bin/sh", ["/bin/sh", "-c", "echo adaptbox-fixture-shell; exit 0"])


if __name__ == "__main__":
    main()
