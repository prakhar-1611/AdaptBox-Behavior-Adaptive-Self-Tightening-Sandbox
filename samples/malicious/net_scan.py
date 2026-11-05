"""Threat class: network scan.

TEST FIXTURE — harmless. Makes many short connection attempts to ports on
loopback (127.0.0.1) only. It touches no external host. The burst of connect()
calls is the signal AdaptBox detects (stage-1 network cut should then stop
further attempts).

Run only inside a disposable VM.
"""

import socket

HOST = "127.0.0.1"          # loopback only — never an external target
PORTS = range(1, 1025)      # a burst of short-lived connects


def main() -> None:
    attempted = 0
    for port in PORTS:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.05)
        try:
            s.connect((HOST, port))
        except OSError:
            pass
        finally:
            s.close()
        attempted += 1
    print(f"attempted {attempted} loopback connects")


if __name__ == "__main__":
    main()
