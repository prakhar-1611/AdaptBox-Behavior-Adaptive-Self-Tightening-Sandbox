"""Benign: a single, legitimate outbound connection.

Many honest scripts make one network call (e.g. an API request). One connect is
below the stage-1 threshold, so this should run uncontained and demonstrates
that AdaptBox does not punish ordinary network use. Targets loopback so it needs
no internet and produces no external traffic.
"""

import socket


def main() -> None:
    # Attempt a single connection to a local port. Success or refusal both fine;
    # the point is exactly one connect() in the whole run.
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(1.0)
    try:
        s.connect(("127.0.0.1", 80))
        print("connected to 127.0.0.1:80")
    except OSError as exc:
        print(f"single connect attempt finished: {exc}")
    finally:
        s.close()


if __name__ == "__main__":
    main()
