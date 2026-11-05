"""Threat class: sensitive file reads.

TEST FIXTURE — harmless. It only attempts to *open and read* well-known
sensitive paths and prints how many bytes it could read. It exfiltrates nothing
and modifies nothing. The point is to produce `openat` calls on protected paths
so AdaptBox's rule engine flags it and stages containment.

Run only inside a disposable VM.
"""

import os

TARGETS = [
    "/etc/shadow",
    "/etc/sudoers",
    os.path.expanduser("~/.ssh/id_rsa"),
    os.path.expanduser("~/.aws/credentials"),
    "/proc/self/environ",
]


def main() -> None:
    for path in TARGETS:
        try:
            with open(path, "rb") as fh:
                data = fh.read()
            print(f"READ {path}: {len(data)} bytes")
        except OSError as exc:
            print(f"DENIED {path}: {exc}")


if __name__ == "__main__":
    main()
