"""Threat class: persistence and privilege escalation.

TEST FIXTURE — harmless. It attempts the classic "stay on the box and become
root" moves, so AdaptBox's system-write and privilege-escalation rules fire. All
of them fail (the sandbox runs it unprivileged), but AdaptBox scores the attempt:

  * append an attacker key to ~/.ssh/authorized_keys  (a back door login)
  * drop a cron job in /etc/cron.d                     (scheduled re-execution)
  * append a command to ~/.bashrc                      (run on next shell)
  * call setuid(0)                                      (become root)

It writes nothing outside these protected paths and makes no network calls.
Run only inside a disposable VM.
"""

import os

ATTACKER_KEY = "ssh-rsa AAAAB3NzaC1yc2E...adaptbox-fixture attacker@evil\n"


def try_write(path: str, text: str) -> None:
    try:
        with open(os.path.expanduser(path), "a") as fh:
            fh.write(text)
        print(f"WROTE {path}")
    except OSError as exc:
        print(f"DENIED {path}: {exc.strerror}")


def main() -> None:
    try_write("~/.ssh/authorized_keys", ATTACKER_KEY)
    try_write("/etc/cron.d/adaptbox-fixture", "* * * * * root /tmp/x\n")
    try_write("~/.bashrc", "\n# adaptbox-fixture\n")

    try:
        os.setuid(0)
        print("setuid(0) succeeded — now root")
    except OSError as exc:
        print(f"setuid(0) denied: {exc.strerror}")


if __name__ == "__main__":
    main()
