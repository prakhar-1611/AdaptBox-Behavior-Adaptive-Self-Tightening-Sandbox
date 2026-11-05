"""Least-privilege seccomp policy generation.

After a run, AdaptBox knows exactly which syscalls the target actually made
(collected by the controller from the monitor). This module turns that observed
set into a minimal allow-list seccomp profile in the OCI / Docker JSON format,
so the same class of code can later be launched already confined — no
hand-written seccomp rules.

The generated profile defaults to SCMP_ACT_ERRNO (deny-by-default) and allows
only the observed syscalls plus a small base set every dynamically-linked
program needs to start and exit cleanly.
"""

from __future__ import annotations

import json
from pathlib import Path

# Syscalls needed for process startup/teardown that may not appear in a short
# trace but must be allowed or nothing runs. Kept deliberately small.
BASE_ALLOW: frozenset[str] = frozenset({
    "execve", "execveat", "brk", "arch_prctl", "access", "faccessat",
    "faccessat2", "openat", "open", "read", "pread64", "close", "fstat",
    "newfstatat", "stat", "lstat", "mmap", "mprotect", "munmap", "rt_sigaction",
    "rt_sigprocmask", "set_tid_address", "set_robust_list", "rseq", "prlimit64",
    "getrandom", "exit", "exit_group", "write", "futex", "getpid", "uname",
    "readlink", "readlinkat", "pread64", "lseek", "getdents64", "ioctl",
})


def build_profile(observed: set[str]) -> dict:
    """Return an OCI seccomp profile dict allowing only observed+base syscalls."""
    allowed = sorted(BASE_ALLOW | {s for s in observed if s.isidentifier()})
    return {
        "defaultAction": "SCMP_ACT_ERRNO",
        "defaultErrnoRet": 1,  # EPERM
        "archMap": [
            {
                "architecture": "SCMP_ARCH_X86_64",
                "subArchitectures": ["SCMP_ARCH_X86", "SCMP_ARCH_X32"],
            }
        ],
        "syscalls": [
            {
                "names": allowed,
                "action": "SCMP_ACT_ALLOW",
            }
        ],
        "_adaptbox": {
            "note": "auto-generated least-privilege profile",
            "observed_count": len(observed),
            "allowed_count": len(allowed),
        },
    }


def generate_policy(observed: set[str], out_dir: Path) -> Path:
    """Write the profile to <out_dir>/seccomp.json and return the path."""
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    profile = build_profile(observed)
    path = out_dir / "seccomp.json"
    path.write_text(json.dumps(profile, indent=2))
    return path


if __name__ == "__main__":  # quick manual check
    import sys
    demo = {"openat", "connect", "clone", "write", "socket"}
    print(json.dumps(build_profile(demo), indent=2))
