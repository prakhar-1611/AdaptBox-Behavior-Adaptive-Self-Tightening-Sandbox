"""Benign: ordinary file processing in the working directory.

Writes, reads back, and summarises a few files it created itself. Touches no
sensitive paths, makes no network calls. Should run uncontained (max stage 0).
"""

import os


def main() -> None:
    os.makedirs("workspace", exist_ok=True)
    total = 0
    for i in range(20):
        path = os.path.join("workspace", f"part_{i:02d}.txt")
        with open(path, "w") as fh:
            fh.write(f"record {i}\n" * (i + 1))
    for name in sorted(os.listdir("workspace")):
        with open(os.path.join("workspace", name)) as fh:
            total += len(fh.read())
    print(f"processed workspace: {total} bytes across 20 files")


if __name__ == "__main__":
    main()
