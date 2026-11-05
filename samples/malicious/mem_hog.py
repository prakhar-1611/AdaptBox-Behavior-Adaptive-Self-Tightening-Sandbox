"""Threat class: memory exhaustion.

TEST FIXTURE — bounded. Allocates memory in chunks to trigger fast RSS growth.
It stops at a hard cap and handles MemoryError, so on an uncontained host it
won't wedge the VM; under AdaptBox, memory.max (stage 3) or the OOM killer stops
it first. The fast mem growth per window is the signal AdaptBox detects.

Run only inside a disposable VM.
"""

import time

CHUNK_MB = 64
HARD_CAP_MB = 4096          # never allocate beyond this even if uncontained


def main() -> None:
    blocks = []
    allocated = 0
    try:
        while allocated < HARD_CAP_MB:
            # Touch every page so the pages are actually resident (RSS grows).
            blocks.append(bytearray(CHUNK_MB * 1024 * 1024))
            for i in range(0, len(blocks[-1]), 4096):
                blocks[-1][i] = 1
            allocated += CHUNK_MB
            print(f"allocated {allocated} MiB")
            time.sleep(0.05)
    except MemoryError:
        print(f"MemoryError at {allocated} MiB — contained")
    print(f"stopped at {allocated} MiB")


if __name__ == "__main__":
    main()
