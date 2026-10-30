#!/usr/bin/env python3
"""CI gate: fail if detector recall drops below the published floor.

The unit tests cover specific shapes. This covers the aggregate: 800 generated
credentials across the realistic leak patterns, with a floor set slightly below
the measured rate so ordinary refactors pass but a broken detector does not.

Exit codes: 0 recall within floor, 1 recall regressed, 2 harness broke.
"""
from __future__ import annotations

import os
import random
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

MIN_RECALL = {
    "secret-named key leaks": 0.95,
    "neutral-named key leaks": 0.90,
    "prefixed credentials": 0.98,
}


def main() -> int:
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    import scanner
    from calibrate import SECRET_KEYS, NEUTRAL_KEYS, generate_leaks, generate_prefixed

    random.seed(2026)
    suites = {
        "secret-named key leaks": generate_leaks(400, SECRET_KEYS),
        "neutral-named key leaks": generate_leaks(200, NEUTRAL_KEYS),
        "prefixed credentials": generate_prefixed(200),
    }
    s = scanner.Scanner()
    failed = False
    print(f"{'suite':<26}{'recall':>9}{'floor':>8}   status")
    for name, cases in suites.items():
        hits = sum(1 for c in cases if s.scan_line(c, 1, "generated"))
        recall = hits / len(cases)
        floor = MIN_RECALL[name]
        ok = recall >= floor
        failed |= not ok
        print(f"{name:<26}{recall:>8.3f} {floor:>8.2f}   {'ok' if ok else 'REGRESSED'}")
        if not ok:
            missed = [c for c in cases if not s.scan_line(c, 1, "generated")][:3]
            for m in missed:
                print(f"    missed: {m}")
    if failed:
        print("\nrecall fell below the published floor", file=sys.stderr)
        return 1
    print("\nrecall within floor")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as exc:  # harness broke, distinct from a recall failure
        print(f"recall harness failed to run: {exc}", file=sys.stderr)
        sys.exit(2)
