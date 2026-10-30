#!/usr/bin/env python3
"""Reproduce the detector's measured false-positive and recall figures.

    python3 scripts/calibrate.py [corpus_dir]

With no argument it reports recall only (generated credentials). Point it at a
large body of ordinary source - a Python checkout, a stdlib directory, a
monorepo - and it also reports the false-positive rate, which is the number
that decides whether the entropy detector is usable.

Nothing here is needed at runtime; it exists so the figures quoted in the
README can be re-derived rather than trusted.
"""
from __future__ import annotations

import os
import random
import string
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import scanner  # noqa: E402

SECRET_KEYS = ["API_KEY", "SECRET_KEY", "DB_PASSWORD", "auth_token", "ACCESS_TOKEN",
               "private_key", "apiKey", "session_secret", "client_secret",
               "encryption_key", "SIGNING_KEY", "redis_password", "jwt_secret"]
NEUTRAL_KEYS = ["value", "data", "config", "payload", "result", "blob", "content", "x"]
HEX = "0123456789abcdef"
B62 = string.ascii_letters + string.digits


def rnd(alphabet: str, n: int) -> str:
    return "".join(random.choice(alphabet) for _ in range(n))


def generate_leaks(n: int = 400, keys=SECRET_KEYS) -> list[str]:
    out = []
    for _ in range(n):
        key = random.choice(keys)
        val = rnd(random.choice([HEX, B62]), random.choice([32, 40, 43, 64]))
        out.append(f"{key} = {val}")
    return out


def generate_prefixed(n: int = 200) -> list[str]:
    shapes = [lambda: f"ghp_{rnd(B62, 36)}", lambda: f"AKIA{rnd(string.ascii_uppercase + string.digits, 16)}",
              lambda: f"sk_live_{rnd(B62, 24)}", lambda: f"xoxb-{rnd(B62, 20)}",
              lambda: f"npm_{rnd(B62, 36)}", lambda: f"sk-ant-{rnd(B62, 24)}"]
    return [f"K = {random.choice(shapes)()}" for _ in range(n)]


def detected(line: str) -> bool:
    return bool(scanner.Scanner().scan_line(line, 1, "generated"))


def report_recall() -> None:
    suites = [("secret-named key leaks", generate_leaks(400)),
              ("neutral-named key leaks", generate_leaks(200, NEUTRAL_KEYS)),
              ("prefixed credentials", generate_prefixed(200))]
    print("RECALL on generated credentials")
    for name, cases in suites:
        hits = sum(1 for c in cases if detected(c))
        print(f"  {name:<26} {hits}/{len(cases)}  ({100 * hits / len(cases):.1f}%)")


def report_precision(corpus: str) -> None:
    lines: list[str] = []
    files = 0
    for root, dirs, names in os.walk(corpus):
        dirs[:] = [d for d in dirs if d not in scanner.SKIP_DIRS]
        for name in names:
            if not name.lower().endswith(scanner.DEFAULT_EXTENSIONS):
                continue
            path = os.path.join(root, name)
            try:
                with open(path, encoding="utf-8", errors="ignore") as fh:
                    lines.extend(fh.readlines())
                files += 1
            except OSError:
                continue
    flagged = [ln for ln in lines if detected(ln)]
    print(f"\nFALSE POSITIVES on {corpus}")
    print(f"  files read          {files}")
    print(f"  lines read          {len(lines)}")
    print(f"  lines flagged       {len(flagged)}")
    if lines:
        print(f"  rate                {100 * len(flagged) / len(lines):.4f}% of lines")
    print("  (each flagged line needs human review; a rate above ~0.1% makes the")
    print("   detector too noisy to leave on in CI)")
    for ln in flagged[:15]:
        print(f"    {ln.strip()[:96]}")


def main(argv: list[str]) -> int:
    random.seed(2026)
    report_recall()
    if argv:
        report_precision(argv[0])
    else:
        print("\n(no corpus given - pass a source tree to measure false positives)")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
