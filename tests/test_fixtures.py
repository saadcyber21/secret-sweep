"""End-to-end gates on the fixtures.

These are the tests CI actually depends on. `fixtures/clean` is committed and
must produce nothing; the dirty tree is generated at test time by
`scripts/make_dirty_fixture.py` (see fixtures/README.md for why) and must
produce findings and exit 1.

Without both directions a detector can silently stop detecting and the build
stays green - which is exactly the failure this repo shipped with originally.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCANNER = os.path.join(ROOT, "scanner.py")
CLEAN = os.path.join(ROOT, "fixtures", "clean")
GENERATOR = os.path.join(ROOT, "scripts", "make_dirty_fixture.py")

sys.path.insert(0, ROOT)
import scanner  # noqa: E402


def make_dirty() -> str:
    out = subprocess.run([sys.executable, GENERATOR], capture_output=True, text=True, check=True)
    return out.stdout.strip().splitlines()[-1]


def run(*args):
    r = subprocess.run([sys.executable, SCANNER, *args], capture_output=True, text=True, cwd=ROOT)
    return r.returncode, r.stdout, r.stderr


# ------------------------------------------------------------------ clean side

def test_clean_fixture_exits_zero():
    code, out, err = run(CLEAN, "--no-color", "--allowlist", os.devnull)
    assert code == 0, f"clean fixture produced findings:\n{out}\n{err}"
    assert "No secrets detected" in out


def test_clean_fixture_has_no_findings():
    assert scanner.Scanner().scan_path(CLEAN) == []


def test_clean_fixture_actually_gets_scanned():
    """Guard the guard: if the clean fixture were empty or skipped, the test
    above would pass without exercising anything."""
    files = scanner.iter_scannable_files(CLEAN)
    assert len(files) >= 3, files
    assert sum(os.path.getsize(f) for f in files) > 500


# ------------------------------------------------------------------ dirty side

def test_dirty_fixture_exits_one():
    dirty = make_dirty()
    try:
        code, _, _ = run(dirty, "--no-color", "--allowlist", os.devnull)
        assert code == 1, f"expected exit 1, got {code}"
    finally:
        shutil.rmtree(dirty, ignore_errors=True)


def test_dirty_fixture_findings():
    dirty = make_dirty()
    try:
        findings = scanner.Scanner().scan_path(dirty)
        rules = {f["rule"] for f in findings}
        for expected in ("AWS Access Key ID", "AWS Secret Access Key", "GitHub Token",
                         "Stripe Secret Key", "Slack Token", "Google API Key",
                         "Private Key Block", "high-entropy-value"):
            assert expected in rules, f"{expected} not detected; got {sorted(rules)}"
        assert len(findings) >= 12, f"expected >=12 findings, got {len(findings)}"
    finally:
        shutil.rmtree(dirty, ignore_errors=True)


def test_dirty_fixture_is_reproducible():
    """The generator is seeded, so two runs must be byte-identical. Without
    this the gates above could pass by luck on one machine and fail on another.
    """
    a, b = make_dirty(), make_dirty()
    try:
        for name in sorted(os.listdir(a)):
            assert open(os.path.join(a, name), "rb").read() == \
                   open(os.path.join(b, name), "rb").read(), name
    finally:
        shutil.rmtree(a, ignore_errors=True)
        shutil.rmtree(b, ignore_errors=True)


def test_every_dirty_finding_has_a_usable_location():
    """A finding you cannot navigate to is not actionable."""
    dirty = make_dirty()
    try:
        findings = scanner.Scanner().scan_path(dirty)
        assert findings
        for f in findings:
            assert os.path.isfile(f["file"]), f["file"]
            lines = open(f["file"], encoding="utf-8").readlines()
            assert 1 <= f["line"] <= len(lines), f
            assert f["column"] >= 1, f
            assert f["line"] == 1 or lines[f["line"] - 1].strip(), f"points at a blank line: {f}"
    finally:
        shutil.rmtree(dirty, ignore_errors=True)


def test_no_raw_secret_appears_in_output():
    """Regression: the original scanner printed the first 20 characters of every
    secret it found, copying leaked credentials into the CI log - which is
    typically less protected than the file they leaked from."""
    dirty = make_dirty()
    try:
        raw = []
        for name in os.listdir(dirty):
            for line in open(os.path.join(dirty, name), encoding="utf-8"):
                raw += scanner.TOKEN.findall(line)
        raw = [t for t in raw if len(t) >= 20]
        assert raw, "no candidate secrets to check"
        for fmt in (["--no-color"], ["--json"]):
            _, out, _ = run(dirty, *fmt, "--allowlist", os.devnull)
            for value in raw:
                assert value not in out, f"raw secret leaked into {fmt} output"
    finally:
        shutil.rmtree(dirty, ignore_errors=True)


def test_generator_writes_into_a_temp_location_by_default():
    """The generated tree must not land inside the repository, or a later commit
    would try to push real-format secrets."""
    dirty = make_dirty()
    try:
        assert os.path.abspath(dirty) != os.path.abspath(ROOT)
        assert ".dirty-fixture" in dirty or tempfile.gettempdir() in dirty
    finally:
        shutil.rmtree(dirty, ignore_errors=True)


# ------------------------------------------------------------------ allowlist

def test_allowlist_suppresses_a_reviewed_finding():
    with tempfile.TemporaryDirectory() as tmp:
        target = os.path.join(tmp, "tree")
        os.makedirs(target)
        value = "AKIA" + "Z7QW9E2R4T6Y8U1I"          # built, never written literally
        open(os.path.join(target, "cfg.env"), "w").write(f"K = {value}\n")
        assert run(target, "--no-color", "--allowlist", os.devnull)[0] == 1
        allow = os.path.join(tmp, "allow")
        open(allow, "w").write("AKIA\n")
        assert run(target, "--no-color", "--allowlist", allow)[0] == 0
