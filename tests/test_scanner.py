"""Tests for secret-sweep. Run: python3 tests/run_tests.py

All credential-shaped constants are generated from a fixed seed at import time.
Two reasons: GitHub push protection correctly rejects committed realistic-format
secrets (see fixtures/README.md), and hand-typed fixtures keep being the wrong
length - a generated token is valid by construction.
"""
from __future__ import annotations

import json
import os
import random
import string
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import scanner
from scanner import (EXIT_CLEAN, EXIT_ERROR, EXIT_SECRETS, Scanner, detect_random_secret,
                     looks_random, mask, shannon_entropy)

_RNG = random.Random(20260101)
_B62 = string.ascii_letters + string.digits
_HEX = "0123456789abcdef"
_B36 = string.ascii_uppercase + string.digits
_B64 = _B62 + "+/"


def _rnd(alphabet, n):
    return "".join(_RNG.choice(alphabet) for _ in range(n))


AWS_KEY = "AKIA" + _rnd(_B36, 16)
AWS_SECRET = _rnd(_B62, 40)
GH_TOKEN = "ghp_" + _rnd(_B62, 36)
SLACK_TOKEN = "xoxb-" + _rnd(_B62, 24)
STRIPE_KEY = "sk_live_" + _rnd(_B62, 24)
NPM_TOKEN = "npm_" + _rnd(_B62, 36)
OPENAI_KEY = "sk-" + _rnd(_B62, 32)
ANTHROPIC_KEY = "sk-ant-" + _rnd(_B62, 32)
GOOGLE_KEY = "AIza" + _rnd(_B62, 35)
PYPI_TOKEN = "pypi-AgEIcHlwaS5vcmc" + _rnd(_B64, 80)
JWT = "eyJ" + _rnd(_B62, 20) + "." + _rnd(_B62, 20) + "." + _rnd(_B62, 20)
HEX64 = _rnd(_HEX, 64)
HEX32 = _rnd(_HEX, 32)
RANDOM_B62 = _rnd(_B62, 35)  # secretsweep:allow
# Built by concatenation so the literal header never appears in this file.
PRIVATE_KEY_HEADER = "-----" + "BEGIN RSA PRIVATE KEY" + "-----"

# ---------------------------------------------------------------- entropy maths

def test_entropy_empty_is_zero():
    assert shannon_entropy("") == 0.0


def test_entropy_single_char_is_zero():
    assert shannon_entropy("aaaaaaaa") == 0.0


def test_entropy_uniform_binary_is_one_bit():
    assert abs(shannon_entropy("ab") - 1.0) < 1e-9


def test_entropy_is_bounded_by_log2_alphabet():
    assert shannon_entropy(RANDOM_B62) <= math_log2(62) + 1e-9


def math_log2(n):
    import math
    return math.log2(n)


def test_entropy_higher_for_random_than_for_english():
    assert shannon_entropy(RANDOM_B62) > shannon_entropy("internationalization")


def test_old_fixed_threshold_missed_real_secrets():
    """Regression: the previous `entropy > 4.5` test was unreachable for
    tokens shorter than 24 characters (max entropy is log2(len)), and it also
    missed longer low-alphabet tokens. Both are common credential shapes."""
    for token in (AWS_KEY, HEX32):
        assert shannon_entropy(token) <= 4.5, f"precondition failed for {token}"
        assert looks_random(token)[0], f"detector still misses {token}"


IDENTIFIER_SHAPES = ["MAX_RETRY_ATTEMPTS_CONFIG", "DATABASE_CONNECTION_STRING",
                     "some_snake_case_variable_name", "get_user_credentials_from_vault"]


def test_identifier_shapes_never_flagged():
    for ident in IDENTIFIER_SHAPES:
        assert scanner.is_probable_identifier(ident), ident
        assert not detect_random_secret(ident)[0], ident


def test_probable_identifier_filter():
    assert scanner.is_probable_identifier("MAX_RETRY_ATTEMPTS_CONFIG")
    assert scanner.is_probable_identifier("some_snake_case_variable_name")
    assert not scanner.is_probable_identifier(RANDOM_B62)
    assert not scanner.is_probable_identifier(HEX64)
    assert not scanner.is_probable_identifier("xoxb123456789012aBcDeFgHiJkLmNoPqRsTuVwX")


def test_uppercase_random_secret_with_digits_still_caught():
    """The identifier filter keys on underscores/ALL-CAPS-letters, not on case,
    so a genuinely random uppercase alphanumeric token is still detected."""
    tok = "Q7W9E2R4X6Y8V1B3N5M0K9J8H7G6F5D4S"  # secretsweep:allow
    assert not scanner.is_probable_identifier(tok)
    assert Scanner().scan_line(f"K = {tok}", 1, "x")


def test_dashed_uuids_are_not_secrets():
    u = "550e8400-e29b-41d4-a716-446655440000"
    assert not looks_random(u)[0]
    assert Scanner().scan_line(f"request_id = {u}", 1, "x") == []


def test_undashed_hex_digest_still_detected():
    """A 32-char hex run is a plausible secret; it must not be waved through
    as a UUID just because its nibbles happen to fit the UUID layout."""
    assert looks_random("5d41402abc4b2a76b9719d911017c592")[0]


# ------------------------------------------------------------------- detector

REAL_SECRETS = {
    "aws_access_key": AWS_KEY,
    "aws_secret_key": AWS_SECRET,
    "slack_token": "xoxb913570248aQxKf3mZpL7wRtYvN2sHj",
    "hex64_sha256": HEX64,
    "hex32_random": "9f3c1a7e5b2d8460ca13fe97d5b20864",
    "jwt_signature": "9cXk2mQ7sTu4xYz0138567aBcDe9g",
    "random_alnum_35": RANDOM_B62,
    "random_b62_40": "7Kp2mXq9Ls4vNw8Rt1Yb6Hj3Df5Gc0EaZuIoPx",
    
}
BENIGN_STRINGS = {
    "snake_case": "database_connection_pool_size",
    "camelCase": "getUserNameFromSession",
    "CONSTANT": "MAX_RETRY_ATTEMPTS_CONFIG",
    "english_compound": "authentication_authorization_encryption",
    "class_name": "SecretsScannerConfiguration",
    "function_name": "validate_user_credentials",
    "long_word": "internationalization",
    "uuid_dashed": "550e8400-e29b-41d4-a716-446655440000",
    "abs_path": "/usr/local/bin/python311",
    "timestamp": "20261030T123456789Z",
    "base64_of_english": "dGhpcyBpcyBhIHRlc3Q",
    "short": "abc123",
}


def test_detector_catches_every_real_secret_shape():
    """REAL_SECRETS holds *unprefixed* random material - the entropy layer's job."""
    missed = [k for k, v in REAL_SECRETS.items() if not detect_random_secret(v)[0]]
    assert not missed, f"detector missed: {missed}"


def test_prefixed_tokens_are_owned_by_the_pattern_layer():
    """The entropy layer deliberately rejects tokens containing `_` or `-`,
    because those are identifier syntax. Prefixed credentials are therefore the
    pattern layer's responsibility - verify each one is actually caught there,
    so the two layers leave no gap between them."""
    for line in (f"v = {GH_TOKEN}", f"v = {SLACK_TOKEN}", f"v = {STRIPE_KEY}",
                 f"v = {NPM_TOKEN}", f"v = {ANTHROPIC_KEY}", f"v = {GOOGLE_KEY}",
                 f"v = {PYPI_TOKEN}", f"v = {JWT}", f"v = {AWS_KEY}"):
        f = Scanner().scan_line(line, 1, "x")
        assert any(x["detector"] == "pattern" for x in f), f"no pattern layer caught: {line}"


def test_detector_rejects_every_benign_string():
    fired = [k for k, v in BENIGN_STRINGS.items() if detect_random_secret(v)[0]]
    assert not fired, f"detector false-positived on: {fired}"


def test_threshold_is_configurable():
    """A token sitting between two thresholds must flip when they move.

    Uses a token whose entropy ratio is ~0.83: passing at a permissive
    threshold and failing at a strict one proves the parameter is actually
    wired through, rather than asserting on a value that would fail either way.
    """
    mid = "BaseProactorEventLoop"  # secretsweep:allow
    assert looks_random(mid, min_ratio=0.10)[0]
    assert not looks_random(mid, min_ratio=0.999)[0]


def test_action_references_are_not_secrets():
    """Regression: `uses: actions/checkout@v4` was reported as a high-entropy
    secret, which would fire in every GitHub Actions workflow ever scanned."""
    for line in ("uses: actions/checkout@v4", "uses: actions/setup-python@v5",
                 "from: node@18", "author = someone@example.com",
                 "dependency = left-pad@1.3.0"):
        assert Scanner().scan_line(line, 1, "workflow.yml") == [], line


def test_sequential_constants_are_not_secrets():
    """Regression: alphabet/hex constants have a perfectly flat character
    distribution and pass any purely distributional entropy test."""
    for const in ("ABCDEFGHIJKLMNOPQRSTUVWXYZ", "0123456789ABCDEF",
                  "abcdefghijklmnopqrstuvwxyz", "0123456789abcdef"):
        assert scanner.ascending_ratio(const) > 0.60, const
        assert not looks_random(const)[0], const


# -------------------------------------------------------------------- masking

def test_mask_hides_the_secret():
    masked = mask(GH_TOKEN)
    assert GH_TOKEN not in masked
    assert GH_TOKEN[10:30] not in masked


def test_mask_keeps_enough_to_identify():
    masked = mask(AWS_KEY)
    assert masked.startswith("AKIA")
    assert f"len={len(AWS_KEY)}" in masked


def test_mask_short_value_fully_redacted():
    assert mask("abc") == "***"


def test_no_finding_contains_a_raw_secret():
    """The scanner must never echo the credential it found."""
    s = Scanner()
    findings = s.scan_line(f'KEY = "{RANDOM_B62}"', 1, "f.py")
    assert findings
    for f in findings:
        assert RANDOM_B62 not in json.dumps(f)


# ------------------------------------------------------------------- patterns

def test_pattern_aws_key():
    f = Scanner().scan_line(f"aws_access_key_id = {AWS_KEY}", 1, "x")
    assert any(x["rule"] == "AWS Access Key ID" and x["severity"] == "CRITICAL" for x in f)


def test_pattern_github_token():
    f = Scanner().scan_line(f"token: {GH_TOKEN}", 1, "x")
    assert any(x["rule"] == "GitHub Token" for x in f)


def test_pattern_private_key_block():
    f = Scanner().scan_line(PRIVATE_KEY_HEADER, 1, "x")
    assert any(x["rule"] == "Private Key Block" for x in f)


def test_pattern_slack_stripe_npm_openai():
    for line in (SLACK_TOKEN, STRIPE_KEY, NPM_TOKEN, OPENAI_KEY, ANTHROPIC_KEY, PYPI_TOKEN, JWT):
        assert Scanner().scan_line(line, 1, "x"), f"missed the pattern for {line[:12]}..."


def test_clean_line_produces_no_findings():
    for line in ["import os", "x = 1", "# a comment about tokens", "def main():",
                 "See https://docs.example.com/guides/getting-started-with-secrets",
                 "The binary lives at /usr/local/bin/python3 and is symlinked"]:
        assert Scanner().scan_line(line, 1, "x") == [], f"false positive on {line!r}"


# ------------------------------------------------------- location + dedup

def test_finding_carries_file_and_line():
    f = Scanner().scan_line(f"K = {AWS_KEY}", 7, "app/config.py")
    assert f[0]["file"] == "app/config.py"
    assert f[0]["line"] == 7
    assert f[0]["column"] == 5


def test_column_points_at_the_secret():
    line = f'OBFUSCATED_TOKEN = "{HEX64}"'
    f = Scanner().scan_line(line, 1, "x")
    assert f
    assert line[f[0]["column"] - 1] == HEX64[0]


def test_one_secret_reported_once():
    """Regression: pattern + entropy both fired on the same credential."""
    for line in (f"K = {AWS_KEY}", f"K = {GH_TOKEN}"):
        f = Scanner().scan_line(line, 1, "x")
        assert len(f) == 1, f"expected 1 finding, got {len(f)}: {f}"
        assert f[0]["detector"] == "pattern"


def test_single_char_variable_is_scanned():
    """Regression: the assignment pattern required >=2 chars on the LHS,
    so `K = <secret>` and `x = <secret>` were never inspected at all."""
    for lhs in ("K", "x", "_", "TOKEN", "a.b.c"):
        f = Scanner().scan_line(f'{lhs} = "{RANDOM_B62}"', 1, "f.py")
        assert f, f"{lhs} = <random> was not scanned"


def test_paths_are_not_reported_as_secrets():
    for line in ["See: /usr/local/bin/python3",
                 "binary = /home/ci/.local/share/node_modules/esbuild/bin/esbuild",
                 "url = https://github.com/user/repo/blob/main/src/scanner.py",
                 "syspath = /usr/lib/python3.11/site-packages"]:
        assert Scanner().scan_line(line, 1, "x") == [], f"false positive: {line}"


def test_entropy_fires_only_for_unprefixed_values():
    f = Scanner().scan_line(f"K = {HEX64}", 1, "x")
    assert len(f) == 1 and f[0]["detector"] == "entropy"


# ---------------------------------------------------------------- allowlist

def test_inline_allow_marker_suppresses():
    assert Scanner().scan_line(f"K = {AWS_KEY}  # secretsweep:allow", 1, "x") == []


def test_allowlist_substring_suppresses():
    s = Scanner(allowlist=[AWS_KEY])
    assert s.scan_line(f"K = {AWS_KEY}", 1, "x") == []
    # a non-matching rule must not suppress anything
    assert Scanner(allowlist=["no-such-value"]).scan_line(f"K = {AWS_KEY}", 1, "x")


def test_allowlist_regex_suppresses():
    s = Scanner(allowlist=[f"re:^{AWS_KEY}$"])
    assert s.scan_line(f"K = {AWS_KEY}", 1, "x") == []
    assert s.scan_line(f"K = {GH_TOKEN}", 1, "x")


def test_allowlist_prefix_regex_suppresses_family():
    s = Scanner(allowlist=["re:^AKIA"])
    assert s.scan_line(f"K = {AWS_KEY}", 1, "x") == []
    assert s.scan_line(f"K = {GH_TOKEN}", 1, "x"), "over-broad rule leaked across families"


def test_bad_allowlist_regex_is_ignored_not_fatal():
    s = Scanner(allowlist=["re:[unclosed"])
    assert s.scan_line(f"K = {AWS_KEY}", 1, "x")


# ------------------------------------------------------------------ scanning

def write(tmp, name, text):
    p = os.path.join(tmp, name)
    os.makedirs(os.path.dirname(p), exist_ok=True)
    with open(p, "w") as fh:
        fh.write(text)
    return p


def test_scan_file_returns_findings_with_paths():
    with tempfile.TemporaryDirectory() as tmp:
        p = write(tmp, "cfg.env", f"AWS_SECRET_ACCESS_KEY={RANDOM_B62}\n")
        f = Scanner().scan_file(p)
        assert f and f[0]["file"] == p


def test_scan_path_recurses_and_skips_vcs():
    with tempfile.TemporaryDirectory() as tmp:
        write(tmp, "src/app.py", f"TOKEN = '{RANDOM_B62}'\n")
        write(tmp, ".git/hooks/x.py", f"TOKEN = '{RANDOM_B62}'\n")
        f = Scanner().scan_path(tmp)
        assert len(f) == 1, f"should skip .git, got {f}"


def test_scan_path_covers_dockerfile_and_sh():
    with tempfile.TemporaryDirectory() as tmp:
        write(tmp, "Dockerfile", f"ENV SECRET {RANDOM_B62}\n")
        write(tmp, "run.sh", f"export SECRET={RANDOM_B62}\n")
        files = [os.path.basename(p) for p in scanner.iter_scannable_files(tmp)]
        assert "Dockerfile" in files and "run.sh" in files


def test_scan_missing_path_raises():
    try:
        Scanner().scan_path("/nonexistent/path/xyz")
    except scanner.ScanError:
        return
    raise AssertionError("expected ScanError")


def test_clean_directory_reports_nothing():
    with tempfile.TemporaryDirectory() as tmp:
        write(tmp, "a.py", "import os\nprint(os.getcwd())\n")
        write(tmp, "b.md", "# Docs\nNothing secret here.\n")
        assert Scanner().scan_path(tmp) == []


# ------------------------------------------------------------------ CLI

def run_cli(*args, allowlist=os.devnull):
    """Run the CLI.

    The allowlist defaults to an empty file so that a .secretsweepignore
    present in the repository cannot silently suppress the fixtures these tests
    assert on. Pass allowlist=None to exercise the scanner's own resolution.
    """
    r = subprocess.run([sys.executable, os.path.join(os.path.dirname(os.path.dirname(
        os.path.abspath(__file__))), "scanner.py"), *args,
        *(("--allowlist", allowlist) if allowlist is not None else ())],
        capture_output=True, text=True)
    return r.returncode, r.stdout, r.stderr


def test_cli_exit_codes():
    with tempfile.TemporaryDirectory() as tmp:
        clean = write(tmp, "clean.py", "x = 1\n")
        dirty = write(tmp, "dirty.py", f"K = {AWS_KEY}\n")
        assert run_cli(clean, "--no-color")[0] == EXIT_CLEAN
        assert run_cli(dirty, "--no-color")[0] == EXIT_SECRETS
        assert run_cli(os.path.join(tmp, "nope.py"), "--no-color")[0] == EXIT_ERROR


def test_cli_json_is_valid_and_masked():
    with tempfile.TemporaryDirectory() as tmp:
        dirty = write(tmp, "d.env", f"K = {AWS_KEY}\n")
        code, out, _ = run_cli(dirty, "--json")
        payload = json.loads(out)
        assert code == EXIT_SECRETS
        assert payload["total"] == 1
        assert payload["by_severity"]["CRITICAL"] == 1
        assert AWS_KEY not in out, "raw secret leaked into JSON output"


def test_allowlist_resolves_from_the_target_not_the_cwd():
    """Regression: the allowlist used to be read from the process working
    directory, so `scanner.py some/dir` picked up an unrelated repo's
    .secretsweepignore and silently suppressed real findings."""
    with tempfile.TemporaryDirectory() as tmp:
        tree = os.path.join(tmp, "tree")
        os.makedirs(tree)
        write(tree, "cfg.env", f"K = {AWS_KEY}\n")
        write(tmp, ".secretsweepignore", "AKIA\n")
        cwd = os.getcwd()
        os.chdir(tmp)
        try:
            # An allowlist in the PARENT of the target must not be inherited.
            assert run_cli("tree", "--no-color", allowlist=None)[0] == EXIT_SECRETS
            # An allowlist inside the target itself must be honoured.
            write(tree, ".secretsweepignore", "AKIA\n")
            assert run_cli("tree", "--no-color", allowlist=None)[0] == EXIT_CLEAN
            # And the result must not change with the invocation directory.
            os.chdir(cwd)
            assert run_cli(tree, "--no-color", allowlist=None)[0] == EXIT_CLEAN
        finally:
            os.chdir(cwd)


def test_cli_version():
    code, out, _ = run_cli("--version")
    assert code == 0 and scanner.__version__ in out
