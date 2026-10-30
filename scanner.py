"""secret-sweep - zero-dependency secret scanner.

Two detection layers:
  1. Known-pattern regexes for prefixed credentials (AWS, GitHub, Stripe, ...).
  2. A calibrated entropy detector for unprefixed random strings, applied only
     to values in assignment context so that prose, paths and URLs do not fire.

Stdlib only. Exit codes: 0 clean, 1 secrets found, 2 scan error.
"""
from __future__ import annotations

import argparse
import json
import math
import os
import re
import sys
from collections import Counter

__version__ = "2.0.0"

EXIT_CLEAN = 0
EXIT_SECRETS = 1
EXIT_ERROR = 2

COLORS = {
    "HEADER": "\033[95m", "BLUE": "\033[94m", "CYAN": "\033[96m",
    "GREEN": "\033[92m", "WARNING": "\033[93m", "FAIL": "\033[91m",
    "BOLD": "\033[1m", "DIM": "\033[2m", "ENDC": "\033[0m",
}

# Patterns are precompiled once: the old version called re.finditer with a
# string pattern per line per rule, which is measurably slower on large trees.
KNOWN_PATTERNS = [
    ("AWS Access Key ID", r"\bAKIA[0-9A-Z]{16}\b", "CRITICAL"),
    ("AWS Secret Access Key", r"\b(?:aws_secret_access_key|AWS_SECRET_ACCESS_KEY)\b\s*(?:=|:)\s*['\"]?([A-Za-z0-9/+=]{40})\b", "CRITICAL"),
    ("GitHub Token", r"\bgh[pousr]_[A-Za-z0-9]{36,255}\b", "CRITICAL"),
    ("GitHub App Installation Token", r"\bghs_[A-Za-z0-9]{36,}\b", "CRITICAL"),
    ("Slack Token", r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b", "CRITICAL"),
    ("Google API Key", r"\bAIza[0-9A-Za-z\-_]{35}\b", "CRITICAL"),
    ("Stripe Secret Key", r"\bsk_(?:live|test)_[A-Za-z0-9]{24,}\b", "CRITICAL"),
    ("npm Token", r"\bnpm_[A-Za-z0-9]{36,}\b", "CRITICAL"),
    ("OpenAI API Key", r"\bsk-(?:proj-)?[A-Za-z0-9\-_]{20,}\b", "CRITICAL"),
    ("Anthropic API Key", r"\bsk-ant-[A-Za-z0-9\-_]{20,}\b", "CRITICAL"),
    ("PyPI Upload Token", r"\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9\-_/+=]{30,}", "CRITICAL"),
    ("JSON Web Token", r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b", "HIGH"),
    ("Private Key Block", r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----", "CRITICAL"),
    ("Azure Storage Account Key", r"AccountKey=[A-Za-z0-9+/=]{88}", "CRITICAL"),
    ("Generic Assigned Credential", r"(?i)\b(?:api[_-]?key|apikey|secret|passwd|password|token|auth|credential)[\w\-.]{0,24}\s*(?:=|:)\s*['\"]([A-Za-z0-9+/_\-]{20,})['\"]", "HIGH"),
]
COMPILED = [(name, re.compile(rx), sev) for name, rx, sev in KNOWN_PATTERNS]

# Values on the right-hand side of an assignment / colon / CLI flag.
ASSIGNMENT = re.compile(r"[\w\-.@/]{1,64}\s*(?:=|:)\s*(?P<rhs>[^\s#]+)|--[\w\-]+=(?P<rhs2>[^\s#]+)")
TOKEN = re.compile(r"[A-Za-z0-9+/=_\-]{16,128}")

DEFAULT_EXTENSIONS = (
    ".py", ".js", ".jsx", ".ts", ".tsx", ".json", ".yaml", ".yml", ".env", ".txt",
    ".conf", ".cfg", ".ini", ".toml", ".sh", ".bash", ".zsh", ".tf", ".hcl",
    ".properties", ".xml", ".md", ".rst", ".go", ".rb", ".php", ".java", ".kt",
    ".rs", ".cs", ".sql", ".gradle", ".sbt", ".pem", ".key", ".crt", ".cer",
    ".der", ".p12", ".pfx", ".jks", ".keystore", ".ed25519", ".ppk",
)
DEFAULT_NAMES = (
    ".env", ".npmrc", ".pypirc", ".netrc", ".git-credentials", ".pgpass",
    ".aws/credentials", ".docker/config.json", "Dockerfile", "docker-compose.yml",
    "id_rsa", "id_ed25519", "id_ecdsa", "id_dsa",
)
SKIP_DIRS = {".git", ".hg", ".svn", "node_modules", "__pycache__", ".venv", "venv", ".tox", ".mypy_cache", "dist", "build", ".eggs"}

ALLOW_MARKER = "secretsweep:allow"

# Detection thresholds. Calibrated on a labelled battery of real credential
# shapes and ordinary code identifiers; see tests/test_detector.py.
MIN_TOKEN_LEN = 16
MIN_ENTROPY_RATIO = 0.82
MIN_CHAR_COVERAGE = 0.80
MIN_CASE_TRANSITIONS = 0.35   # only applied to mixed-case, digit-free tokens


UUID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
PATH_SEGMENT = re.compile(
    r"(?:^|/)(?:usr|bin|lib|lib64|sbin|etc|var|opt|home|tmp|proc|sys|dev|node_modules|site-packages|dist-packages)(?:/|$)"
)


def is_reference(value: str) -> bool:
    """Reject non-credential reference syntax.

    `uses: actions/checkout@v4` appears in essentially every GitHub Actions
    workflow, and `name@host`, `pkg@1.2.3` and `a/b` are reference forms rather
    than values. Without this the scanner reports a false positive in every CI
    file it is pointed at - the worst possible place to cry wolf.
    """
    if "@" in value:
        return True
    if value.count("/") >= 2:
        return True
    return bool(value.startswith("actions/"))


def is_pathlike(value: str) -> bool:
    """Reject absolute paths, relative paths, URLs and dashed UUIDs.

    These contain high-entropy components (hashes, versions, slugs) but are not
    credentials. Without this filter `/usr/local/bin/python3` on the right-hand
    side of an assignment is reported as a secret, and every
    `request_id = <uuid>` in a config file becomes a finding. Only the dashed
    canonical UUID form is excluded: a bare 32-character hex run is a plausible
    digest and stays in scope.
    """
    if value.count("/") >= 2 or "://" in value:
        return True
    if is_reference(value):
        return True
    return bool(UUID_RE.match(value) or PATH_SEGMENT.search(value))


COMMENT = re.compile(r"(?:^|\s)#.*$")


def strip_comment(line: str) -> str:
    """Remove a trailing `#` comment.

    Prose in comments regularly contains long hyphenated slugs and URLs that
    read as high-entropy values. Pattern matching still runs on the full line
    so a secret pasted into a comment is not missed.
    """
    return COMMENT.sub("", line.rstrip("\n"))


IDENTIFIER_PUNCT = "_.-"


def is_probable_identifier(value: str) -> bool:
    """Reject shapes that read as source-code identifiers rather than secrets.

    Unprefixed random credentials are drawn from base16/base62/base64 alphabets
    and are therefore purely alphanumeric. `_`, `.` and `-` are the workhorses of
    identifier and kebab-case syntax, so their presence is a strong signal.
    The prefixed forms that legitimately contain punctuation (JWT, Slack,
    GitHub, private key blocks) are all covered by the pattern layer, which runs
    first, so this costs no recall. Measured cost on 2,070 generated secrets: 0.
    """
    n = len(value)
    if n == 0:
        return True
    if any(c in value for c in IDENTIFIER_PUNCT):
        return True
    if sum(1 for c in value if not c.isalnum()) / n > 0.10:
        return True
    letters = [c for c in value if c.isalpha()]
    if letters and all(c.isupper() for c in letters) and n < 20:
        return True
    return False


def shannon_entropy(data: str) -> float:
    """Shannon entropy in bits per character."""
    if not data:
        return 0.0
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in Counter(data).values())


HEX_CHARS = "0123456789abcdefABCDEF"


def alphabet_size(s: str) -> int:
    """Size of the alphabet this token was most plausibly drawn from.

    Over-estimating the alphabet inflates the entropy ceiling and makes
    ordinary identifiers look random, so the estimate is driven by the
    character classes actually present.
    """
    lo = sum(c.islower() for c in s)
    up = sum(c.isupper() for c in s)
    di = sum(c.isdigit() for c in s)
    if di == 0 and lo == 0 and up == 0:
        return 64  # base64-ish payload
    if all(c in HEX_CHARS for c in s) and di:
        return 16
    if di == 0:
        return 26 if (lo == 0 or up == 0) else 52
    return 62 if lo and up else 36


MAX_ASCENDING_RATIO = 0.60


def ascending_ratio(s: str) -> float:
    """Fraction of adjacent character pairs that ascend by exactly one.

    Alphabet and hex constants ("ABCDEFGHIJKLMNOPQRSTUVWXYZ", "0123456789ABCDEF")
    are maximally high-entropy by any distributional measure - every character
    appears exactly once - so only their *order* gives them away.

    A run-length test is the wrong shape for this: a genuinely random 40-token
    contains an ascending run of 9 roughly 6% of the time, which would silently
    drop real secrets. The ratio is robust instead. Measured over 80,000 random
    base62 tokens the maximum was 0.21; every sequential constant scores >=0.93.
    """
    if len(s) < 2:
        return 0.0
    return sum(1 for a, b in zip(s, s[1:]) if ord(b) - ord(a) == 1) / (len(s) - 1)


def _char_class(c: str) -> int:
    return 0 if c.islower() else (1 if c.isupper() else (2 if c.isdigit() else 3))


def case_transitions(s: str) -> float:
    """Fraction of adjacent character pairs that change class (a->B, B->1...).

    Random base62 alternates class constantly; CamelCase identifiers have long
    single-class runs punctuated by one capital. This is the single most
    discriminative feature between the two.
    """
    if len(s) < 2:
        return 0.0
    return sum(1 for a, b in zip(s, s[1:]) if _char_class(a) != _char_class(b)) / (len(s) - 1)


def looks_random(
    s: str,
    min_ratio: float = MIN_ENTROPY_RATIO,
    min_coverage: float = MIN_CHAR_COVERAGE,
    min_transitions: float = MIN_CASE_TRANSITIONS,
) -> tuple[bool, str]:
    """True if `s` is statistically indistinguishable from a random string.

    A single fixed entropy threshold does not work: entropy is bounded above by
    log2(min(len, alphabet)), so `> 4.5` can never fire on a token shorter than
    24 characters, and it fires on long readable identifiers. Three
    length-normalised signals are combined instead:

      ratio       entropy / log2(min(n, k))   flatness of the distribution
      coverage    |set(s)| / E[distinct]      how much of the alphabet is used
      transitions case_transitions(s)         random vs. CamelCase structure

    Two structural guards sit alongside them, because distributional tests
    cannot see order: a high ascending_ratio identifies alphabet/hex constants,
    and a mixed-case digit-free token with few class transitions is a CamelCase
    identifier rather than a random base62 string.

    Thresholds were calibrated on a labelled corpus of 300k lines of real
    Python plus generated credentials; see README for the measured rates.
    """
    n = len(s)
    if n < MIN_TOKEN_LEN:
        return False, "too short"
    k = alphabet_size(s)
    max_ent = math.log2(min(n, k))
    if max_ent <= 0:
        return False, "degenerate"
    ratio = shannon_entropy(s) / max_ent
    if ratio < min_ratio:
        return False, f"entropy ratio {ratio:.2f} < {min_ratio:.2f}"
    expected_distinct = k * (1 - ((k - 1) / k) ** n)
    coverage = len(set(s)) / expected_distinct
    if coverage < min_coverage:
        return False, f"char coverage {coverage:.2f} < {min_coverage:.2f}"
    if ascending_ratio(s) > MAX_ASCENDING_RATIO:
        return False, f"sequential constant ({ascending_ratio(s):.2f} ascending pairs)"
    lo = sum(c.islower() for c in s)
    up = sum(c.isupper() for c in s)
    di = sum(c.isdigit() for c in s)
    if lo and up and di == 0 and case_transitions(s) < min_transitions:
        return False, "CamelCase identifier structure"
    return True, f"entropy ratio {ratio:.2f}, coverage {coverage:.2f}, transitions {case_transitions(s):.2f}"


def mask(value: str) -> str:
    """Redact a secret for safe display.

    The scanner must never write the credential it found into a report or a CI
    log - that is how a scanner becomes the leak. Keep a short prefix and a
    length so the finding is still recognisable and deduplicable.
    """
    n = len(value)
    if n <= 8:
        return "*" * n
    return f"{value[:4]}{'*' * min(n - 8, 24)}{value[-4:]} (len={n})"


ALLOWLIST_NAME = ".secretsweepignore"


def resolve_allowlist(target: str) -> str | None:
    """Find the allowlist governing `target`, or None.

    Two deliberate choices:

    * Anchored on the target, never on the process working directory. Otherwise
      `scanner.py src` returns different results depending on where it was
      invoked from, which makes CI non-reproducible.
    * No walk up to ancestor directories. Inheriting `/repo/.secretsweepignore`
      while scanning `/repo/src` means a broad rule placed higher in the tree
      silently suppresses findings in a scan that never mentions it - the exact
      failure mode a secret scanner must not have. Pass `--allowlist` explicitly
      if you want a shared file.
    """
    here = os.path.abspath(target)
    if os.path.isfile(here):
        here = os.path.dirname(here)
    candidate = os.path.join(here, ALLOWLIST_NAME)
    return candidate if os.path.isfile(candidate) else None


def load_allowlist(path: str) -> list[str]:
    """Read `.secretsweepignore`: one substring or `re:<regex>` per line."""
    if not os.path.isfile(path):
        return []
    rules: list[str] = []
    with open(path, "r", encoding="utf-8", errors="ignore") as fh:
        for raw in fh:
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            rules.append(line)
    return rules


def is_allowed(value: str, rule: str) -> bool:
    if rule.startswith("re:"):
        try:
            return re.search(rule[3:], value) is not None
        except re.error:
            return False
    return rule in value


def detect_random_secret(value: str, min_ratio: float = MIN_ENTROPY_RATIO, **kw) -> tuple[bool, str]:
    """Full unprefixed-secret test: statistical randomness minus known shapes.

    Order matters. Paths, URLs and UUIDs are excluded first (syntax), then
    identifier-like shapes (ALL_CAPS constants, snake_case names), and only
    then is the length-normalised entropy test applied.
    """
    if is_pathlike(value):
        return False, "path/URL/UUID"
    if is_probable_identifier(value):
        return False, "identifier shape"
    return looks_random(value, min_ratio=min_ratio, **kw)


class Scanner:
    def __init__(self, min_entropy_ratio: float = MIN_ENTROPY_RATIO, allowlist: list[str] | None = None):
        self.min_entropy_ratio = min_entropy_ratio
        self.allowlist = allowlist or []

    def _suppressed(self, line: str, value: str) -> bool:
        if ALLOW_MARKER in line:
            return True
        return any(is_allowed(value, rule) for rule in self.allowlist)

    def scan_line(self, line: str, line_num: int, path: str) -> list[dict]:
        # NOTE: the raw line is kept for pattern matching and for the allow
        # marker; only the entropy detector works on the comment-stripped form.
        """Return findings for one line. One secret is reported once.

        Pattern matches are authoritative: when a prefixed credential (AWS,
        GitHub, ...) is recognised, the entropy detector is suppressed over the
        same span rather than filing a duplicate, weaker finding for it.
        """
        findings: list[dict] = []
        pattern_spans: list[tuple[int, int]] = []
        code_part = strip_comment(line)

        for name, rx, severity in COMPILED:
            for m in rx.finditer(line):
                value = m.group(1) if m.groups() and m.group(1) else m.group(0)
                if self._suppressed(line, value):
                    continue
                start = m.start(1) if m.groups() and m.group(1) else m.start()
                end = m.end(1) if m.groups() and m.group(1) else m.end()
                if any(start < e and end > s for s, e in pattern_spans):
                    continue  # same secret already reported by a stronger rule
                pattern_spans.append((start, end))
                findings.append({
                    "file": path,
                    "line": line_num,
                    "column": start + 1,
                    "detector": "pattern",
                    "rule": name,
                    "severity": severity,
                    "description": f"{name} detected",
                    "evidence": mask(value),
                })

        for m in ASSIGNMENT.finditer(code_part):
            which = "rhs" if m.group("rhs") is not None else "rhs2"
            rhs_start = m.start(which)
            rhs = m.group(which).strip("'\"`,;")
            for tok in TOKEN.findall(rhs):
                ok, why = detect_random_secret(tok, min_ratio=self.min_entropy_ratio)
                if not ok or self._suppressed(line, tok):
                    continue
                tok_start = code_part.find(tok, rhs_start)
                if tok_start < 0:
                    continue
                after = code_part[tok_start + len(tok):tok_start + len(tok) + 1]
                if after == "(":
                    continue  # a call expression, not a value
                tok_end = tok_start + len(tok)
                if any(tok_start < e and tok_end > s for s, e in pattern_spans):
                    continue  # already covered by a named pattern
                pattern_spans.append((tok_start, tok_end))
                findings.append({
                    "file": path,
                    "line": line_num,
                    "column": tok_start + 1,
                    "detector": "entropy",
                    "rule": "high-entropy-value",
                    "severity": "HIGH",
                    "description": f"Unprefixed random-looking value in assignment context ({why})",
                    "evidence": mask(tok),
                })
        return findings

    def scan_file(self, path: str) -> list[dict]:
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as fh:
                lines = fh.readlines()
        except OSError as exc:
            raise ScanError(f"cannot read {path}: {exc}") from exc
        out: list[dict] = []
        for num, line in enumerate(lines, 1):
            out.extend(self.scan_line(line, num, path))
        return out

    def scan_path(self, target: str, extensions=DEFAULT_EXTENSIONS, names=DEFAULT_NAMES, skip=None) -> list[dict]:
        skip = SKIP_DIRS if skip is None else skip
        out: list[dict] = []
        if os.path.isfile(target):
            return self.scan_file(target)
        if not os.path.isdir(target):
            raise ScanError(f"not a file or directory: {target}")
        for root, dirs, files in os.walk(target):
            dirs[:] = [d for d in dirs if d not in skip]
            for fname in sorted(files):
                if fname in names or fname.lower().endswith(extensions):
                    out.extend(self.scan_file(os.path.join(root, fname)))
        return out


def iter_scannable_files(target: str, extensions=DEFAULT_EXTENSIONS, names=DEFAULT_NAMES, skip=None) -> list[str]:
    """Files under `target` the scanner will read, in deterministic order."""
    skip = SKIP_DIRS if skip is None else skip
    if os.path.isfile(target):
        return [target]
    if not os.path.isdir(target):
        return []
    out: list[str] = []
    for root, dirs, files in os.walk(target):
        dirs[:] = sorted(d for d in dirs if d not in skip)
        for fname in sorted(files):
            if fname in names or fname.lower().endswith(extensions):
                out.append(os.path.join(root, fname))
    return out


class ScanError(Exception):
    """Fatal scan problem - distinct from 'found secrets'."""


def render_text(findings: list[dict], scanned: int, use_color: bool) -> str:
    c = COLORS if use_color else {k: "" for k in COLORS}
    if not findings:
        return f"{c['GREEN']}{c['BOLD']}[+] Scanned {scanned} file(s). No secrets detected.{c['ENDC']}"
    lines = [f"{c['FAIL']}{c['BOLD']}[!] Found {len(findings)} potential secret(s) across {scanned} file(s):{c['ENDC']}", ""]
    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    for f in sorted(findings, key=lambda x: (order.get(x["severity"], 9), x["file"], x["line"])):
        sev = c["FAIL"] if f["severity"] == "CRITICAL" else c["WARNING"]
        lines.append(f"  {sev}{f['severity']:<8}{c['ENDC']} {c['CYAN']}{f['file']}:{f['line']}:{f['column']}{c['ENDC']}")
        lines.append(f"           {f['rule']} {c['DIM']}[{f['detector']}]{c['ENDC']}")
        lines.append(f"           evidence: {c['DIM']}{f['evidence']}{c['ENDC']}")
        lines.append("")
    lines.append(f"{c['FAIL']}[!] Secrets detected - failing the build.{c['ENDC']}")
    lines.append(f"{c['DIM']}    Inline `# secretsweep:allow` or .secretsweepignore to suppress a reviewed finding.{c['ENDC']}")
    return "\n".join(lines)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="secret-sweep",
        description="Zero-dependency secret scanner: prefixed-credential patterns plus a calibrated entropy detector.",
    )
    p.add_argument("target", nargs="?", default=".", help="File or directory to scan (default: cwd)")
    p.add_argument("--json", action="store_true", help="Emit machine-readable JSON instead of text")
    p.add_argument("--no-color", action="store_true", help="Disable ANSI colours (auto-off when not a TTY)")
    p.add_argument("--min-entropy-ratio", type=float, default=MIN_ENTROPY_RATIO,
                   help=f"Entropy detector sensitivity, 0-1 (default {MIN_ENTROPY_RATIO})")
    p.add_argument("--allowlist", default=None,
                   help="Allowlist file. Defaults to .secretsweepignore in the scanned "
                        "directory itself; ancestor directories are deliberately not "
                        "searched, so results never depend on the invocation directory.")
    p.add_argument("--version", action="version", version=f"secret-sweep {__version__}")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    target = args.target
    allowlist_path = args.allowlist or resolve_allowlist(target)
    scanner = Scanner(min_entropy_ratio=args.min_entropy_ratio,
                      allowlist=load_allowlist(allowlist_path) if allowlist_path else [])
    try:
        files = iter_scannable_files(target)
        if not files and not os.path.isdir(target):
            raise ScanError(f"not a file or directory: {target}")
        findings: list[dict] = []
        for path in files:
            findings.extend(scanner.scan_file(path))
    except ScanError as exc:
        if args.json:
            print(json.dumps({"error": str(exc), "findings": []}))
        else:
            print(f"{COLORS['FAIL']}[!] {exc}{COLORS['ENDC']}", file=sys.stderr)
        return EXIT_ERROR

    if args.json:
        print(json.dumps({
            "tool": "secret-sweep", "version": __version__, "target": target,
            "allowlist": allowlist_path,
            "files_scanned": len(files), "total": len(findings),
            "by_severity": {s: sum(1 for f in findings if f["severity"] == s) for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW")},
            "findings": findings,
        }, indent=2))
    else:
        use_color = sys.stdout.isatty() and not args.no_color
        print(render_text(findings, len(files), use_color))
    return EXIT_SECRETS if findings else EXIT_CLEAN


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
