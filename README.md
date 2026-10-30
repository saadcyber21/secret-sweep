# secret-sweep

A secret scanner in one dependency-free Python file. Two detection layers: regex
rules for prefixed credentials, and an entropy detector for the unprefixed random
strings that rules cannot describe — with **published, reproducible** false-positive
and recall numbers instead of adjectives.

[![CI](https://github.com/saadcyber21/secret-sweep/actions/workflows/validate.yml/badge.svg)](https://github.com/saadcyber21/secret-sweep/actions/workflows/validate.yml)
[![Python](https://img.shields.io/badge/python-3.10%20%7C%203.11%20%7C%203.12%20%7C%203.13-blue)](https://github.com/saadcyber21/secret-sweep/actions/workflows/validate.yml)
[![dependencies](https://img.shields.io/badge/dependencies-0-brightgreen)](pyproject.toml)
[![tests](https://img.shields.io/badge/tests-56-brightgreen)](tests)

```
$ python3 scripts/make_dirty_fixture.py fixtures/dirty   # synthetic - see fixtures/README.md
$ python3 scanner.py fixtures/dirty --no-color

[!] Found 13 potential secret(s) across 4 file(s):

  CRITICAL fixtures/dirty/config.env:3:19
           AWS Access Key ID [pattern]
           evidence: AKIA************QR6I (len=20)

  CRITICAL fixtures/dirty/id_ed25519:1:1
           Private Key Block [pattern]
           evidence: ----*******************---- (len=27)

  HIGH     fixtures/dirty/config.env:9:20
           high-entropy-value [entropy]
           evidence: d1dc************************a0d6 (len=64)

  ... 10 more, all masked

[!] Secrets detected - failing the build.
    Inline `# secretsweep:allow` or .secretsweepignore to suppress a reviewed finding.
```
Exit `0` clean · `1` secrets found · `2` scan error. Findings carry
`file:line:column`, and secrets are masked in every output format.

## Quickstart

```bash
git clone https://github.com/saadcyber21/secret-sweep
cd secret-sweep

python3 scanner.py .                      # scan a tree
python3 scanner.py src/config.py          # scan one file
python3 scanner.py . --json               # machine-readable
python3 scanner.py . --min-entropy-ratio 0.88   # trade recall for precision
python3 tests/run_tests.py                # 56 tests, no pytest needed
```

No install step and nothing to resolve: stdlib only, Python 3.10+.

## Measured behaviour

Every figure below is produced by a command you can run. The calibration harness
is in the repo, not in a notebook nobody can reproduce.

```bash
python3 scripts/calibrate.py /path/to/some/large/source/tree
```

| | result | corpus |
|---|---|---|
| Recall — secret-named key leaks | **99.5%** | 400 generated |
| Recall — neutral-named key leaks | **99.0%** | 200 generated |
| Recall — prefixed credentials | **100%** | 200 generated |
| False positives | **23 lines / 304,467 (0.0076%)** | CPython 3.11 stdlib, 669 files |

The last row is the one that matters. An entropy detector is a heuristic, and a
heuristic that flags one line per file gets switched off within a week. On the
same corpus the naive `entropy > 4.5` test this replaced flagged **610 lines** —
26× noisier, and it still missed real credentials.

Reproduce the comparison:

```bash
python3 scripts/calibrate.py /usr/lib/python3.11
```

CI enforces the recall floors in `scripts/check_recall.py`, so a refactor that
quietly breaks detection fails the build rather than the next incident review.

## How detection works

### Layer 1 — patterns

Fifteen compiled rules for credentials with recognisable prefixes: AWS access key
IDs and secret keys, GitHub `ghp_`/`ghs_`/`gho_`, Slack `xox[baprs]-`, Google
`AIza`, Stripe `sk_live_`, npm, OpenAI, Anthropic, PyPI, JWTs, private key blocks,
Azure storage keys, and a generic `password|token|secret = "…"` rule.

Patterns run first and are authoritative. When one matches, the entropy layer is
suppressed over that span, so a single credential is reported once instead of
twice by two detectors.

### Layer 2 — entropy

For secrets with no prefix — the majority of real leaks — randomness is the only
available signal. A single fixed entropy threshold does not work, because entropy
is bounded above by `log2(min(len, alphabet))`:

> `entropy > 4.5` **cannot fire on any token shorter than 24 characters.**
> An AWS access key ID is 20 characters. The threshold was unreachable.

Three length-normalised signals replace it:

| signal | formula | separates |
|---|---|---|
| `ratio` | `entropy / log2(min(n, k))` | flat distribution vs. skewed |
| `coverage` | `\|set(s)\| / E[distinct in random s]` | alphabet use vs. repetition |
| `transitions` | fraction of adjacent chars changing case class | base62 vs. CamelCase |

plus three structural guards, because distributional tests cannot see *order* or
*syntax*:

- **Sequential constants** — `ABCDEFGHIJKLMNOPQRSTUVWXYZ` has a perfectly flat
  distribution and passes any entropy test. Detected by ascending-pair ratio:
  measured over 80,000 random base62 tokens the maximum was 0.21; every
  sequential constant scores ≥0.93. A run-*length* test was tried first and
  rejected — a genuine 40-character token contains an ascending run of 9 about 6%
  of the time, which would have silently dropped real secrets.
- **Identifier syntax** — `_`, `.` and `-` are rejected outright. Unprefixed
  random credentials are base16/base62/base64 and never contain them; the
  prefixed forms that do are owned by layer 1. Measured recall cost on 2,070
  generated secrets: **0**.
- **Assignment context** — entropy candidates are drawn from the right-hand side
  of `key = value`, `key: value` and `--flag=value`, not from every token on the
  line. This is what stops `/usr/local/bin/python3` in a sentence from firing.

### Masking

Findings print `AKIA************MPLE (len=20)`, never the credential. The
original version of this tool printed the first 20 characters of every secret it
found, which means running it in CI copied leaked credentials into a build log
that is typically less protected than the file they leaked from. A test now
asserts that no fixture secret appears in text or JSON output.

## Using it in CI

```yaml
- name: Scan for secrets
  run: python scanner.py . --no-color    # exits 1 on findings
```

The workflow in this repo does more than that, and is worth copying: it asserts
a **clean fixture produces nothing** *and* a **dirty fixture produces findings**.
A scanner whose detector stops detecting still passes its unit tests, so the
fixture pair is gated from both directions.

## Suppressing a reviewed finding

```python
api_key = "not-a-real-key-placeholder"   # secretsweep:allow
```

or a a `.secretsweepignore` in the scanned directory:

```
not-a-real-key                 # substring rule
re:^test-fixture-[A-Za-z0-9]+$ # regex rule
```

Resolution is anchored on the scan target, never on the working directory, and
ancestor directories are deliberately **not** searched — otherwise a broad rule
placed higher in the tree silently suppresses findings in a scan that never
mentions it. Pass `--allowlist` explicitly for a shared file. Both behaviours are
regression-tested.

### A note on the fixtures

`fixtures/dirty/` contains **synthetic credentials**, and the AWS/Stripe values
are the placeholders published in those vendors' own public documentation. They
are deliberately not valid-format live credentials: GitHub push protection
correctly rejects pushes containing realistic secret formats, and bypassing it
to commit a scary-looking fake key would be the wrong trade.

Format-realistic detection is covered instead by `scripts/calibrate.py`, which
generates credentials in memory and never writes them to a file. That is also
where the recall figures come from.

## Limitations

Stated plainly, because a scanner that overstates its coverage is worse than one
that does not exist:

- **Entropy findings need human review.** At 0.0076% false positives the
  detector is usable in CI, not infallible. The residual false positives on
  CPython are CamelCase Win32 bindings (`WaitForSingleObject`) and zipfile
  struct constants (`sizeEndCentDir64Locator`) — long single-case identifiers
  with an unusual character mix.
- **It scans working-tree content only.** No git history, so it will not find a
  secret that was committed and later deleted. Use `gitleaks` or `trufflehog`
  for history.
- **No verification.** It does not call provider APIs to confirm a credential is
  live, so it cannot tell a leaked key from a rotated one.
- **Text files only.** Binary formats, minified bundles and encoded payloads
  (a base64-wrapped `.env`) are out of scope.
- **The recall corpus is generated, not harvested.** Credentials are synthesised
  from known shapes. Real-world leaks include formats nobody thought to generate,
  and the honest reading of 99.5% is "99.5% of the shapes I modelled".
- **Tuned on Python.** Calibration ran against CPython. Other ecosystems have
  different identifier conventions; the structural guards should generalise, but
  that is an expectation, not a measurement.

## Compared with

| tool | language | history | verification | entropy |
|---|---|---|---|---|
| [gitleaks](https://github.com/gitleaks/gitleaks) | Go | yes | no | yes |
| [trufflehog](https://github.com/trufflesecurity/trufflehog) | Go | yes | **yes** | yes |
| [detect-secrets](https://github.com/Yelp/detect-secrets) | Python | no | plugins | yes |
| **secret-sweep** | Python (stdlib) | no | no | yes, calibrated |

This is not a better tool than those. It is a single readable file you can vendor
into an air-gapped pipeline with no toolchain, and its detector's error rate is
measured rather than asserted.

## Layout

```
scanner.py                  the tool (one file, stdlib only)
tests/
  test_scanner.py           detector, masking, patterns, allowlist, CLI
  test_fixtures.py          end-to-end gates on fixtures/
  run_tests.py              zero-dependency runner
fixtures/
  clean/                    committed; must produce zero findings (CI gate)
  README.md                 why there is no committed dirty fixture
scripts/
  make_dirty_fixture.py     generates the dirty tree at test time (CI gate)
  calibrate.py              reproduces every number in this README
  check_recall.py           CI gate on recall floors
.secretsweepignore          allowlist, exercised by CI
```

## License

MIT — see [LICENSE](LICENSE).
