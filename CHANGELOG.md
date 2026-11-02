# Changelog

Versions follow the calibrated detector's behaviour, not its ambitions.

## 2.0.0 — current

- Entropy layer replaced `entropy > 4.5` with three length-normalised signals
  (`ratio`, `coverage`, `transitions`) plus three structural guards (identifier
  syntax, sequential constants, assignment context). The old threshold could not
  fire on any token shorter than 24 characters — a 20-character AWS access key
  ID was undetectable by construction.
- Measured on CPython 3.11 stdlib (669 files, 304,467 lines): **23 false
  positives (0.0076%)**, against 610 for the threshold it replaced. Recall
  99.5% secret-named / 99.0% neutral-named / 100% prefixed, on generated corpora.
  `scripts/calibrate.py` reproduces every figure; `scripts/check_recall.py`
  gates CI.
- All output formats mask findings (`AKIA************MPLE`); a test asserts no
  fixture secret appears in text or JSON output.
- Fifteen pattern rules; patterns are authoritative and suppress the entropy
  layer over their span, so one credential is reported once.
- 56 tests, stdlib only, no install step.

## Before 2.0.0

History predates public versioning; see `git log`. The 1.x line is the naive
threshold and is preserved in the commit history exactly so the comparison in
the README stays reproducible.
