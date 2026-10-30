#!/usr/bin/env bash
set -euo pipefail
# Credentials come from the environment; nothing is hard-coded here.
export APP_ENV="${APP_ENV:-production}"
python3 -m app --timeout=30 --retries=3
