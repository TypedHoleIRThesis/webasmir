#!/usr/bin/env bash
set -euo pipefail
root="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
python_bin="${ASMWEBIR_PYTHON:-$root/.venv/bin/python}"
export PYTHONPATH="$root/src${PYTHONPATH:+:$PYTHONPATH}"
exec "$python_bin" -m asmwebir.benchmark.runner "$@"
