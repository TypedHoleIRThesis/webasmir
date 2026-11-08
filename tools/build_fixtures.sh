#!/usr/bin/env bash
# Build the running-example fixtures in the pinned Ubuntu 22.04 GCC image
# (same Dockerfile as experiments/llm-decompile-test/benchmark).
set -euo pipefail
here="$(cd "$(dirname "$0")/.." && pwd)"
dockerfile="$here/../llm-decompile-test/benchmark/Dockerfile"
image=type-recovery-bench:ubuntu22.04
docker image inspect "$image" >/dev/null 2>&1 || \
  docker build --platform linux/amd64 -t "$image" -f "$dockerfile" "$(dirname "$dockerfile")"
docker run --rm --platform linux/amd64 -v "$here/tests/fixtures:/work" "$image" bash -c '
  set -e
  for o in O0 O1 O2; do
    gcc -$o -g -fno-pie -no-pie -fno-stack-protector -fcf-protection=none -o running_example.$o.dbg running_example.c
    cp running_example.$o.dbg running_example.$o.elf
    strip --strip-debug running_example.$o.elf
    cp running_example.$o.dbg running_example.$o.stripped
    strip --strip-all running_example.$o.stripped
  done
  gcc --version | head -1 > toolchain.txt'
ls -la "$here/tests/fixtures"
