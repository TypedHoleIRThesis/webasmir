#!/usr/bin/env bash
# Build tiny.c with the same image and flags as webasmir/tools/build_fixtures.sh.
# Usage: ./build.sh [levels...]   (default: O0 O1)
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
image=type-recovery-bench:ubuntu22.04
levels="${*:-O0 O1}"
docker run --rm --platform linux/amd64 -v "$here:/work" -w /work -e LEVELS="$levels" "$image" bash -c '
  set -e
  for o in $LEVELS; do
    gcc -$o -g -fno-pie -no-pie -fno-stack-protector -fcf-protection=none -o tiny.$o.dbg tiny.c
    cp tiny.$o.dbg tiny.$o.elf && strip --strip-debug tiny.$o.elf
    cp tiny.$o.dbg tiny.$o.stripped && strip --strip-all tiny.$o.stripped
  done'
ls -la "$here"
