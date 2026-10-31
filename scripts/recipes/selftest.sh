#!/usr/bin/env bash
set -euo pipefail
if [ "$#" -ne 2 ]; then
  echo 'usage: selftest.sh SRC OUT' >&2
  exit 1
fi
SRC=$1
OUT=$2
mkdir -p "$OUT"
cc -std=c11 -Wall -Wextra -Werror "$SRC/tests/fixtures/selftest/hello.c" -o "$OUT/hello"
