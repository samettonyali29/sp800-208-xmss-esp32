#!/bin/bash
# Copyright (c) 2026 The sp800-208-xmss-esp32 authors
# SPDX-License-Identifier: Apache-2.0
#
# Generates examples/xmss_test_vectors/xmss_vectors.h with the XMSS reference
# implementation (https://github.com/XMSS/xmss-reference, CC0; needs gcc and
# the OpenSSL development headers, e.g. libssl-dev).
#
# Usage: bash scripts/gen_test_vectors.sh [output.h]
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
OUT="${1:-$HERE/../examples/xmss_test_vectors/xmss_vectors.h}"
REF="$HERE/.kat-data/xmss-reference"
REF_COMMIT="${REF_COMMIT:-master}"
if [ ! -d "$REF" ]; then
  mkdir -p "$HERE/.kat-data"
  curl -sL "https://github.com/XMSS/xmss-reference/archive/$REF_COMMIT.tar.gz" | tar -xz -C "$HERE/.kat-data"
  mv "$HERE/.kat-data/xmss-reference-$REF_COMMIT" "$REF"
fi
BUILD="$(mktemp -d)"
trap 'rm -rf "$BUILD"' EXIT
gcc -O2 -w -I"$REF" -o "$BUILD/kat_gen" "$HERE/kat_gen.c" \
  "$REF"/{params,hash,fips202,hash_address,wots,xmss_commons,xmss_core,utils,randombytes}.c -lcrypto
"$BUILD/kat_gen" > "$OUT"
echo "wrote $OUT ($(wc -c < "$OUT") bytes)" >&2
