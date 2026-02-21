#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

PULSE=(go run ./cmd/pulse/)

echo "==> Generating secret key..."
SK=$("${PULSE[@]}" keys keygen --base58)
echo "    Secret key: ${SK:0:32}..."

echo "==> Deriving public key..."
PK=$("${PULSE[@]}" keys pubkey --key "$SK")
echo "    Public key: ${PK:0:32}..."

echo "==> Signing message: 'Hello World!'"
SIG=$("${PULSE[@]}" keys sign --key "$SK" --message "Hello World!")
echo "    Signature:  ${SIG:0:32}..."

echo "==> Verifying valid signature..."
"${PULSE[@]}" keys verify --pubkey "$PK" --message "Hello World!" --signature "$SIG"

echo "==> Verifying with incorrect message (expecting invalid)..."
if "${PULSE[@]}" keys verify --pubkey "$PK" --message "Wrong message!" --signature "$SIG" 2>/dev/null; then
    echo "    FAIL: signature should not have verified" >&2
    exit 1
fi
echo "    signature invalid (correct)"

echo "==> Verifying with incorrect signature (expecting invalid)..."
BAD_SIG=$(echo "$SIG" | tr 'A-Za-z' 'B-ZAb-za')
if "${PULSE[@]}" keys verify --pubkey "$PK" --message "Hello World!" --signature "$BAD_SIG" 2>/dev/null; then
    echo "    FAIL: signature should not have verified" >&2
    exit 1
fi
echo "    signature invalid (correct)"
