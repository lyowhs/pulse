#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

TMPDIR_RUN=$(mktemp -d)
trap 'rm -rf "$TMPDIR_RUN"' EXIT

echo "==> Building pulse..."
go build -o "$TMPDIR_RUN/pulse" ./cmd/pulse/
PULSE=("$TMPDIR_RUN/pulse")

# ── base64 (string) case ──────────────────────────────────────────────────────

echo ""
echo "==> [base64] Generating base58 secret key..."
SK=$("${PULSE[@]}" keys keygen --base58)
echo "    Secret key: ${SK:0:32}..."

echo "==> [base64] Deriving public key..."
PK=$("${PULSE[@]}" keys pubkey --key "$SK")
echo "    Public key: ${PK:0:32}..."

echo "==> [base64] Signing 'Hello World!'"
SIG=$("${PULSE[@]}" keys sign --key "$SK" --message "Hello World!" --base64)
echo "    Signature:  ${SIG:0:32}..."

echo "==> [base64] Verifying valid signature..."
"${PULSE[@]}" keys verify --pubkey "$PK" --message "Hello World!" --signature "$SIG" --base64

echo "==> [base64] Verifying with wrong message (expecting invalid)..."
if "${PULSE[@]}" keys verify --pubkey "$PK" --message "Wrong message!" --signature "$SIG" --base64 2>/dev/null; then
    echo "    FAIL: signature should not have verified" >&2; exit 1
fi
echo "    signature invalid (correct)"

echo "==> [base64] Verifying with tampered signature (expecting invalid)..."
BAD_SIG=$(echo "$SIG" | tr 'A-Za-z' 'B-ZAb-za')
if "${PULSE[@]}" keys verify --pubkey "$PK" --message "Hello World!" --signature "$BAD_SIG" --base64 2>/dev/null; then
    echo "    FAIL: signature should not have verified" >&2; exit 1
fi
echo "    signature invalid (correct)"

# ── binary case ───────────────────────────────────────────────────────────────
# FN-DSA signatures structurally contain NUL (0x00) bytes due to their
# Golomb-like coefficient encoding, so they cannot be passed as shell arguments.
# The binary section therefore:
#   • Tests keygen --binary by checking the output file size.
#   • Tests sign --binary by confirming the binary output is a valid signature
#     (by base64-encoding the file and verifying with --base64).
#   • Skips verify --binary here; it is covered by Go unit tests.

echo ""
echo "==> [binary] Generating binary secret key..."
"${PULSE[@]}" keys keygen --binary > "$TMPDIR_RUN/sk.bin"
SK_BYTES=$(wc -c < "$TMPDIR_RUN/sk.bin" | tr -d ' ')
echo "    Secret key: (${SK_BYTES} bytes)"
if [ "$SK_BYTES" -ne 1281 ]; then
    echo "    FAIL: expected 1281 bytes" >&2; exit 1
fi

echo "==> [binary] Generating base58 key pair..."
SK_B58=$("${PULSE[@]}" keys keygen --base58)
PK_B58=$("${PULSE[@]}" keys pubkey --key "$SK_B58")

echo "==> [binary] Signing 'Hello World!' with binary output..."
"${PULSE[@]}" keys sign --key "$SK_B58" --message "Hello World!" --binary > "$TMPDIR_RUN/sig.bin"
SIG_BYTES=$(wc -c < "$TMPDIR_RUN/sig.bin" | tr -d ' ')
echo "    Signature:  (${SIG_BYTES} bytes)"

echo "==> [binary] Confirming binary signature is valid (base64-encoding for verify)..."
SIG_B64=$(base64 < "$TMPDIR_RUN/sig.bin" | tr -d '\n')
"${PULSE[@]}" keys verify --pubkey "$PK_B58" --message "Hello World!" --signature "$SIG_B64" --base64

echo "==> [binary] Confirming binary signature fails for wrong message..."
if "${PULSE[@]}" keys verify --pubkey "$PK_B58" --message "Wrong message!" --signature "$SIG_B64" --base64 2>/dev/null; then
    echo "    FAIL: signature should not have verified" >&2; exit 1
fi
echo "    signature invalid (correct)"

echo ""
echo "All tests passed."
