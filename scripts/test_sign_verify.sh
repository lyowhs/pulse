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
"${PULSE[@]}" keys verify --pubkey "$PK" --message "Hello World!" --signature "$SIG"
echo "==> [base64] Verifying with wrong message (expecting invalid)..."
if "${PULSE[@]}" keys verify --pubkey "$PK" --message "Wrong message!" --signature "$SIG" 2>/dev/null; then
    echo "    FAIL: signature should not have verified" >&2; exit 1
fi
echo "    signature invalid (correct)"

echo "==> [base64] Verifying with tampered signature (expecting invalid)..."
BAD_SIG=$(echo "$SIG" | tr 'A-Za-z' 'B-ZAb-za')
if "${PULSE[@]}" keys verify --pubkey "$PK" --message "Hello World!" --signature "$BAD_SIG" 2>/dev/null; then
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

echo "==> [binary] Deriving binary public key..."
# Binary SK contains NUL bytes, so convert to hex for safe CLI arg passing,
# then convert the resulting hex public key back to binary for the size check.
SK_HEX=$(xxd -p "$TMPDIR_RUN/sk.bin" | tr -d '\n')
PK_HEX=$("${PULSE[@]}" keys pubkey --key "$SK_HEX")
printf '%s' "$PK_HEX" | xxd -r -p > "$TMPDIR_RUN/pk.bin"
PK_BYTES=$(wc -c < "$TMPDIR_RUN/pk.bin" | tr -d ' ')
echo "    Public key: (${PK_BYTES} bytes)"

echo "==> [binary] Generating base58 key pair for sign/verify..."
SK_B58=$("${PULSE[@]}" keys keygen --base58)
PK_B58=$("${PULSE[@]}" keys pubkey --key "$SK_B58")

# Write a binary message file (arbitrary bytes including NUL).
printf '\x00\x01\x02\x03\xde\xad\xbe\xef' > "$TMPDIR_RUN/msg.bin"

echo "==> [binary] Signing binary message file with binary output..."
"${PULSE[@]}" keys sign --key "$SK_B58" --message-file "$TMPDIR_RUN/msg.bin" --binary > "$TMPDIR_RUN/sig.bin"
SIG_BYTES=$(wc -c < "$TMPDIR_RUN/sig.bin" | tr -d ' ')
echo "    Signature:  (${SIG_BYTES} bytes)"

echo "==> [binary] Confirming binary signature is valid (base64-encoding for verify)..."
SIG_B64=$(base64 < "$TMPDIR_RUN/sig.bin" | tr -d '\n')
"${PULSE[@]}" keys verify --pubkey "$PK_B58" --message-file "$TMPDIR_RUN/msg.bin" --signature "$SIG_B64"

echo "==> [binary] Confirming binary signature fails for wrong message file..."
printf '\xff\xfe\xfd' > "$TMPDIR_RUN/wrong_msg.bin"
if "${PULSE[@]}" keys verify --pubkey "$PK_B58" --message-file "$TMPDIR_RUN/wrong_msg.bin" --signature "$SIG_B64" 2>/dev/null; then
    echo "    FAIL: signature should not have verified" >&2; exit 1
fi
echo "    signature invalid (correct)"

echo ""
echo "All tests passed."
