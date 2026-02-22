# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

Go module: `example.com/pulse/pulse` (Go 1.25.3)

Post-quantum cryptography CLI using FN-DSA (lattice-based digital signatures).

## Common Commands

```bash
go build ./...              # Build all packages
go test ./...               # Run all tests
go test ./... -run TestFoo  # Run a specific test
go vet ./...                # Static analysis
bash scripts/test_sign_verify.sh  # End-to-end CLI test
```

## Architecture

```
cmd/pulse/              # CLI entry point
  main.go               # Calls Execute()
  root.go               # Root cobra command, viper config (prefix: PULSE_)
  keys/                 # `pulse keys` subcommand package
    keys.go             # Registers persistent --key/--key-file flags and subcommands
    keygen.go           # keys keygen --hex | --base58 | --binary
    pubkey.go           # keys pubkey --key|--key-file <sk>
    sign.go             # keys sign --key|--key-file <sk> --message|--message-file --base64|--binary
    verify.go           # keys verify --pubkey|--pubkey-file <vk> --message|--message-file --signature <sig>
    key.go              # shared signingKeyString() and verifyingKeyString() helpers
    message.go          # shared messageBytes() helper for sign and verify

pkg/
  crypto/falcon/        # Vendored FN-DSA implementation (go-fn-dsa)
    pubkey.go           # Added: PublicKeyFromSecretKey(skey []byte) ([]byte, error)
  keys/                 # Domain logic — encoding-agnostic key/sign/verify operations
    keys.go             # Generate, PublicKey, Sign, Verify, Encode, Decode
    keys_test.go
  vdf/                  # Wesolowski VDF implementation
    vdf.go              # VDF.Evaluate / VDF.Verify
    modulus.go          # DefaultModulus() RSA-2048, GenerateModulus()
    vdf_test.go
```

## Key Conventions

**Key encoding** (`pkg/keys`): `Decode` auto-detects hex → base58 → binary fallback (never errors). `Encode` preserves the detected encoding. `PublicKey` output encoding matches input encoding.

**Signature encoding** (`cmd/pulse/keys/verify.go`): auto-detected — valid base64 is used as-is; anything else is treated as raw binary and base64-encoded before being passed to `pkg/keys`.

**Binary I/O**: FN-DSA keys (1281 bytes) and signatures (666 bytes) structurally contain NUL bytes, so they cannot be passed as shell arguments. Binary keys/signatures must be written to files via redirection and passed with tools like `xxd` or `base64` when used as CLI arguments.

**Cobra/Viper wiring**: `--key` and `--key-file` are persistent flags on the `keys` command, both bound to viper (`PULSE_KEY`, `PULSE_KEY_FILE`). `--pubkey`, `--pubkey-file`, and `--signature` are bound per-command. `--message` falls back to viper but is read directly from the flag first to avoid subcommand scoping issues.
