# Pulse

Post-quantum cryptography CLI.

## keys

The `keys` command groups all key generation and signature operations. The signing key is a global flag available to all subcommands.

```
pulse keys [--key <secret-key>] <command>
```

| Flag | Description |
|---|---|
| `--key` | Hex, base58, or raw binary encoded signing key (env: `PULSE_KEY`) |

---

### keys keygen

Generate a new signing key pair and print the signing (secret) key to stdout. The output encoding is selected with a required flag.

```
pulse keys keygen --hex | --base58 | --binary
```

| Flag | Description |
|---|---|
| `--hex` | Output the signing key as a hex-encoded string |
| `--base58` | Output the signing key as a base58-encoded string |
| `--binary` | Output the signing key as raw binary bytes |

`--hex`, `--base58`, and `--binary` are mutually exclusive.

**Examples**

Generate a base58-encoded signing key:

```sh
$ pulse keys keygen --base58
2ppYSmLDJstBxnSk93R5hZdh6JVNQPat7eKL4wY...
```

Generate a hex-encoded signing key:

```sh
$ pulse keys keygen --hex
5968014d2a3f8bc4e1f2a09c3b7d56e1a84f2c...
```

Generate a raw binary signing key:

```sh
$ pulse keys keygen --binary > signing.key
```

Store a key in a shell variable for use in subsequent commands:

```sh
SK=$(pulse keys keygen --base58)
```

---

### keys pubkey

Derive the verifying (public) key from a signing (secret) key. The output encoding matches the input encoding — a base58 key produces a base58 public key, a hex key produces a hex public key, and a binary key produces raw binary output.

```
pulse keys pubkey --key <secret-key>
```

| Flag | Description |
|---|---|
| `--key` | Hex, base58, or raw binary encoded signing key (required, env: `PULSE_KEY`) |

**Examples**

Derive a public key from a base58 signing key:

```sh
$ pulse keys pubkey --key "$SK"
32kWXnipz7SmWmRCGjGoJ4NokAPCiwZf3ACpKAu...
```

Pipe directly from `keygen`:

```sh
$ pulse keys keygen --base58 | xargs -I{} pulse keys pubkey --key {}
32kWXnipz7SmWmRCGjGoJ4NokAPCiwZf3ACpKAu...
```

Derive a public key from a binary signing key file:

```sh
$ pulse keys pubkey --key "$(cat signing.key)" > verifying.key
```

---

### keys sign

Sign a message using a signing key.

```
pulse keys sign --key <secret-key> --message <message> --base64 | --binary
```

| Flag | Description |
|---|---|
| `--key` | Hex, base58, or raw binary encoded signing key (required, env: `PULSE_KEY`) |
| `--message` | Message to sign (required, env: `PULSE_MESSAGE`) |
| `--base64` | Output the signature as a base64-encoded string |
| `--binary` | Output the signature as raw binary bytes |

`--base64` and `--binary` are mutually exclusive.

**Examples**

Sign a message and output base64:

```sh
$ pulse keys sign --key "$SK" --message "Hello World!" --base64
ObHohkPYPEy9fB0jUuyCkF0aLwyDOOP+Gc7x1R...
```

Sign a binary message and write a binary signature to a file:

```sh
$ pulse keys sign --key "$SK" --message "$(cat data.bin)" --binary > sig.bin
```

Store the signature in a shell variable:

```sh
SIG=$(pulse keys sign --key "$SK" --message "Hello World!" --base64)
```

---

### keys verify

Verify a signature against a message and public key. Exits with code `0` and prints `signature valid` on success, or exits with a non-zero code and prints `signature invalid` on failure.

```
pulse keys verify --pubkey <public-key> --message <message> --signature <signature> --base64 | --binary
```

| Flag | Description |
|---|---|
| `--pubkey` | Hex, base58, or raw binary encoded verifying key (required, env: `PULSE_PUBKEY`) |
| `--message` | Message that was signed (required, env: `PULSE_MESSAGE`) |
| `--signature` | Signature to verify (required, env: `PULSE_SIGNATURE`) |
| `--base64` | Signature is base64-encoded |
| `--binary` | Signature is raw binary bytes |

`--base64` and `--binary` are mutually exclusive.

**Examples**

Verify a valid base64 signature:

```sh
$ pulse keys verify --pubkey "$PK" --message "Hello World!" --signature "$SIG" --base64
signature valid
```

Verify a binary signature against a binary message:

```sh
$ pulse keys verify --pubkey "$PK" --message "$(cat data.bin)" --signature "$(cat sig.bin)" --binary
signature valid
```

Verify with the wrong message (exits non-zero):

```sh
$ pulse keys verify --pubkey "$PK" --message "Wrong message" --signature "$SIG" --base64
Error: signature invalid
```

Verify with a tampered signature (exits non-zero):

```sh
$ pulse keys verify --pubkey "$PK" --message "Hello World!" --signature "aW52YWxpZA==" --base64
Error: signature invalid
```

---

### Full example

Generate a key pair, sign a message, and verify the signature in one pipeline:

```sh
# Generate keys
SK=$(pulse keys keygen --base58)
PK=$(pulse keys pubkey --key "$SK")

# Sign
SIG=$(pulse keys sign --key "$SK" --message "Hello World!" --base64)

# Verify
pulse keys verify --pubkey "$PK" --message "Hello World!" --signature "$SIG" --base64
# signature valid
```

### Environment variables

All flags can be set via environment variables, which is useful for scripting without repeatedly passing long key strings.

| Variable | Equivalent flag |
|---|---|
| `PULSE_KEY` | `--key` |
| `PULSE_PUBKEY` | `--pubkey` |
| `PULSE_MESSAGE` | `--message` |
| `PULSE_SIGNATURE` | `--signature` |

```sh
export PULSE_KEY=$(pulse keys keygen --base58)
export PULSE_PUBKEY=$(pulse keys pubkey)
export PULSE_MESSAGE="Hello World!"
export PULSE_SIGNATURE=$(pulse keys sign --base64)

pulse keys verify --base64
# signature valid
```
