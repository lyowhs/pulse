# Wiresocket Protocol Specification

> **DRAFT** — This document reflects implementation as of 2026-02-26 and is pending formal review.

Version: 1 (`noisePrologue = "wiresocket v1"`)

---

## 1. Overview

Wiresocket is a WireGuard-inspired, encrypted UDP event-stream protocol.
It provides a bidirectional, multi-channel event stream between a client and
server over a single UDP socket.

**Key properties:**

- **Transport**: UDP (connectionless)
- **Encryption**: Noise IK over X25519 / ChaCha20-Poly1305 / BLAKE2s
- **Authentication**: Both static keys (server always; client optionally)
- **Multiplexing**: up to 256 independent channels per session (channel IDs 0–255)
- **Fragmentation**: frames exceeding one UDP datagram are split across up to 65 535 fragments
- **DoS mitigation**: WireGuard-style cookies (XChaCha20-Poly1305)
- **Replay protection**: 4096-entry sliding window
- **Reliable delivery**: optional per-channel sequencing, cumulative + selective ACKs (SACK), retransmit with exponential backoff, and window-based flow control
- **Rate limiting**: optional per-session send rate cap (token bucket; configurable bytes-per-second)

All multi-byte integers are **little-endian** unless stated otherwise.

---

## 2. Cryptographic Primitives

| Primitive | Algorithm | Notes |
|---|---|---|
| DH | X25519 (RFC 7748) | Low-order-point rejection enforced |
| AEAD (handshake) | ChaCha20-Poly1305 (RFC 8439) | |
| AEAD (transport) | ChaCha20-Poly1305 | One AEAD instance per direction, cached per session |
| AEAD (cookie reply) | XChaCha20-Poly1305 | 24-byte random nonce |
| Hash | BLAKE2s-256 | |
| MAC | Keyed BLAKE2s-256 | `BLAKE2s(key=K, data=D)` |
| KDF | HKDF-BLAKE2s | See §2.1 |
| Keypairs | X25519 | RFC 7748 clamping applied |

### 2.1 KDF

```
prk     = MAC(key=ck, data=input)
T[1]    = MAC(key=prk, data=0x01)
T[i]    = MAC(key=prk, data=T[i-1] || byte(i))
```

`kdf2(ck, input)` returns `(T[1], T[2])`.
`kdf3(ck, input)` returns `(T[1], T[2], T[3])`.

### 2.2 Initial chaining key and hash

```
initialCK = "Noise_IK_25519_ChaChaPoly_BLAKE2s"   (zero-padded to 32 bytes)
initialH  = HASH(initialCK || "wiresocket v1")
```

Both are computed once at process startup.

### 2.3 AEAD nonce

Transport AEAD nonces are 12 bytes:

```
nonce[0:4]  = 0x00 0x00 0x00 0x00
nonce[4:12] = counter (uint64 LE)
```

### 2.4 MAC1 derivation

```
mac1_key = HASH("mac1----" || receiver_static_pub)
MAC1     = MAC(mac1_key, message_body)[0:16]
```

`message_body` is everything in the serialised message before the MAC fields.

### 2.5 MAC2 derivation

```
MAC2 = MAC(key=cookie[0:16] zero-extended to 32 bytes, data=message_body)[0:16]
```

---

## 3. Packet Types

The first byte of every UDP datagram is a **type tag**:

| Value | Name | Size (bytes) |
|---|---|---|
| 1 | HandshakeInit | 148 |
| 2 | HandshakeResp | 92 |
| 3 | CookieReply | 64 |
| 4 | Data | 16 + ciphertext |
| 5 | Disconnect | 32 (16 header + 16 AEAD tag) |
| 6 | Keepalive | 32 (16 header + 16 AEAD tag) |
| 7 | DataFragment | 16 + ciphertext |

---

## 4. Wire Formats

### 4.1 HandshakeInit (type 1, 148 bytes)

Sent by the initiator to begin a session.

```
Offset  Size  Field
------  ----  -----
0       1     type = 0x01
1       3     reserved (zero)
4       4     sender_index         uint32 LE — initiator's session token
8       32    ephemeral            initiator ephemeral public key (X25519)
40      48    encrypted_static     AEAD(initiator static pub key, 32 plain + 16 tag)
88      28    encrypted_timestamp  AEAD(TAI64N timestamp, 12 plain + 16 tag)
116     16    mac1                 MAC1 keyed by responder's static pub
132     16    mac2                 MAC2 keyed by cookie (zeros if no cookie)
```

`sender_index` is a random 32-bit token chosen by the initiator.
It is used as `receiver_index` in all subsequent packets the server sends
to this session.

`encrypted_timestamp` carries a 12-byte TAI64N timestamp
(`uint64 BE seconds` || `uint32 BE nanoseconds`).
The TAI epoch offset applied is `0x4000000000000000`.
The responder rejects timestamps more than ±180 seconds from its own clock.

### 4.2 HandshakeResp (type 2, 92 bytes)

Sent by the responder in reply to a valid HandshakeInit.

```
Offset  Size  Field
------  ----  -----
0       1     type = 0x02
1       3     reserved (zero)
4       4     sender_index         uint32 LE — responder's session token
8       4     receiver_index       uint32 LE — echoes initiator's sender_index
12      32    ephemeral            responder ephemeral public key (X25519)
44      16    encrypted_nil        AEAD(empty plaintext) — 0 plain + 16 tag
60      16    mac1                 MAC1 keyed by initiator's static pub
76      16    mac2                 MAC2 keyed by cookie (zeros if no cookie)
```

### 4.3 CookieReply (type 3, 64 bytes)

Sent by the server instead of HandshakeResp when under load.
The cookie must be used in MAC2 of the retried HandshakeInit.

```
Offset  Size  Field
------  ----  -----
0       1     type = 0x03
1       3     reserved (zero)
4       4     receiver_index       uint32 LE — echoes initiator's sender_index
8       24    nonce                random 24-byte XChaCha20 nonce
32      32    encrypted_cookie     XChaCha20-Poly1305(cookie, 16 plain + 16 tag)
```

The XChaCha20-Poly1305 key is the MAC1 from the HandshakeInit zero-extended
to 32 bytes. Only the genuine initiator (who knows its own MAC1) can decrypt
the cookie.

### 4.4 Data (type 4)

Carries one encrypted Frame. Total size: `16 + len(plaintext) + 16`.

```
Offset  Size  Field
------  ----  -----
0       1     type = 0x04
1       3     reserved (zero)
4       4     receiver_index       uint32 LE — recipient's session token
8       8     counter              uint64 LE — monotonic send counter
16      N+16  ciphertext           ChaCha20-Poly1305(frame_bytes, N plain + 16 tag)
```

AAD is empty. The nonce is constructed from `counter` (see §2.3).

### 4.5 Disconnect (type 5, 32 bytes)

Authenticated graceful shutdown notification. Same header layout as Data
with an AEAD over empty plaintext.

```
Offset  Size  Field
------  ----  -----
0       1     type = 0x05
1       3     reserved (zero)
4       4     receiver_index       uint32 LE
8       8     counter              uint64 LE
16      16    AEAD tag             ChaCha20-Poly1305(empty) — 0 plain + 16 tag
```

### 4.6 Keepalive (type 6, 32 bytes)

Liveness probe. Same layout as Disconnect with type 6.

```
Offset  Size  Field
------  ----  -----
0       1     type = 0x06
1       3     reserved (zero)
4       4     receiver_index       uint32 LE
8       8     counter              uint64 LE
16      16    AEAD tag             ChaCha20-Poly1305(empty) — 0 plain + 16 tag
```

A keepalive is sent whenever no data has been exchanged for `KeepaliveInterval`
(default 10 s). The counter participates in replay protection.

### 4.7 DataFragment (type 7)

Carries one encrypted fragment of a large Frame.
Total size: `16 + 8 + len(frag_data) + 16`.

```
Offset  Size  Field
------  ----  -----
0       1     type = 0x07
1       3     reserved (zero)
4       4     receiver_index       uint32 LE
8       8     counter              uint64 LE
16      N+24  ciphertext           ChaCha20-Poly1305(frag_plain, (8+M) plain + 16 tag)
```

The **plaintext** inside the ciphertext has its own sub-header:

```
Plain offset  Size  Field
------------  ----  -----
0             4     frame_id     uint32 LE — unique per frame within a session
4             2     frag_index   uint16 LE — zero-based index of this fragment
6             2     frag_count   uint16 LE — total number of fragments (1–65535)
8             M     frag_data    raw fragment bytes
```

`frame_id` is a monotonically increasing counter scoped to the sending session.
All fragments of the same frame share the same `frame_id`.

---

## 5. Noise IK Handshake

The handshake follows the **Noise IK** pattern
(`Noise_IK_25519_ChaChaPoly_BLAKE2s`):

```
Pre-messages:
  -> s   (responder's static public key known to initiator out-of-band)

Messages:
  -> e, es, s, ss    (HandshakeInit)
  <- e, ee, se       (HandshakeResp)
```

### 5.1 Symmetric State

Both sides maintain a symmetric state `(ck, h, k, nonce)`:

- `ck` — chaining key, starts as `initialCK`
- `h` — transcript hash, starts as `initialH`
- `k` — current AEAD key (empty until first `mixKey`)
- `nonce` — per-key counter, reset to 0 on each `mixKey`

**`mixHash(data)`**: `h = HASH(h || data)`

**`mixKey(dh_out)`**: `(ck, k) = kdf2(ck, dh_out)` ; `nonce = 0`

**`encryptAndHash(plain)`**: `c = AEAD_Seal(k, nonce++, h, plain)` ; `mixHash(c)` ; return `c`

**`decryptAndHash(cipher)`**: `p = AEAD_Open(k, nonce++, h, cipher)` ; `mixHash(cipher)` ; return `p`

### 5.2 Initiator: CreateInit

Starting state: `ck = initialCK`, `h = HASH(initialCK || "wiresocket v1")`.

```
Pre-message:
  mixHash(responder_static_pub)

Message construction:
  mixHash(e_pub)                         # -> e
  (ck, k) = kdf2(ck, DH(e_priv, s_resp_pub))  # -> es
  encrypted_static  = encryptAndHash(s_init_pub)  # -> s
  (ck, k) = kdf2(ck, DH(s_init_priv, s_resp_pub)) # -> ss
  encrypted_timestamp = encryptAndHash(TAI64N())
  mac1 = MAC1(responder_static_pub, msg_body_without_macs)
  mac2 = MAC2(cookie, msg_body_without_mac2)   # zero if no cookie
```

### 5.3 Responder: ConsumeInit

```
Pre-message:
  mixHash(local_static_pub)

Verification and processing:
  verify MAC1
  mixHash(e_init_pub)                    # -> e
  (ck, k) = kdf2(ck, DH(s_resp_priv, e_init_pub)) # -> es
  s_init_pub = decryptAndHash(encrypted_static)    # -> s
  (ck, k) = kdf2(ck, DH(s_resp_priv, s_init_pub)) # -> ss
  timestamp = decryptAndHash(encrypted_timestamp)
  validate timestamp within ±180 s
```

### 5.4 Responder: CreateResp

Continues immediately after ConsumeInit.

```
  mixHash(e_resp_pub)                    # -> e
  (ck, k) = kdf2(ck, DH(e_resp_priv, e_init_pub)) # -> ee
  (ck, k) = kdf2(ck, DH(e_resp_priv, s_init_pub)) # -> se
  encrypted_nil = encryptAndHash(empty)
  mac1 = MAC1(initiator_static_pub, resp_body_without_macs)
  mac2 = 0 (no cookie in response)
```

### 5.5 Initiator: ConsumeResp

```
  mixHash(e_resp_pub)                    # <- e
  (ck, k) = kdf2(ck, DH(e_init_priv, e_resp_pub)) # <- ee
  (ck, k) = kdf2(ck, DH(s_init_priv, e_resp_pub)) # <- se
  decryptAndHash(encrypted_nil)          # proves responder identity
```

### 5.6 Transport Key Derivation (SPLIT)

After both sides complete the handshake:

```
(T_initiator_send, T_initiator_recv) = kdf2(ck, empty)
```

- Initiator sends with `T_initiator_send`, receives with `T_initiator_recv`.
- Responder sends with `T_initiator_recv`, receives with `T_initiator_send`.

---

## 6. Cookie / DoS Mitigation

When the server is under load, it may respond to HandshakeInit with a
CookieReply instead of HandshakeResp.

### 6.1 Cookie derivation (server side)

The server maintains a 32-byte `cookie_secret` rotated every 2 minutes.

```
cookie_key = MAC(key=cookie_secret, data="cookie--" || server_static_pub)
cookie     = MAC(key=cookie_key, data=client_addr_string)[0:16]
```

`client_addr_string` is the client's UDP address formatted as `"ip:port"`.

### 6.2 CookieReply construction

```
key = mac1_from_HandshakeInit zero-extended to 32 bytes
nonce = random 24 bytes
encrypted_cookie = XChaCha20-Poly1305-Seal(key, nonce, cookie, aad=empty)
```

### 6.3 MAC2 retry

On receiving a CookieReply, the initiator decrypts the cookie and retries
HandshakeInit with:

```
MAC2 = MAC2(cookie, message_body_without_mac2)[0:16]
```

The server accepts a HandshakeInit with a valid MAC2 even under load.

---

## 7. Session Lifecycle

```
Client                          Server
  |                               |
  |------ HandshakeInit --------->|
  |                               | (may send CookieReply if under load)
  |<----- HandshakeResp ----------|
  |                               |
  |  [session established]        |
  |                               |
  |<===== Data / Fragments ======>|
  |<===== Keepalives ============>|
  |                               |
  |------ Disconnect ------------>|  (or timeout)
```

### 7.1 Session indices

Each side independently picks a random 32-bit `session_index`.
The sender places the **recipient's** index in every outgoing data packet's
`receiver_index` field so the recipient can route it to the correct session.

### 7.2 Send counter

The sender maintains a monotonically increasing 64-bit counter starting at 0.
The counter is used both as the AEAD nonce and for the receiver's replay window.
When the counter reaches `2^64 - 1` it wraps to 0 and the session is closed,
forcing a new handshake.

### 7.3 Timeouts and keepalives

| Parameter | Default | Description |
|---|---|---|
| `KeepaliveInterval` | 10 s | Send keepalive if data idle for this long |
| `SessionTimeout` | 180 s | Close session if no packet received for this long |
| `RekeyAfterTime` | 180 s | Initiate new handshake after this session age |
| `RekeyAfterMessages` | 2^60 | Initiate new handshake after this many packets sent |

Each side enforces its own timeout independently.

Keepalive receipt does **not** reset the data-idle timer; a peer that only
sends keepalives will still receive them in return.

---

## 8. Replay Protection

Incoming data, keepalive, disconnect, and fragment packets are all subject to
replay protection using a 4096-entry sliding window implemented as a
`[64]uint64` bitmap (64 words × 64 bits).

```
Window covers: [head - 4095, head]
```

- If `counter > head`: accepted (new high-water mark).
- If `counter < head - 4095`: rejected (too old).
- Otherwise: check bitmask. If bit already set: rejected (duplicate).

The window is updated (`head` advanced, bitmap updated) only after AEAD
decryption succeeds. `head` is stored atomically for a lock-free fast path
on the common case of strictly in-order delivery.

**Why 4096 entries?** On Linux, `sendFragments` allocates all N fragment
counters in a tight loop *before* the `sendmmsg` batch is written to the
socket. A concurrent keepalive send can steal a counter mid-loop and arrive
at the peer before the fragment batch, causing the peer's `head` to advance
past the early fragment counters. With the original 64-entry window, a
difference ≥ 64 triggered spurious replay rejections and permanent event
loss. A 4096-entry window safely accommodates the maximum in-flight fragment
count with ample headroom.

---

## 9. Fragmentation

Frames whose serialised plaintext exceeds `maxFragPayload` bytes are split
into multiple DataFragment packets.

### 9.1 Default MTU parameters

| Parameter | Value | Derivation |
|---|---|---|
| Default MaxPacketSize | 1232 bytes | IPv6 min path MTU (1280) − IPv6 header (40) − UDP header (8) |
| Default maxFragPayload | 1192 bytes | 1232 − DataHeader(16) − FragmentHeader(8) − AEADTag(16) |
| Maximum fragments per frame | 65 535 | `frag_count` is uint16 |
| Maximum frame size at default MTU | ≈ 78 MB | 65 535 × 1192 bytes |

### 9.2 Reassembly

The receiver maintains a map of partial frames keyed by `frame_id`.
When all `frag_count` fragments for a `frame_id` arrive, the payloads are
concatenated in `frag_index` order and the result is decoded as a Frame.

Incomplete fragment sets are garbage-collected after `2 × KeepaliveInterval`
of inactivity. At most `MaxIncompleteFrames` (default 64, configurable per
`ServerConfig`/`DialConfig`) partial frames are buffered per session; excess
fragments are silently dropped.

Duplicate fragments (same `frame_id` + `frag_index`) are ignored.

---

## 10. Frame Wire Format

A **Frame** is the plaintext inside a Data or reassembled DataFragment packet.
It uses a custom encoding that is a strict subset of Protocol Buffers wire
format, allowing standard proto decoders to parse it as an extension of the
proto schema.

```
Byte 0:       channel_id    (uint8, raw — not proto-encoded)
Bytes 1..N:   events        (field-1 LEN records, one per event)
[optional]    Seq           (field-2 varint)  — omitted when 0 (unreliable)
[optional]    AckSeq        (field-3 varint)  — omitted when 0
[optional]    AckBitmap     (field-4 I64 LE)  — omitted when 0
[optional]    WindowSize    (field-5 varint)  — omitted when 0
```

Each event body is encoded as a Protocol Buffers–style LEN field:

```
varint(0x0A)             # field=1, wire type=2 (LEN)  → event body follows
varint(len(event_body))  # byte length of event body
event_body[0]            # event type (uint8, 0–254 app-defined; 255 internal)
event_body[1:]           # opaque payload bytes (may be empty)
```

The reliability fields are appended after all events using these proto tags:

```
varint(0x10)             # field=2, wire type=0 (varint)  → Seq (uint32)
varint(0x18)             # field=3, wire type=0 (varint)  → AckSeq (uint32)
varint(0x21)             # field=4, wire type=1 (I64 LE)  → AckBitmap (uint64)
varint(0x28)             # field=5, wire type=0 (varint)  → WindowSize (uint32)
```

All four reliability fields are zero-omitted, preserving backward
compatibility with peers that implement only unreliable delivery.

A **standalone ACK** frame carries no events (`Events` is empty) and has
`Seq == 0`; it carries only `AckSeq`, `AckBitmap`, and `WindowSize`.

Multiple events may be packed into a single Frame (coalescing).

### 10.1 Channel IDs

| Value | Usage |
|---|---|
| 0 | Default channel |
| 1–254 | Application-defined channels |
| 255 | Internal (`channelCloseType`) |

Event type 255 (`channelCloseType`) on any channel signals that the remote
peer has closed that channel. The receiver evicts the channel and signals any
blocked `Recv` callers with an error.

---

## 11. Reliable Delivery

Reliable delivery is opt-in per channel via `Channel.SetReliable(ReliableCfg)`.
Channels that do not call `SetReliable` have zero overhead; all reliability
fields in their frames are zero and ignored on receipt.

### 11.1 Sequence numbers

Sequence numbers are `uint32`, starting at **1** (0 is reserved to mean
"unreliable"). The sender assigns a monotonically increasing sequence number
to each outgoing frame in `preSend`. Sequence numbers reset to 1 whenever
the underlying session reconnects (persistent connections).

### 11.2 Cumulative ACK

`AckSeq` carries the **next expected** sequence number (TCP-style). A value
of `AckSeq = N` means the receiver has received all frames with
`seq ∈ [1, N-1]` in order and is waiting for `seq == N`. The sender frees
all pending frames with `seq < AckSeq`.

### 11.3 Selective ACK (SACK)

`AckBitmap` is a 64-bit SACK bitmap. Bit `i` (LSB = bit 0) is set when
the frame with sequence number `AckSeq + i + 1` has been received out of
order. The sender uses this to free selectively acknowledged frames without
waiting for gap-filling retransmits.

The receiver maintains an out-of-order (OOO) buffer of at most
`reliableOOOWindow = 64` slots. Frames arriving more than 64 positions ahead
of the expected sequence are dropped.

### 11.4 Flow control (window)

`WindowSize` reports how many additional frames the sender of the ACK can
accept (receive-buffer headroom). The remote sender blocks when
`numPending >= peerWindow`. `WindowSize` is updated dynamically as the
receiver's channel buffer drains. The initial window equals the configured
`ReliableCfg.WindowSize` (default 256).

### 11.5 ACK timing

ACKs are **piggybacked** on outgoing data frames whenever possible: before
a data frame is sent, any pending ACK state is consumed and written into
the frame's `AckSeq`/`AckBitmap`/`WindowSize` fields at no extra cost.

When no data is ready to send, a **standalone ACK** is dispatched after at
most `ACKDelay` (default 20 ms) by a `time.AfterFunc` timer.

### 11.6 Retransmit

A single retransmit timer (`time.AfterFunc`) is armed per channel after any
frame is sent. On firing it retransmits the oldest unACKed frame and
reschedules itself with **exponential backoff** (RTO doubles each retry,
capped at `maxRTO = 30 s`). After `MaxRetries` (default 10) consecutive
retransmit attempts the channel is closed.

The retransmit timer is reset to `BaseRTO` (default 200 ms) whenever an ACK
frees at least one frame.

### 11.7 Reconnect behaviour

When a persistent `Conn` reconnects, `reset()` is called on every channel
that has a `reliableState`. This purges all pending frames, resets `nextSeq`
to 1, restores `peerWindow` to the configured maximum, and broadcasts on the
flow-control condition variable to unblock any goroutines waiting in
`preSend`. The receiver-side `expectSeq` is also reset to 1 and the OOO
buffer is cleared.

In-flight frames that had not been ACKed before the reconnect are discarded;
the application layer is responsible for any end-to-end retransmission policy
across reconnects.

---

## 12. Numeric Limits

| Constant | Value |
|---|---|
| `sizeHandshakeInit` | 148 bytes |
| `sizeHandshakeResp` | 92 bytes |
| `sizeCookieReply` | 64 bytes |
| `sizeDataHeader` | 16 bytes |
| `sizeFragmentHeader` | 8 bytes |
| `sizeAEADTag` | 16 bytes |
| `sizeKeepalive` / `sizeDisconnect` | 32 bytes |
| `defaultMaxPacketSize` | 1232 bytes |
| `defaultMaxFragPayload` | 1192 bytes |
| `MaxIncompleteFrames` (default) | 64 (configurable) |
| `windowWords` | 64 |
| `windowSize` (replay) | 4096 (= 64 words × 64 bits) |
| `maxTimestampSkew` | 180 s |
| `cookieRotation` | 2 min |
| `rekeyAfterTime` | 180 s |
| `rekeyAfterMessages` | 2^60 |
| Maximum fragments per frame | 65 535 |
| Maximum channels | 256 (IDs 0–255) |
| `defaultReliableWindow` | 256 frames |
| `defaultBaseRTO` | 200 ms |
| `defaultMaxRetries` | 10 |
| `defaultACKDelay` | 20 ms |
| `maxRTO` | 30 s |
| `reliableOOOWindow` | 64 slots |

---

## 13. Implementation Notes

### Batch sends (Linux)

On Linux, outgoing fragments are sent in a single `sendmmsg(2)` syscall via
`ipv4.PacketConn.WriteBatch` (IPv4 sockets) or `ipv6.PacketConn.WriteBatch`
(IPv6 sockets). On other platforms, fragments are sent in a loop of
individual `sendmsg` calls.

### Batch receives

Incoming UDP datagrams are read in batches of up to 64 (server) or 16
(client) messages per `recvmmsg(2)` syscall via `ipv4.PacketConn.ReadBatch`.

### Buffer pools

Send and receive paths use `sync.Pool`-backed byte slices to reduce GC
pressure. AEAD operations write ciphertext and plaintext in-place into pool
buffers; no additional allocation occurs on the hot path when buffers have
sufficient capacity.

### Socket buffers

Both client and server request 4 MiB `SO_RCVBUF` / `SO_SNDBUF`. On Linux,
this may be silently clamped by `net.core.rmem_max` / `wmem_max`
(default ≈ 208 KiB). To guarantee the full 4 MiB, either raise the sysctl:

```bash
sysctl -w net.core.rmem_max=4194304
sysctl -w net.core.wmem_max=4194304
```

or use `SO_RCVBUFFORCE` (requires `CAP_NET_ADMIN`).
In Docker, pass `--sysctl net.core.rmem_max=4194304`.

### Rate limiting

When `SendRateLimitBPS` is non-zero in `ServerConfig` or `DialConfig`, a
token-bucket limiter is installed on the session's send path. The burst
capacity is 2× the per-second rate, allowing short bursts to proceed at
full wire speed. The limiter is checked in `session.send()` and
`session.sendFragments()` before each write; it sleeps on a timer when
tokens are exhausted and aborts early if the session closes.

### Pipeline sizing (`ProbeUDPRecvBufSize`)

Benchmark and high-throughput pipeline code should call
`wiresocket.ProbeUDPRecvBufSize(requested int) int` to determine the actual
achievable receive-buffer size before computing `inflightCap`. On Linux
without `CAP_NET_ADMIN`, `SO_RCVBUF` is clamped by `net.core.rmem_max`; the
probe function creates a temporary loopback socket, applies
`SO_RCVBUFFORCE` (falling back to `SO_RCVBUF`), reads back the result with
`getsockopt`, and divides by 2 to undo the kernel's automatic doubling. On
other platforms it returns `requested` unchanged. Using the probed value
prevents the in-flight frame count from exceeding what the kernel buffer can
hold, avoiding packet loss under burst sends.
