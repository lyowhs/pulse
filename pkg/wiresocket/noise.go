package wiresocket

import (
	"encoding/binary"
	"errors"
	"time"
)

// Noise_IK_25519_ChaChaPoly_BLAKE2s
//
// Pre-message: responder's static public key is known to the initiator.
//
//	-> e, es, s, ss
//	<- e, ee, se
//
// After the handshake both parties derive symmetric transport keys via SPLIT.

const (
	noiseProtocolName = "Noise_IK_25519_ChaChaPoly_BLAKE2s"
	noisePrologue     = "UDPStream v1"

	// Label prefixes for MAC1 and cookie derivation (WireGuard convention).
	labelMAC1   = "mac1----"
	labelCookie = "cookie--"
)

// initialCK and initialH are derived once at startup from the protocol name
// and prologue.
var (
	initialCK [32]byte
	initialH  [32]byte
)

func init() {
	// h = protocol_name (zero-padded if ≤ 32 bytes, hashed if > 32 bytes)
	name := []byte(noiseProtocolName)
	var h [32]byte
	if len(name) <= 32 {
		copy(h[:], name)
	} else {
		h = hashFn(name)
	}
	initialCK = h
	// Mix prologue into h.
	initialH = hashFn(h[:], []byte(noisePrologue))
}

// ─── symmetric state ─────────────────────────────────────────────────────────

type symmetricState struct {
	ck    [32]byte // chaining key
	h     [32]byte // transcript hash
	k     [32]byte // current AEAD key
	hasK  bool
	nonce uint64 // per-key nonce counter
}

func newSymmetricState() *symmetricState {
	return &symmetricState{ck: initialCK, h: initialH}
}

// mixHash incorporates data into the transcript hash.
func (ss *symmetricState) mixHash(data []byte) {
	ss.h = hashFn(ss.h[:], data)
}

// mixKey updates ck and k from new DH output.
func (ss *symmetricState) mixKey(dhOut [32]byte) {
	ck, k := kdf2(ss.ck, dhOut[:])
	ss.ck = ck
	ss.k = k
	ss.hasK = true
	ss.nonce = 0
}

// encryptAndHash encrypts plain under the current key with h as AAD,
// appends the tag, mixes the ciphertext into h, and returns the ciphertext.
func (ss *symmetricState) encryptAndHash(plain []byte) []byte {
	if !ss.hasK {
		ss.mixHash(plain)
		return append([]byte(nil), plain...)
	}
	cipher := encryptAEAD(nil, ss.k, ss.nonce, ss.h[:], plain)
	ss.nonce++
	ss.mixHash(cipher)
	return cipher
}

// decryptAndHash decrypts and authenticates cipher, mixes it into h, and
// returns the plaintext.
func (ss *symmetricState) decryptAndHash(cipher []byte) ([]byte, error) {
	if !ss.hasK {
		ss.mixHash(cipher)
		return append([]byte(nil), cipher...), nil
	}
	plain, err := decryptAEAD(ss.k, ss.nonce, ss.h[:], cipher)
	if err != nil {
		return nil, err
	}
	ss.nonce++
	ss.mixHash(cipher)
	return plain, nil
}

// split derives the two transport keys from the final chaining key.
// initiatorSend is the key used by the initiator to send data.
// initiatorRecv is the key used by the initiator to receive data.
func (ss *symmetricState) split() (initiatorSend, initiatorRecv [32]byte) {
	r := kdf(ss.ck, nil, 2)
	return r[0], r[1]
}

// ─── handshake state ─────────────────────────────────────────────────────────

// noiseState carries state through a single Noise IK handshake.
type noiseState struct {
	sym         *symmetricState
	localStatic Keypair
	remoteStatic [32]byte // responder's static pub (known to initiator upfront)
	localEph    Keypair
	remoteEph   [32]byte // filled when receiving a message
}

// ─── initiator ───────────────────────────────────────────────────────────────

// newInitiatorState creates a Noise IK handshake state for the initiator.
// remoteStatic is the responder's long-term public key.
func newInitiatorState(local Keypair, remoteStatic [32]byte) (*noiseState, error) {
	eph, err := GenerateKeypair()
	if err != nil {
		return nil, err
	}
	ns := &noiseState{
		sym:          newSymmetricState(),
		localStatic:  local,
		remoteStatic: remoteStatic,
		localEph:     eph,
	}
	// Pre-message: mix responder's static public key.
	ns.sym.mixHash(remoteStatic[:])
	return ns, nil
}

// CreateInit builds and returns a HandshakeInit message plus the mac1 key
// so the caller can stamp MAC1 before sending.
func (ns *noiseState) CreateInit(senderIndex uint32) (*HandshakeInit, error) {
	// -> e
	ns.sym.mixHash(ns.localEph.Public[:])

	// -> es: DH(e_initiator, s_responder)
	dhES, err := dhSafe(ns.localEph.Private, ns.remoteStatic)
	if err != nil {
		return nil, err
	}
	ns.sym.mixKey(dhES)

	// -> s: encrypt initiator static public key
	encS := ns.sym.encryptAndHash(ns.localStatic.Public[:])

	// -> ss: DH(s_initiator, s_responder)
	dhSS, err := dhSafe(ns.localStatic.Private, ns.remoteStatic)
	if err != nil {
		return nil, err
	}
	ns.sym.mixKey(dhSS)

	// payload: TAI64N timestamp
	ts := tai64n()
	encTS := ns.sym.encryptAndHash(ts[:])

	msg := &HandshakeInit{
		SenderIndex: senderIndex,
	}
	copy(msg.Ephemeral[:], ns.localEph.Public[:])
	if len(encS) != 48 {
		return nil, errors.New("udpstream: unexpected encrypted_static length")
	}
	copy(msg.EncryptedStatic[:], encS)
	if len(encTS) != 28 {
		return nil, errors.New("udpstream: unexpected encrypted_timestamp length")
	}
	copy(msg.EncryptedTimestamp[:], encTS)

	// Compute MAC1 over the message body (everything before the MAC fields).
	msg.MAC1 = computeMAC1(ns.remoteStatic, msg.mac1Body())
	// MAC2 left as zero (no cookie yet).
	return msg, nil
}

// ConsumeResp processes a HandshakeResp received from the responder.
// Call TransportKeys() afterward to get the symmetric keys.
func (ns *noiseState) ConsumeResp(msg *HandshakeResp) error {
	// <- e
	copy(ns.remoteEph[:], msg.Ephemeral[:])
	ns.sym.mixHash(ns.remoteEph[:])

	// <- ee: DH(e_initiator, e_responder)
	dhEE, err := dhSafe(ns.localEph.Private, ns.remoteEph)
	if err != nil {
		return err
	}
	ns.sym.mixKey(dhEE)

	// <- se: DH(s_initiator, e_responder)
	dhSE, err := dhSafe(ns.localStatic.Private, ns.remoteEph)
	if err != nil {
		return err
	}
	ns.sym.mixKey(dhSE)

	// Decrypt empty payload (just the AEAD tag — proves responder identity).
	_, err = ns.sym.decryptAndHash(msg.EncryptedNil[:])
	return err
}

// ─── responder ───────────────────────────────────────────────────────────────

// newResponderState creates a Noise IK handshake state for the responder.
func newResponderState(local Keypair) (*noiseState, error) {
	eph, err := GenerateKeypair()
	if err != nil {
		return nil, err
	}
	ns := &noiseState{
		sym:         newSymmetricState(),
		localStatic: local,
		localEph:    eph,
	}
	// Pre-message: mix our own static public key (responder).
	ns.sym.mixHash(local.Public[:])
	return ns, nil
}

// ConsumeInit processes a HandshakeInit from the initiator.
// Returns the initiator's static public key on success.
// Call CreateResp() next to build the response.
func (ns *noiseState) ConsumeInit(msg *HandshakeInit) ([32]byte, error) {
	// Verify MAC1.
	expectedMAC1 := computeMAC1(ns.localStatic.Public, msg.mac1Body())
	if expectedMAC1 != msg.MAC1 {
		return [32]byte{}, errors.New("udpstream: MAC1 mismatch")
	}

	// <- e
	copy(ns.remoteEph[:], msg.Ephemeral[:])
	ns.sym.mixHash(ns.remoteEph[:])

	// <- es: DH(s_responder, e_initiator)
	dhES, err := dhSafe(ns.localStatic.Private, ns.remoteEph)
	if err != nil {
		return [32]byte{}, err
	}
	ns.sym.mixKey(dhES)

	// <- s: decrypt initiator static public key
	plainS, err := ns.sym.decryptAndHash(msg.EncryptedStatic[:])
	if err != nil {
		return [32]byte{}, err
	}
	var initiatorPub [32]byte
	copy(initiatorPub[:], plainS)

	// <- ss: DH(s_responder, s_initiator)
	dhSS, err := dhSafe(ns.localStatic.Private, initiatorPub)
	if err != nil {
		return [32]byte{}, err
	}
	ns.sym.mixKey(dhSS)

	// Decrypt timestamp payload (12 bytes).
	tsPlain, err := ns.sym.decryptAndHash(msg.EncryptedTimestamp[:])
	if err != nil {
		return [32]byte{}, err
	}
	// Validate timestamp to prevent replay (must be within ±180 s of now).
	if err := validateTimestamp(tsPlain); err != nil {
		return [32]byte{}, err
	}

	ns.remoteStatic = initiatorPub
	return initiatorPub, nil
}

// CreateResp builds a HandshakeResp message after ConsumeInit succeeds.
func (ns *noiseState) CreateResp(senderIndex, receiverIndex uint32) (*HandshakeResp, error) {
	// -> e
	ns.sym.mixHash(ns.localEph.Public[:])

	// -> ee: DH(e_responder, e_initiator)
	dhEE, err := dhSafe(ns.localEph.Private, ns.remoteEph)
	if err != nil {
		return nil, err
	}
	ns.sym.mixKey(dhEE)

	// -> se: DH(e_responder, s_initiator)
	dhSE, err := dhSafe(ns.localEph.Private, ns.remoteStatic)
	if err != nil {
		return nil, err
	}
	ns.sym.mixKey(dhSE)

	// Encrypt empty payload.
	encNil := ns.sym.encryptAndHash(nil)

	msg := &HandshakeResp{
		SenderIndex:   senderIndex,
		ReceiverIndex: receiverIndex,
	}
	copy(msg.Ephemeral[:], ns.localEph.Public[:])
	if len(encNil) != 16 {
		return nil, errors.New("udpstream: unexpected encrypted_nil length")
	}
	copy(msg.EncryptedNil[:], encNil)

	// MAC1 over the response body, using the initiator's static pub as key.
	msg.MAC1 = computeMAC1(ns.remoteStatic, msg.mac1Body())
	return msg, nil
}

// TransportKeys returns the symmetric send/recv keys for this side.
// For the initiator: send = initiatorSend, recv = initiatorRecv.
// For the responder: send = initiatorRecv, recv = initiatorSend.
func (ns *noiseState) TransportKeys(isInitiator bool) (sendKey, recvKey [32]byte) {
	initiatorSend, initiatorRecv := ns.sym.split()
	if isInitiator {
		return initiatorSend, initiatorRecv
	}
	return initiatorRecv, initiatorSend
}

// ─── MAC1 helpers ────────────────────────────────────────────────────────────

// computeMAC1Key derives the MAC1 key from a static public key.
// key = HASH("mac1----" || static_pub)
func computeMAC1Key(staticPub [32]byte) [32]byte {
	return hashFn([]byte(labelMAC1), staticPub[:])
}

// computeMAC1 computes MAC1 for a handshake message body.
func computeMAC1(receiverStatic [32]byte, msgBody []byte) [16]byte {
	k := computeMAC1Key(receiverStatic)
	full := mac(k, msgBody)
	var out [16]byte
	copy(out[:], full[:16])
	return out
}

// ─── timestamp ───────────────────────────────────────────────────────────────

// tai64n returns a 12-byte TAI64N timestamp:
// 8 bytes (big-endian) seconds since TAI epoch + 4 bytes nanoseconds.
func tai64n() [12]byte {
	t := time.Now()
	var b [12]byte
	// TAI offset: 2^62 seconds between TAI epoch (1 Jan 1 CE) and Unix epoch.
	const taiOffset = uint64(0x4000000000000000)
	binary.BigEndian.PutUint64(b[:8], uint64(t.Unix())+taiOffset)
	binary.BigEndian.PutUint32(b[8:], uint32(t.Nanosecond()))
	return b
}

const maxTimestampSkew = 180 * time.Second

func validateTimestamp(b []byte) error {
	if len(b) < 12 {
		return errors.New("udpstream: timestamp too short")
	}
	const taiOffset = uint64(0x4000000000000000)
	secs := int64(binary.BigEndian.Uint64(b[:8]) - taiOffset)
	t := time.Unix(secs, 0)
	skew := time.Since(t)
	if skew < 0 {
		skew = -skew
	}
	if skew > maxTimestampSkew {
		return errors.New("udpstream: handshake timestamp out of range")
	}
	return nil
}
