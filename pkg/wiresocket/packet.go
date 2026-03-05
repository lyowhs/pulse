package wiresocket

import (
	"encoding/binary"
	"errors"
)

// Packet type tags (first byte of every UDP datagram).
const (
	typeHandshakeInit = 1
	typeHandshakeResp = 2
	typeCookieReply   = 3
	typeData          = 4
	typeDisconnect    = 5
	typeKeepalive     = 6
	typeDataFragment  = 7
)

// Wire sizes.
const (
	sizeHandshakeInit  = 148 // 1+3+4+32+48+28+16+16
	sizeHandshakeResp  = 92  // 1+3+4+4+32+16+16+16
	sizeCookieReply    = 64  // 1+3+4+24+32
	sizeDataHeader     = 16  // 1+3+4+8  (payload follows)
	sizeAEADTag        = 16
	sizeKeepalive      = sizeDataHeader + sizeAEADTag // type=6, AEAD over empty payload
	sizeDisconnect     = sizeDataHeader + sizeAEADTag // type=5, same layout as keepalive
	sizeFragmentHeader = 8                            // frame_id(4) + frag_index(2) + frag_count(2)

	// defaultMaxFragPayload is the maximum plaintext data bytes per fragment
	// when MaxPacketSize is not configured.
	// Sized to keep the UDP datagram under 1232 bytes (IPv6 minimum path MTU
	// of 1280 minus 40-byte IPv6 header minus 8-byte UDP header):
	//   1232 - sizeDataHeader(16) - sizeFragmentHeader(8) - sizeAEADTag(16) = 1192
	defaultMaxFragPayload = 1192

	// defaultMaxPacketSize is the UDP datagram size implied by defaultMaxFragPayload.
	defaultMaxPacketSize = 1232
)

// MaxFragmentPayload returns the maximum plaintext data bytes that fit in one
// UDP fragment for the given packet size limit.  This is the payload budget
// after subtracting the data header, fragment header, and AEAD tag overhead.
func MaxFragmentPayload(mtu int) int {
	v := mtu - sizeDataHeader - sizeFragmentHeader - sizeAEADTag
	if v < 0 {
		return 0
	}
	return v
}

// MaxEventPayload returns the maximum event payload size in bytes that can be
// sent as a single (possibly fragmented) frame at the given UDP MTU.  Events
// larger than this value would require more than 65535 fragments and cannot
// be transmitted.
func MaxEventPayload(mtu int) int {
	maxFrag := MaxFragmentPayload(mtu)
	if maxFrag <= 0 {
		return 0
	}
	return 65535 * maxFrag
}

// ─── HandshakeInit ───────────────────────────────────────────────────────────

// HandshakeInit is the first message sent by the initiator.
//
// Wire layout (148 bytes):
//
//	[0]    type = 1
//	[1:4]  reserved (zeros)
//	[4:8]  sender_index (uint32 LE)
//	[8:40]   ephemeral public key (32 bytes)
//	[40:88]  encrypted_static (32 bytes cipher + 16 bytes tag)
//	[88:116] encrypted_timestamp (12 bytes cipher + 16 bytes tag)
//	[116:132] mac1 (16 bytes)
//	[132:148] mac2 (16 bytes)
type HandshakeInit struct {
	SenderIndex        uint32
	Ephemeral          [32]byte
	EncryptedStatic    [48]byte
	EncryptedTimestamp [28]byte
	MAC1               [16]byte
	MAC2               [16]byte
}

func (m *HandshakeInit) marshal() []byte {
	b := make([]byte, sizeHandshakeInit)
	b[0] = typeHandshakeInit
	binary.LittleEndian.PutUint32(b[4:], m.SenderIndex)
	copy(b[8:], m.Ephemeral[:])
	copy(b[40:], m.EncryptedStatic[:])
	copy(b[88:], m.EncryptedTimestamp[:])
	copy(b[116:], m.MAC1[:])
	copy(b[132:], m.MAC2[:])
	return b
}

func parseHandshakeInit(b []byte) (*HandshakeInit, error) {
	if len(b) < sizeHandshakeInit || b[0] != typeHandshakeInit {
		return nil, errors.New("wiresocket: invalid HandshakeInit")
	}
	m := &HandshakeInit{}
	m.SenderIndex = binary.LittleEndian.Uint32(b[4:])
	copy(m.Ephemeral[:], b[8:40])
	copy(m.EncryptedStatic[:], b[40:88])
	copy(m.EncryptedTimestamp[:], b[88:116])
	copy(m.MAC1[:], b[116:132])
	copy(m.MAC2[:], b[132:148])
	return m, nil
}

// mac1Body returns the bytes covered by MAC1 (everything before the MAC fields).
func (m *HandshakeInit) mac1Body() []byte {
	return m.marshal()[:116]
}

// ─── HandshakeResp ───────────────────────────────────────────────────────────

// HandshakeResp is the response sent by the responder.
//
// Wire layout (92 bytes):
//
//	[0]    type = 2
//	[1:4]  reserved (zeros)
//	[4:8]  sender_index (uint32 LE)
//	[8:12] receiver_index (uint32 LE)
//	[12:44] ephemeral public key (32 bytes)
//	[44:60] encrypted_empty (0 bytes plain + 16 bytes tag)
//	[60:76] mac1 (16 bytes)
//	[76:92] mac2 (16 bytes)
type HandshakeResp struct {
	SenderIndex   uint32
	ReceiverIndex uint32
	Ephemeral     [32]byte
	EncryptedNil  [16]byte
	MAC1          [16]byte
	MAC2          [16]byte
}

func (m *HandshakeResp) marshal() []byte {
	b := make([]byte, sizeHandshakeResp)
	b[0] = typeHandshakeResp
	binary.LittleEndian.PutUint32(b[4:], m.SenderIndex)
	binary.LittleEndian.PutUint32(b[8:], m.ReceiverIndex)
	copy(b[12:], m.Ephemeral[:])
	copy(b[44:], m.EncryptedNil[:])
	copy(b[60:], m.MAC1[:])
	copy(b[76:], m.MAC2[:])
	return b
}

func parseHandshakeResp(b []byte) (*HandshakeResp, error) {
	if len(b) < sizeHandshakeResp || b[0] != typeHandshakeResp {
		return nil, errors.New("wiresocket: invalid HandshakeResp")
	}
	m := &HandshakeResp{}
	m.SenderIndex = binary.LittleEndian.Uint32(b[4:])
	m.ReceiverIndex = binary.LittleEndian.Uint32(b[8:])
	copy(m.Ephemeral[:], b[12:44])
	copy(m.EncryptedNil[:], b[44:60])
	copy(m.MAC1[:], b[60:76])
	copy(m.MAC2[:], b[76:92])
	return m, nil
}

func (m *HandshakeResp) mac1Body() []byte {
	return m.marshal()[:60]
}

// ─── CookieReply ─────────────────────────────────────────────────────────────

// CookieReply is sent by the server when it is under load instead of
// HandshakeResp.  The cookie is XChaCha20-Poly1305-encrypted using the
// initiator's mac1 as the key.
//
// Wire layout (64 bytes):
//
//	[0]    type = 3
//	[1:4]  reserved
//	[4:8]  receiver_index (uint32 LE)
//	[8:32] nonce (24 bytes, random)
//	[32:64] encrypted_cookie (16 bytes cookie + 16 bytes tag)
type CookieReply struct {
	ReceiverIndex   uint32
	Nonce           [24]byte
	EncryptedCookie [32]byte
}

func (m *CookieReply) marshal() []byte {
	b := make([]byte, sizeCookieReply)
	b[0] = typeCookieReply
	binary.LittleEndian.PutUint32(b[4:], m.ReceiverIndex)
	copy(b[8:], m.Nonce[:])
	copy(b[32:], m.EncryptedCookie[:])
	return b
}

func parseCookieReply(b []byte) (*CookieReply, error) {
	if len(b) < sizeCookieReply || b[0] != typeCookieReply {
		return nil, errors.New("wiresocket: invalid CookieReply")
	}
	m := &CookieReply{}
	m.ReceiverIndex = binary.LittleEndian.Uint32(b[4:])
	copy(m.Nonce[:], b[8:32])
	copy(m.EncryptedCookie[:], b[32:64])
	return m, nil
}

// ─── DataHeader ──────────────────────────────────────────────────────────────

// DataHeader precedes an encrypted payload in a data packet.
//
// Wire layout (16 bytes):
//
//	[0]    type = 4
//	[1:4]  reserved
//	[4:8]  receiver_index (uint32 LE)
//	[8:16] counter (uint64 LE)
type DataHeader struct {
	ReceiverIndex uint32
	Counter       uint64
}

func marshalDataHeader(idx uint32, counter uint64) []byte {
	b := make([]byte, sizeDataHeader)
	b[0] = typeData
	binary.LittleEndian.PutUint32(b[4:], idx)
	binary.LittleEndian.PutUint64(b[8:], counter)
	return b
}

func parseDataHeader(b []byte) (DataHeader, error) {
	if len(b) < sizeDataHeader || b[0] != typeData {
		return DataHeader{}, errors.New("wiresocket: invalid DataHeader")
	}
	return DataHeader{
		ReceiverIndex: binary.LittleEndian.Uint32(b[4:]),
		Counter:       binary.LittleEndian.Uint64(b[8:]),
	}, nil
}
