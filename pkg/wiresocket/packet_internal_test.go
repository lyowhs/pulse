package wiresocket

import (
	"testing"
)

// TestMaxFragmentPayload verifies the formula: mtu - dataHeader - fragHeader - AEADTag.
func TestMaxFragmentPayload(t *testing.T) {
	tests := []struct {
		mtu  int
		want int
	}{
		{1232, 1192},  // defaultMaxPacketSize → defaultMaxFragPayload
		{1472, 1432},  // common Ethernet MTU
		{100, 60},     // small MTU
		{40, 0},       // exactly at or below overhead; must not go negative
		{1, 0},        // degenerate
	}
	for _, tc := range tests {
		got := MaxFragmentPayload(tc.mtu)
		if got != tc.want {
			t.Errorf("MaxFragmentPayload(%d) = %d, want %d", tc.mtu, got, tc.want)
		}
	}
}

// TestHandshakeInitMarshalParse verifies that marshalling and parsing a
// HandshakeInit roundtrips all fields correctly.
func TestHandshakeInitMarshalParse(t *testing.T) {
	original := &HandshakeInit{
		SenderIndex: 0xDEADBEEF,
	}
	for i := range original.Ephemeral {
		original.Ephemeral[i] = byte(i)
	}
	for i := range original.EncryptedStatic {
		original.EncryptedStatic[i] = byte(i + 32)
	}
	for i := range original.EncryptedTimestamp {
		original.EncryptedTimestamp[i] = byte(i + 80)
	}
	for i := range original.MAC1 {
		original.MAC1[i] = byte(i + 100)
	}
	for i := range original.MAC2 {
		original.MAC2[i] = byte(i + 116)
	}

	wire := original.marshal()
	if len(wire) != sizeHandshakeInit {
		t.Fatalf("marshal len = %d, want %d", len(wire), sizeHandshakeInit)
	}
	if wire[0] != typeHandshakeInit {
		t.Errorf("type byte = %d, want %d", wire[0], typeHandshakeInit)
	}

	parsed, err := parseHandshakeInit(wire)
	if err != nil {
		t.Fatalf("parseHandshakeInit: %v", err)
	}
	if parsed.SenderIndex != original.SenderIndex {
		t.Errorf("SenderIndex: got %d, want %d", parsed.SenderIndex, original.SenderIndex)
	}
	if parsed.Ephemeral != original.Ephemeral {
		t.Error("Ephemeral mismatch")
	}
	if parsed.EncryptedStatic != original.EncryptedStatic {
		t.Error("EncryptedStatic mismatch")
	}
	if parsed.EncryptedTimestamp != original.EncryptedTimestamp {
		t.Error("EncryptedTimestamp mismatch")
	}
	if parsed.MAC1 != original.MAC1 {
		t.Error("MAC1 mismatch")
	}
	if parsed.MAC2 != original.MAC2 {
		t.Error("MAC2 mismatch")
	}
}

// TestHandshakeInitParseTooShort verifies that parsing a truncated buffer
// returns an error.
func TestHandshakeInitParseTooShort(t *testing.T) {
	_, err := parseHandshakeInit(make([]byte, sizeHandshakeInit-1))
	if err == nil {
		t.Error("parseHandshakeInit accepted a truncated buffer")
	}
}

// TestHandshakeInitParseWrongType verifies that a buffer with the wrong type
// byte is rejected.
func TestHandshakeInitParseWrongType(t *testing.T) {
	b := make([]byte, sizeHandshakeInit)
	b[0] = typeHandshakeResp // wrong
	_, err := parseHandshakeInit(b)
	if err == nil {
		t.Error("parseHandshakeInit accepted wrong type byte")
	}
}

// TestHandshakeRespMarshalParse verifies HandshakeResp roundtrip.
func TestHandshakeRespMarshalParse(t *testing.T) {
	original := &HandshakeResp{
		SenderIndex:   0x11223344,
		ReceiverIndex: 0x55667788,
	}
	for i := range original.Ephemeral {
		original.Ephemeral[i] = byte(i + 1)
	}
	for i := range original.EncryptedNil {
		original.EncryptedNil[i] = byte(i + 50)
	}
	for i := range original.MAC1 {
		original.MAC1[i] = byte(i + 70)
	}
	for i := range original.MAC2 {
		original.MAC2[i] = byte(i + 86)
	}

	wire := original.marshal()
	if len(wire) != sizeHandshakeResp {
		t.Fatalf("marshal len = %d, want %d", len(wire), sizeHandshakeResp)
	}
	if wire[0] != typeHandshakeResp {
		t.Errorf("type byte = %d, want %d", wire[0], typeHandshakeResp)
	}

	parsed, err := parseHandshakeResp(wire)
	if err != nil {
		t.Fatalf("parseHandshakeResp: %v", err)
	}
	if parsed.SenderIndex != original.SenderIndex {
		t.Errorf("SenderIndex: got %d, want %d", parsed.SenderIndex, original.SenderIndex)
	}
	if parsed.ReceiverIndex != original.ReceiverIndex {
		t.Errorf("ReceiverIndex: got %d, want %d", parsed.ReceiverIndex, original.ReceiverIndex)
	}
	if parsed.Ephemeral != original.Ephemeral {
		t.Error("Ephemeral mismatch")
	}
	if parsed.EncryptedNil != original.EncryptedNil {
		t.Error("EncryptedNil mismatch")
	}
	if parsed.MAC1 != original.MAC1 {
		t.Error("MAC1 mismatch")
	}
	if parsed.MAC2 != original.MAC2 {
		t.Error("MAC2 mismatch")
	}
}

// TestHandshakeRespParseTooShort verifies rejection of truncated buffers.
func TestHandshakeRespParseTooShort(t *testing.T) {
	_, err := parseHandshakeResp(make([]byte, sizeHandshakeResp-1))
	if err == nil {
		t.Error("parseHandshakeResp accepted a truncated buffer")
	}
}

// TestCookieReplyMarshalParse verifies CookieReply roundtrip.
func TestCookieReplyMarshalParse(t *testing.T) {
	original := &CookieReply{
		ReceiverIndex: 0xCAFEBABE,
	}
	for i := range original.Nonce {
		original.Nonce[i] = byte(i + 10)
	}
	for i := range original.EncryptedCookie {
		original.EncryptedCookie[i] = byte(i + 40)
	}

	wire := original.marshal()
	if len(wire) != sizeCookieReply {
		t.Fatalf("marshal len = %d, want %d", len(wire), sizeCookieReply)
	}
	if wire[0] != typeCookieReply {
		t.Errorf("type byte = %d, want %d", wire[0], typeCookieReply)
	}

	parsed, err := parseCookieReply(wire)
	if err != nil {
		t.Fatalf("parseCookieReply: %v", err)
	}
	if parsed.ReceiverIndex != original.ReceiverIndex {
		t.Errorf("ReceiverIndex: got %d, want %d", parsed.ReceiverIndex, original.ReceiverIndex)
	}
	if parsed.Nonce != original.Nonce {
		t.Error("Nonce mismatch")
	}
	if parsed.EncryptedCookie != original.EncryptedCookie {
		t.Error("EncryptedCookie mismatch")
	}
}

// TestCookieReplyParseTooShort verifies rejection of truncated buffers.
func TestCookieReplyParseTooShort(t *testing.T) {
	_, err := parseCookieReply(make([]byte, sizeCookieReply-1))
	if err == nil {
		t.Error("parseCookieReply accepted truncated buffer")
	}
}

// TestDataHeaderMarshalParse verifies DataHeader roundtrip.
func TestDataHeaderMarshalParse(t *testing.T) {
	const idx uint32 = 0xAABBCCDD
	const counter uint64 = 0x0102030405060708

	wire := marshalDataHeader(idx, counter)
	if len(wire) != sizeDataHeader {
		t.Fatalf("marshalDataHeader len = %d, want %d", len(wire), sizeDataHeader)
	}
	if wire[0] != typeData {
		t.Errorf("type byte = %d, want %d", wire[0], typeData)
	}

	hdr, err := parseDataHeader(wire)
	if err != nil {
		t.Fatalf("parseDataHeader: %v", err)
	}
	if hdr.ReceiverIndex != idx {
		t.Errorf("ReceiverIndex: got %d, want %d", hdr.ReceiverIndex, idx)
	}
	if hdr.Counter != counter {
		t.Errorf("Counter: got %d, want %d", hdr.Counter, counter)
	}
}

// TestDataHeaderParseTooShort verifies rejection of truncated buffers.
func TestDataHeaderParseTooShort(t *testing.T) {
	_, err := parseDataHeader(make([]byte, sizeDataHeader-1))
	if err == nil {
		t.Error("parseDataHeader accepted truncated buffer")
	}
}

// TestDataHeaderParseWrongType verifies rejection of wrong type byte.
func TestDataHeaderParseWrongType(t *testing.T) {
	b := marshalDataHeader(1, 1)
	b[0] = typeHandshakeInit
	_, err := parseDataHeader(b)
	if err == nil {
		t.Error("parseDataHeader accepted wrong type byte")
	}
}

// TestHandshakeInitMAC1Body verifies that mac1Body returns exactly 116 bytes
// (the region before the MAC fields in the HandshakeInit wire format).
func TestHandshakeInitMAC1Body(t *testing.T) {
	msg := &HandshakeInit{SenderIndex: 1}
	body := msg.mac1Body()
	if len(body) != 116 {
		t.Errorf("HandshakeInit.mac1Body() len = %d, want 116", len(body))
	}
}

// TestHandshakeRespMAC1Body verifies that mac1Body returns exactly 60 bytes.
func TestHandshakeRespMAC1Body(t *testing.T) {
	msg := &HandshakeResp{SenderIndex: 1, ReceiverIndex: 2}
	body := msg.mac1Body()
	if len(body) != 60 {
		t.Errorf("HandshakeResp.mac1Body() len = %d, want 60", len(body))
	}
}
