// Package proto defines the application-layer event types exchanged over an
// encrypted wiresocket session. Encoding is a hand-rolled protobuf wire format
// (field numbers match stream.proto) with no external code-generation
// dependency — run "protoc --go_out=. stream.proto" to replace with generated
// code if preferred.
package proto

import (
	"encoding/binary"
	"errors"
	"math/bits"
)

// Event is a single application-level event.
type Event struct {
	Sequence    uint64
	TimestampUs int64
	Type        string
	Payload     []byte
}

// Frame batches one or more Events into a single encrypted UDP payload.
type Frame struct {
	Events []*Event
}

// Marshal serialises f into protobuf wire format.
func (f *Frame) Marshal() []byte {
	var b []byte
	for _, e := range f.Events {
		em := e.marshal()
		b = appendLenField(b, 1, em)
	}
	return b
}

// UnmarshalFrame parses a Frame from protobuf wire bytes.
func UnmarshalFrame(b []byte) (*Frame, error) {
	f := &Frame{}
	for len(b) > 0 {
		field, wt, val, lv, rest, err := consumeField(b)
		if err != nil {
			return nil, err
		}
		b = rest
		if field == 1 && wt == 2 {
			e := &Event{}
			if err := e.unmarshal(lv); err != nil {
				return nil, err
			}
			f.Events = append(f.Events, e)
		}
		_ = val
	}
	return f, nil
}

// marshal serialises e into protobuf wire format (not exported; use Frame).
func (e *Event) marshal() []byte {
	var b []byte
	if e.Sequence != 0 {
		b = appendVarintField(b, 1, e.Sequence)
	}
	if e.TimestampUs != 0 {
		b = appendVarintField(b, 2, uint64(e.TimestampUs))
	}
	if e.Type != "" {
		b = appendLenField(b, 3, []byte(e.Type))
	}
	if len(e.Payload) > 0 {
		b = appendLenField(b, 4, e.Payload)
	}
	return b
}

// unmarshal parses e from protobuf wire bytes.
func (e *Event) unmarshal(b []byte) error {
	for len(b) > 0 {
		field, wt, val, lv, rest, err := consumeField(b)
		if err != nil {
			return err
		}
		b = rest
		switch {
		case field == 1 && wt == 0:
			e.Sequence = val
		case field == 2 && wt == 0:
			e.TimestampUs = int64(val)
		case field == 3 && wt == 2:
			e.Type = string(lv)
		case field == 4 && wt == 2:
			e.Payload = append([]byte(nil), lv...)
		}
	}
	return nil
}

// ─── wire helpers ────────────────────────────────────────────────────────────

func appendVarint(b []byte, v uint64) []byte {
	for v >= 0x80 {
		b = append(b, byte(v)|0x80)
		v >>= 7
	}
	return append(b, byte(v))
}

func appendVarintField(b []byte, field int, v uint64) []byte {
	b = appendVarint(b, uint64(field<<3|0)) // wire type 0 = VARINT
	return appendVarint(b, v)
}

func appendLenField(b []byte, field int, data []byte) []byte {
	b = appendVarint(b, uint64(field<<3|2)) // wire type 2 = LEN
	b = appendVarint(b, uint64(len(data)))
	return append(b, data...)
}

// consumeVarint reads a varint from b, returning (value, remaining, error).
func consumeVarint(b []byte) (uint64, []byte, error) {
	var v uint64
	for i, by := range b {
		if i == 10 {
			return 0, nil, errors.New("proto: varint overflow")
		}
		v |= uint64(by&0x7f) << (7 * uint(i))
		if by < 0x80 {
			return v, b[i+1:], nil
		}
	}
	return 0, nil, errors.New("proto: truncated varint")
}

// consumeField reads one protobuf field from b.
// Returns: (fieldNumber, wireType, varintValue, lenValue, remaining, error).
// For VARINT fields, val is the value. For LEN fields, lv is the payload.
func consumeField(b []byte) (field, wt int, val uint64, lv, rest []byte, err error) {
	var tag uint64
	tag, b, err = consumeVarint(b)
	if err != nil {
		return
	}
	field = int(tag >> 3)
	wt = int(tag & 0x7)
	switch wt {
	case 0: // VARINT
		val, rest, err = consumeVarint(b)
	case 1: // I64
		if len(b) < 8 {
			err = errors.New("proto: truncated I64")
			return
		}
		val = binary.LittleEndian.Uint64(b[:8])
		rest = b[8:]
	case 2: // LEN
		var l uint64
		l, b, err = consumeVarint(b)
		if err != nil {
			return
		}
		if uint64(len(b)) < l {
			err = errors.New("proto: truncated LEN value")
			return
		}
		lv = b[:l]
		rest = b[l:]
	case 5: // I32
		if len(b) < 4 {
			err = errors.New("proto: truncated I32")
			return
		}
		val = uint64(binary.LittleEndian.Uint32(b[:4]))
		rest = b[4:]
	default:
		err = errors.New("proto: unknown wire type")
	}
	return
}

// packedVarintSize returns the number of bytes required to encode v as a
// protobuf varint. Exported for use by packet-size estimators.
func PackedVarintSize(v uint64) int {
	if v == 0 {
		return 1
	}
	return (bits.Len64(v) + 6) / 7
}
