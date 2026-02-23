// Package proto defines the application-layer event types exchanged over an
// encrypted wiresocket session.
//
// Wire encoding is custom:
//   - Each Event body begins with two raw bytes: [type][channel_id].
//   - Any remaining bytes are the payload.
//   - A Frame is a sequence of length-prefixed Event bodies (proto field 1,
//     wire type LEN).
package proto

import (
	"encoding/binary"
	"errors"
)

// Event is a single application-level event.
type Event struct {
	Type      uint8  // event type (0–254 application-defined; 255 internal)
	ChannelId uint8  // logical channel (0 = default)
	Payload   []byte // opaque binary payload
}

// Frame batches one or more Events into a single encrypted UDP payload.
type Frame struct {
	Events []*Event
}

// Marshal serialises f into wire format.
func (f *Frame) Marshal() []byte {
	var b []byte
	for _, e := range f.Events {
		b = appendLenField(b, 1, e.marshal())
	}
	return b
}

// UnmarshalFrame parses a Frame from wire bytes.
func UnmarshalFrame(b []byte) (*Frame, error) {
	f := &Frame{}
	for len(b) > 0 {
		field, wt, _, lv, rest, err := consumeField(b)
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
	}
	return f, nil
}

// marshal serialises e: [type byte][channel_id byte][payload...].
func (e *Event) marshal() []byte {
	b := []byte{e.Type, e.ChannelId}
	return append(b, e.Payload...)
}

// unmarshal parses e from wire bytes.
func (e *Event) unmarshal(b []byte) error {
	if len(b) < 2 {
		return errors.New("proto: event body too short")
	}
	e.Type = b[0]
	e.ChannelId = b[1]
	if len(b) > 2 {
		e.Payload = append([]byte(nil), b[2:]...)
	}
	return nil
}

// ─── wire helpers ─────────────────────────────────────────────────────────────

func appendVarint(b []byte, v uint64) []byte {
	for v >= 0x80 {
		b = append(b, byte(v)|0x80)
		v >>= 7
	}
	return append(b, byte(v))
}

func appendLenField(b []byte, field int, data []byte) []byte {
	b = appendVarint(b, uint64(field<<3|2)) // wire type 2 = LEN
	b = appendVarint(b, uint64(len(data)))
	return append(b, data...)
}

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
