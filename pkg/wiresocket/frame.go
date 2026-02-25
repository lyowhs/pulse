package wiresocket

// Wire encoding is custom:
//   - A Frame begins with one raw byte: [channel_id].
//   - Followed by a sequence of length-prefixed Event bodies (proto field 1,
//     wire type LEN).
//   - Each Event body begins with one raw byte: [type].
//   - Any remaining bytes are the payload.

import (
	"encoding/binary"
	"errors"
)

// Event is a single application-level event.
type Event struct {
	Type    uint8  // event type (0–254 application-defined; 255 internal)
	Payload []byte // opaque binary payload
}

// Frame batches one or more Events for a single channel into one encrypted UDP
// payload.  All events in a frame share the same ChannelId.
type Frame struct {
	ChannelId uint8
	Events    []*Event
}

// AppendMarshal appends the frame's wire encoding to dst and returns the
// extended slice.  It is allocation-free when dst has sufficient capacity.
// Wire format: [channel_id(1)] [field-1 LEN event-body]...
// where event-body = [type(1)][payload...].
func (f *Frame) AppendMarshal(dst []byte) []byte {
	dst = append(dst, f.ChannelId)
	for _, e := range f.Events {
		body := 1 + len(e.Payload)
		dst = appendVarint(dst, 0x0A) // field 1, wire type LEN
		dst = appendVarint(dst, uint64(body))
		dst = append(dst, e.Type)
		dst = append(dst, e.Payload...)
	}
	return dst
}

// Marshal serialises f into wire format: [channel_id][LEN-field events...].
func (f *Frame) Marshal() []byte { return f.AppendMarshal(nil) }

// UnmarshalFrame parses a Frame from wire bytes.
//
// It does a fast pre-pass over the body to count events and compute total
// payload bytes, then allocates all Event structs in one batch slice and all
// payloads in one backing buffer.  This replaces the previous approach of one
// heap allocation per Event and one per payload, reducing GC pressure on
// high-throughput receive paths from O(2N) to O(3) allocations per frame.
func UnmarshalFrame(b []byte) (*Frame, error) {
	if len(b) == 0 {
		return &Frame{}, nil
	}
	f := &Frame{ChannelId: b[0]}
	body := b[1:]
	if len(body) == 0 {
		return f, nil
	}

	// Pre-pass: count events and sum payload bytes so we can batch-allocate.
	nEvents, payloadBytes := scanEvents(body)
	if nEvents == 0 {
		return f, nil
	}

	// One allocation for all Event structs.  Each &batch[i] escapes to the
	// caller via f.Events; the backing array lives as long as any *Event from
	// this frame is reachable.
	batch := make([]Event, nEvents)

	// One allocation for all payload bytes.  Skipped when all payloads are empty.
	var payloadBuf []byte
	if payloadBytes > 0 {
		payloadBuf = make([]byte, payloadBytes)
	}
	payloadOff := 0

	f.Events = make([]*Event, 0, nEvents)
	i := 0
	for len(body) > 0 {
		field, wt, _, lv, rest, err := consumeField(body)
		if err != nil {
			return nil, err
		}
		body = rest
		if field == 1 && wt == 2 {
			if len(lv) < 1 {
				return nil, errors.New("wiresocket: event body too short")
			}
			e := &batch[i]
			e.Type = lv[0]
			if len(lv) > 1 {
				n := len(lv) - 1
				// Three-index slice caps e.Payload so no append can spill into
				// a subsequent event's region within payloadBuf.
				e.Payload = payloadBuf[payloadOff : payloadOff+n : payloadOff+n]
				copy(e.Payload, lv[1:])
				payloadOff += n
			}
			f.Events = append(f.Events, e)
			i++
		}
	}
	return f, nil
}

// scanEvents does a single fast pre-pass over frame body bytes (after the
// channel-ID byte) to count LEN-encoded field-1 entries and sum their payload
// sizes.  Both values are used by UnmarshalFrame for batch allocation.
func scanEvents(b []byte) (count, payloadBytes int) {
	for len(b) > 0 {
		field, wt, _, lv, rest, err := consumeField(b)
		if err != nil {
			break
		}
		b = rest
		if field == 1 && wt == 2 {
			count++
			if len(lv) > 1 { // lv = [type(1)][payload...]; subtract type byte
				payloadBytes += len(lv) - 1
			}
		}
	}
	return
}

// marshal serialises e: [type byte][payload...].
func (e *Event) marshal() []byte {
	return append([]byte{e.Type}, e.Payload...)
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
			return 0, nil, errors.New("wiresocket: varint overflow")
		}
		v |= uint64(by&0x7f) << (7 * uint(i))
		if by < 0x80 {
			return v, b[i+1:], nil
		}
	}
	return 0, nil, errors.New("wiresocket: truncated varint")
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
			err = errors.New("wiresocket: truncated I64")
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
			err = errors.New("wiresocket: truncated LEN value")
			return
		}
		lv = b[:l]
		rest = b[l:]
	case 5: // I32
		if len(b) < 4 {
			err = errors.New("wiresocket: truncated I32")
			return
		}
		val = uint64(binary.LittleEndian.Uint32(b[:4]))
		rest = b[4:]
	default:
		err = errors.New("wiresocket: unknown wire type")
	}
	return
}
