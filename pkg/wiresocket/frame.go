package wiresocket

// Wire encoding is custom:
//   - A Frame begins with two bytes: [channel_id_lo][channel_id_hi] (uint16 LE).
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
//
// The reliability fields (Seq, AckSeq, AckBitmap, WindowSize) are optional:
// zero values are omitted from the wire encoding and ignored on receipt,
// preserving backward compatibility with peers that do not implement reliable
// delivery.
type Frame struct {
	ChannelId uint16
	Events    []*Event

	// Seq is the sender's frame sequence number for reliable channels.
	// 0 means the frame is unreliable (no ACK expected).
	// Reliable senders assign values starting at 1.
	Seq uint32

	// AckSeq is a cumulative ACK: the sender has received all reliable frames
	// with sequence numbers 1..AckSeq in order.  0 means nothing received yet.
	AckSeq uint32

	// AckBitmap is a selective-ACK (SACK) bitmap.  Bit i (LSB = bit 0) is set
	// when the sender has received the frame with sequence number AckSeq+i+1
	// out of order.
	AckBitmap uint64

	// WindowSize is the number of additional reliable frames the sender of this
	// frame can accept.  Carried in ACK frames to implement flow control.
	WindowSize uint32
}

// AppendMarshal appends the frame's wire encoding to dst and returns the
// extended slice.  It is allocation-free when dst has sufficient capacity.
//
// Wire format:
//
//	[channel_id(2)]                   uint16 little-endian
//	[field-1 LEN event-body]...       where event-body = [type(1)][payload...]
//	[field-2 varint Seq]              omitted when Seq == 0
//	[field-3 varint AckSeq]           omitted when AckSeq == 0
//	[field-4 I64 AckBitmap]           omitted when AckBitmap == 0
//	[field-5 varint WindowSize]       omitted when WindowSize == 0
func (f *Frame) AppendMarshal(dst []byte) []byte {
	dst = append(dst, byte(f.ChannelId), byte(f.ChannelId>>8))
	for _, e := range f.Events {
		body := 1 + len(e.Payload)
		dst = appendVarint(dst, 0x0A) // field 1, wire type LEN
		dst = appendVarint(dst, uint64(body))
		dst = append(dst, e.Type)
		dst = append(dst, e.Payload...)
	}
	if f.Seq != 0 {
		dst = appendVarint(dst, 0x10) // field 2, wire type 0 (varint)
		dst = appendVarint(dst, uint64(f.Seq))
	}
	if f.AckSeq != 0 {
		dst = appendVarint(dst, 0x18) // field 3, wire type 0 (varint)
		dst = appendVarint(dst, uint64(f.AckSeq))
	}
	if f.AckBitmap != 0 {
		dst = appendVarint(dst, 0x21) // field 4, wire type 1 (I64)
		dst = append(dst,
			byte(f.AckBitmap),
			byte(f.AckBitmap>>8),
			byte(f.AckBitmap>>16),
			byte(f.AckBitmap>>24),
			byte(f.AckBitmap>>32),
			byte(f.AckBitmap>>40),
			byte(f.AckBitmap>>48),
			byte(f.AckBitmap>>56),
		)
	}
	if f.WindowSize != 0 {
		dst = appendVarint(dst, 0x28) // field 5, wire type 0 (varint)
		dst = appendVarint(dst, uint64(f.WindowSize))
	}
	return dst
}

// Marshal serialises f into wire format: [channel_id(2)][LEN-field events...].
func (f *Frame) Marshal() []byte { return f.AppendMarshal(nil) }

// wireSize returns the exact number of bytes that AppendMarshal will append.
// Used to right-size the pool buffer before marshaling, routing small frames
// to the small pool (2 KB) instead of the large pool (65 KB).
func (f *Frame) wireSize() int {
	n := 2 // channel_id uint16 LE
	for _, e := range f.Events {
		body := 1 + len(e.Payload)
		n++ // field tag 0x0A fits in 1 varint byte (tag < 0x80)
		n += varintSize(uint64(body))
		n += body
	}
	if f.Seq != 0 {
		n++ // tag 0x10
		n += varintSize(uint64(f.Seq))
	}
	if f.AckSeq != 0 {
		n++ // tag 0x18
		n += varintSize(uint64(f.AckSeq))
	}
	if f.AckBitmap != 0 {
		n += 9 // tag 0x21 (1 byte) + I64 (8 bytes)
	}
	if f.WindowSize != 0 {
		n++ // tag 0x28
		n += varintSize(uint64(f.WindowSize))
	}
	return n
}

// varintSize returns the number of bytes needed to encode v as a varint.
func varintSize(v uint64) int {
	n := 1
	for v >= 0x80 {
		v >>= 7
		n++
	}
	return n
}

// UnmarshalFrame parses a Frame from wire bytes.
//
// Item 8 optimization: the pre-pass (scanEvents) is replaced by a fast inline
// scan (fastScanEvents) that exploits the wire encoding invariants to avoid
// general-purpose consumeField overhead:
//   - Events (field 1, wire type LEN) always come before reliability fields.
//   - The common case has a single-byte LEN varint (body_len ≤ 127).
//   - The scan stops at the first non-event byte, skipping reliability fields.
//
// This makes the pre-pass ~2x faster than the original scanEvents while
// keeping the two-pass allocation strategy (4 allocs per frame).
func UnmarshalFrame(b []byte) (*Frame, error) {
	if len(b) == 0 {
		return &Frame{}, nil
	}
	if len(b) < 2 {
		return nil, errors.New("wiresocket: frame too short for channel ID")
	}
	f := &Frame{ChannelId: uint16(b[0]) | uint16(b[1])<<8}
	body := b[2:]
	if len(body) == 0 {
		return f, nil
	}

	// Fast pre-pass: count events and sum payload bytes for batch allocation.
	// Do NOT return early when nEvents == 0: the body may still contain
	// reliability fields (Seq, AckSeq, AckBitmap, WindowSize) that must be
	// parsed by the decode loop below, e.g. standalone ACK frames.
	nEvents, payloadBytes := fastScanEvents(body)

	// One allocation for all Event structs.
	batch := make([]Event, nEvents)

	// One allocation for all payload bytes.
	var payloadBuf []byte
	if payloadBytes > 0 {
		payloadBuf = make([]byte, payloadBytes)
	}
	payloadOff := 0

	f.Events = make([]*Event, 0, nEvents)
	i := 0
	for len(body) > 0 {
		field, wt, val, lv, rest, err := consumeField(body)
		if err != nil {
			return nil, err
		}
		body = rest
		switch {
		case field == 1 && wt == 2:
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
		case field == 2 && wt == 0:
			f.Seq = uint32(val)
		case field == 3 && wt == 0:
			f.AckSeq = uint32(val)
		case field == 4 && wt == 1:
			f.AckBitmap = val
		case field == 5 && wt == 0:
			f.WindowSize = uint32(val)
		}
	}
	return f, nil
}

// fastScanEvents counts field-1 LEN events and sums their payload bytes.
// It is a faster drop-in replacement for the original scanEvents:
//
//   - Events (field 1, wire type LEN, tag byte 0x0A) always precede reliability
//     fields in the wire encoding produced by AppendMarshal.  The scan stops at
//     the first non-0x0A tag byte, skipping all reliability fields.
//   - The common case (body_len ≤ 127) uses a single-byte LEN varint, handled
//     with a direct byte read instead of the general consumeVarint loop.
//
// Errors (truncated varint, truncated body) cause the scan to stop early;
// the decode loop's consumeField call will produce the proper error.
func fastScanEvents(b []byte) (count, payloadBytes int) {
	for len(b) >= 2 && b[0] == 0x0A { // field 1, wire type LEN
		b = b[1:] // consume tag
		if b[0] < 0x80 {
			// Single-byte LEN varint (body_len ≤ 127): fast path.
			l := int(b[0])
			b = b[1:]
			if len(b) < l {
				return // truncated body: stop scan
			}
			count++
			if l > 1 {
				payloadBytes += l - 1 // subtract type byte
			}
			b = b[l:]
		} else {
			// Multi-byte LEN varint (body_len ≥ 128): decode varint then skip body.
			var l uint64
			var err error
			l, b, err = consumeVarint(b)
			if err != nil {
				return
			}
			if uint64(len(b)) < l {
				return // truncated
			}
			count++
			if l > 1 {
				payloadBytes += int(l) - 1
			}
			b = b[l:]
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
