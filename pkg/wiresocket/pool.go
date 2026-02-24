package wiresocket

import "sync"

// sendBufPool recycles large buffers for the outgoing packet path.
// Capacity: sizeDataHeader + 65519 (max plain) + sizeAEADTag — fits any packet.
var sendBufPool = &sync.Pool{
	New: func() any { b := make([]byte, 0, 65535+sizeAEADTag); return &b },
}

// recvBufPool recycles buffers for AEAD.Open output on the receive path.
var recvBufPool = &sync.Pool{
	New: func() any { b := make([]byte, 0, 65535); return &b },
}
