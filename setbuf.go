//go:build !linux

package wiresocket

import "net"

// setSocketBuffers sets the kernel socket receive and send buffers for conn.
// On non-Linux platforms the standard SetReadBuffer / SetWriteBuffer calls are
// used directly; there is no privileged bypass mechanism.
func setSocketBuffers(conn *net.UDPConn, size int) {
	if err := conn.SetReadBuffer(size); err != nil {
		dbg("socket: SetReadBuffer failed", "requested", size, "err", err)
	}
	if err := conn.SetWriteBuffer(size); err != nil {
		dbg("socket: SetWriteBuffer failed", "requested", size, "err", err)
	}
	dbg("socket: buffers configured", "size_bytes", size)
}
