//go:build linux

package wiresocket

import (
	"net"
	"syscall"
)

// setSocketBuffers sets the kernel SO_RCVBUF and SO_SNDBUF for conn to size.
//
// On Linux, net.UDPConn.SetReadBuffer / SetWriteBuffer issue SO_RCVBUF /
// SO_SNDBUF setsockopt calls, which the kernel silently clamps to
// net.core.rmem_max / wmem_max (typically ~208 KiB on stock kernels).
// At large packet sizes (e.g. 65507 bytes) only a handful of packets fit in
// that buffer before the kernel starts dropping datagrams.
//
// SO_RCVBUFFORCE and SO_SNDBUFFORCE bypass that cap when the process holds
// CAP_NET_ADMIN (e.g. runs as root or has the capability granted).  If the
// capability is absent the call fails silently and we fall back to the
// standard setsockopt.  A diagnostic log line is emitted when the allocated
// buffer is still smaller than requested so the operator knows to either
// grant the capability or raise net.core.rmem_max / wmem_max.
func setSocketBuffers(conn *net.UDPConn, size int) {
	rc, err := conn.SyscallConn()
	if err != nil {
		// Fallback: best-effort via the standard API.
		_ = conn.SetReadBuffer(size)
		_ = conn.SetWriteBuffer(size)
		return
	}

	var actualRcv, actualSnd int
	_ = rc.Control(func(fd uintptr) {
		ifd := int(fd)

		// Try the privileged variant first; fall back on EPERM.
		if e := syscall.SetsockoptInt(ifd, syscall.SOL_SOCKET, syscall.SO_RCVBUFFORCE, size); e != nil {
			_ = syscall.SetsockoptInt(ifd, syscall.SOL_SOCKET, syscall.SO_RCVBUF, size)
		}
		if e := syscall.SetsockoptInt(ifd, syscall.SOL_SOCKET, syscall.SO_SNDBUFFORCE, size); e != nil {
			_ = syscall.SetsockoptInt(ifd, syscall.SOL_SOCKET, syscall.SO_SNDBUF, size)
		}

		// Read back what the kernel actually allocated.
		// Linux doubles the value in getsockopt for internal accounting.
		actualRcv, _ = syscall.GetsockoptInt(ifd, syscall.SOL_SOCKET, syscall.SO_RCVBUF)
		actualSnd, _ = syscall.GetsockoptInt(ifd, syscall.SOL_SOCKET, syscall.SO_SNDBUF)
	})

	// Divide by 2 to undo the kernel doubling before comparing.
	if actualRcv/2 < size/2 {
		dbg("socket: receive buffer clamped by kernel",
			"requested", size,
			"actual", actualRcv/2,
			"hint", "raise net.core.rmem_max or grant CAP_NET_ADMIN for full throughput",
		)
	} else {
		dbg("socket: buffers configured", "rcvbuf", actualRcv/2, "sndbuf", actualSnd/2)
	}
}
