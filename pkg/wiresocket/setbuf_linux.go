//go:build linux

package wiresocket

import (
	"net"
	"sync"
	"syscall"
)

var (
	probeOnce   sync.Once
	probeResult int
)

// ProbeUDPRecvBufSize returns the actual kernel-allocated UDP receive buffer
// size achievable for a socket requesting size bytes.
//
// It creates a temporary loopback UDP socket, applies the same
// SO_RCVBUFFORCE → SO_RCVBUF fallback logic used by setSocketBuffers, reads
// back the actual value with GetsockoptInt (dividing by 2 to undo the kernel's
// internal doubling), and then closes the probe socket.  The returned value
// represents the usable receive buffer available to real sessions.
//
// Callers should use the returned value — not the requested size — when sizing
// pipeline parameters such as inflightCap so that in-flight data does not
// exceed what the kernel will actually buffer.
//
// The result is memoized: the kernel limit (net.core.rmem_max) does not change
// during process lifetime, so only one probe socket is ever opened.
func ProbeUDPRecvBufSize(requested int) int {
	probeOnce.Do(func() { probeResult = probeUDPRecvBufSizeOnce(requested) })
	return probeResult
}

func probeUDPRecvBufSizeOnce(requested int) int {
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		return requested
	}
	defer conn.Close()

	rc, err := conn.SyscallConn()
	if err != nil {
		return requested
	}

	var actual int
	_ = rc.Control(func(fd uintptr) {
		ifd := int(fd)
		if e := syscall.SetsockoptInt(ifd, syscall.SOL_SOCKET, syscall.SO_RCVBUFFORCE, requested); e != nil {
			_ = syscall.SetsockoptInt(ifd, syscall.SOL_SOCKET, syscall.SO_RCVBUF, requested)
		}
		v, _ := syscall.GetsockoptInt(ifd, syscall.SOL_SOCKET, syscall.SO_RCVBUF)
		actual = v / 2 // undo kernel doubling
	})

	if actual < 1 {
		actual = requested
	}
	return actual
}

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
