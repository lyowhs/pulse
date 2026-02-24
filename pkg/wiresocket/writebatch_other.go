//go:build !linux

package wiresocket

import (
	"net"

	"golang.org/x/net/ipv6"
)

// newIPv6PacketConn returns nil on non-Linux platforms.
// ipv6.PacketConn.WriteBatch uses sendmsg control messages that fail on macOS
// for dual-stack sockets sending to IPv4 destinations; sendmmsg(2) does not
// exist on non-Linux anyway, so there is no batch throughput benefit.
func newIPv6PacketConn(_ *net.UDPConn) *ipv6.PacketConn {
	return nil
}
