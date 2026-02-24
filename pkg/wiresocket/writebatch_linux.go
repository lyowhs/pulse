package wiresocket

import (
	"net"

	"golang.org/x/net/ipv6"
)

// newIPv6PacketConn returns an ipv6.PacketConn for use with WriteBatch.
// On Linux, WriteBatch maps to sendmmsg(2) and provides real batch throughput.
func newIPv6PacketConn(conn *net.UDPConn) *ipv6.PacketConn {
	return ipv6.NewPacketConn(conn)
}
