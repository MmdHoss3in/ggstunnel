//go:build !linux || (!amd64 && !arm64)

package carrier

import (
	"context"
	"net"
	"syscall"
)

func (b *BIP) readLoop(ctx context.Context) { b.readLoopScalar(ctx) }

func sendBIPMessages(fd int, packets [][]byte, peer net.IP) (int, error) {
	address := &syscall.SockaddrInet4{}
	copy(address.Addr[:], peer.To4())
	for i, packet := range packets { if err := syscall.Sendto(fd, packet, 0, address); err != nil { return i, err } }
	return len(packets), nil
}
