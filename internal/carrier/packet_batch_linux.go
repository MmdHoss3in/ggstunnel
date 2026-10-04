//go:build linux && (amd64 || arm64)

package carrier

import (
	"context"
	"errors"
	"log"
	"net"
	"runtime"
	"syscall"
	"time"
	"unsafe"
)

const bipReceiveBatch = 16

// mmsghdr is msghdr followed by a uint32 length and 64-bit ABI padding.
// recvmmsg is always nonblocking; runtime poll/deadlines handle waiting.
type bipMessage struct {
	header syscall.Msghdr
	length uint32
	pad    uint32
}
type bipSocketBatch struct {
	data [bipReceiveBatch][2048]byte
	iov  [bipReceiveBatch]syscall.Iovec
	msg  [bipReceiveBatch]bipMessage
}

func newBIPSocketBatch() *bipSocketBatch {
	b := new(bipSocketBatch)
	for i := range b.msg {
		b.iov[i].Base = &b.data[i][0]
		b.iov[i].SetLen(len(b.data[i]))
		b.msg[i].header.Iov = &b.iov[i]
		b.msg[i].header.Iovlen = 1
	}
	return b
}

func (b *bipSocketBatch) read(fd uintptr) (int, error) {
	for i := range b.msg {
		b.msg[i].header.Flags = 0
		b.msg[i].length = 0
	}
	n, _, errno := syscall.Syscall6(syscall.SYS_RECVMMSG, fd, uintptr(unsafe.Pointer(&b.msg[0])), bipReceiveBatch, syscall.MSG_DONTWAIT, 0, 0)
	runtime.KeepAlive(b)
	if errno != 0 {
		return 0, errno
	}
	return int(n), nil
}

func sendBIPMessages(fd int, packets [][]byte, peer net.IP) (int, error) {
	if len(packets) == 0 {
		return 0, nil
	}
	if len(packets) > 64 {
		return 0, syscall.EINVAL
	}
	var messages [64]bipMessage
	var iov [64]syscall.Iovec
	address := syscall.RawSockaddrInet4{Family: syscall.AF_INET}
	if peer != nil {
		if peer.To4() == nil {
			return 0, syscall.EINVAL
		}
		copy(address.Addr[:], peer.To4())
	}
	for i, packet := range packets {
		if len(packet) == 0 {
			return 0, syscall.EINVAL
		}
		iov[i].Base = &packet[0]
		iov[i].SetLen(len(packet))
		messages[i].header.Iov = &iov[i]
		messages[i].header.Iovlen = 1
		if peer != nil {
			messages[i].header.Name = (*byte)(unsafe.Pointer(&address))
			messages[i].header.Namelen = syscall.SizeofSockaddrInet4
		}
	}
	for {
		n, _, errno := syscall.Syscall6(bipSendMmsg, uintptr(fd), uintptr(unsafe.Pointer(&messages[0])), uintptr(len(packets)), syscall.MSG_DONTWAIT, 0, 0)
		runtime.KeepAlive(packets)
		runtime.KeepAlive(iov)
		runtime.KeepAlive(address)
		if errno == syscall.EINTR {
			continue
		}
		if errno != 0 {
			return 0, errno
		}
		return int(n), nil
	}
}

func (b *BIP) readLoop(ctx context.Context) {
	err := b.readLoopBatch(ctx)
	if errors.Is(err, syscall.ENOSYS) {
		log.Printf("BIP batched receive unavailable; using scalar receive")
		b.readLoopScalar(ctx)
		return
	}
	if err != nil && ctx.Err() == nil {
		b.fail(err)
	}
}

func (b *BIP) readLoopBatch(ctx context.Context) error {
	conn, err := b.recv.SyscallConn()
	if err != nil {
		return err
	}
	batch := newBIPSocketBatch()
	nextDeadline := time.Time{}
	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		now := time.Now()
		if !now.Before(nextDeadline) {
			if err := b.recv.SetReadDeadline(now.Add(time.Second)); err != nil {
				return err
			}
			nextDeadline = now.Add(500 * time.Millisecond)
		}
		count := 0
		var receiveErr error
		err = conn.Read(func(fd uintptr) bool {
			for {
				count, receiveErr = batch.read(fd)
				if errors.Is(receiveErr, syscall.EINTR) {
					continue
				}
				return !errors.Is(receiveErr, syscall.EAGAIN)
			}
		})
		if err != nil {
			if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
				continue
			}
			return err
		}
		if receiveErr != nil {
			return receiveErr
		}
		packets := make([][]byte, 0, count)
		for i := 0; i < count; i++ {
			n := int(batch.msg[i].length)
			if batch.msg[i].header.Flags&syscall.MSG_TRUNC != 0 || n < 20 || n > len(batch.data[i]) {
				continue
			}
			packet := batch.data[i][:n]
			ihl := int(packet[0]&15) * 4
			if packet[0]>>4 != 4 || ihl < 20 || ihl > n || packet[9] != 1 || !net.IP(packet[12:16]).Equal(b.peer) {
				continue
			}
			body := packet[ihl:]
			if len(body) < 72 || len(body) > 1480 || string(body[8:12]) != bipMagic {
				continue
			}
			packets = append(packets, append([]byte(nil), body...))
		}
		if len(packets) == 0 { continue }
		select {
		case b.incomingBatches <- packets:
		case <-ctx.Done():
			return ctx.Err()
		default:
			b.pendingOverflow.Add(uint64(len(packets)))
		}
	}
}
