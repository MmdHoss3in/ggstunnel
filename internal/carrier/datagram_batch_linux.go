//go:build linux && (amd64 || arm64)

package carrier

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"syscall"
	"time"
	"unsafe"
)

type datagramSocket interface {
	SyscallConn() (syscall.RawConn, error)
	SetWriteDeadline(time.Time) error
}

// Each message keeps its own source and boundary. Do not connect UDP merely to
// batch it: connected UDP can turn a peer's startup ICMP error into a fatal read.
func readDatagramBatch(ctx context.Context, socket datagramSocket, deliver func([]byte, net.IP, int)) error {
	conn, err := socket.SyscallConn()
	if err != nil {
		return err
	}
	batch := newBIPSocketBatch()
	for i := range batch.msg {
		batch.msg[i].header.Name = (*byte)(unsafe.Pointer(&batch.addresses[i]))
		batch.msg[i].header.Namelen = syscall.SizeofSockaddrInet4
	}
	for {
		if ctx.Err() != nil {
			return ctx.Err()
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
			return err
		}
		if receiveErr != nil {
			return receiveErr
		}
		for i := 0; i < count; i++ {
			n := int(batch.msg[i].length)
			if n == 0 || n > len(batch.data[i]) || batch.msg[i].header.Flags&syscall.MSG_TRUNC != 0 || batch.addresses[i].Family != syscall.AF_INET {
				continue
			}
			var portBytes [2]byte
			binary.NativeEndian.PutUint16(portBytes[:], batch.addresses[i].Port)
			deliver(batch.data[i][:n], net.IP(batch.addresses[i].Addr[:]), int(binary.BigEndian.Uint16(portBytes[:])))
		}
	}
}

func writeDatagramBatch(socket datagramSocket, packets [][]byte, peer net.IP, port int) (int, error) {
	conn, err := socket.SyscallConn()
	if err != nil {
		return 0, err
	}
	sent := 0
	for sent < len(packets) {
		n := 0
		var sendErr error
		err = conn.Write(func(fd uintptr) bool {
			n, sendErr = sendIPv4Messages(int(fd), packets[sent:], peer, port)
			return !errors.Is(sendErr, syscall.EAGAIN)
		})
		if err != nil {
			return sent, err
		}
		sent += n
		if sendErr != nil {
			return sent, sendErr
		}
		if n == 0 {
			return sent, io.ErrNoProgress
		}
	}
	return sent, nil
}

func (u *UDP) readLoop(ctx context.Context) {
	err := readDatagramBatch(ctx, u.conn, func(payload []byte, source net.IP, port int) {
		u.stats.receive(len(payload))
		if !source.Equal(u.peer.IP) || port != u.peer.Port {
			u.stats.sourceRejected.Add(1)
			return
		}
		if len(payload) > u.cfg.ReceiveFrameLimit() {
			u.stats.formatRejected.Add(1)
			return
		}
		cp := append([]byte(nil), payload...)
		select {
		case u.rx <- cp:
		case <-ctx.Done():
		case <-u.closeCh:
		default:
			u.stats.rxDrops.Add(1)
		}
	})
	if errors.Is(err, syscall.ENOSYS) {
		u.readLoopScalar(ctx)
		return
	}
	select {
	case <-u.closeCh:
		return
	case <-ctx.Done():
		return
	default:
	}
	if err != nil {
		u.stats.rxErrors.Add(1)
		u.fail(err)
	}
}

func (r *rawCarrier) readLoop(ctx context.Context) {
	err := readDatagramBatch(ctx, r.conn, func(packet []byte, source net.IP, _ int) {
		if len(packet) < 20 || packet[0]>>4 != 4 {
			r.stats.formatRejected.Add(1)
			return
		}
		ihl := int(packet[0]&15) * 4
		if ihl < 20 || ihl > len(packet) {
			r.stats.formatRejected.Add(1)
			return
		}
		r.stats.receive(len(packet) - ihl)
		if !source.Equal(r.peer.IP) {
			r.stats.sourceRejected.Add(1)
			return
		}
		payload, ok := r.unwrap(packet[ihl:])
		if !ok || len(payload) == 0 || len(payload) > r.cfg.ReceiveFrameLimit() {
			r.stats.formatRejected.Add(1)
			return
		}
		cp := append([]byte(nil), payload...)
		select {
		case r.rx <- cp:
		case <-ctx.Done():
		case <-r.closeCh:
		default:
			r.stats.rxDrops.Add(1)
		}
	})
	if errors.Is(err, syscall.ENOSYS) {
		r.readLoopScalar(ctx)
		return
	}
	select {
	case <-r.closeCh:
		return
	case <-ctx.Done():
		return
	default:
	}
	if err != nil {
		r.stats.rxErrors.Add(1)
		select {
		case r.errors <- err:
		default:
		}
	}
}

func writeQueuedDatagrams(ctx context.Context, closed <-chan struct{}, tx <-chan []byte, socket datagramSocket, peer net.IP, port int, timeout time.Duration, wrap func([]byte) []byte, scalar func([]byte) error, metrics ...*datagramStats) error {
	packets := make([][]byte, 0, 32)
	fallback := false
	for {
		select {
		case <-closed:
			return nil
		case <-ctx.Done():
			return nil
		default:
		}
		select {
		case first := <-tx:
			clear(packets)
			packets = packets[:0]
			packets = append(packets, wrap(first))
		batch:
			for len(packets) < 32 {
				select {
				case next := <-tx:
					packets = append(packets, wrap(next))
				default:
					break batch
				}
			}
			if err := socket.SetWriteDeadline(time.Now().Add(timeout)); err != nil {
				return err
			}
			sent := 0
			if !fallback {
				var err error
				sent, err = writeDatagramBatch(socket, packets, peer, port)
				if len(metrics) > 0 {
					for _, p := range packets[:sent] {
						metrics[0].sent(len(p))
					}
				}
				if errors.Is(err, syscall.ENOSYS) {
					fallback = true
				} else if err != nil {
					if errors.Is(err, syscall.EMSGSIZE) && len(metrics) > 0 {
						metrics[0].txDrops.Add(uint64(len(packets) - sent))
					}
					return err
				}
			}
			for _, p := range packets[sent:] {
				if err := scalar(p); err != nil {
					if errors.Is(err, syscall.EMSGSIZE) && len(metrics) > 0 {
						metrics[0].txDrops.Add(uint64(len(packets) - sent))
					}
					return err
				}
				if len(metrics) > 0 {
					metrics[0].sent(len(p))
				}
				sent++
			}
		case <-ctx.Done():
			return nil
		case <-closed:
			return nil
		}
	}
}

func (u *UDP) writeLoop(ctx context.Context) {
	var err error
	for {
		err = writeQueuedDatagrams(ctx, u.closeCh, u.tx, u.conn, u.peer.IP, u.peer.Port, u.cfg.IdleTimeout(), func(p []byte) []byte { return p }, func(p []byte) error { _, err := u.conn.WriteToUDP(p, u.peer); return err }, &u.stats)
		if !u.cfg.Transport.PathMTU || !errors.Is(err, syscall.EMSGSIZE) {
			break
		}
		u.stats.txErrors.Add(1)
	}
	select {
	case <-u.closeCh:
		return
	case <-ctx.Done():
		return
	default:
	}
	if err != nil {
		u.stats.txErrors.Add(1)
		u.fail(err)
	}
}

func (r *rawCarrier) writeLoop(ctx context.Context) {
	err := writeQueuedDatagrams(ctx, r.closeCh, r.tx, r.conn, r.peer.IP, 0, r.cfg.IdleTimeout(), r.wrap, func(p []byte) error { _, err := r.conn.WriteToIP(p, r.peer); return err }, &r.stats)
	select {
	case <-r.closeCh:
		return
	case <-ctx.Done():
		return
	default:
	}
	if err != nil {
		r.stats.txErrors.Add(1)
		select {
		case r.errors <- err:
		default:
		}
	}
}
