package engine

import (
	"context"
	"io"
	"sync"
	"sync/atomic"
)

// deviceBridge owns the physical descriptor for the lifetime of Engine.Run.
// Closing a transport generation cancels its I/O without removing routes or
// closing forwards. The bounded reader keeps draining during authentication.
type deviceBridge struct {
	device    packetDevice
	queue     *fairPacketQueue
	ctx       context.Context
	cancel    context.CancelFunc
	writes    chan *deviceWrite
	writePool sync.Pool
	workers   sync.WaitGroup
	once      sync.Once
}

type deviceWrite struct {
	ctx    context.Context
	packet []byte
	result chan writeResult
	owners atomic.Int32
}
type writeResult struct {
	n   int
	err error
}

func newDeviceBridge(parent context.Context, device packetDevice, queue *fairPacketQueue, drop func()) *deviceBridge {
	ctx, cancel := context.WithCancel(parent)
	b := &deviceBridge{device: device, queue: queue, ctx: ctx, cancel: cancel, writes: make(chan *deviceWrite, 1)}
	b.writePool.New = func() any { return &deviceWrite{result: make(chan writeResult, 1)} }
	b.workers.Add(2)
	go func() {
		defer b.workers.Done()
		buf := make([]byte, 65535)
		for {
			n, err := device.Read(buf)
			if err != nil {
				queue.close(err)
				return
			}
			if ctx.Err() != nil {
				return
			}
			if n > 0 && !queue.push(buf[:n]) {
				drop()
			}
		}
	}()
	go func() {
		defer b.workers.Done()
		for {
			select {
			case <-ctx.Done():
				return
			case req := <-b.writes:
				if req.ctx.Err() != nil {
					req.result <- writeResult{err: req.ctx.Err()}
					b.releaseWrite(req)
					continue
				}
				n, err := device.Write(req.packet)
				if err == nil && n != len(req.packet) {
					err = io.ErrShortWrite
				}
				req.result <- writeResult{n, err}
				b.releaseWrite(req)
				if err != nil {
					queue.close(err)
					return
				}
			}
		}
	}()
	return b
}

// Caller and physical writer each own a lease. A cancelled caller must not
// recycle its buffer/channel while a blocked physical write still uses them.
func (b *deviceBridge) releaseWrite(req *deviceWrite) {
	if req.owners.Add(-1) != 0 {
		return
	}
	select {
	case <-req.result:
	default:
	}
	req.ctx = nil
	req.packet = req.packet[:0]
	b.writePool.Put(req)
}

func (b *deviceBridge) Close() error {
	b.once.Do(func() {
		b.cancel()
		b.queue.close(io.EOF)
		_ = b.device.Close()
		b.workers.Wait()
	})
	return nil
}

type generationDevice struct {
	bridge *deviceBridge
	ctx    context.Context
	cancel context.CancelFunc
}

func (b *deviceBridge) generation(parent context.Context) *generationDevice {
	ctx, cancel := context.WithCancel(parent)
	return &generationDevice{b, ctx, cancel}
}
func (d *generationDevice) Read(p []byte) (int, error) {
	packet, err := d.ReadPacket()
	if err != nil {
		return 0, err
	}
	if len(packet) > len(p) {
		return 0, io.ErrShortBuffer
	}
	return copy(p, packet), nil
}

// The queue hands off an owned packet. Production transmission can seal it
// directly instead of copying it into another 64KiB read buffer first.
func (d *generationDevice) ReadPacket() ([]byte, error) {
	return d.bridge.queue.pop(d.ctx)
}
func (d *generationDevice) Write(p []byte) (int, error) {
	req := d.bridge.writePool.Get().(*deviceWrite)
	req.ctx = d.ctx
	req.packet = append(req.packet[:0], p...)
	req.owners.Store(2)
	queued := false
	defer func() {
		if !queued {
			d.bridge.releaseWrite(req) // no physical writer acquired its lease
		}
		d.bridge.releaseWrite(req)
	}()
	select {
	case <-d.ctx.Done():
		return 0, d.ctx.Err()
	case <-d.bridge.ctx.Done():
		return 0, d.bridge.ctx.Err()
	case d.bridge.writes <- req:
		queued = true
	}
	select {
	case <-d.ctx.Done():
		return 0, d.ctx.Err()
	case <-d.bridge.ctx.Done():
		return 0, d.bridge.ctx.Err()
	case result := <-req.result:
		return result.n, result.err
	}
}
func (d *generationDevice) Close() error { d.cancel(); return nil }
