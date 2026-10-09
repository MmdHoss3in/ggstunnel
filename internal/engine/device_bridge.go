package engine

import (
	"context"
	"io"
	"sync"
)

// deviceBridge owns the physical descriptor for the lifetime of Engine.Run.
// Closing a transport generation cancels its I/O without removing routes or
// closing forwards. The bounded reader keeps draining during authentication.
type deviceBridge struct {
	device  packetDevice
	queue   *fairPacketQueue
	ctx     context.Context
	cancel  context.CancelFunc
	writes  chan deviceWrite
	workers sync.WaitGroup
	once    sync.Once
}

type deviceWrite struct {
	ctx    context.Context
	packet []byte
	result chan writeResult
}
type writeResult struct {
	n   int
	err error
}

func newDeviceBridge(parent context.Context, device packetDevice, queue *fairPacketQueue, drop func()) *deviceBridge {
	ctx, cancel := context.WithCancel(parent)
	b := &deviceBridge{device: device, queue: queue, ctx: ctx, cancel: cancel, writes: make(chan deviceWrite, 1)}
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
					continue
				}
				n, err := device.Write(req.packet)
				if err == nil && n != len(req.packet) {
					err = io.ErrShortWrite
				}
				req.result <- writeResult{n, err}
				if err != nil {
					queue.close(err)
					return
				}
			}
		}
	}()
	return b
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
	packet, err := d.bridge.queue.pop(d.ctx)
	if err != nil {
		return 0, err
	}
	if len(packet) > len(p) {
		return 0, io.ErrShortBuffer
	}
	return copy(p, packet), nil
}
func (d *generationDevice) Write(p []byte) (int, error) {
	req := deviceWrite{d.ctx, append([]byte(nil), p...), make(chan writeResult, 1)}
	select {
	case <-d.ctx.Done():
		return 0, d.ctx.Err()
	case <-d.bridge.ctx.Done():
		return 0, d.bridge.ctx.Err()
	case d.bridge.writes <- req:
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
