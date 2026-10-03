package engine

import (
	"bytes"
	"context"
	"ggstunnel/internal/carrier"
	"ggstunnel/internal/config"
	"io"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type packetDeviceFake struct {
	in, out chan []byte
	closed  chan struct{}
	once    sync.Once
}

func (d *packetDeviceFake) Read(p []byte) (int, error) {
	select {
	case b := <-d.in:
		return copy(p, b), nil
	case <-d.closed:
		return 0, io.EOF
	}
}
func (d *packetDeviceFake) Write(p []byte) (int, error) {
	select {
	case d.out <- append([]byte(nil), p...):
		return len(p), nil
	case <-d.closed:
		return 0, io.EOF
	}
}
func (d *packetDeviceFake) Close() error { d.once.Do(func() { close(d.closed) }); return nil }

type memoryPacketIO struct {
	in     chan []byte
	peer   *memoryPacketIO
	closed chan struct{}
	once   sync.Once
	drop   atomic.Bool
}

func (p *memoryPacketIO) Receive(ctx context.Context) ([]byte, error) {
	select {
	case b := <-p.in:
		return b, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-p.closed:
		return nil, io.EOF
	}
}
func (p *memoryPacketIO) Send(b []byte) error {
	body := b[20:]
	if body[12] == 5 && p.drop.CompareAndSwap(false, true) {
		return nil
	}
	for i := 0; i < 2; i++ {
		select {
		case p.peer.in <- append([]byte(nil), body...):
		case <-p.closed:
			return io.EOF
		default:
		}
	}
	return nil
}
func (p *memoryPacketIO) Close() error { p.once.Do(func() { close(p.closed) }); return nil }
func TestEncryptedEngineFragmentationEndToEnd(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ioA := &memoryPacketIO{in: make(chan []byte, 2048), closed: make(chan struct{})}
	ioB := &memoryPacketIO{in: make(chan []byte, 2048), closed: make(chan struct{})}
	ioA.peer = ioB
	ioB.peer = ioA
	var engines [2]*Engine
	var devices [2]*packetDeviceFake
	done := make(chan error, 2)
	for i := 0; i < 2; i++ {
		role := "server"
		if i == 1 {
			role = "client"
		}
		c := &config.Config{Role: role, Profile: "bip", PSK: "0123456789abcdef0123456789abcdef", Real: config.RealConfig{LocalIP: "198.51.100.10", PeerIP: "203.0.113.20"}, TUN: config.TUNConfig{LocalAddr: "10.77.1.1", RemoteAddr: "10.77.1.2"}}
		c.ApplyDefaults()
		c.Tuner.Mode = "adaptive"
		c.Performance.MaxFramePayload = 512
		c.Transport.BIPMaxRetries = 12
		c.Transport.BIPRTOMS = 50
		e, err := New(c)
		if err != nil {
			t.Fatal(err)
		}
		d := &packetDeviceFake{in: make(chan []byte, 32), out: make(chan []byte, 32), closed: make(chan struct{})}
		e.tun = d
		engines[i] = e
		devices[i] = d
		backend := ioA
		if i == 1 {
			backend = ioB
		}
		if err = e.carrier.(*carrier.BIP).StartPacketIO(ctx, backend); err != nil {
			t.Fatal(err)
		}
		go func(e *Engine) { done <- e.runWorkers(ctx) }(e)
	}
	const n = 20
	for i := 0; i < n; i++ {
		devices[0].in <- bytes.Repeat([]byte{byte(i + 1)}, 900)
		devices[1].in <- bytes.Repeat([]byte{byte(i + 1)}, 1000)
	}
	for side, d := range devices {
		seen := map[byte]bool{}
		deadline := time.After(3 * time.Second)
		for len(seen) < n {
			select {
			case p := <-d.out:
				expected := 1000
				if side == 1 {
					expected = 900
				}
				if len(p) != expected || !bytes.Equal(p, bytes.Repeat(p[:1], expected)) {
					t.Fatal("decryption/reassembly corruption")
				}
				if seen[p[0]] {
					t.Fatal("duplicate IP delivery")
				}
				seen[p[0]] = true
			case err := <-done:
				t.Fatalf("engine ended: %v", err)
			case <-deadline:
				t.Fatalf("side %d received %d packets", side, len(seen))
			}
		}
	}
	cancel()
	for i := 0; i < 2; i++ {
		select {
		case err := <-done:
			if err != nil {
				t.Fatal(err)
			}
		case <-time.After(time.Second):
			t.Fatal("engine cleanup timed out")
		}
	}
}
