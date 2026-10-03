package engine

import (
	"context"
	"encoding/binary"
	"errors"
	"ggstunnel/internal/config"
	"ggstunnel/internal/frame"
	"testing"
	"time"
)

func flowPacket(port, seq uint16) []byte {
	p := make([]byte, 40)
	p[0], p[9] = 0x45, 6
	p[12], p[16] = 10, 11
	binary.BigEndian.PutUint16(p[20:], port)
	binary.BigEndian.PutUint16(p[22:], 443)
	binary.BigEndian.PutUint16(p[24:], seq)
	return p
}

func TestFairQueueRetainsSparseFlowAcrossBulkOverflow(t *testing.T) {
	q := newFairPacketQueue()
	for i := 0; i < fairPacketsPerFlow; i++ {
		if !q.push(flowPacket(1, uint16(i))) {
			t.Fatal("early overflow")
		}
	}
	for i := 0; i < 1000; i++ {
		if q.push(flowPacket(1, 999)) {
			t.Fatal("unbounded flow")
		}
	}
	small := flowPacket(2, 42)
	if !q.push(small) {
		t.Fatal("bulk displaced sparse flow")
	}
	small[24] = 255 // queue owns the packet
	first, _ := q.pop(context.Background())
	second, _ := q.pop(context.Background())
	if binary.BigEndian.Uint16(first[24:]) != 0 || binary.BigEndian.Uint16(second[20:]) != 2 || binary.BigEndian.Uint16(second[24:]) != 42 {
		t.Fatal("fairness or ownership violated")
	}
	for i := 1; i < fairPacketsPerFlow; i++ {
		p, err := q.pop(context.Background())
		if err != nil || binary.BigEndian.Uint16(p[24:]) != uint16(i) {
			t.Fatal("flow reordered", i, err)
		}
	}
	if q.bytes != 0 || q.count != 0 {
		t.Fatal("retained drained payload")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := q.pop(ctx); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}

func TestFairQueueFlowMemoryAndCloseBounds(t *testing.T) {
	q := newFairPacketQueue()
	for i := 0; i < fairFlows; i++ {
		if !q.push(flowPacket(uint16(i), 0)) {
			t.Fatal(i)
		}
	}
	if q.push(flowPacket(fairFlows, 0)) {
		t.Fatal("unbounded flow count")
	}
	for i := 0; i < fairFlows; i++ {
		if _, err := q.pop(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if !q.push(flowPacket(fairFlows, 0)) {
		t.Fatal("idle flow cache could not be evicted")
	}
	q.bytes = fairBytes
	if q.push(flowPacket(0, 0)) {
		t.Fatal("unbounded byte count")
	}
	sentinel := errors.New("read failed")
	q.close(sentinel)
	if _, err := q.pop(context.Background()); !errors.Is(err, sentinel) {
		t.Fatal(err)
	}
}

func TestPacketFlowIPv6FragmentsAndMalformed(t *testing.T) {
	a, b := flowPacket(1, 0), flowPacket(2, 0)
	if packetFlow(a) == packetFlow(b) {
		t.Fatal("ports not separated")
	}
	a[6], b[6] = 0x20, 0x20
	if packetFlow(a) != packetFlow(b) {
		t.Fatal("fragment payload interpreted as ports")
	}
	v := make([]byte, 44)
	v[0], v[6] = 0x60, 17
	w := append([]byte(nil), v...)
	w[40] = 1
	if packetFlow(v) == packetFlow(w) {
		t.Fatal("IPv6 ports not separated")
	}
	if packetFlow([]byte{0x45}) != (flowKey{}) {
		t.Fatal("malformed packet key")
	}
}

type heldCarrier struct {
	fakeCarrier
	gate chan struct{}
	out  chan []byte
}

func (c *heldCarrier) SendContext(ctx context.Context, p []byte) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-c.gate:
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case c.out <- p:
		return nil
	}
}
func TestBIPDrainsTUNDuringBlockedCarrierAndCancels(t *testing.T) {
	for _, abort := range []bool{false, true} {
		cfg := &config.Config{Profile: "bip"}
		cfg.ApplyDefaults()
		codec, _ := frame.NewCodec("0123456789abcdef")
		receiver, _ := frame.NewCodec("0123456789abcdef")
		d := &packetDeviceFake{in: make(chan []byte, 128), closed: make(chan struct{})}
		c := &heldCarrier{gate: make(chan struct{}), out: make(chan []byte, 128)}
		e := &Engine{cfg: cfg, tun: d, codec: codec, carrier: c}
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan error, 1)
		go func() { done <- e.tunToCarrier(ctx) }()
		for i := 0; i < 100; i++ {
			d.in <- flowPacket(1, uint16(i))
		}
		d.in <- flowPacket(2, 42)
		deadline := time.Now().Add(time.Second)
		for len(d.in) > 0 && time.Now().Before(deadline) {
			time.Sleep(time.Millisecond)
		}
		if len(d.in) > 0 || e.tunQueueDrops.Load() == 0 {
			cancel()
			t.Fatal("blocked carrier stopped TUN draining or failed to bound bulk")
		}
		if !abort {
			close(c.gate)
			found := false
			for i := 0; i < 3; i++ {
				select {
				case p := <-c.out:
					decoded, err := receiver.Open(p)
					if err != nil {
						cancel()
						t.Fatal(err)
					}
					if binary.BigEndian.Uint16(decoded.Payload[20:]) == 2 {
						found = true
					}
				case <-time.After(time.Second):
					cancel()
					t.Fatal("sparse flow not delivered")
				}
			}
			if !found {
				cancel()
				t.Fatal("bulk starved sparse flow")
			}
		}
		cancel()
		select {
		case err := <-done:
			if !errors.Is(err, context.Canceled) {
				t.Fatal(err)
			}
		case <-time.After(time.Second):
			t.Fatal("blocked pipeline failed to cancel")
		}
	}
}
