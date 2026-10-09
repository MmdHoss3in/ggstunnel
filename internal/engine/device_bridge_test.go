package engine

import (
	"bytes"
	"context"
	"errors"
	"io"
	"sync"
	"testing"
	"time"
)

func TestPersistentDeviceGenerationCancellationAndQueuedTraffic(t *testing.T) {
	physical := &packetDeviceFake{in: make(chan []byte, 16), out: make(chan []byte, 16), closed: make(chan struct{})}
	bridge := newDeviceBridge(context.Background(), physical, newFairPacketQueue(), func() { t.Error("unexpected overflow") })
	defer bridge.Close()
	first := bridge.generation(context.Background())
	done := make(chan error, 1)
	go func() { _, err := first.Read(make([]byte, 64)); done <- err }()
	first.Close()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("generation read remained blocked")
	}
	select {
	case <-physical.closed:
		t.Fatal("recovery closed physical TUN")
	default:
	}
	packet := flowPacket(42, 7)
	physical.in <- packet
	second := bridge.generation(context.Background())
	defer second.Close()
	buf := make([]byte, 64)
	n, err := second.Read(buf)
	if err != nil || !bytes.Equal(buf[:n], packet) {
		t.Fatal("recovery lost queued packet", err)
	}
	if n, err := second.Write(packet); err != nil || n != len(packet) {
		t.Fatal(err)
	}
	if got := <-physical.out; !bytes.Equal(got, packet) {
		t.Fatal("physical write changed")
	}
	bridge.Close()
	select {
	case <-physical.closed:
	default:
		t.Fatal("physical TUN leaked at shutdown")
	}
}

type heldPacketDevice struct {
	*packetDeviceFake
	entered chan struct{}
	release chan struct{}
}

func (d *heldPacketDevice) Write(p []byte) (int, error) {
	d.entered <- struct{}{}
	select {
	case <-d.release:
		return d.packetDeviceFake.Write(p)
	case <-d.closed:
		return 0, io.EOF
	}
}

func TestPersistentDeviceCancelledWriteRetainsOwnedBuffer(t *testing.T) {
	physical := &heldPacketDevice{
		packetDeviceFake: &packetDeviceFake{in: make(chan []byte), out: make(chan []byte, 2), closed: make(chan struct{})},
		entered:          make(chan struct{}, 2), release: make(chan struct{}, 2),
	}
	bridge := newDeviceBridge(context.Background(), physical, newFairPacketQueue(), func() {})
	defer bridge.Close()
	first := bridge.generation(context.Background())
	original := flowPacket(1, 1)
	input := append([]byte(nil), original...)
	done := make(chan error, 1)
	go func() { _, err := first.Write(input); done <- err }()
	select {
	case <-physical.entered:
	case <-time.After(time.Second):
		t.Fatal("physical write did not start")
	}
	first.Close()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("cancelled generation remained blocked")
	}
	for i := range input {
		input[i] = 0xff
	}
	second := bridge.generation(context.Background())
	defer second.Close()
	next := flowPacket(2, 2)
	go func() { _, err := second.Write(next); done <- err }()
	physical.release <- struct{}{}
	select {
	case got := <-physical.out:
		if !bytes.Equal(got, original) {
			t.Fatal("cancelled writer's leased packet was recycled or aliased")
		}
	case <-time.After(time.Second):
		t.Fatal("first physical write stalled")
	}
	physical.release <- struct{}{}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("next generation stalled")
	}
	if got := <-physical.out; !bytes.Equal(got, next) {
		t.Fatal("next packet corrupted")
	}
}

func TestPersistentDeviceConcurrentPooledWriteIntegrity(t *testing.T) {
	const count = 128
	physical := &packetDeviceFake{in: make(chan []byte), out: make(chan []byte, count), closed: make(chan struct{})}
	bridge := newDeviceBridge(context.Background(), physical, newFairPacketQueue(), func() {})
	defer bridge.Close()
	gen := bridge.generation(context.Background())
	defer gen.Close()
	var workers sync.WaitGroup
	for i := 0; i < count; i++ {
		workers.Add(1)
		go func(i int) {
			defer workers.Done()
			p := flowPacket(uint16(i), uint16(i))
			if n, err := gen.Write(p); err != nil || n != len(p) {
				t.Errorf("write: %d %v", n, err)
			}
		}(i)
	}
	finished := make(chan struct{})
	go func() { workers.Wait(); close(finished) }()
	select {
	case <-finished:
	case <-time.After(3 * time.Second):
		t.Fatal("concurrent writes stalled")
	}
	seen := make(map[string]bool)
	for i := 0; i < count; i++ {
		seen[string(<-physical.out)] = true
	}
	for i := 0; i < count; i++ {
		if !seen[string(flowPacket(uint16(i), uint16(i)))] {
			t.Fatal("pooled write duplicated or corrupted", i)
		}
	}
}

func BenchmarkPersistentDeviceWrite(b *testing.B) {
	physical := &packetDeviceFake{in: make(chan []byte), out: make(chan []byte, 1), closed: make(chan struct{})}
	bridge := newDeviceBridge(context.Background(), physical, newFairPacketQueue(), func() {})
	defer bridge.Close()
	gen := bridge.generation(context.Background())
	defer gen.Close()
	packet := make([]byte, 1280)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := gen.Write(packet); err != nil {
			b.Fatal(err)
		}
		<-physical.out
	}
}

func TestPersistentDeviceCancelsBlockedPhysicalWrite(t *testing.T) {
	physical := &packetDeviceFake{in: make(chan []byte), out: make(chan []byte), closed: make(chan struct{})}
	bridge := newDeviceBridge(context.Background(), physical, newFairPacketQueue(), func() {})
	defer bridge.Close()
	gen := bridge.generation(context.Background())
	done := make(chan error, 1)
	go func() { _, err := gen.Write(flowPacket(1, 1)); done <- err }()
	gen.Close()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("generation blocked on physical writer")
	}
}

func TestFairQueueExpiresPacketsWithoutReorderingFreshFlows(t *testing.T) {
	q := newFairPacketQueue()
	now := time.Unix(10, 0)
	q.now = func() time.Time { return now }
	q.maxAge = time.Second
	expired := 0
	q.expired = func() { expired++ }
	q.push(flowPacket(1, 1))
	q.push(flowPacket(2, 1))
	now = now.Add(time.Second)
	fresh := flowPacket(3, 2)
	q.push(fresh)
	got, err := q.pop(context.Background())
	if err != nil || !bytes.Equal(got, fresh) || expired != 2 || q.bytes != 0 || q.count != 0 {
		t.Fatal("stale flow cleanup failed", expired, err)
	}
}

func TestFairQueueExpiredFullFlowAcceptsFreshRetry(t *testing.T) {
	q := newFairPacketQueue()
	now := time.Unix(10, 0)
	q.now = func() time.Time { return now }
	q.maxAge = time.Second
	expired := 0
	q.expired = func() { expired++ }
	for i := 0; i < fairPacketsPerFlow; i++ {
		if !q.push(flowPacket(1, uint16(i))) {
			t.Fatal("early flow limit")
		}
	}
	now = now.Add(time.Second)
	fresh := flowPacket(1, 999)
	if !q.push(fresh) {
		t.Fatal("stale full flow rejected fresh retransmission")
	}
	got, err := q.pop(context.Background())
	if err != nil || !bytes.Equal(got, fresh) || expired != fairPacketsPerFlow || q.bytes != 0 || q.count != 0 {
		t.Fatal("stale ready entry or duplicate scheduling", expired, err)
	}
}

func TestFairQueueExpiredFlowLimitAdmitsNewFlow(t *testing.T) {
	q := newFairPacketQueue()
	now := time.Unix(10, 0)
	q.now = func() time.Time { return now }
	q.maxAge = time.Second
	for i := 0; i < fairFlows; i++ {
		if !q.push(flowPacket(uint16(i), 0)) {
			t.Fatal(i)
		}
	}
	now = now.Add(time.Second)
	fresh := flowPacket(fairFlows, 1)
	if !q.push(fresh) {
		t.Fatal("expired ready ring rejected new flow")
	}
	got, err := q.pop(context.Background())
	if err != nil || !bytes.Equal(got, fresh) || q.count != 0 || q.bytes != 0 {
		t.Fatal("ready ring was corrupted", err)
	}
}
