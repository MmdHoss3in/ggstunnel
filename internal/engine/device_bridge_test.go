package engine

import (
	"bytes"
	"context"
	"errors"
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
	fresh := flowPacket(1, 2)
	q.push(fresh)
	got, err := q.pop(context.Background())
	if err != nil || !bytes.Equal(got, fresh) || expired != 2 || q.bytes != 0 || q.count != 0 {
		t.Fatal("stale flow cleanup failed", expired, err)
	}
}
