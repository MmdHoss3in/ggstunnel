package carrier

import (
	"context"
	"encoding/binary"
	"ggstunnel/internal/config"
	"io"
	"net"
	"testing"
	"time"
)

func TestWideSACKNegotiationAndLegacyFallback(t *testing.T) {
	for _, wide := range []bool{false, true} {
		t.Run(map[bool]string{false: "legacy", true: "wide"}[wide], func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			link := &simLink{copies: 1, adaptive: true, requests: make(map[[3]uint16]time.Time)}
			link.configure = func(c *config.Config) {
				c.Performance.QueueSize = 8192
				if !wide && c.Role == "client" {
					c.Performance.QueueSize = 4096
				}
			}
			a, b := link.start(t, 0, ctx), link.start(t, 1, ctx)
			want := 4096
			if wide {
				want = 8192
			}
			waitFor(t, func() bool {
				return a.PeerSession() != 0 && b.PeerSession() != 0 && a.SnapshotTuner().WindowLimit == want && b.SnapshotTuner().WindowLimit == want
			})
		})
	}
}

func TestWideSACKHighestSlotAndBoundedHorizon(t *testing.T) {
	b := spanSender(t, 0)
	b.peerSpan = bipWideSpan
	b.rxAck.seen = make(map[uint32]bool)
	b.rxAck.seen[8192] = true
	extra := b.ackExtension(0)
	if len(extra) != 1016 || binary.BigEndian.Uint64(extra[1008:]) != 1<<63 {
		t.Fatal("8192nd slot missing")
	}
	b.queuePending(outData{seq: 8192}, pendingModeRequest, time.Now())
	b.processWideAckAt(0, 0, extra, time.Now().Add(time.Second))
	if len(b.pending) != 0 {
		t.Fatal("highest-slot ACK did not clear pending")
	}
	b.dataSeq, b.txAckBase = 8192, 0
	b.deliverOne(8, 1, 1, pendingModeRequest, time.Now())
	if b.dataSeq != 8192 {
		t.Fatal("sender crossed negotiated ACK horizon")
	}
	b.processPeerAckAt(8192, 0, time.Now())
	b.deliverOne(8, 1, 1, pendingModeRequest, time.Now())
	if b.dataSeq != 8193 {
		t.Fatal("sender did not resume")
	}
}

func TestPersistentRetransmissionHoleRequiresFreshGuardedSnapshots(t *testing.T) {
	b := testBIP(t)
	b.tuner = adaptiveTuner()
	b.tuner.srtt = 80 * time.Millisecond
	now := time.Now()
	b.queuePending(outData{seq: 1, retries: 2}, pendingModeRequest, now)
	original := b.pending[1].deadline
	for i := 0; i < 20; i++ {
		b.recoverPersistentHole(0, 0b11110, nil, false, now.Add(100*time.Millisecond))
	}
	if b.pending[1].deadline != original {
		t.Fatal("reordering guard ignored")
	}
	for i := 0; i < 2; i++ {
		b.recoverPersistentHole(0, 0b11110, nil, false, now.Add(200*time.Millisecond))
	}
	if b.pending[1].deadline != original {
		t.Fatal("insufficient snapshots accelerated retry")
	}
	b.recoverPersistentHole(0, 0b11110, nil, false, now.Add(200*time.Millisecond))
	p, ok := b.takeTimedOut(now.Add(200*time.Millisecond), time.Second)
	if !ok || !p.fast || p.item.seq != 1 {
		t.Fatal("lost retransmission did not recover")
	}
	b.queuePending(p.item, pendingModeRequest, now.Add(200*time.Millisecond))
	if b.pending[1].sacked != 0 || b.pending[1].fast {
		t.Fatal("evidence leaked across transmission attempts")
	}
}

func TestPathReturnDoesNotResetRetryBudget(t *testing.T) {
	b := testBIP(t)
	b.tuner = adaptiveTuner()
	b.tuner.srtt = 80 * time.Millisecond
	now := time.Now()
	b.queuePending(outData{seq: 1, retries: 4}, pendingModeRequest, now.Add(-time.Second))
	b.expeditePathRetries(now)
	if b.pending[1].item.retries != 4 || b.pending[1].deadline.After(now.Add(100*time.Millisecond)) {
		t.Fatal("path recovery discarded retry budget or kept stale backoff")
	}
}

func TestWideSACKWrapHighestSlot(t *testing.T) {
	base := ^uint32(0) - 32
	highest := base
	for i := 0; i < 8192; i++ {
		highest = nextSequence(highest)
	}
	b := spanSender(t, base)
	b.peerSpan = bipWideSpan
	b.rxAck = sackWindow{init: true, max: base, seen: make(map[uint32]bool)}
	b.recordRXSeqLocked(highest)
	extra := b.ackExtension(base)
	if len(extra) != 1016 || binary.BigEndian.Uint64(extra[1008:]) != 1<<63 {
		t.Fatal("wrapped highest slot did not use the negotiated SACK horizon")
	}
	b.queuePending(outData{seq: highest}, pendingModeRequest, time.Now())
	b.processWideAckAt(base, 0, extra, time.Now().Add(time.Second))
	if len(b.pending) != 0 {
		t.Fatal("wrapped highest slot was not acknowledged")
	}
	b.dataSeq = highest
	b.deliverOne(8, 1, 1, pendingModeRequest, time.Now())
	if b.dataSeq != highest {
		t.Fatal("wrapped sender crossed the cumulative ACK horizon")
	}
	b.processPeerAckAt(highest, 0, time.Now())
	b.deliverOne(8, 1, 1, pendingModeRequest, time.Now())
	if b.dataSeq != nextSequence(highest) {
		t.Fatal("wrapped sender did not resume after hole recovery")
	}
}

func TestTCPBatchPreservesFramesAndFlushesIsolatedPacket(t *testing.T) {
	c := simConfig("server")
	x := NewTCP(c)
	defer x.Close()
	writer, reader := net.Pipe()
	defer reader.Close()
	defer writer.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	for i := 0; i < 100; i++ {
		if err := x.Send([]byte{byte(i), 42}); err != nil {
			t.Fatal(err)
		}
	}
	done := make(chan error, 1)
	go func() { done <- x.writeLoop(ctx, writer) }()
	reader.SetReadDeadline(time.Now().Add(2 * time.Second))
	for i := 0; i < 100; i++ {
		var header [4]byte
		if _, err := io.ReadFull(reader, header[:]); err != nil {
			t.Fatal(err)
		}
		size := binary.BigEndian.Uint32(header[:])
		if size != 2 {
			t.Fatal("frame boundary damaged")
		}
		var data [2]byte
		if _, err := io.ReadFull(reader, data[:]); err != nil {
			t.Fatal(err)
		}
		if data[0] != byte(i) || data[1] != 42 {
			t.Fatal("batched frame corrupted")
		}
	}
	if err := x.Send([]byte{123}); err != nil {
		t.Fatal(err)
	}
	reader.SetReadDeadline(time.Now().Add(time.Second))
	var last [5]byte
	if _, err := io.ReadFull(reader, last[:]); err != nil || last[4] != 123 {
		t.Fatal("isolated frame waited for another packet")
	}
	cancel()
	writer.Close()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("TCP writer leaked")
	}
}
