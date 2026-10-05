package carrier

import (
	"context"
	"encoding/binary"
	"testing"
	"time"

	"ggstunnel/internal/config"
)

func TestSmallBacklogRetainsLargeFlightWindow(t *testing.T) {
	c := simConfig("server")
	c.Performance.QueueSize = 8192
	x, err := NewBIP(c)
	if err != nil {
		t.Fatal(err)
	}
	b := x.(*BIP)
	defer b.Close()
	if cap(b.tx) != 64 || b.window() != 4096 || b.tuner.maxWindow != 4096 {
		t.Fatal("queue latency bound must not shrink the high-BDP flight window")
	}
}

func TestPendingHeapDeadlineOrderAndCleanup(t *testing.T) {
	b := testBIP(t)
	b.tuner = adaptiveTuner()
	now := time.Now()
	b.queuePending(outData{seq: 1, retries: 4}, pendingModeFast, now.Add(-100*time.Millisecond))
	b.queuePending(outData{seq: 2}, pendingModeFast, now)
	p, ok := b.takeTimedOut(now.Add(90*time.Millisecond), time.Second)
	if !ok || p.item.seq != 2 {
		t.Fatal("retry heap did not select earliest deadline")
	}
	b.processPeerAckAt(1, 0, now.Add(100*time.Millisecond))
	if len(b.retryHeap) != 0 || len(b.pending) != 0 {
		t.Fatal("ACK left stale retry entries")
	}
}

func TestOneCongestionCutPerTransmittedFlight(t *testing.T) {
	b := testBIP(t)
	b.tuner = adaptiveTuner()
	b.tuner.cwnd = 256
	b.dataSeq = 300
	now := time.Now()
	b.noteDeliveryLoss(&pendingData{item: outData{seq: 100}}, now)
	b.noteDeliveryLoss(&pendingData{item: outData{seq: 200}}, now.Add(time.Second))
	if b.tuner.cuts != 1 || b.tuner.window() != 128 {
		t.Fatal("one flight was penalized repeatedly")
	}
	b.dataSeq = 400
	b.noteDeliveryLoss(&pendingData{item: outData{seq: 350}}, now.Add(2*time.Second))
	if b.tuner.cuts != 2 || b.tuner.window() != 64 {
		t.Fatal("new flight loss failed to reduce congestion window")
	}
}

func TestPathTransitionPreservesSlowStartAndLossThreshold(t *testing.T) {
	x := adaptiveTuner()
	threshold := x.threshold
	x.pathChanged()
	if x.threshold != threshold {
		t.Fatal("healthy path change disabled slow start")
	}
	now := time.Now()
	x.onAck(16, 80*time.Millisecond, now)
	if x.window() != 32 {
		t.Fatal("initial growth was throttled")
	}
	// Establish capacity beyond the setup-ping/startup allowance before
	// requiring an authenticated path change to preserve a loss threshold.
	x.onAck(48, 80*time.Millisecond, now.Add(time.Second))
	x.onTimeout(now)
	window, threshold := x.window(), x.threshold
	x.pathChanged()
	if x.window() != window || x.threshold != threshold {
		t.Fatal("path change erased congestion evidence")
	}
}

func TestBIPSendContextBackpressureAndCancellation(t *testing.T) {
	c := simConfig("server")
	ca, err := NewBIP(c)
	if err != nil {
		t.Fatal(err)
	}
	b := ca.(*BIP)
	defer b.Close()
	for i := 0; i < cap(b.tx); i++ {
		if err := b.Send([]byte("full")); err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- b.SendContext(ctx, []byte("kept")) }()
	select {
	case err := <-done:
		t.Fatalf("full queue did not wait: %v", err)
	case <-time.After(10 * time.Millisecond):
	}
	<-b.tx
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("space did not unblock producer")
	}
	go func() { done <- b.SendContext(ctx, []byte("cancelled")) }()
	cancel()
	select {
	case err := <-done:
		if err != context.Canceled {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("cancellation stuck")
	}
	go func() { done <- b.SendContext(context.Background(), []byte("closed")) }()
	b.Close()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("closed carrier accepted blocked send")
		}
	case <-time.After(time.Second):
		t.Fatal("close stuck")
	}
}

func TestACKBatchRetainsReplyTuple(t *testing.T) {
	b := testBIP(t)
	b.active = 8
	var packets [][]byte
	b.emit = func(p []byte) error { packets = append(packets, append([]byte(nil), p...)); return nil }
	now := time.Now()
	for i := 1; i <= 16; i++ {
		b.scheduleAck(wirePacket{typ: 8, id: 5, tuple: uint16(i)}, now, false)
	}
	if len(packets) != 1 || packets[0][20] != 0 || binary.BigEndian.Uint16(packets[0][26:28]) != 16 {
		t.Fatal("ACK batch lost stateful reply tuple")
	}
	b.scheduleAck(wirePacket{typ: 8, id: 5, tuple: 17}, now, false)
	if b.ackDue.IsZero() {
		t.Fatal("short batch has no deadline")
	}
	b.flushAck(now.Add(10 * time.Millisecond))
	if len(packets) != 2 || !b.ackDue.IsZero() {
		t.Fatal("short batch was not flushed")
	}
}

func TestHealthyFastDoesNotPerpetuatePullPolling(t *testing.T) {
	b := testBIP(t)
	b.active = 8
	b.tx = make(chan []byte, 4)
	b.tx <- []byte("one")
	b.tx <- []byte("two")
	b.fastHealthy.Store(true)
	var flags byte
	b.emit = func(p []byte) error { flags = p[20+13]; return nil }
	b.deliverOne(0, 4, 5, pendingModePull, time.Now())
	if flags&bipFlagPulled == 0 || flags&bipFlagMore != 0 {
		t.Fatal("healthy FAST perpetuates PULL polling")
	}
	if len(b.tx) != 1 {
		t.Fatal("PULL did not deliver its response")
	}
}

// Exercise repeated loss after ramp-up; a DATA timeout must not invalidate a
// working FAST probe or erase the learned congestion window via pathChanged.
func TestFastPathSurvivesDataLoss(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	l := &simLink{adaptive: true, delay: 10 * time.Millisecond, copies: 1, requests: make(map[[3]uint16]time.Time)}
	defer func() { cancel(); l.schedulerWorkers.Wait() }()
	l.configure = func(c *config.Config) {
		c.Tuner.UnlimitedRate = true
		c.Tuner.MaxBurst = 128
		c.Transport.BIPFastTTLMS = 1000
		c.Transport.BIPFastProbeMS = 100
		c.Transport.BIPRTOMS = 100
	}
	a := l.start(t, 0, ctx)
	b := l.start(t, 1, ctx)
	waitFor(t, func() bool { return a.SnapshotStats().FastHealthy && a.SnapshotTuner().Resets > 0 })
	before := a.SnapshotStats().FastDemotions
	dropped := false
	l.mu.Lock()
	l.filter = func(from int, p []byte) bool {
		if from == 0 && p[12] == bipKindData && !dropped {
			dropped = true
			return false
		}
		return true
	}
	l.mu.Unlock()
	for i := 0; i < 100; i++ {
		if err := a.SendContext(ctx, []byte{byte(i)}); err != nil {
			t.Fatal(err)
		}
	}
	seen := map[byte]bool{}
	deadline := time.After(5 * time.Second)
	for len(seen) < 100 {
		select {
		case p := <-b.Recv():
			if seen[p[0]] {
				t.Fatal("duplicate")
			}
			seen[p[0]] = true
		case <-deadline:
			t.Fatal("loss recovery stalled")
		}
	}
	waitFor(t, func() bool { return a.SnapshotStats().Pending == 0 })
	if a.SnapshotStats().FastDemotions != before {
		t.Fatal("DATA loss demoted a healthy FAST path")
	}
	if a.SnapshotStats().Retransmits == 0 {
		t.Fatal("test did not exercise loss")
	}
}
