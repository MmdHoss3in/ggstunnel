package carrier

import (
	"math"
	"testing"
	"time"
)

func adaptiveTuner() *bipTuner {
	c := simConfig("server")
	c.Tuner.Mode = "adaptive"
	return newBIPTuner(c)
}

func TestTunerNewCarrierDoesNotInheritBootstrapThreshold(t *testing.T) {
	for _, clean := range []int{0, 16, 256} {
		x := adaptiveTuner()
		now := time.Unix(100, 0)
		x.pathChangedTo(pendingModeRequest)
		x.onAck(clean, 80*time.Millisecond, now)
		x.onTimeout(now.Add(time.Second))
		bootstrapThreshold, window, credit := x.threshold, x.window(), x.credit
		x.pathChangedTo(pendingModeFast)
		if x.window() != window || x.credit != credit || x.threshold != float64(x.maxWindow) {
			t.Fatal("new carrier must retain flight/credit and learn its own capacity")
		}
		x.onAck(16, 80*time.Millisecond, now.Add(2*time.Second))
		if x.window() != window+16 {
			t.Fatal("working path inherited blocked bootstrap additive recovery")
		}
		x.onTimeout(now.Add(3 * time.Second))
		fastThreshold, window := x.threshold, x.window()
		x.pathChangedTo(pendingModeRequest)
		if x.threshold != bootstrapThreshold || x.window() != window {
			t.Fatal("request path lost its congestion history")
		}
		x.pathChangedTo(pendingModeFast)
		if x.threshold != fastThreshold || x.window() != window {
			t.Fatal("revisited FAST path lost its congestion history")
		}
		resets := x.resets
		x.pathChangedTo(pendingModeFast)
		if x.resets != resets {
			t.Fatal("unchanged carrier reset timing")
		}
	}
}
func TestTunerDelayLossRecoveryAndBounds(t *testing.T) {
	x := adaptiveTuner()
	now := time.Unix(100, 0)
	x.onAck(16, 100*time.Millisecond, now)
	if x.srtt != 100*time.Millisecond || x.rto != 300*time.Millisecond || x.window() != 32 {
		t.Fatalf("initial %+v", x.snapshot())
	}
	x.onAck(1, 300*time.Millisecond, now.Add(time.Second))
	if x.srtt != 125*time.Millisecond || x.variance != 87500*time.Microsecond || x.rto != 475*time.Millisecond {
		t.Fatalf("delay %+v", x.snapshot())
	}
	before := x.window()
	x.onTimeout(now.Add(2 * time.Second))
	if x.window() >= before || x.cuts != 1 {
		t.Fatal("loss did not reduce window")
	}
	x.onTimeout(now.Add(2*time.Second + time.Millisecond))
	if x.cuts != 1 {
		t.Fatal("same loss episode cut multiple times")
	}
	after := x.window()
	x.onAck(100, 100*time.Millisecond, now.Add(2*time.Second+time.Millisecond))
	if x.window() != after {
		t.Fatal("window grew inside recovery")
	}
	x.onAck(100, 100*time.Millisecond, now.Add(3*time.Second))
	if x.window() <= after {
		t.Fatal("recovery did not grow")
	}
	x.onAck(5000, 60*time.Second, now.Add(4*time.Second))
	if x.rto > 10*time.Second || x.window() > 512 || math.IsNaN(x.rate()) {
		t.Fatal("upper bounds exceeded")
	}
	x.onAck(1, time.Nanosecond, now.Add(5*time.Second))
	if x.rto < 50*time.Millisecond || x.rate() > float64(x.cfg.MaxPPS) {
		t.Fatal("lower bound/rate exceeded")
	}
	capacity := x.window()
	x.pathChanged()
	if x.srtt != 0 || x.window() != capacity || x.rto != 80*time.Millisecond {
		t.Fatal("old path timing retained")
	}
}

func TestTunerTokenBucketAndBackoff(t *testing.T) {
	x := adaptiveTuner()
	x.cfg.MaxPPS = 10
	x.cfg.MaxBurst = 2
	x.reset()
	now := time.Unix(100, 0)
	if !x.allow(now, true) || !x.allow(now, true) || x.allow(now, true) {
		t.Fatal("initial burst bound")
	}
	if x.allow(now.Add(50*time.Millisecond), true) {
		t.Fatal("sent ahead of pacing")
	}
	if !x.allow(now.Add(100*time.Millisecond), true) {
		t.Fatal("fractional credit lost")
	}
	now = now.Add(time.Hour)
	if !x.allow(now, true) || !x.allow(now, true) || x.allow(now, true) {
		t.Fatal("idle created unbounded burst")
	}
	if x.timeout(1) != 160*time.Millisecond || x.timeout(32) > 10*time.Second {
		t.Fatal("retry backoff bounds")
	}
}

func TestTunerKarnAndDuplicateACK(t *testing.T) {
	b := testBIP(t)
	b.tuner = adaptiveTuner()
	now := time.Unix(100, 0)
	b.queuePending(outData{seq: 1, retries: 1}, pendingModeFast, now)
	b.processPeerAckAt(1, 0, now.Add(100*time.Millisecond))
	if b.tuner.samples != 0 || b.tuner.acked != 1 {
		t.Fatal("retry supplied RTT sample")
	}
	b.queuePending(outData{seq: 2}, pendingModeFast, now)
	b.processPeerAckAt(2, 0, now.Add(100*time.Millisecond))
	if b.tuner.samples != 1 || b.tuner.srtt != 100*time.Millisecond {
		t.Fatal("clean ACK sample missing")
	}
	before := b.tuner.window()
	b.processPeerAckAt(2, 0, now.Add(time.Second))
	if b.tuner.samples != 1 || b.tuner.acked != 2 || b.tuner.window() != before {
		t.Fatal("duplicate ACK inflated controller")
	}
}

func TestTunerManualAndFrozenDeadline(t *testing.T) {
	c := simConfig("server")
	x := newBIPTuner(c)
	now := time.Unix(100, 0)
	x.onAck(30, 10*time.Millisecond, now)
	x.onTimeout(now)
	if x.timeout(4) != 80*time.Millisecond || x.window() != 512 || !x.allow(now, true) {
		t.Fatal("manual behavior changed")
	}
	b := testBIP(t)
	b.tuner = adaptiveTuner()
	b.queuePending(outData{seq: 1}, pendingModeFast, now)
	b.tuner.onAck(1, time.Millisecond, now)
	if _, ok := b.takeTimedOut(now.Add(60*time.Millisecond), time.Second); ok {
		t.Fatal("new RTT shortened existing deadline")
	}
	if _, ok := b.takeTimedOut(now.Add(80*time.Millisecond), time.Second); !ok {
		t.Fatal("captured timeout missing")
	}
}

func TestSACKSenderAcrossWrap(t *testing.T) {
	b := testBIP(t)
	now := time.Now()
	for _, seq := range []uint32{0xffffffff, 1, 2, 3} {
		b.queuePending(outData{seq: seq}, pendingModeFast, now)
	}
	b.processPeerAckAt(0xfffffffe, 0b0101, now.Add(time.Millisecond))
	if len(b.pending) != 2 || b.pending[1] == nil || b.pending[3] == nil {
		t.Fatal("SACK wrap offset incorrect")
	}
}
