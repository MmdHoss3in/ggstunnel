package carrier

import (
	"context"
	"errors"
	"testing"
	"time"

	"ggstunnel/internal/config"
)

func TestFieldStallEmptyAuthenticatedPullCannotPreventFallback(t *testing.T) {
	for _, wire := range []string{"legacy", "compact"} {
		for peer := 0; peer < 7; peer++ {
			a, b := replyControlPeers(t, wire)
			a.cfg.Transport.BIPPullTimeoutMS = 300
			a.cfg.Transport.BIPRTOMS = 250
			a.cfg.Tuner.Mode = "adaptive"
			a.tuner = newBIPTuner(a.cfg)
			a.tuner.cwnd = 1
			a.emit = func([]byte) error { return nil }
			now := time.Unix(100, 0)
			a.dataSeq = 1
			a.queuePending(outData{seq: 1, data: []byte("retained")}, pendingModePull, now)
			if a.requestFallback(now, false) {
				t.Fatal("discovery skipped PULL")
			}
			for i := 1; i <= 20; i++ {
				at := now.Add(time.Duration(i) * 100 * time.Millisecond)
				body, err := b.encode(wirePacket{typ: 8, kind: bipKindPullProbe, sender: b.localID, target: a.localID, number: uint64(i)})
				if err != nil {
					t.Fatal(err)
				}
				a.handle(body, at)
				if i >= 10 && !a.requestFallback(at, false) {
					t.Fatal("empty authenticated PULL kept failed data path selected")
				}
			}
			if a.pending[1] == nil || a.active != b.localID || a.deliveryHealth.lastAck != (time.Time{}) {
				t.Fatal("fallback reset identity/flight or controls invented DATA progress")
			}
		}
	}
}

func TestFieldStallActorControlsOnlyTriggersRecovery(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	l := &simLink{adaptive: true, copies: 1, requests: make(map[[3]uint16]time.Time)}
	l.configure = func(c *config.Config) { c.Transport.BIPDeadTimeoutSec = 1 }
	l.filter = func(_ int, p []byte) bool { return p[12] != bipKindData }
	a, b := l.start(t, 0, ctx), l.start(t, 1, ctx)
	waitFor(t, func() bool { return a.PeerSession() == b.localID && b.PeerSession() == a.localID })
	if err := a.Send([]byte("not delivered")); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-a.Errors():
		if !errors.Is(err, ErrBIPDeliveryStalled) {
			t.Fatal("fresh controls hid the delivery deadline", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("actor never recovered a control-only connection")
	}
}

func TestFieldStallActorDelayedACKObtainsCleanTiming(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	l := &simLink{adaptive: true, delay: 200 * time.Millisecond, copies: 1, requests: make(map[[3]uint16]time.Time)}
	l.configure = func(c *config.Config) {
		c.Tuner.Algorithm = "delivery"
		c.Transport.BIPRTOMS = 250
		c.Transport.BIPFastProbeMS = 100
		c.Transport.BIPFastTTLMS = 3500
	}
	a, b := l.start(t, 0, ctx), l.start(t, 1, ctx)
	waitFor(t, func() bool { return a.SnapshotStats().FastHealthy && b.SnapshotStats().FastHealthy })
	for i := 0; i < 32; i++ {
		if err := a.SendContext(ctx, []byte{byte(i)}); err != nil {
			t.Fatal(err)
		}
	}
	for i := 0; i < 32; i++ {
		select {
		case packet := <-b.Recv():
			if len(packet) != 1 || packet[0] != byte(i) {
				t.Fatal("delayed ACK path corrupted or reordered payload")
			}
		case <-ctx.Done():
			t.Fatal("delayed-ACK flight stopped making progress")
		}
	}
	waitFor(t, func() bool { return a.SnapshotTuner().RTTSamples > 0 && a.SnapshotStats().Pending == 0 })
	if a.SnapshotTuner().Window <= 1 || a.SnapshotStats().Retransmits == 0 {
		t.Fatal("delayed original ACK case did not repair and escape the one-frame trap")
	}
}

func TestFieldStallUsefulPullACKKeepsPathAndIdleIsHealthy(t *testing.T) {
	b := testBIP(t)
	b.cfg.ApplyDefaults()
	now := time.Unix(100, 0)
	b.queuePending(outData{seq: 1, data: []byte("pending")}, pendingModePull, now)
	b.requestFallback(now, false)
	b.processPeerAckAt(1, 0, now.Add(200*time.Millisecond))
	b.queuePending(outData{seq: 2, data: []byte("next")}, pendingModePull, now.Add(210*time.Millisecond))
	if b.requestFallback(now.Add(400*time.Millisecond), false) {
		t.Fatal("useful PULL ACK was treated as an empty probe")
	}
	b.processPeerAckAt(2, 0, now.Add(450*time.Millisecond))
	if err := b.maintainDeliveryProgress(now.Add(time.Hour)); err != nil || b.SnapshotStats().DeliveryStalled {
		t.Fatal("idle peer was declared delivery-stalled")
	}
}

func TestFieldStallControlsCannotHideDeadlineAndACKResetsIt(t *testing.T) {
	b := testBIP(t)
	b.cfg.ApplyDefaults()
	b.cfg.Transport.BIPDeadTimeoutSec = 10
	now := time.Unix(100, 0)
	b.queuePending(outData{seq: 1, data: []byte("pending")}, pendingModePull, now)
	if err := b.maintainDeliveryProgress(now); err != nil {
		t.Fatal(err)
	}
	for i := 1; i < 10; i++ {
		at := now.Add(time.Duration(i) * time.Second)
		b.observePeerActivity(at)
		if err := b.maintainDeliveryProgress(at); err != nil {
			t.Fatal("early hard recovery", err)
		}
	}
	if !b.SnapshotStats().DeliveryStalled {
		t.Fatal("nonproductive controls hid soft delivery stall")
	}
	if err := b.maintainDeliveryProgress(now.Add(10 * time.Second)); !errors.Is(err, ErrBIPDeliveryStalled) {
		t.Fatal("missing recoverable deadline", err)
	}
	b.processPeerAckAt(1, 0, now.Add(10*time.Second))
	b.queuePending(outData{seq: 2}, pendingModePull, now.Add(10*time.Second))
	if err := b.maintainDeliveryProgress(now.Add(11 * time.Second)); err != nil || b.SnapshotStats().DeliverySilenceMS != 1000 {
		t.Fatal("real delivery did not restart progress clock")
	}
	b.deliveryHealth.reset()
	if b.SnapshotStats().DeliveryStalled || b.SnapshotStats().DeliverySilenceMS != 0 {
		t.Fatal("new authenticated generation inherited stalled status")
	}
}

func TestFieldStallRetryACKBootstrapsTimerWithoutInventingRTT(t *testing.T) {
	b := testBIP(t)
	b.cfg.ApplyDefaults()
	b.cfg.Tuner.Mode = "adaptive"
	b.cfg.Tuner.Algorithm = "delivery"
	b.cfg.Transport.BIPRTOMS = 250
	b.tuner = newBIPTuner(b.cfg)
	b.tuner.cwnd, b.tuner.threshold = 1, 1
	b.tuningPath = pendingModePull
	now := time.Unix(100, 0)
	b.queuePending(outData{seq: 1, data: []byte("original")}, pendingModePull, now)
	first := b.pending[1].item
	first.retries = 1
	b.queuePending(first, pendingModePull, now.Add(250*time.Millisecond))
	b.processPeerAckAt(1, 0, now.Add(400*time.Millisecond))
	if b.tuner.window() != 2 || b.tuner.rto != 800*time.Millisecond || b.tuner.srtt != 0 || b.tuner.samples != 0 || b.tuner.delivery.baseRTT != 0 {
		t.Fatal("retry progress fabricated RTT or left one-frame initial timer trap")
	}
	// The longer initial deadline now permits an actual unambiguous sample.
	b.queuePending(outData{seq: 2, data: []byte("clean")}, pendingModePull, now.Add(500*time.Millisecond))
	b.processPeerAckAt(2, 0, now.Add(900*time.Millisecond))
	if b.tuner.srtt != 400*time.Millisecond || b.tuner.samples != 1 || b.tuner.delivery.baseRTT == 0 {
		t.Fatal("clean ACK could not establish the delivery clock")
	}
}

func TestFieldStallRetryDiscoveryBoundsAndOldPathExclusion(t *testing.T) {
	b := testBIP(t)
	b.cfg.ApplyDefaults()
	b.cfg.Tuner.Mode = "adaptive"
	b.cfg.Tuner.Algorithm = "delivery"
	b.tuner = newBIPTuner(b.cfg)
	b.tuner.cwnd = 1
	b.tuningPath = pendingModeFast
	now := time.Unix(100, 0)
	b.queuePending(outData{seq: 1, retries: 1}, pendingModePull, now)
	b.processPeerAckAt(1, 0, now.Add(time.Second))
	if b.tuner.window() != 1 || b.tuner.rto != b.tuner.initialRTO {
		t.Fatal("old path repaired ACK contaminated current bootstrap")
	}
	for i := 0; i < 200; i++ {
		b.tuner.onRetryProgress(time.Hour, now.Add(time.Duration(i)*time.Second))
	}
	if b.tuner.window() > 16 || b.tuner.rto > time.Duration(b.cfg.Tuner.MaxRTOMS)*time.Millisecond || b.tuner.samples != 0 {
		t.Fatal("repaired ACKs created unbounded discovery or false timing")
	}
}

func TestFieldStallSparsePullFeedbackAndRepeatedHoldGapsStayBounded(t *testing.T) {
	b := testBIP(t)
	b.cfg.ApplyDefaults()
	b.cfg.Tuner.Mode = "adaptive"
	b.cfg.Tuner.UnlimitedRate = true
	b.tuner = newBIPTuner(b.cfg)
	now := time.Unix(100, 0)
	for i := 0; i <= 100; i++ {
		at := now.Add(time.Duration(i) * 100 * time.Millisecond)
		b.pollingRate(at, i%2 == 0)
	}
	if rate := b.pollingRate(now.Add(10100*time.Millisecond), true); rate > 5 {
		t.Fatal("short MORE gaps replenished unanswered discovery", rate)
	}
	b.poll.requests = map[uint32]time.Time{pullTuple(1, 2): now.Add(10100 * time.Millisecond)}
	if !b.poll.reply(1, 2, now.Add(10110*time.Millisecond)) {
		t.Fatal("correlated reply rejected")
	}
	b.poll.accepted++
	if rate := b.pollingRate(now.Add(10200*time.Millisecond), true); rate < 50 || rate > 100 {
		t.Fatal("one DATA reply funded excessive polling", rate)
	}
}
