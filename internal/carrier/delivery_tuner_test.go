package carrier

import (
	"testing"
	"time"
)

func TestDeliveryControllerRepairsLossAndRespondsToQueueOrStall(t *testing.T) {
	c := simConfig("server")
	c.Tuner.Mode, c.Tuner.Algorithm = "adaptive", "delivery"
	x := newBIPTuner(c)
	now := time.Unix(100, 0)
	for round := 0; round < 8; round++ {
		for i := 0; i < x.window(); i++ {
			x.onSend(1200, false, now)
		}
		now = now.Add(100 * time.Millisecond)
		count := x.window()
		x.onAck(count, 100*time.Millisecond, now)
		x.onDelivered(count*1200, count, true, now)
		x.onFastLoss(now)
	}
	if x.window() <= 16 || x.cuts != 0 || x.delivery.repairs == 0 || x.delivery.rate <= 0 {
		t.Fatal("isolated loss collapsed a working delivery clock", x.snapshot())
	}
	before := x.window()
	for i := 0; i < 8; i++ {
		now = now.Add(150 * time.Millisecond)
		x.onAck(8, 150*time.Millisecond, now)
		x.onDelivered(9600, 8, true, now)
	}
	if x.window() >= before || x.cuts == 0 {
		t.Fatal("persistent queue ignored", x.snapshot())
	}
	before = x.window()
	x.onTimeout(now.Add(10 * time.Second))
	if x.window() > max(1, before/2) {
		t.Fatal("stalled path did not back off", x.snapshot())
	}
}

func TestDeliveryControllerIdleAndDuplicateACKCannotProbe(t *testing.T) {
	c := simConfig("server")
	c.Tuner.Mode, c.Tuner.Algorithm = "adaptive", "delivery"
	x := newBIPTuner(c)
	now := time.Unix(100, 0)
	x.onSend(100, false, now)
	x.onAck(1, 80*time.Millisecond, now.Add(80*time.Millisecond))
	before := x.window()
	x.onDelivered(100, 1, false, now.Add(80*time.Millisecond))
	x.onDelivered(1000000, 0, true, now.Add(time.Second))
	if x.window() != before || x.delivery.flightBytes != 0 {
		t.Fatal("idle/duplicate traffic grew capacity", x.snapshot())
	}
	x.pathChanged()
	if x.delivery.rate != 0 || x.delivery.baseRTT != 0 {
		t.Fatal("new path inherited stale delivery/RTT")
	}
}

func TestDeliveryBaselineDoesNotNormalizePersistentQueue(t *testing.T) {
	d := deliveryController{}
	now := time.Unix(100, 0)
	d.observeRTT(80*time.Millisecond, now, false)
	d.observeRTT(150*time.Millisecond, now.Add(time.Hour), false)
	if d.baseRTT != 80*time.Millisecond || d.queueDelay(150*time.Millisecond) != 70*time.Millisecond {
		t.Fatal("persistent queue became the base RTT")
	}
}

func TestDeliveryCleanStartupDoesNotBecomeSteadyProbeAfterFirstEpoch(t *testing.T) {
	c := simConfig("server")
	c.Tuner.Mode, c.Tuner.Algorithm = "adaptive", "delivery"
	x := newBIPTuner(c)
	now := time.Unix(100, 0)
	for round := 0; round < 5; round++ {
		count := x.window()
		x.onSend(count*1200, false, now)
		now = now.Add(80 * time.Millisecond)
		x.onAck(count, 80*time.Millisecond, now)
		x.onDelivered(count*1200, count, true, now)
	}
	if x.window() != x.maxWindow || x.cuts != 0 {
		t.Fatal("clean startup was throttled by first delivery epoch", x.snapshot())
	}
	x.onFastLoss(now)
	if x.threshold >= float64(x.maxWindow) {
		t.Fatal("repair did not exit clean startup")
	}
}
