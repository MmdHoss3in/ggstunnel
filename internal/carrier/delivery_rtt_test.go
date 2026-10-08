package carrier

import (
	"testing"
	"time"
)

func TestDeliveryBaselineRejectsReorderOutliersAndRecalibratesSparseFlight(t *testing.T) {
	d := deliveryController{}
	now := time.Unix(100, 0)
	d.observeRTT(80*time.Millisecond, now, false)
	for i := 0; i < 200; i++ {
		now = now.Add(10 * time.Millisecond)
		sample := 80 * time.Millisecond
		if i%4 == 0 {
			sample = 400 * time.Microsecond
		}
		d.observeRTT(sample, now, false)
	}
	if d.baseRTT != 80*time.Millisecond {
		t.Fatal("outlier poisoned baseline", d.baseRTT)
	}
	for i := 0; i < 60; i++ {
		now = now.Add(150 * time.Millisecond)
		d.observeRTT(150*time.Millisecond, now, true)
	}
	if d.baseRTT != 150*time.Millisecond {
		t.Fatal("sparse path did not recalibrate", d.baseRTT)
	}
}

func TestDeliveryOldFlightCannotRepeatedlyCutRepairPacing(t *testing.T) {
	c := simConfig("server")
	c.Tuner.Mode, c.Tuner.Algorithm = "adaptive", "delivery"
	x := newBIPTuner(c)
	x.cwnd, x.threshold, x.srtt = 128, 128, 150*time.Millisecond
	now := time.Unix(100, 0)
	x.delivery.baseRTT = 80 * time.Millisecond
	x.delivery.rtt.lastQueueCut = now
	x.delivery.rtt.cleanSent = now.Add(-time.Second)
	x.onSend(1200, false, now)
	x.onDelivered(1200, 1, true, now.Add(time.Second))
	x.onFastLoss(now.Add(time.Second))
	x.onTimeout(now.Add(time.Second))
	if x.window() != 128 || x.cuts != 0 {
		t.Fatal("stale RTT collapsed repair pacing", x.snapshot())
	}
	x.onAck(1, 150*time.Millisecond, now.Add(2*time.Second))
	x.onDelivered(1200, 1, true, now.Add(2*time.Second))
	if x.window() >= 128 || x.cuts != 1 {
		t.Fatal("fresh queue evidence ignored", x.snapshot())
	}
}
