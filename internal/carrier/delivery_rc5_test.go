package carrier

import (
	"testing"
	"time"
)

func TestDeliveryLowQueueProbeEscapesSelfLimitedRate(t *testing.T) {
	c := simConfig("server")
	c.Tuner.Mode, c.Tuner.Algorithm = "adaptive", "delivery"
	x := newBIPTuner(c)
	now := time.Unix(100, 0)
	x.cwnd, x.threshold = 128, 64
	x.srtt = 80 * time.Millisecond
	x.delivery.baseRTT = x.srtt
	x.delivery.rate = 128 * 1200 / x.srtt.Seconds()
	x.delivery.average = 1200
	before := x.window()
	for i := 0; i < 20; i++ {
		n := x.window()
		x.onSend(n*1200, false, now)
		now = now.Add(80 * time.Millisecond)
		x.onDelivered(n*1200, n, true, now)
	}
	if x.window() <= before || x.window() > x.maxWindow || x.cuts != 0 {
		t.Fatal("low-queue probe collapsed/escaped bounds", x.snapshot())
	}
}
func TestDeliveryAppLimitedEpochsDoNotEraseBusyPeak(t *testing.T) {
	c := simConfig("server")
	c.Tuner.Mode, c.Tuner.Algorithm = "adaptive", "delivery"
	x := newBIPTuner(c)
	now := time.Unix(100, 0)
	x.srtt = 80 * time.Millisecond
	x.delivery.baseRTT = x.srtt
	x.delivery.epoch = now
	x.onDelivered(120000, 100, true, now.Add(x.srtt))
	peak := x.delivery.rate
	for i := 0; i < 12; i++ {
		now = now.Add(x.srtt)
		x.onDelivered(100, 1, false, now.Add(x.srtt))
	}
	if x.delivery.rate < peak || x.delivery.appLimitedEpochs == 0 {
		t.Fatal("application idle poisoned rate", x.delivery.rate, peak)
	}
}
func TestDeliveryWorkingClockBoundsRepairDelayButStallBacksOff(t *testing.T) {
	c := simConfig("server")
	c.Tuner.Mode, c.Tuner.Algorithm = "adaptive", "delivery"
	x := newBIPTuner(c)
	now := time.Unix(100, 0)
	x.srtt = 80 * time.Millisecond
	x.delivery.baseRTT = x.srtt
	x.rto = 160 * time.Millisecond
	x.delivery.rate = 1000000
	x.delivery.lastProgress = now
	if x.timeoutAt(6, now) > 4*x.rto {
		t.Fatal("working clock repairs waited exponential seconds")
	}
	if x.timeoutAt(6, now.Add(time.Second)) <= 4*x.rto {
		t.Fatal("genuine stall lost exponential backoff")
	}
}
