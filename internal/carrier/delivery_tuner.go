package carrier

import (
	"math"
	"time"
)

// A bounded delivery/queue controller, not an implementation of BBR. Only
// newly authenticated ACKs contribute bytes. Karn's clean samples supply RTT;
// Rate epochs span at least one measured RTT. This bounds short ACK bursts,
// but is not a full per-packet delivery-rate sampler. Peaks expire in eight epochs.
type deliveryController struct {
	rtt                                  deliveryRTT
	baseRTT                              time.Duration
	epoch, lastProgress, lastAdjust      time.Time
	bytes, packets, flightBytes, repairs uint64
	average, rate                        float64
	peaks                                [8]float64
	round                                int
}

func (d *deliveryController) queueDelay(srtt time.Duration) time.Duration {
	if d.baseRTT == 0 {
		return 0
	}
	return max(0, srtt-d.baseRTT)
}

func (d *deliveryController) resetPath() {
	flight, repairs := d.flightBytes, d.repairs
	*d = deliveryController{flightBytes: flight, repairs: repairs}
}

func (t *bipTuner) queueBudget() time.Duration {
	return time.Duration(max(1, t.cfg.QueueDelayMS)) * time.Millisecond
}

func (t *bipTuner) onSend(size int, retry bool, now time.Time) {
	if !t.adaptive() || t.cfg.Algorithm != "delivery" || retry {
		return
	}
	t.delivery.flightBytes += uint64(max(0, size))
	if t.delivery.epoch.IsZero() {
		t.delivery.epoch = now
	}
}

func (t *bipTuner) workingDeliveryClock(now time.Time) bool {
	d := &t.delivery
	return t.cfg.Algorithm == "delivery" && d.rate > 0 &&
		!d.lastProgress.IsZero() && now.Sub(d.lastProgress) <= max(t.srtt, d.baseRTT)*2
}

func (t *bipTuner) finishDeliveryStartup() {
	d := &t.delivery
	if t.threshold < float64(t.maxWindow) || d.average <= 0 || d.rate <= 0 {
		return
	}
	// A policer may drop packets without building a queue. Exit clean startup
	// on repair evidence instead of growing indefinitely against that policer.
	t.threshold = math.Min(float64(t.maxWindow), math.Max(1, 1.5*d.rate*d.baseRTT.Seconds()/d.average))
	t.cwnd = math.Min(t.cwnd, t.threshold)
	t.credit = math.Min(t.credit, float64(t.burst()))
}

func (t *bipTuner) onDelivered(bytes, packets int, backlogged bool, now time.Time) {
	if !t.adaptive() || t.cfg.Algorithm != "delivery" || packets <= 0 {
		return
	}
	d := &t.delivery
	d.lastProgress = now
	d.flightBytes -= min(d.flightBytes, uint64(max(0, bytes)))
	d.bytes += uint64(max(0, bytes))
	d.packets += uint64(packets)
	if d.epoch.IsZero() {
		d.epoch = now
		return
	}
	span := now.Sub(d.epoch)
	if d.baseRTT == 0 || span < max(t.srtt, d.baseRTT) || span <= 0 {
		return
	}
	d.peaks[d.round%len(d.peaks)] = float64(d.bytes) / span.Seconds()
	d.round = (d.round + 1) % len(d.peaks)
	d.rate = 0
	for _, sample := range d.peaks {
		d.rate = math.Max(d.rate, sample)
	}
	if d.packets > 0 {
		d.average = float64(d.bytes) / float64(d.packets)
	}
	d.bytes, d.packets, d.epoch = 0, 0, now
	if d.average <= 0 || now.Sub(d.lastAdjust) < max(t.srtt, d.baseRTT) {
		return
	}
	d.lastAdjust = now
	if now.Before(t.recoveryUntil) {
		return
	}
	bdp := d.rate * d.baseRTT.Seconds() / d.average
	if d.queueDelay(t.srtt) >= t.queueBudget() {
		// Pre-cut originals and retry-only ACKs describe the old flight.
		// Keep its bounded repair pacing until fresh clean timing is available.
		if !d.rtt.cleanSent.After(d.rtt.lastQueueCut) {
			return
		}
		// Persistent queue is capacity evidence even when every packet arrives.
		// Reduce once per measured RTT, bounded by learned delivery and flight.
		t.cwnd = math.Max(1, math.Min(t.cwnd*0.85, bdp*1.5))
		t.threshold = t.cwnd
		t.credit = math.Min(t.credit, float64(t.burst()))
		t.cuts++
		d.rtt.lastQueueCut = now
	} else if backlogged {
		if t.threshold >= float64(t.maxWindow) {
			// The first ACK epoch is not a capacity ceiling. Let clean ACKs
			// finish bounded startup until queue or repair supplies evidence.
			return
		}
		// Probe from observed delivery and current capacity, never a fixed
		// hundreds-of-packets floor. Application-limited ACKs do not probe.
		target := math.Min(math.Max(1, bdp*1.5), t.cwnd*1.25)
		t.cwnd = math.Min(float64(t.maxWindow), target)
		t.threshold = math.Min(float64(t.maxWindow), math.Max(1, bdp*1.5))
		t.credit = math.Min(t.credit, float64(t.burst()))
	}
}
