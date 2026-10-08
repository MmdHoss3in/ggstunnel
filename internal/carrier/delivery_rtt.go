package carrier

import (
	"slices"
	"time"
)

type deliveryRTT struct {
	samples                               [31]time.Duration
	count, index                          int
	lastEstimate, lowerSince, sparseSince time.Time
	lowerCandidate                        time.Duration
	cleanSent, lastQueueCut               time.Time
}

func (d *deliveryController) observeRTT(sample time.Duration, now time.Time, sparse bool) {
	if sample <= 0 {
		return
	}
	r := &d.rtt
	r.cleanSent = now.Add(-sample)
	r.samples[r.index] = sample
	r.index = (r.index + 1) % len(r.samples)
	r.count = min(r.count+1, len(r.samples))
	if sparse {
		if r.sparseSince.IsZero() {
			r.sparseSince = now
		}
	} else {
		r.sparseSince = time.Time{}
	}
	if d.baseRTT == 0 {
		d.baseRTT = sample
		return
	}
	if r.count < len(r.samples) || now.Sub(r.lastEstimate) < max(d.baseRTT, time.Millisecond) {
		return
	}
	r.lastEstimate = now
	ordered := r.samples
	slices.Sort(ordered[:])
	median := ordered[len(ordered)/2]
	// Accelerated/reordered ACK outliers must not establish a permanent
	// sub-ms baseline on an 80ms path. Confirm a robust lower estimate.
	if median < d.baseRTT {
		if r.lowerSince.IsZero() || median > r.lowerCandidate*5/4 || median < r.lowerCandidate*3/4 {
			r.lowerCandidate, r.lowerSince = median, now
		} else if now.Sub(r.lowerSince) >= 2*d.baseRTT {
			d.baseRTT = median
			r.lowerSince = time.Time{}
		}
	} else {
		r.lowerSince = time.Time{}
		// Aging alone cannot normalize a full self-induced queue. Upward
		// recalibration requires fresh clean samples of a verified sparse flight.
		if median > d.baseRTT && !r.sparseSince.IsZero() && now.Sub(r.sparseSince) >= max(500*time.Millisecond, 3*d.baseRTT) {
			d.baseRTT = median
		}
	}
}
