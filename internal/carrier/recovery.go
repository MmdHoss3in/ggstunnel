package carrier

import "time"

// Frozen deadlines may expire more than one RTO apart for packets in the
// same flight. A time-only guard would halve cwnd again for the same loss
// episode. Mark the transmitted flight when a cut actually takes place.
func (b *BIP) noteDeliveryLoss(p *pendingData, now time.Time) {
	if b.tuner == nil || (b.lossFlightSet && !seqAfter(p.item.seq, b.lossFlightEnd)) {
		return
	}
	// A retry from the old carrier is not congestion evidence for a newly
	// authenticated path. It still consumes the ordinary retry/flight budgets.
	if b.tuningPath != 0 && p.mode != b.tuningPath {
		return
	}
	before := b.tuner.cuts
	if p.fast {
		b.tuner.onFastLoss(now)
	} else {
		b.tuner.onTimeout(now)
	}
	if b.tuner.cuts != before {
		b.lossFlightEnd = b.dataSeq
		b.lossFlightSet = true
	}
}
