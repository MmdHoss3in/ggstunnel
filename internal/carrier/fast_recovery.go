package carrier

import (
	"container/heap"
	"sort"
	"time"
)

// Caller holds ackMu. Only newly acknowledged packets count as loss evidence;
// replayed SACKs and duplicate ACKs cannot repeatedly accelerate a retry.
func (b *BIP) detectSACKLoss(delivered []uint32, now time.Time) {
	base := b.txAckBase
	n := 0
	for _, seq := range delivered {
		if seqAfter(seq, base) {
			delivered[n] = seq
			n++
		}
	}
	delivered = delivered[:n]
	if len(delivered) == 0 {
		return
	}
	sort.Slice(delivered, func(i, j int) bool {
		return sequenceDistance(base, delivered[i]) < sequenceDistance(base, delivered[j])
	})
	guard := 10 * time.Millisecond
	if b.tuner != nil && b.tuner.srtt > 0 {
		guard = max(guard, b.tuner.srtt/4)
	}
	for seq, p := range b.pending {
		if p.item.retries != 0 || p.fast || p.index < 0 {
			continue
		}
		distance := sequenceDistance(base, seq)
		i := sort.Search(len(delivered), func(i int) bool {
			return sequenceDistance(base, delivered[i]) > distance
		})
		p.sacked += len(delivered) - i
		if p.sacked < 3 {
			continue
		}
		// Leave a short reordering allowance. The actor's normal paced retry
		// path handles the frame, congestion accounting and retry limits.
		deadline := maxTime(now, p.sent.Add(guard))
		if deadline.Before(p.deadline) {
			p.deadline = deadline
			p.fast = true
			heap.Fix(&b.retryHeap, p.index)
			b.nextPullRetryCheck = time.Time{}
		}
	}
}

func maxTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return b
	}
	return a
}
