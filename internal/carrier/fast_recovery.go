package carrier

import (
	"container/heap"
	"encoding/binary"
	mbits "math/bits"
	"sort"
	"time"
)

// Caller holds ackMu. Only newly acknowledged packets count as loss evidence;
// replayed SACKs and duplicate ACKs cannot repeatedly accelerate a retry.
func (b *BIP) detectSACKLoss(delivered []ackDelivery, now time.Time) {
	base := b.txAckBase
	n := 0
	for _, item := range delivered {
		if seqAfter(item.seq, base) {
			delivered[n] = item
			n++
		}
	}
	delivered = delivered[:n]
	if len(delivered) == 0 {
		return
	}
	sort.Slice(delivered, func(i, j int) bool {
		return sequenceDistance(base, delivered[i].seq) < sequenceDistance(base, delivered[j].seq)
	})
	guard := 10 * time.Millisecond
	if b.tuner != nil && b.tuner.srtt > 0 {
		guard = max(guard, b.tuner.srtt/4)
	}
	for seq, p := range b.pending {
		if p.fast || p.index < 0 {
			continue
		}
		distance := sequenceDistance(base, seq)
		i := sort.Search(len(delivered), func(i int) bool {
			return sequenceDistance(base, delivered[i].seq) > distance
		})
		if p.item.retries == 0 {
			p.sacked += len(delivered) - i
		} else {
			for _, item := range delivered[i:] {
				// A retry needs evidence from packets sent AFTER that retry. Old
				// SACK evidence cannot repeatedly retry the same transmission.
				if item.sent.After(p.sent) {
					p.sacked++
				}
			}
		}
		if p.sacked < 3 {
			continue
		}
		// Leave a short reordering allowance. The actor's normal paced retry
		// path handles the frame, congestion accounting and retry limits.
		allowance := guard
		if p.item.retries > 0 && b.tuner != nil {
			allowance = max(allowance, b.tuner.srtt*5/4)
		}
		// Reordering is observed when SACK evidence arrives, usually an RTT
		// after transmission. A send-time-only grace has already elapsed then
		// and would turn a briefly reordered original into immediate loss.
		deadline := maxTime(now.Add(guard), p.sent.Add(allowance))
		if deadline.Before(p.deadline) {
			p.deadline = deadline
			p.fast = true
			heap.Fix(&b.retryHeap, p.index)
			b.nextPullRetryCheck = time.Time{}
		}
	}
}

// A fresh verified probe after a failed path avoids waiting on stale exponential
// retry deadlines. The normal paced scheduler and retry budget remain in charge.
func (b *BIP) expeditePathRetries(now time.Time) {
	b.ackMu.Lock()
	defer b.ackMu.Unlock()
	delay := 100 * time.Millisecond
	if b.tuner != nil {
		delay = max(delay, b.tuner.srtt)
	}
	for _, p := range b.pending {
		if p.item.retries == 0 || p.index < 0 {
			continue
		}
		deadline := maxTime(now.Add(delay), p.sent.Add(delay))
		if deadline.Before(p.deadline) {
			p.deadline, p.fast = deadline, true
			heap.Fix(&b.retryHeap, p.index)
		}
	}
	b.nextPullRetryCheck = time.Time{}
}

func maxTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return b
	}
	return a
}

// Retransmissions can also be lost after every later frame was already SACKed.
// Fresh authenticated ACK snapshots may then repeat the same retained data.
// After two measured RTTs, three such snapshots can recover that persistent
// hole. Replay filtering is done by handle; initial transmissions still require
// distinct newly delivered packets. queuePending resets evidence per attempt.
func (b *BIP) recoverPersistentHole(ack uint32, bits uint64, payload []byte, wide bool, now time.Time) {
	b.ackMu.Lock()
	defer b.ackMu.Unlock()
	guard := 200 * time.Millisecond
	if b.tuner != nil && b.tuner.srtt > 0 {
		guard = max(50*time.Millisecond, 2*b.tuner.srtt)
	}
	highest := uint32(0)
	if bits != 0 {
		highest = uint32(64 - mbits.LeadingZeros64(bits))
	}
	if wide {
		for block := 0; block < len(payload)/8; block++ {
			word := binary.BigEndian.Uint64(payload[block*8:])
			if word != 0 {
				highest = uint32((block+1)*64 + 64 - mbits.LeadingZeros64(word))
			}
		}
	}
	if highest == 0 {
		return
	}
	for seq, p := range b.pending {
		if p.item.retries == 0 || p.fast || p.index < 0 || now.Sub(p.sent) < guard || !seqAfter(seq, ack) || sequenceDistance(ack, seq) >= highest {
			continue
		}
		p.sacked++
		if p.sacked >= 3 && now.Before(p.deadline) {
			p.deadline, p.fast = now, true
			heap.Fix(&b.retryHeap, p.index)
			b.nextPullRetryCheck = time.Time{}
		}
	}
}
