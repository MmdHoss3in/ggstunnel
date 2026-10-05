package carrier

import (
	"testing"
	"time"
)

func timedSACKSender(t *testing.T, retry int) (*BIP, time.Time) {
	b := testBIP(t)
	b.tuner = adaptiveTuner()
	b.tuner.srtt = 80 * time.Millisecond
	b.tuner.rto = 250 * time.Millisecond
	now := time.Unix(100, 0)
	b.queuePending(outData{seq: 1}, pendingModeFast, now)
	b.queuePending(outData{seq: 2, retries: retry}, pendingModeFast, now.Add(time.Millisecond))
	return b, now
}

func TestTimedSACKSmallFlightSettlesReorderBeforeRecovery(t *testing.T) {
	for _, reordered := range []bool{false, true} {
		b, now := timedSACKSender(t, 0)
		b.processPeerAckAt(0, 1<<1, now.Add(81*time.Millisecond))
		p := b.pending[1]
		if !p.fast || p.deadline != now.Add(121*time.Millisecond) || p.item.retries != 0 {
			t.Fatal("small flight lost its longer time-based reorder allowance")
		}
		if _, ok := b.takeTimedOut(now.Add(110*time.Millisecond), time.Second); ok {
			t.Fatal("timed recovery fired inside reordering allowance")
		}
		if reordered {
			b.processPeerAckAt(2, 0, now.Add(110*time.Millisecond))
			if len(b.pending) != 0 || len(b.retryHeap) != 0 || b.tuner.cuts != 0 {
				t.Fatal("reordered original was retried or penalized")
			}
		} else {
			p, ok := b.takeTimedOut(now.Add(121*time.Millisecond), time.Second)
			if !ok || !p.fast || p.item.seq != 1 {
				t.Fatal("thin flight waited for ordinary RTO despite guarded delivery evidence")
			}
		}
	}
}

func TestTimedSACKIgnoresAmbiguousRetriesAndDuplicateEvidence(t *testing.T) {
	b, now := timedSACKSender(t, 1)
	deadline := b.pending[1].deadline
	b.processPeerAckAt(0, 1<<1, now.Add(81*time.Millisecond))
	if b.pending[1].deadline != deadline || b.pending[1].fast {
		t.Fatal("ambiguous retransmission ACK supplied timed loss evidence")
	}
	b, now = timedSACKSender(t, 0)
	deadline = b.pending[1].deadline
	// Feedback far earlier than a credible RTT cannot schedule time-based loss.
	b.processPeerAckAt(0, 1<<1, now.Add(2*time.Millisecond))
	for i := 0; i < 50; i++ {
		b.processPeerAckAt(0, 1<<1, now.Add(100*time.Millisecond))
	}
	if b.pending[1].deadline != deadline || b.pending[1].fast {
		t.Fatal("repeated old SACKs manufactured new timed delivery evidence")
	}
}

func TestTimedSACKRetainsRequestCarrierAndJitterGuards(t *testing.T) {
	b, now := timedSACKSender(t, 0)
	b.pending[1].mode = pendingModeRequest
	deadline := b.pending[1].deadline
	b.processPeerAckAt(0, 1<<1, now.Add(81*time.Millisecond))
	if b.pending[1].deadline != deadline {
		t.Fatal("timed SACK bypassed the unproven request guard")
	}
	b, now = timedSACKSender(t, 0)
	b.tuner.variance = 35 * time.Millisecond
	b.processPeerAckAt(0, 1<<1, now.Add(81*time.Millisecond))
	if b.pending[1].deadline != now.Add(151*time.Millisecond) {
		t.Fatal("timed SACK ignored measured jitter")
	}
}

func TestTimedSACKSmallFlightAcrossSequenceWrap(t *testing.T) {
	b := testBIP(t)
	b.tuner = adaptiveTuner()
	b.tuner.srtt = 80 * time.Millisecond
	b.tuner.rto = 250 * time.Millisecond
	b.txAckBase = 0xfffffffe
	now := time.Unix(100, 0)
	b.queuePending(outData{seq: 0xffffffff}, pendingModeFast, now)
	b.queuePending(outData{seq: 1}, pendingModeFast, now.Add(time.Millisecond))
	b.processPeerAckAt(0xfffffffe, 1<<1, now.Add(81*time.Millisecond))
	if p := b.pending[0xffffffff]; p == nil || !p.fast || p.deadline != now.Add(121*time.Millisecond) || len(b.pending) != 1 {
		t.Fatal("time-based loss evidence crossed the reserved-zero wrap incorrectly")
	}
}
