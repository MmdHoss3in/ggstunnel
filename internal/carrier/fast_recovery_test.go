package carrier

import (
	"testing"
	"time"
)

func TestSACKFastRecoveryNeedsDistinctEvidence(t *testing.T) {
	b := testBIP(t)
	b.tuner = adaptiveTuner()
	b.tuner.srtt = 80 * time.Millisecond
	now := time.Now()
	for seq := uint32(1); seq <= 5; seq++ {
		b.queuePending(outData{seq: seq}, pendingModeFast, now)
	}
	original := b.pending[1].deadline
	for i := 0; i < 10; i++ {
		b.processPeerAckAt(0, 1<<1, now.Add(time.Millisecond))
	}
	if b.pending[1].deadline != original || b.pending[1].sacked != 1 {
		t.Fatal("duplicate SACK accelerated recovery")
	}
	b.processPeerAckAt(0, 0b11110, now.Add(2*time.Millisecond))
	if _, ok := b.takeTimedOut(now.Add(19*time.Millisecond), time.Second); ok {
		t.Fatal("reordering allowance was ignored")
	}
	p, ok := b.takeTimedOut(now.Add(21*time.Millisecond), time.Second)
	if !ok || p.item.seq != 1 || !p.fast {
		t.Fatal("SACK hole did not enter fast recovery")
	}
	// A reordered original arrives before the scheduled retry: remove the
	// accelerated heap entry, without an unnecessary retransmission.
	b.processPeerAckAt(1, 0, now.Add(22*time.Millisecond))
	if len(b.pending) != 0 || len(b.retryHeap) != 0 {
		t.Fatal("ACK left recovery work behind")
	}
}

func TestSACKFastRecoveryAcrossSequenceWrap(t *testing.T) {
	b := testBIP(t)
	b.tuner = adaptiveTuner()
	b.txAckBase = 0xfffffffd
	now := time.Now()
	for _, seq := range []uint32{0xfffffffe, 0xffffffff, 1, 2} {
		b.queuePending(outData{seq: seq}, pendingModeFast, now)
	}
	b.processPeerAckAt(0xfffffffd, 0b1110, now.Add(20*time.Millisecond))
	p, ok := b.takeTimedOut(now.Add(21*time.Millisecond), time.Second)
	if !ok || p.item.seq != 0xfffffffe || !p.fast {
		t.Fatal("wrapped SACK hole did not recover")
	}
}
