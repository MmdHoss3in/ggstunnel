package carrier

import (
	"testing"
	"time"
)

// A cumulative ACK acknowledges the oldest packet after receiver batching.
// Sampling only its newest packet hides the delay experienced by older data.
func TestTunerCumulativeACKIncludesOldestCleanDelay(t *testing.T) {
	b := testBIP(t)
	b.tuner = adaptiveTuner()
	now := time.Unix(100, 0)
	b.queuePending(outData{seq: 1}, pendingModeRequest, now.Add(-240*time.Millisecond))
	b.queuePending(outData{seq: 2}, pendingModeRequest, now.Add(-80*time.Millisecond))
	b.processPeerAckAt(2, 0, now)
	if b.tuner.srtt != 240*time.Millisecond {
		t.Fatalf("batched ACK hides oldest delay: got %v, want 240ms", b.tuner.srtt)
	}
	if b.tuner.rto < 480*time.Millisecond || len(b.pending) != 0 {
		t.Fatal("unsafe timeout or ACK cleanup")
	}
}

func TestTunerBatchExcludesRetransmittedOldest(t *testing.T) {
	b := testBIP(t)
	b.tuner = adaptiveTuner()
	now := time.Unix(100, 0)
	b.queuePending(outData{seq: 1, retries: 1}, pendingModeRequest, now.Add(-time.Second))
	b.queuePending(outData{seq: 2}, pendingModeRequest, now.Add(-80*time.Millisecond))
	b.processPeerAckAt(2, 0, now)
	if b.tuner.srtt != 80*time.Millisecond || b.tuner.acked != 2 {
		t.Fatal("Karn exclusion or ACK accounting changed")
	}
}
