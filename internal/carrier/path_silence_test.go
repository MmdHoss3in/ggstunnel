package carrier

import (
	"testing"
	"time"
)

func TestPathSilencePreservesRetryBudgetAndRequiresFreshReturn(t *testing.T) {
	b := testBIP(t)
	b.tuner = adaptiveTuner()
	now := time.Now()
	b.lastPeerActivity = now
	b.queuePending(outData{seq: 1, retries: 3}, pendingModeRequest, now)
	if b.pathUnresponsive(now.Add(time.Millisecond)) { t.Fatal("healthy path suspended") }
	if !b.pathUnresponsive(now.Add(time.Minute)) { t.Fatal("complete outage consumed retry budget") }
	old := b.pending[1].deadline
	if b.pending[1].item.retries != 3 { t.Fatal("outage changed budget") }
	b.observePeerActivity(now.Add(time.Minute))
	if b.pathUnresponsive(now.Add(time.Minute+time.Millisecond)) { t.Fatal("fresh return did not resume scheduling") }
	if b.pending[1].item.retries != 3 { t.Fatal("return reset retry budget") }
	if old.Before(now) { t.Fatal("invalid fixture") }
	if b.pending[1].deadline.After(now.Add(time.Minute+100*time.Millisecond)) { t.Fatal("stale backoff retained") }
}
