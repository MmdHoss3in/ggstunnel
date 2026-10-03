package carrier

import (
	"bytes"
	"context"
	"sync/atomic"
	"testing"
	"time"
)

func TestAdaptiveDelayedLinkAndPathTransition(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	l := &simLink{adaptive: true, delay: 15 * time.Millisecond, copies: 1, dropFirst: true, requests: make(map[[3]uint16]time.Time)}
	defer func() { cancel(); l.schedulerWorkers.Wait() }()
	var blocked atomic.Bool
	l.filter = func(_ int, p []byte) bool {
		if !blocked.Load() {
			return true
		}
		return p[12] != bipKindFastProbe && p[12] != bipKindFastAck && p[12] != bipKindPullProbe
	}
	a := l.start(t, 0, ctx)
	b := l.start(t, 1, ctx)
	waitFor(t, func() bool { return a.PeerSession() == b.localID && b.PeerSession() == a.localID })
	total := uint64(0)
	transfer := func(label string) {
		for i := 0; i < 60; i++ {
			p := []byte{byte(i), byte(len(label))}
			if err := a.Send(p); err != nil {
				t.Fatal(err)
			}
		}
		seen := map[byte]bool{}
		deadline := time.After(5 * time.Second)
		for len(seen) < 60 {
			select {
			case p := <-b.Recv():
				if len(p) != 2 || p[0] >= 60 || !bytes.Equal(p, []byte{p[0], byte(len(label))}) || seen[p[0]] {
					t.Fatal("corrupt/duplicate delivery")
				}
				seen[p[0]] = true
			case err := <-a.Errors():
				t.Fatal(err)
			case <-deadline:
				t.Fatal("adaptive transfer timed out")
			}
		}
		total += 60
		waitFor(t, func() bool { return a.SnapshotStats().Pending == 0 && a.SnapshotTuner().AckedFrames >= total })
	}
	waitFor(t, func() bool { return a.SnapshotStats().FastHealthy })
	transfer("fast")
	// A lost frame may be rescued by an authenticated PULL before the timeout
	// sweep cuts cwnd. Require recovery, not one particular scheduling order.
	waitFor(t, func() bool { return a.SnapshotTuner().RTTSamples > 0 && a.SnapshotStats().Retransmits > 0 })
	before := a.SnapshotTuner()
	if before.SRTTMS < 20 || before.SRTTMS > 150 || before.PacingPPS > 10000 {
		t.Fatalf("delayed path estimate %+v", before)
	}
	blocked.Store(true)
	waitFor(t, func() bool { return !a.SnapshotStats().FastHealthy })
	transfer("compat")
	waitFor(t, func() bool { return a.SnapshotStats().CompatDataTx > 0 && a.SnapshotTuner().Resets > before.Resets })
	blocked.Store(false)
	waitFor(t, func() bool { return a.SnapshotStats().FastHealthy })
	transfer("fast-return")
	t.Logf("final stats=%+v tuner=%+v", a.SnapshotStats(), a.SnapshotTuner())
}
