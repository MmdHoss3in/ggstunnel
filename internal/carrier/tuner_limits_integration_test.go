package carrier

import (
	"context"
	"strings"
	"testing"
	"time"

	"ggstunnel/internal/config"
)

func TestAdaptiveActorEnforcesRateAcrossPaths(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var emitted []time.Time
	l := &simLink{adaptive: true, copies: 1, requests: make(map[[3]uint16]time.Time)}
	l.configure = func(c *config.Config) { c.Tuner.MaxPPS = 50; c.Tuner.MaxBurst = 2 }
	l.filter = func(from int, p []byte) bool {
		if from == 0 && p[12] == bipKindData {
			emitted = append(emitted, time.Now())
		}
		return true
	}
	a := l.start(t, 0, ctx)
	b := l.start(t, 1, ctx)
	waitFor(t, func() bool { return a.PeerSession() == b.localID && b.PeerSession() == a.localID })
	for i := 0; i < 8; i++ {
		if err := a.Send([]byte{byte(i)}); err != nil {
			t.Fatal(err)
		}
	}
	for i := 0; i < 8; i++ {
		select {
		case <-b.Recv():
		case err := <-a.Errors():
			t.Fatal(err)
		case <-time.After(time.Second):
			t.Fatal("rate-limited delivery stalled")
		}
	}
	l.mu.Lock()
	times := append([]time.Time(nil), emitted...)
	l.mu.Unlock()
	if len(times) < 8 {
		t.Fatal("missing transmissions")
	}
	// Eight data frames with an initial burst of two need six rate credits.
	if times[7].Sub(times[0]) < 110*time.Millisecond {
		t.Fatalf("rate ceiling bypassed: %s", times[7].Sub(times[0]))
	}
}

func TestAdaptiveRetryExhaustionIsBounded(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	l := &simLink{adaptive: true, copies: 1, requests: make(map[[3]uint16]time.Time)}
	l.configure = func(c *config.Config) {
		c.Transport.BIPMaxRetries = 2
		c.Transport.BIPRTOMS = 50
		c.Tuner.MaxRTOMS = 200
	}
	l.filter = func(_ int, p []byte) bool { return p[12] != bipKindData }
	a := l.start(t, 0, ctx)
	b := l.start(t, 1, ctx)
	waitFor(t, func() bool { return a.PeerSession() == b.localID && b.PeerSession() == a.localID })
	if err := a.Send([]byte("blackhole")); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-a.Errors():
		if err == nil || !strings.Contains(err.Error(), "delivery timeout") {
			t.Fatalf("wrong error: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("blackhole did not fail within bounded retries")
	}
	s := a.SnapshotStats()
	if s.Retransmits != 2 || s.PendingExpired != 1 {
		t.Fatalf("unbounded retry %+v", s)
	}
}
