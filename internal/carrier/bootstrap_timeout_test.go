package carrier

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestBIPHandshakeDeadlineAndTelemetry(t *testing.T) {
	b := testBIP(t)
	b.cfg.ApplyDefaults()
	now := time.Now()
	b.startedAt = now
	if err := b.maintainPeerLiveness(now.Add(89 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if b.SnapshotStats().HandshakeWaitMS != 89000 {
		t.Fatal("initial wait is invisible")
	}
	if err := b.maintainPeerLiveness(now.Add(90 * time.Second)); !errors.Is(err, ErrBIPHandshakeTimeout) {
		t.Fatalf("no bounded recovery: %v", err)
	}
	b.active = 9
	b.observePeerActivity(now.Add(91 * time.Second))
	if err := b.maintainPeerLiveness(now.Add(91 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if b.SnapshotStats().HandshakeWaitMS != 0 {
		t.Fatal("authenticated peer retains initial wait")
	}
}

func TestBIPActorSignalsInitialHandshakeTimeout(t *testing.T) {
	b := testBIP(t)
	b.cfg.ApplyDefaults()
	b.cfg.Transport.BIPHandshakeTimeoutSec = 1
	b.startedAt = time.Now()
	b.emit = func([]byte) error { return nil }
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() { defer close(done); b.run(ctx) }()
	select {
	case err := <-b.Errors():
		if !errors.Is(err, ErrBIPHandshakeTimeout) {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("bootstrap actor stuck indefinitely")
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("actor leaked")
	}
}
