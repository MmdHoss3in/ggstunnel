package carrier

import (
	"bytes"
	"context"
	"testing"
	"time"

	"ggstunnel/internal/config"
)

// Keep this regression compatible with the released source so cloud CI can
// demonstrate the failure before applying the recovery change.
func TestBIPAuthenticatedRehandshakeRestoresQueuedData(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	l := &simLink{adaptive: true, copies: 1, requests: make(map[[3]uint16]time.Time)}
	l.configure = func(c *config.Config) { c.Transport.RetryIntervalSec = 1 }
	blocked := false
	helloOpened := false
	l.filter = func(from int, body []byte) bool {
		if blocked && from == 0 && body[12] == bipKindHello {
			blocked = false
			helloOpened = true
		}
		return !blocked
	}
	a := l.start(t, 0, ctx)
	b := l.start(t, 1, ctx)
	waitFor(t, func() bool {
		return a.PeerSession() == b.localID && b.PeerSession() == a.localID &&
			a.SnapshotStats().FastHealthy && b.SnapshotStats().FastHealthy
	})
	l.mu.Lock()
	blocked = true
	l.mu.Unlock()
	const count = 32
	for i := 0; i < count; i++ {
		if err := a.SendContext(ctx, []byte{byte(i), 9, 7}); err != nil {
			t.Fatal(err)
		}
	}
	deadline := time.After(4 * time.Second)
	for i := 0; i < count; i++ {
		select {
		case packet := <-b.Recv():
			if !bytes.Equal(packet, []byte{byte(i), 9, 7}) {
				t.Fatalf("queued data lost order or integrity at %d: %x", i, packet)
			}
		case <-deadline:
			t.Fatal("authenticated rehandshake did not restore queued data")
		}
	}
	l.mu.Lock()
	opened := helloOpened
	l.mu.Unlock()
	if !opened || a.PeerSession() != b.localID || b.PeerSession() != a.localID {
		t.Fatal("recovery skipped rehandshake or changed the live identity")
	}
	waitFor(t, func() bool { return a.SnapshotStats().Pending == 0 })
}
