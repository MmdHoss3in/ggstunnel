package carrier

import (
	"context"
	"encoding/binary"
	"errors"
	"testing"
	"time"

	"ggstunnel/internal/config"
)

func TestBIPSilentRehandshakeIsBoundedAndReflectionsDoNotConfirmPeer(t *testing.T) {
	b := testBIP(t)
	b.cfg.ApplyDefaults()
	b.active = 9
	b.peerID.Store(9)
	now := time.Now()
	b.lastPeerActivity = now
	b.lastHello = now
	b.queuePending(outData{seq: 1, data: []byte("retained"), retries: 2}, pendingModeRequest, now)
	var packets [][]byte
	b.emit = func(packet []byte) error {
		packets = append(packets, append([]byte(nil), packet[20:]...))
		return nil
	}
	for i := 4; i <= 8; i++ {
		at := now.Add(time.Duration(i) * time.Second)
		if err := b.maintainPeerLiveness(at); err != nil {
			t.Fatal(err)
		}
		if len(packets) > 0 {
			reflection := append([]byte(nil), packets[len(packets)-1]...)
			reflection[0] = 0
			binary.BigEndian.PutUint16(reflection[2:4], 0)
			binary.BigEndian.PutUint16(reflection[2:4], checksum(reflection))
			b.handle(reflection, at)
		}
	}
	stats := b.SnapshotStats()
	if len(packets) != 3 || stats.RehandshakeTries != 3 || stats.PeerSilenceMS != 8000 || stats.ReflectionsSuppressed == 0 {
		t.Fatalf("unbounded probes or reflection refreshed liveness: %+v", stats)
	}
	if b.pending[1].item.retries != 2 || b.lastPeerActivity != now {
		t.Fatal("rehandshake consumed retries or accepted own reflection")
	}
	if err := b.maintainPeerLiveness(now.Add(90 * time.Second)); !errors.Is(err, ErrBIPPeerUnresponsive) {
		t.Fatalf("silent active peer did not trigger bounded recovery: %v", err)
	}
	if len(packets) != 3 {
		t.Fatal("sent a probe after declaring the identity dead")
	}
	b.observePeerActivity(now.Add(91 * time.Second))
	if b.peerSilenceMS.Load() != 0 || b.pathUnresponsive(now.Add(91*time.Second)) {
		t.Fatal("fresh authenticated return did not clear silence")
	}
}

func TestBIPQuietBelowDeadTimeoutPreservesLiveFlight(t *testing.T) {
	b := testBIP(t)
	b.cfg.ApplyDefaults()
	b.active = 9
	now := time.Now()
	b.lastPeerActivity = now
	b.lastHello = now
	b.emit = func([]byte) error { return nil }
	b.queuePending(outData{seq: 1, retries: 1}, pendingModeRequest, now)
	if err := b.maintainPeerLiveness(now.Add(60 * time.Second)); err != nil {
		t.Fatal("a sixty-second blackout discarded the flight", err)
	}
	if b.pending[1].item.retries != 1 || b.active != 9 {
		t.Fatal("short blackout reset a live identity")
	}
	b.active = 0
	if err := b.maintainPeerLiveness(now.Add(time.Hour)); err != nil {
		t.Fatal("initial handshake caused repeated identity churn", err)
	}
}

func TestBIPSilentPeerSignalsRecoveryDespiteEchoReplies(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	l := &simLink{adaptive: true, copies: 1, requests: make(map[[3]uint16]time.Time)}
	l.configure = func(c *config.Config) {
		c.Transport.BIPDeadTimeoutSec = 1
		c.Transport.RetryIntervalSec = 1
	}
	blocked := false
	l.filter = func(from int, body []byte) bool {
		if !blocked {
			return true
		}
		if body[0] == 8 {
			reflection := append([]byte(nil), body...)
			reflection[0] = 0
			binary.BigEndian.PutUint16(reflection[2:4], 0)
			binary.BigEndian.PutUint16(reflection[2:4], checksum(reflection))
			select {
			case l.ends[from].incoming <- reflection:
			default:
			}
		}
		return false
	}
	a := l.start(t, 0, ctx)
	b := l.start(t, 1, ctx)
	waitFor(t, func() bool { return a.SnapshotStats().FastHealthy && b.SnapshotStats().FastHealthy })
	l.mu.Lock()
	blocked = true
	l.mu.Unlock()
	if err := a.SendContext(ctx, []byte("data-before-silence")); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-a.Errors():
		if !errors.Is(err, ErrBIPPeerUnresponsive) {
			t.Fatalf("wrong recovery signal: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("kernel echo replies kept a dead peer alive")
	}
	if stats := a.SnapshotStats(); stats.ReflectionsSuppressed == 0 || stats.PeerSilenceMS < 1000 {
		t.Fatalf("silence did not survive verified reflections: %+v", stats)
	}
}
