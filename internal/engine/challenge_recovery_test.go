package engine

import (
	"testing"
	"time"

	"ggstunnel/internal/config"
	"ggstunnel/internal/session"
)

func TestRecoveryChallengeUsesFreshBoundIdentity(t *testing.T) {
	c := &config.Config{Role: "server", Profile: "udp", PSK: "0123456789abcdef0123456789abcdef", Real: config.RealConfig{LocalIP: "198.51.100.10", PeerIP: "203.0.113.20", ListenAddr: "198.51.100.10:24443", PeerAddr: "203.0.113.20:24443"}, TUN: config.TUNConfig{LocalAddr: "10.77.1.1", RemoteAddr: "10.77.1.2"}}
	c.ApplyDefaults()
	c.Transport.WireMode = "opaque"
	c.Transport.OpaqueSession = "challenge"
	e, err := New(c)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = e.carrier.Close() }()
	if !e.recoverable(session.ErrRotationLimit) {
		t.Fatal("bounded generic retirement cannot recover")
	}
	old := e.codec.SessionID()
	e.rxPackets.Store(55)
	_ = e.carrier.Close()
	if err := e.refreshTransport(); err != nil {
		t.Fatal(err)
	}
	if e.codec.SessionID() == old || e.rxPackets.Load() != 55 {
		t.Fatal("identity/counters not preserved correctly")
	}
	s := e.SnapshotTelemetry(time.Now())
	if s.Carrier == nil || s.Carrier.SessionMode != "challenge" || s.PeerAuthenticated {
		t.Fatal("misleading initial generic stats", s)
	}
}
