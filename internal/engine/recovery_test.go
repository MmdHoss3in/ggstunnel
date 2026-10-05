package engine

import (
	"errors"
	"fmt"
	"testing"

	"ggstunnel/internal/carrier"
	"ggstunnel/internal/config"
	"ggstunnel/internal/frame"
	"ggstunnel/internal/session"
)

func TestRecoveryUsesFreshIdentityAndPreservesCounters(t *testing.T) {
	for _, profile := range []string{"bip", "tcp", "udp", "icmp", "gre"} {
		c := &config.Config{Role: "server", Profile: profile, PSK: "0123456789abcdef0123456789abcdef",
			Real: config.RealConfig{LocalIP: "198.51.100.10", PeerIP: "203.0.113.20", ListenAddr: "198.51.100.10:24443", PeerAddr: "203.0.113.20:24443"},
			TUN:  config.TUNConfig{LocalAddr: "10.77.1.1", RemoteAddr: "10.77.1.2"}}
		c.ApplyDefaults()
		e, err := New(c)
		if err != nil {
			t.Fatal(err)
		}
		if !e.recoverable(fmt.Errorf("wrapped: %w", frame.ErrKeyLifetime)) || e.recoverable(errors.New("kernel failure")) || e.recoverable(nil) {
			t.Fatal("incorrect recovery classification")
		}
		for _, err := range []error{carrier.ErrBIPDeliveryTimeout, carrier.ErrBIPPeerUnresponsive, carrier.ErrBIPHandshakeTimeout, session.ErrRotationLimit} {
			if e.recoverable(err) != (profile == "bip") {
				t.Fatal("BIP recovery applied to wrong transport")
			}
		}
		old := e.codec.SessionID()
		e.txPackets.Store(17)
		for i := 0; i < 3; i++ {
			e.carrier.Close()
			if err := e.refreshTransport(); err != nil {
				t.Fatal(err)
			}
			if e.codec.SessionID() == old || e.txPackets.Load() != 17 {
				t.Fatal("recovery reused key or lost counters")
			}
			old = e.codec.SessionID()
		}
		e.carrier.Close()
	}
}
