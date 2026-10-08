package config

import "testing"

func TestOpaqueChallengeRequiresExplicitCompatibleWire(t *testing.T) {
	c := &Config{Role: "server", Profile: "udp", PSK: "0123456789abcdef", Real: RealConfig{LocalIP: "198.51.100.1", PeerIP: "203.0.113.1", ListenAddr: "198.51.100.1:24001", PeerAddr: "203.0.113.1:24001"}, TUN: TUNConfig{LocalAddr: "10.77.1.1", RemoteAddr: "10.77.1.2"}}
	c.ApplyDefaults()
	c.Transport.WireMode = "opaque"
	c.Transport.OpaqueSession = "challenge"
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"legacy", ""} {
		c.Transport.WireMode = mode
		if err := c.Validate(); err == nil {
			t.Fatal("challenge silently downgraded", mode)
		}
	}
	c.Transport.WireMode = "opaque"
	c.Transport.OpaqueSession = "unknown"
	if err := c.Validate(); err == nil {
		t.Fatal("unknown lifecycle accepted")
	}
}
