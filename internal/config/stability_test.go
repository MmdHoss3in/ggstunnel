package config

import "testing"

func stabilityConfig(profile string) *Config {
	c := &Config{Role: "server", Profile: profile, PSK: "0123456789abcdef0123456789abcdef", Real: RealConfig{LocalIP: "198.51.100.10", PeerIP: "203.0.113.20", ListenAddr: "198.51.100.10:24443", PeerAddr: "203.0.113.20:24443"}, TUN: TUNConfig{LocalAddr: "10.77.1.1", RemoteAddr: "10.77.1.2"}}
	c.ApplyDefaults()
	return c
}

func TestStabilityBoundsAndLegacyDefaults(t *testing.T) {
	for _, profile := range []string{"bip", "tcp", "udp"} {
		c := stabilityConfig(profile)
		if err := c.Validate(); err != nil {
			t.Fatal(err)
		}
		if c.Performance.QueueMaxAgeMS != 5000 || c.Transport.PathMTU {
			t.Fatal("unexpected queue/discovery default")
		}
		if (c.Transport.SessionMaxAgeSec == 21600) != (profile == "bip") {
			t.Fatal("legacy generic lifecycle changed")
		}
		c.Transport.PathMTU = true
		if (c.Validate() == nil) != (profile == "bip") {
			t.Fatal("unsupported discovery enabled", profile)
		}
	}
	c := stabilityConfig("udp")
	c.Transport.WireMode = "opaque"
	c.Transport.OpaqueSession = "challenge"
	c.Transport.PathMTU = true
	c.Transport.SessionMaxAgeSec = 30
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, age := range []int{-1, 1, 29, 86401} {
		c.Transport.SessionMaxAgeSec = age
		if c.Validate() == nil {
			t.Fatal("invalid age", age)
		}
	}
	c.Transport.SessionMaxAgeSec = 30
	for _, age := range []int{-1, 99, 30001} {
		c.Performance.QueueMaxAgeMS = age
		if c.Validate() == nil {
			t.Fatal("invalid queue age", age)
		}
	}
}
