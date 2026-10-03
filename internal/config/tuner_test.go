package config

import "testing"

func TestTunerDefaultsAndValidation(t *testing.T) {
	base := func() *Config {
		c := &Config{Role: "server", Profile: "bip", PSK: "0123456789abcdef", Real: RealConfig{LocalIP: "198.51.100.10", PeerIP: "203.0.113.20"}, TUN: TUNConfig{LocalAddr: "10.77.1.1", RemoteAddr: "10.77.1.2"}}
		c.ApplyDefaults()
		return c
	}
	c := base()
	if c.Tuner.Mode != "manual" || c.Telemetry.IntervalSec != 5 {
		t.Fatal("old config compatibility changed")
	}
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	cases := []func(*Config){
		func(c *Config) { c.Tuner.Mode = "unknown" },
		func(c *Config) { c.Tuner.MinRTOMS = -1 },
		func(c *Config) { c.Tuner.MaxRTOMS = 20 },
		func(c *Config) { c.Tuner.MaxPPS = 0 },
		func(c *Config) { c.Tuner.MaxBurst = 129 },
		func(c *Config) { c.Telemetry.IntervalSec = 0 },
	}
	for i, f := range cases {
		c := base()
		f(c)
		if c.Validate() == nil {
			t.Fatalf("invalid tuner case %d accepted", i)
		}
	}
	c = base()
	c.Tuner.Mode = "adaptive"
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
}
