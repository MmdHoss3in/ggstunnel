//go:build audit

package config

import "testing"

func auditConfig() *Config {
	c := &Config{Role: "server", Profile: "bip", PSK: "0123456789abcdef", Real: RealConfig{LocalIP: "198.51.100.10", PeerIP: "203.0.113.20"}, TUN: TUNConfig{LocalAddr: "10.77.1.1", RemoteAddr: "10.77.1.2"}}
	c.ApplyDefaults()
	return c
}

func TestAuditRejectNegativeQueue(t *testing.T) {
	c := auditConfig()
	c.Performance.QueueSize = -1
	if err := c.Validate(); err == nil {
		t.Fatal("negative queue accepted; NewBIP would panic allocating a channel")
	}
}

func TestAuditRejectNegativeHeartbeat(t *testing.T) {
	c := auditConfig()
	c.Transport.HeartbeatSec = -1
	if err := c.Validate(); err == nil {
		t.Fatal("negative heartbeat accepted; time.NewTicker would panic")
	}
}

func TestAuditPreserveExplicitMTU(t *testing.T) {
	c := auditConfig()
	c.Performance.Profile = "speed"
	c.TUN.MTU = 1280
	c.ApplyDefaults()
	if c.TUN.MTU != 1280 {
		t.Fatalf("explicit MTU replaced with %d", c.TUN.MTU)
	}
}
