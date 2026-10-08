package config

import "testing"

func TestSafePayloadPreservesMTUAndOpaqueOverhead(t *testing.T) {
	for _, tc := range []struct {
		profile, wire string
		mtu, want     int
	}{
		{"bip", "", 1500, 1348}, {"bip", "", 1200, 1048},
		{"udp", "opaque", 1200, 1135}, {"dcpi", "opaque", 1200, 1143},
		{"gre", "opaque", 1200, 1119}, {"ipip", "opaque", 1200, 1123},
		{"icmp", "opaque", 1200, 1135}, {"tcp", "opaque", 1200, 1348},
	} {
		if got := SafePayload(tc.profile, tc.wire, tc.mtu, 1348); got != tc.want {
			t.Fatalf("%s %s: got %d want %d", tc.profile, tc.wire, got, tc.want)
		}
	}
}

func TestLocalPayloadClampDoesNotShrinkReceiveContract(t *testing.T) {
	c := Config{Performance: PerformanceConfig{MaxFramePayload: 1280}}
	c.PreserveReceiveFrameLimit()
	c.Performance.MaxFramePayload = 1048
	c.PreserveReceiveFrameLimit()
	if c.ReceiveFrameLimit() != 1340 {
		t.Fatal("peer receive contract shrank with local TX MTU")
	}
	copy := c
	if copy.ReceiveFrameLimit() != 1340 {
		t.Fatal("recovery lost receive contract")
	}
}
