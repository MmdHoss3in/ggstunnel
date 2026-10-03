package carrier

import (
	"bytes"
	"encoding/binary"
	"testing"

	"ggstunnel/internal/config"
)

func rawTestCfg(role, profile string) *config.Config {
	c := &config.Config{Role: role, Profile: profile, PSK: "0123456789abcdef", Real: config.RealConfig{LocalIP: "198.51.100.10", PeerIP: "203.0.113.20"}, TUN: config.TUNConfig{LocalAddr: "10.77.1.1", RemoteAddr: "10.77.1.2"}, Performance: config.PerformanceConfig{QueueSize: 64, MaxFramePayload: 1000}}
	c.ApplyDefaults()
	return c
}

func TestGREWrapUnwrap(t *testing.T) {
	ci, _ := NewRaw(rawTestCfg("server", "gre"), "gre")
	r := ci.(*rawCarrier)
	in := []byte("encrypted-frame")
	w := r.wrap(in)
	if len(w) < 28 || binary.BigEndian.Uint16(w[2:4]) != 0x0800 || w[4]>>4 != 4 {
		t.Fatal("GRE packet is not GRE + IPv4")
	}
	out, ok := r.unwrap(w)
	if !ok || !bytes.Equal(out, in) {
		t.Fatalf("bad roundtrip %q", out)
	}
}

func TestIPIPWrapUnwrap(t *testing.T) {
	ci, _ := NewRaw(rawTestCfg("server", "ipip"), "ipip")
	r := ci.(*rawCarrier)
	in := []byte("encrypted-frame")
	w := r.wrap(in)
	if len(w) < 24 || w[0]>>4 != 4 || w[9] != 253 {
		t.Fatal("IPIP payload is not an inner IPv4 packet")
	}
	out, ok := r.unwrap(w)
	if !ok || !bytes.Equal(out, in) {
		t.Fatalf("bad roundtrip %q", out)
	}
}
