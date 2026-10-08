package carrier

import (
	"bytes"
	"testing"
)

func TestDCPIUsesDedicatedProtocolAndPreservesOpaquePacket(t *testing.T) {
	c := simConfig("server")
	c.Profile, c.Transport.WireMode = "dcpi", "opaque"
	carrier, err := NewRaw(c, "dcpi")
	if err != nil {
		t.Fatal(err)
	}
	r := carrier.(*rawCarrier)
	payload := bytes.Repeat([]byte{77}, 150)
	if r.network != "ip4:58" || !bytes.Equal(r.wrap(payload), payload) {
		t.Fatal("wrong DCPI carrier or added public marker")
	}
	got, ok := r.unwrap(payload)
	if !ok || !bytes.Equal(got, payload) {
		t.Fatal("DCPI changed authenticated bytes")
	}
}

func TestOpaqueRawLayoutsRemoveMarkersAndRetainValidHeaders(t *testing.T) {
	for _, kind := range []string{"icmp", "gre", "ipip"} {
		c := simConfig("server")
		c.Profile, c.Transport.WireMode = kind, "opaque"
		carrier, err := NewRaw(c, kind)
		if err != nil {
			t.Fatal(err)
		}
		r := carrier.(*rawCarrier)
		payload := bytes.Repeat([]byte{71}, 80)
		wire := r.wrap(payload)
		for _, marker := range []string{"IPXI", "IPXG", "IPX4"} {
			if bytes.Contains(wire, []byte(marker)) {
				t.Fatal("public marker survived", kind)
			}
		}
		got, ok := r.unwrap(wire)
		if !ok || !bytes.Equal(payload, got) {
			t.Fatal("valid raw header rejected", kind)
		}
	}
}
