package carrier

import (
	"net"
	"testing"
)

func TestOpaqueTCPHandshakeAuthenticationAndWireMismatch(t *testing.T) {
	for _, tc := range []struct {
		serverWire, clientWire, clientKey string
		ok                                bool
	}{
		{"opaque", "opaque", "0123456789abcdef", true},
		{"opaque", "opaque", "fedcba9876543210", false},
		{"opaque", "", "0123456789abcdef", false},
		{"", "opaque", "0123456789abcdef", false},
	} {
		a, b := net.Pipe()
		sc, cc := baseCfg("server", "tcp"), baseCfg("client", "tcp")
		sc.Transport.WireMode, cc.Transport.WireMode, cc.PSK = tc.serverWire, tc.clientWire, tc.clientKey
		sv, cl := NewTCP(sc), NewTCP(cc)
		result := make(chan error, 1)
		go func() { defer a.Close(); result <- sv.serverHandshake(a) }()
		clientErr := cl.clientHandshake(b)
		b.Close()
		serverErr := <-result
		if tc.ok != (clientErr == nil && serverErr == nil) {
			t.Fatal("wrong handshake result", tc, clientErr, serverErr)
		}
	}
}
