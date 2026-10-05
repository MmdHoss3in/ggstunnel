//go:build linux

package carrier

import (
	"context"
	"errors"
	"syscall"
	"testing"
	"time"
)

func TestBIPRawLoopback(t *testing.T) {
	testBIPRawLoopback(t, "")
}

func TestBIPCompactRawLoopback(t *testing.T) {
	testBIPRawLoopback(t, "compact")
}

func testBIPRawLoopback(t *testing.T, mode string) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ca := simConfig("server")
	ca.Transport.BIPWireMode = mode
	ca.Real.LocalIP = "127.0.0.1"
	ca.Real.PeerIP = "127.0.0.2"
	cb := simConfig("client")
	cb.Transport.BIPWireMode = mode
	cb.Real.LocalIP = "127.0.0.2"
	cb.Real.PeerIP = "127.0.0.1"
	ai, err := NewBIP(ca)
	if err != nil {
		t.Fatal(err)
	}
	a := ai.(*BIP)
	bi, err := NewBIP(cb)
	if err != nil {
		t.Fatal(err)
	}
	b := bi.(*BIP)
	if err = a.Start(ctx); err != nil {
		if errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EACCES) {
			t.Skipf("raw socket unavailable: %v", err)
		}
		t.Fatal(err)
	}
	defer a.Close()
	if err = b.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	waitFor(t, func() bool { return a.PeerSession() == b.localID && b.PeerSession() == a.localID })
	for _, pair := range [][2]*BIP{{a, b}, {b, a}} {
		if err = pair[0].Send([]byte("kernel raw ICMP")); err != nil {
			t.Fatal(err)
		}
		select {
		case p := <-pair[1].rx:
			if string(p) != "kernel raw ICMP" {
				t.Fatal("bad raw payload")
			}
		case err := <-pair[0].errors:
			t.Fatal(err)
		case <-time.After(2 * time.Second):
			t.Fatal("raw transfer timed out")
		}
	}
}
