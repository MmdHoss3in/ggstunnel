package carrier

import (
	"context"
	"errors"
	"net"
	"os"
	"sync"
	"testing"
	"time"
)

func TestUDPConcurrentStartCloseAndClosedSend(t *testing.T) {
	for i := 0; i < 50; i++ {
		cfg := baseCfg("server", "udp")
		cfg.Real.ListenAddr, cfg.Real.PeerAddr = "127.0.0.1:0", "127.0.0.1:24443"
		cfg.ApplyDefaults()
		u := NewUDP(cfg)
		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			if err := u.Start(context.Background()); err != nil && !errors.Is(err, ErrClosed) {
				t.Error(err)
			}
		}()
		go func() { defer wg.Done(); u.Close() }()
		wg.Wait()
		u.Close()
		if err := u.Send([]byte("closed")); !errors.Is(err, ErrClosed) {
			t.Fatalf("closed UDP accepted traffic: %v", err)
		}
		if err := u.Start(context.Background()); err == nil {
			t.Fatal("closed UDP restarted")
		}
	}
}
func TestTCPShutdownClosesUnauthenticatedHandshake(t *testing.T) {
	cfg := baseCfg("server", "tcp")
	cfg.Real.ListenAddr = "127.0.0.1:0"
	cfg.ApplyDefaults()
	s := NewTCP(cfg)
	if err := s.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	c, err := net.Dial("tcp4", s.ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	limit := time.Now().Add(time.Second)
	for {
		s.mu.Lock()
		count := len(s.connections)
		s.mu.Unlock()
		if count != 0 {
			break
		}
		if time.Now().After(limit) {
			t.Fatal("handshake connection not tracked")
		}
		time.Sleep(time.Millisecond)
	}
	done := make(chan struct{})
	go func() { s.Close(); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Close waited for handshake timeout")
	}
	if err := s.Send([]byte("closed")); !errors.Is(err, ErrClosed) {
		t.Fatal("closed TCP accepted traffic")
	}
	if err := s.Start(context.Background()); err == nil {
		t.Fatal("closed TCP restarted")
	}
}
func TestRawCarrierConcurrentStartClose(t *testing.T) {
	if os.Getenv("GGS_KERNEL_TEST") != "1" {
		t.Skip("requires disposable privileged runner")
	}
	for _, kind := range []string{"icmp", "gre", "ipip"} {
		for i := 0; i < 10; i++ {
			cfg := baseCfg("server", kind)
			cfg.ApplyDefaults()
			iface, err := NewRaw(cfg, kind)
			if err != nil {
				t.Fatal(err)
			}
			r := iface.(*rawCarrier)
			var wg sync.WaitGroup
			wg.Add(2)
			go func() {
				defer wg.Done()
				if err := r.Start(context.Background()); err != nil && !errors.Is(err, ErrClosed) {
					t.Error(err)
				}
			}()
			go func() { defer wg.Done(); r.Close() }()
			wg.Wait()
			r.Close()
			if !errors.Is(r.Send([]byte("closed")), ErrClosed) {
				t.Fatal("closed raw socket accepted traffic")
			}
		}
	}
}
