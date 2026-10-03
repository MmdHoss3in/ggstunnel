package carrier

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	"ggstunnel/internal/config"
)

func freeTCP(t *testing.T) string {
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	a := l.Addr().String()
	l.Close()
	return a
}
func baseCfg(role, profile string) *config.Config {
	return &config.Config{Role: role, Profile: profile, PSK: "0123456789abcdef", Real: config.RealConfig{LocalIP: "127.0.0.1", PeerIP: "127.0.0.1"}, TUN: config.TUNConfig{LocalAddr: "10.0.0.1", RemoteAddr: "10.0.0.2"}, Transport: config.TransportConfig{RetryIntervalSec: 1, DialTimeoutSec: 1, SockBuf: 1 << 20}, Performance: config.PerformanceConfig{QueueSize: 64, MaxFramePayload: 1000}}
}
func TestTCPCarrierLoopback(t *testing.T) {
	addr := freeTCP(t)
	s := baseCfg("server", "tcp")
	s.Real.ListenAddr = addr
	s.ApplyDefaults()
	c := baseCfg("client", "tcp")
	c.Real.PeerAddr = addr
	c.ApplyDefaults()
	sv := NewTCP(s)
	cl := NewTCP(c)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := sv.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer sv.Close()
	if err := cl.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer cl.Close()
	time.Sleep(100 * time.Millisecond)
	if err := cl.Send([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	select {
	case x := <-sv.Recv():
		if string(x) != "hello" {
			t.Fatal(string(x))
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout")
	}
	if err := sv.Send([]byte("world")); err != nil {
		t.Fatal(err)
	}
	select {
	case x := <-cl.Recv():
		if string(x) != "world" {
			t.Fatal(string(x))
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout")
	}
}
func TestUDPCarrierLoopback(t *testing.T) {
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := pc.LocalAddr().(*net.UDPAddr).Port
	pc.Close()
	addr := fmt.Sprintf("127.0.0.1:%d", port)
	s := baseCfg("server", "udp")
	s.Real.ListenAddr = addr
	clientAddr := freeTCP(t)
	s.Real.PeerAddr = clientAddr
	s.ApplyDefaults()
	c := baseCfg("client", "udp")
	c.Real.ListenAddr = clientAddr
	c.Real.PeerAddr = addr
	c.ApplyDefaults()
	sv := NewUDP(s)
	cl := NewUDP(c)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := sv.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer sv.Close()
	if err := cl.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer cl.Close()
	if err := cl.Send([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	select {
	case x := <-sv.Recv():
		if string(x) != "hello" {
			t.Fatal(string(x))
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout")
	}
	time.Sleep(50 * time.Millisecond)
	if err := sv.Send([]byte("world")); err != nil {
		t.Fatal(err)
	}
	select {
	case x := <-cl.Recv():
		if string(x) != "world" {
			t.Fatal(string(x))
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout")
	}
}
