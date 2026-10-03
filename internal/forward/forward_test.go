package forward

import (
	"context"
	"io"
	"net"
	"testing"
	"time"
)

func TestTCPForwardAndShutdown(t *testing.T) {
	echo, e := net.Listen("tcp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer echo.Close()
	go func() {
		c, e := echo.Accept()
		if e == nil {
			defer c.Close()
			io.Copy(c, c)
		}
	}()
	g, e := Start(context.Background(), []Rule{{"tcp", "127.0.0.1:0", echo.Addr().String()}})
	if e != nil {
		t.Fatal(e)
	}
	addr := g.closers[0].(net.Listener).Addr().String()
	c, e := net.Dial("tcp4", addr)
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(time.Second))
	c.Write([]byte("hello"))
	b := make([]byte, 5)
	if _, e = io.ReadFull(c, b); e != nil || string(b) != "hello" {
		t.Fatal(e)
	}
	done := make(chan struct{})
	go func() { g.Close(); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("forward shutdown stuck")
	}
}
func TestUDPForwardAndShutdown(t *testing.T) {
	echo, e := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if e != nil {
		t.Fatal(e)
	}
	defer echo.Close()
	go func() {
		b := make([]byte, 100)
		n, a, e := echo.ReadFromUDP(b)
		if e == nil {
			echo.WriteToUDP(b[:n], a)
		}
	}()
	g, e := Start(context.Background(), []Rule{{"udp", "127.0.0.1:0", echo.LocalAddr().String()}})
	if e != nil {
		t.Fatal(e)
	}
	c, e := net.Dial("udp4", g.closers[0].(*net.UDPConn).LocalAddr().String())
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(time.Second))
	c.Write([]byte("hello"))
	b := make([]byte, 100)
	n, e := c.Read(b)
	if e != nil || string(b[:n]) != "hello" {
		t.Fatal(e)
	}
	g.Close()
}
