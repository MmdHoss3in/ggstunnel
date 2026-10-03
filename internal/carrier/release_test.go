package carrier

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"testing"
	"time"
)

func receiveEqual(t *testing.T, c Carrier, want []byte) {
	t.Helper()
	select {
	case got := <-c.Recv():
		if !bytes.Equal(got, want) {
			t.Fatal("wrong peer/payload")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("delivery timeout")
	}
}
func TestNineTCPPeersAndReconnect(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	for i := 0; i < 9; i++ {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			t.Parallel()
			s := baseCfg("server", "tcp")
			s.Real.ListenAddr = freeTCP(t)
			s.PSK = fmt.Sprintf("unique-strong-psk-%03d", i)
			s.ApplyDefaults()
			c := baseCfg("client", "tcp")
			c.Real.PeerAddr = s.Real.ListenAddr
			c.PSK = s.PSK
			c.ApplyDefaults()
			sv := NewTCP(s)
			cl := NewTCP(c)
			// Parent test context remains live until all parallel subtests finish.
			local, cancel := context.WithCancel(context.WithoutCancel(ctx))
			defer cancel()
			if err := sv.Start(local); err != nil {
				t.Fatal(err)
			}
			defer sv.Close()
			if err := cl.Start(local); err != nil {
				t.Fatal(err)
			}
			for j := 0; j < 64; j++ {
				payload := []byte(fmt.Sprintf("peer-%d-packet-%d", i, j))
				cl.Send(payload)
				receiveEqual(t, sv, payload)
				sv.Send(payload)
				receiveEqual(t, cl, payload)
			}
			cl.Close()
			cl2 := NewTCP(c)
			if err := cl2.Start(local); err != nil {
				t.Fatal(err)
			}
			defer cl2.Close()
			cl2.Send([]byte("reconnected"))
			receiveEqual(t, sv, []byte("reconnected"))
		})
	}
}

type shortWriter struct{ bytes.Buffer }

func (w *shortWriter) Write(p []byte) (int, error) {
	if len(p) > 3 {
		p = p[:3]
	}
	return w.Buffer.Write(p)
}
func TestTCPShortWrites(t *testing.T) {
	w := &shortWriter{}
	if err := writeFull(w, []byte("complete frame")); err != nil || w.String() != "complete frame" {
		t.Fatal(err, w.String())
	}
}
func TestTCPHandshakeRejectsWrongKey(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	s := NewTCP(baseCfg("server", "tcp"))
	c := NewTCP(baseCfg("client", "tcp"))
	c.cfg.PSK = "wrong-but-long-key"
	done := make(chan error, 1)
	go func() { done <- s.serverHandshake(a) }()
	if err := c.clientHandshake(b); err == nil {
		t.Fatal("accepted wrong server")
	}
	b.Close()
	if err := <-done; err == nil {
		t.Fatal("accepted wrong client")
	}
}
func TestUDPSpoofDoesNotRedirect(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	peer, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	s := baseCfg("server", "udp")
	s.Real.ListenAddr = "127.0.0.1:0"
	s.Real.PeerAddr = peer.LocalAddr().String()
	s.ApplyDefaults()
	sv := NewUDP(s)
	if err := sv.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer sv.Close()
	attacker, err := net.Dial("udp4", sv.conn.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer attacker.Close()
	attacker.Write([]byte("redirect"))
	select {
	case <-sv.Recv():
		t.Fatal("accepted foreign endpoint")
	case <-time.After(30 * time.Millisecond):
	}
	sv.Send([]byte("legitimate"))
	peer.SetReadDeadline(time.Now().Add(time.Second))
	buf := make([]byte, 50)
	n, _, err := peer.ReadFromUDP(buf)
	if err != nil || string(buf[:n]) != "legitimate" {
		t.Fatal("redirected reply", err)
	}
}
func TestTCPChallengeNotReplayable(t *testing.T) {
	s := NewTCP(baseCfg("server", "tcp"))
	var oldProof []byte
	for round := 0; round < 2; round++ {
		a, b := net.Pipe()
		done := make(chan error, 1)
		go func() { done <- s.serverHandshake(a); a.Close() }()
		hello := append([]byte("GGT2"), make([]byte, 32)...)
		writeFull(b, hello)
		reply := make([]byte, 64)
		io.ReadFull(b, reply)
		proof := s.proof("client", append(hello[4:], reply[:32]...))
		if round == 0 {
			oldProof = proof
		} else {
			proof = oldProof
		}
		writeFull(b, proof)
		err := <-done
		b.Close()
		if (round == 0) != (err == nil) {
			t.Fatal("challenge replay", round, err)
		}
	}
}
