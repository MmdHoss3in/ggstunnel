package carrier

import (
	"context"
	"net"
	"testing"
	"time"
)

func TestUDPStatsDistinguishWrongSourceFromAcceptedData(t *testing.T) {
	peer, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	foreign, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer foreign.Close()
	c := simConfig("server")
	c.Profile = "udp"
	c.Real.ListenAddr = "127.0.0.1:0"
	c.Real.PeerAddr = peer.LocalAddr().String()
	u := NewUDP(c)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := u.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer u.Close()
	address := u.conn.LocalAddr().(*net.UDPAddr)
	_, _ = foreign.WriteToUDP([]byte("wrong"), address)
	_, _ = peer.WriteToUDP([]byte("valid"), address)
	select {
	case p := <-u.Recv():
		if string(p) != "valid" {
			t.Fatal("wrong source delivered")
		}
	case <-time.After(time.Second):
		t.Fatal("valid source lost")
	}
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		s := u.SnapshotStats()
		if s.SocketRxPackets == 2 && s.SourceRejected == 1 && s.SocketRxBytes == 10 {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("socket/source accounting incorrect", u.SnapshotStats())
}
