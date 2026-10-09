package carrier

import (
	"context"
	"errors"
	"testing"
	"time"

	"ggstunnel/internal/config"
	"ggstunnel/internal/pathmtu"
)

func TestPathProbeExactWireSizeAndAuthenticatedReply(t *testing.T) {
	for _, compact := range []bool{false, true} {
		ctx, cancel := context.WithCancel(context.Background())
		l := &simLink{copies: 1, requests: make(map[[3]uint16]time.Time), configure: func(c *config.Config) {
			if compact {
				c.Transport.BIPWireMode = "compact"
			}
		}}
		a, b := l.start(t, 0, ctx), l.start(t, 1, ctx)
		waitFor(t, func() bool { return a.PeerSession() != 0 && b.PeerSession() != 0 })
		for _, size := range []int{256, 1000, 1280} {
			probeCtx, stop := context.WithTimeout(ctx, time.Second)
			if err := a.ProbePath(probeCtx, size); err != nil {
				stop()
				cancel()
				t.Fatal(err)
			}
			stop()
		}
		cancel()
		a.Close()
		b.Close()
		// Encode outside a running actor to exercise SACK and padding bounds.
		for _, sack := range []uint64{0, 1, ^uint64(0)} {
			c := simConfig("server")
			if compact {
				c.Transport.BIPWireMode = "compact"
			}
			x, err := NewBIP(c)
			if err != nil {
				t.Fatal(err)
			}
			sender := x.(*BIP)
			sender.emit = func([]byte) error { return nil }
			sender.active = 9
			sender.sessionKey = []byte("test-key")
			sender.rxAck = sackWindow{init: true, max: 0, seen: make(map[uint32]bool)}
			for bit := uint32(0); bit < 64; bit++ {
				if sack&(uint64(1)<<bit) != 0 {
					sender.rxAck.seen[bit+1] = true
				}
			}
			p, _ := pathmtu.Request(1500)
			wire, err := sender.prepareWire(8, 1, 2, bipKindFastProbe, 0, 7, p, 9)
			if err != nil || len(wire) != 1500 {
				t.Fatal("probe does not cover exact complete wire size", compact, len(wire), err)
			}
		}
	}
}

func TestPathReplyCannotPromoteFastOrAcceptWrongNonce(t *testing.T) {
	b := testBIP(t)
	request, _ := pathmtu.Request(1200)
	result := make(chan error, 1)
	b.pathPending = &bipPathPending{bipPathRequest{context.Background(), request, result}, 17, 8}
	reply := pathmtu.Reply(request)
	reply[8] ^= 1
	b.acceptPathReply(wirePacket{sender: 8, token: 17, payload: reply})
	select {
	case <-result:
		t.Fatal("wrong nonce completed probe")
	default:
	}
	b.acceptPathReply(wirePacket{sender: 8, token: 17})
	if err := <-result; !errors.Is(err, pathmtu.ErrUnsupported) {
		t.Fatal(err)
	}
	if b.fastHealthy.Load() || !b.fastUntil.IsZero() {
		t.Fatal("size probe promoted FAST path")
	}
}
