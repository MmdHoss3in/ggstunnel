package carrier

import (
	"context"
	"encoding/binary"
	"testing"
	"time"
)

func TestBIPSingleReplyStatefulHandshake(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	// A stricter per-(identifier,sequence) appliance model than Linux's
	// identifier-based conntrack: one EchoReply per originated request.
	l := &simLink{adaptive: true, stateful: true, singleReply: true, delay: 10 * time.Millisecond, copies: 1, requests: make(map[[3]uint16]time.Time)}
	// Only the foreign endpoint can initiate discovery; simultaneous HELLOs
	// would hide the duplicated request tuple in the legacy handshake.
	l.filter = func(from int, p []byte) bool {
		return from != 0 || p[0] != 8 || p[12] != bipKindHello
	}
	a, b := l.start(t, 0, ctx), l.start(t, 1, ctx)
	waitFor(t, func() bool { return a.PeerSession() == b.localID && b.PeerSession() == a.localID })
	for i := 1; i <= 32; i++ {
		payload := []byte{byte(i)}
		if err := a.SendContext(ctx, payload); err != nil {
			t.Fatal(err)
		}
		if err := b.SendContext(ctx, payload); err != nil {
			t.Fatal(err)
		}
	}
	for _, e := range []*BIP{a, b} {
		for i := 1; i <= 32; i++ {
			select {
			case p := <-e.Recv():
				if len(p) != 1 || p[0] != byte(i) {
					t.Fatal("stateful DATA corrupted or reordered")
				}
			case <-time.After(3 * time.Second):
				t.Fatal("stateful DATA stalled")
			}
		}
	}
}

func TestFASTReplyRetriesAvoidBlockedRequestDirection(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	l := &simLink{adaptive: true, delay: 10 * time.Millisecond, copies: 1, requests: make(map[[3]uint16]time.Time)}
	dropped := false
	l.filter = func(from int, p []byte) bool {
		if from == 0 && p[0] == 8 && p[12] < bipKindHello {
			return false
		}
		// Remove the tuple-assisted rescue to exercise the usable FAST path.
		if from == 1 && p[12] == bipKindPullProbe {
			return false
		}
		if from == 0 && p[12] == bipKindData && binary.BigEndian.Uint32(p[40:44]) == 9 && !dropped {
			dropped = true
			return false
		}
		return true
	}
	a, b := l.start(t, 0, ctx), l.start(t, 1, ctx)
	waitFor(t, func() bool { return a.SnapshotStats().FastHealthy && a.PeerSession() != 0 && b.PeerSession() != 0 })
	for i := 1; i <= 32; i++ {
		if err := a.SendContext(ctx, []byte{byte(i)}); err != nil {
			t.Fatal(err)
		}
	}
	deadline := time.After(3 * time.Second)
	for i := 1; i <= 32; i++ {
		select {
		case p := <-b.Recv():
			if len(p) != 1 || p[0] != byte(i) {
				t.Fatal("FAST retry corrupted or reordered DATA")
			}
		case err := <-a.Errors():
			t.Fatal(err)
		case <-deadline:
			t.Fatal("healthy FAST retry used blocked EchoRequest")
		}
	}
	if a.SnapshotStats().Retransmits == 0 {
		t.Fatal("test did not exercise loss")
	}
}
