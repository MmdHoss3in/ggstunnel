package carrier

import (
	"context"
	"encoding/binary"
	"testing"
	"time"
)

func TestFieldServerRequestsBlockedAndReplyLoss(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	l := &simLink{adaptive: true, copies: 1, requests: make(map[[3]uint16]time.Time)}
	dropped := false
	l.filter = func(from int, p []byte) bool {
		// Mirror the observed direction: Iran requests fail, peer requests work.
		if from == 0 && p[0] == 8 {
			return false
		}
		if from == 0 && p[12] == bipKindData && binary.BigEndian.Uint32(p[40:44]) == 277 && !dropped {
			dropped = true
			return false
		}
		return true
	}
	a := l.start(t, 0, ctx)
	b := l.start(t, 1, ctx)
	waitFor(t, func() bool { return a.PeerSession() == b.localID && b.PeerSession() == a.localID })
	for i := uint32(1); i <= 350; i++ {
		p := make([]byte, 1200)
		binary.BigEndian.PutUint32(p, i)
		if err := a.Send(p); err != nil {
			t.Fatal(err)
		}
	}
	seen := map[uint32]bool{}
	deadline := time.After(8 * time.Second)
	for len(seen) < 350 {
		select {
		case p := <-b.Recv():
			seq := binary.BigEndian.Uint32(p)
			if seq < 1 || seq > 350 || seen[seq] {
				t.Fatal("invalid/duplicate delivery")
			}
			seen[seq] = true
		case err := <-a.Errors():
			t.Fatalf("reply loss killed server: %v", err)
		case <-deadline:
			t.Fatalf("received %d/350", len(seen))
		}
	}
	waitFor(t, func() bool { return a.SnapshotStats().Pending == 0 })
	if a.SnapshotStats().Retransmits == 0 {
		t.Fatal("lost frame was not retried")
	}
	if a.SnapshotStats().Backlog != 0 {
		t.Fatal("backlog stalled")
	}
}

func TestVerifiedKernelReflectionIsNotMACFailureOrACK(t *testing.T) {
	b := testBIP(t)
	b.active = 8
	body, err := b.encode(wirePacket{typ: 8, kind: bipKindData, sender: b.localID, target: 8, number: 1, token: 1, payload: []byte("original")})
	if err != nil {
		t.Fatal(err)
	}
	body[0] = 0
	binary.BigEndian.PutUint16(body[2:4], 0)
	binary.BigEndian.PutUint16(body[2:4], checksum(body))
	b.queuePending(outData{seq: 1}, pendingModeRequest, time.Now())
	b.handle(body, time.Now())
	if b.reflectionsSuppressed.Load() != 1 || b.hmacFail.Load() != 0 || b.SnapshotStats().Pending != 1 {
		t.Fatal("reflection changed ACK/MAC counters")
	}
	body[len(body)-1] ^= 1
	binary.BigEndian.PutUint16(body[2:4], 0)
	binary.BigEndian.PutUint16(body[2:4], checksum(body))
	b.handle(body, time.Now())
	if b.hmacFail.Load() != 1 {
		t.Fatal("real tamper not counted")
	}
}
