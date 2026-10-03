package carrier

import (
	"math"
	"testing"
	"time"
)

func spanSender(t *testing.T, base uint32) *BIP {
	b := testBIP(t)
	b.tx = make(chan []byte, 8192)
	b.cfg.Performance.QueueSize = 8192
	b.emit = func([]byte) error { return nil }
	b.active = 8
	b.dataSeq = base
	b.txAckBase = base
	for i := 0; i < 5000; i++ {
		b.tx <- []byte("test frame")
	}
	return b
}

func TestSACKSpanStopsAtMissing4136(t *testing.T) {
	b := spanSender(t, 4135)
	now := time.Unix(100, 0)
	for i := 0; i < 4096; i++ {
		b.deliverOne(8, 1, uint16(i), pendingModeRequest, now)
	}
	// The hole at 4136 remains; all 4095 later packets are SACKed.
	extra := make([]byte, 504)
	for i := range extra {
		extra[i] = 255
	}
	b.processWideAckAt(4135, ^uint64(1), extra, now.Add(80*time.Millisecond))
	if len(b.pending) != 1 {
		t.Fatal("SACK cleanup failed")
	}
	b.deliverOne(8, 1, 65, pendingModeRequest, now.Add(90*time.Millisecond))
	if b.dataSeq != 8231 {
		t.Fatalf("sent unacknowledgeable seq=%d past SACK horizon 8231", b.dataSeq)
	}
	b.processPeerAckAt(8231, 0, now.Add(100*time.Millisecond))
	b.deliverOne(8, 1, 66, pendingModeRequest, now.Add(101*time.Millisecond))
	if b.dataSeq != 8232 {
		t.Fatal("did not resume after missing packet recovered")
	}
}

func TestSACKSpanWrapSkipsZero(t *testing.T) {
	b := spanSender(t, math.MaxUint32-32)
	now := time.Unix(100, 0)
	for i := 0; i < 4096; i++ {
		b.deliverOne(8, 1, uint16(i), pendingModeRequest, now)
	}
	if b.dataSeq != 4064 {
		t.Fatalf("4096-slot wrap blocked early at %d", b.dataSeq)
	}
	b.deliverOne(8, 1, 65, pendingModeRequest, now)
	if b.dataSeq != 4064 {
		t.Fatal("4097th packet crossed SACK horizon")
	}
	b.processPeerAckAt(4064, 0, now.Add(time.Second))
	b.deliverOne(8, 1, 66, pendingModeRequest, now.Add(time.Second))
	if b.dataSeq != 4065 {
		t.Fatal("wrap recovery stalled")
	}
}
