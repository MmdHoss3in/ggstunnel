package carrier

import (
	"testing"
	"time"
)

func TestPersistentHoleNarrowRangeAcrossWrap(t *testing.T) {
	b := testBIP(t)
	now := time.Unix(100, 0)
	for _, seq := range []uint32{0xfffffffe, 0xffffffff, 1, 2, 3, 4, 5, 6} {
		b.queuePending(outData{seq: seq, retries: 1}, pendingModePull, now)
		b.pending[seq].deadline = now.Add(time.Second)
	}
	for i := 0; i < 3; i++ {
		b.recoverPersistentHole(0xfffffffd, 1<<2, nil, false, now.Add(300*time.Millisecond))
	}
	for seq, p := range b.pending {
		want := seq == 0xfffffffe || seq == 0xffffffff
		if p.fast != want {
			t.Fatalf("persistent recovery crossed advertised range at %08x", seq)
		}
	}
}
