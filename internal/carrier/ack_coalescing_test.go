package carrier

import (
	"testing"
	"time"
)

func TestACKPiggybackRequiresActualTransmissionAndMatchingState(t *testing.T) {
	for _, tc := range []struct {
		name    string
		fail    bool
		typ     byte
		stale   bool
		wide    bool
		cleared bool
	}{
		{"fresh", false, 0, false, false, true}, {"failed", true, 0, false, false, false}, {"wrong_direction", false, 8, false, false, false}, {"stale_batch", false, 0, true, false, false}, {"wide_sack", false, 0, false, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := testBIP(t)
			b.active = 9
			b.sessionKey = make([]byte, 32)
			b.emit = func([]byte) error { return nil }
			b.rxAck.max = 1
			b.scheduleAck(wirePacket{typ: 8, id: 3, tuple: 7}, time.Now(), false)
			packet, err := b.prepareWire(tc.typ, 3, 7, bipKindData, 0, 1, []byte("data"), 9)
			if err != nil {
				t.Fatal(err)
			}
			if tc.stale {
				b.rxAck.max = 2
			}
			if tc.wide {
				b.rxAck.seen[100] = true
			}
			b.recordWireResult(packet, !tc.fail)
			if b.ackDue.IsZero() != tc.cleared {
				t.Fatalf("ACK cleared=%v expected %v", b.ackDue.IsZero(), tc.cleared)
			}
			if tc.cleared && b.SnapshotStats().ACKsCoalesced != 1 {
				t.Fatal("coalescing invisible")
			}
		})
	}
}
