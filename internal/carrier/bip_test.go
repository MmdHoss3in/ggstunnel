package carrier

import (
	"testing"
	"time"

	"ggstunnel/internal/config"
)

func testBIP(t *testing.T) *BIP {
	t.Helper()
	c := &config.Config{}
	c.Performance.QueueSize = 128
	c.Transport.BIPMaxRetries = 2
	return &BIP{cfg: c, pending: make(map[uint32]*pendingData), rxAck: sackWindow{}, localID: 7, master: []byte("0123456789abcdef0123456789abcdef"), sessionKey: []byte("test-key"), rx: make(chan []byte, 128)}
}

func TestSACKWindowDuplicateAndOrdering(t *testing.T) {
	b := testBIP(t)
	for _, seq := range []uint32{100, 101, 103, 102} {
		if !b.recordRXSeq(seq) {
			t.Fatalf("seq %d unexpectedly duplicate", seq)
		}
	}
	if b.recordRXSeq(102) {
		t.Fatal("duplicate sequence accepted")
	}
	ack, bits := b.takeAckForSend()
	if ack != 103 {
		t.Fatalf("ack=%d want 103", ack)
	}
	if bits != 0 {
		t.Fatalf("contiguous delivery should leave no SACK holes: %x", bits)
	}

}

func TestSACKWindowWrap(t *testing.T) {
	b := testBIP(t)
	seqs := []uint32{0xfffffffe, 0xffffffff, 1, 2}
	for _, seq := range seqs {
		if !b.recordRXSeq(seq) {
			t.Fatalf("wrap seq %08x rejected", seq)
		}
	}
	ack, _ := b.takeAckForSend()
	if ack != 2 {
		t.Fatalf("ack after wrap=%08x want 00000002", ack)
	}
}

func TestPendingAckAndTimeout(t *testing.T) {
	b := testBIP(t)
	now := time.Now()
	b.queuePending(outData{data: []byte("a"), seq: 100}, pendingModeFast, now)
	b.queuePending(outData{data: []byte("b"), seq: 101}, pendingModePull, now)

	// ACK 101 and 100 via two low SACK bits.
	if !b.processPeerAck(101, 0b11) {
		t.Fatal("expected fast packet acknowledgement")
	}
	if len(b.pending) != 0 {
		t.Fatalf("pending=%d want 0", len(b.pending))
	}

	b.queuePending(outData{data: []byte("c"), seq: 102}, pendingModeFast, now.Add(-time.Second))
	pd, ok := b.takeTimedOut(now, 250*time.Millisecond)
	if !ok || pd.item.seq != 102 {
		t.Fatalf("timed out=%v ok=%v", pd, ok)
	}
}

func TestPacketTagChangesWithTupleAndPayload(t *testing.T) {
	b := testBIP(t)
	p := wirePacket{typ: 8, kind: bipKindData, sender: 7, target: 8, number: 1, payload: []byte("hello")}
	body, _ := b.encode(p)
	tag := packetMAC(b.sessionKey, body)
	body[6] ^= 1
	if tag == packetMAC(b.sessionKey, body) {
		t.Fatal("tuple not bound")
	}
	body[6] ^= 1
	body[len(body)-1] ^= 1
	if tag == packetMAC(b.sessionKey, body) {
		t.Fatal("payload not bound")
	}
	body[len(body)-1] ^= 1
	body[0] = 0
	if tag == packetMAC(b.sessionKey, body) {
		t.Fatal("type not bound")
	}
}

func BenchmarkSACKRecord(bm *testing.B) {
	b := testBIP(&testing.T{})
	bm.ReportAllocs()
	for i := 0; i < bm.N; i++ {
		b.recordRXSeq(uint32(i + 1))
	}
}
