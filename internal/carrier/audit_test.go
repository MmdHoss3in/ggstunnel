//go:build audit

package carrier

import (
	"testing"
	"time"
)

// These tests specify desired behavior and intentionally expose baseline defects.
func TestAuditACKBeyond64Packets(t *testing.T) {
	b := testBIP(t)
	for s := uint32(1); s <= 128; s++ {
		b.queuePending(outData{seq: s, data: []byte{1}}, pendingModeFast, time.Now())
		b.recordRXSeq(s)
	}
	ack, bits := b.takeAckForSend()
	b.processPeerAck(ack, bits)
	if len(b.pending) != 0 {
		t.Fatalf("all 128 arrived, but %d remain pending", len(b.pending))
	}
}

func TestAuditCarrierRestartSequence(t *testing.T) {
	b := testBIP(t)
	b.recordRXSeq(100000)
	if err := b.resetPeer(100); err == nil {
		t.Fatal("unauthenticated reset accepted")
	}
	// Real wire handshake restart is covered by the integration test.
	authorizeForTest(t, b, 100)
	// Authenticated session resets start numbering at one.
	if !b.recordRXSeq(1) {
		t.Fatal("fresh restarted peer sequence rejected as stale")
	}
}
