//go:build audit

package frame

import (
	"testing"
	"time"
)

func TestAuditReassemblySessionCollision(t *testing.T) {
	r := NewReassembler(time.Second)
	a := Header{SessionID: 1, PacketID: 1, FragCount: 2, FragIndex: 0}
	b := Header{SessionID: 1 ^ (uint64(1) << 17) ^ (uint64(2) << 17), PacketID: 2, FragCount: 2, FragIndex: 1}
	r.Add(a, []byte("session-A"))
	if out, ok := r.Add(b, []byte("session-B")); ok {
		t.Fatalf("mixed distinct packets: %q", out)
	}
}

func TestAuditReplayAtWindowBoundary(t *testing.T) {
	r := NewReplayGuard(64)
	r.Commit(1, 136)
	if r.Precheck(1, 72) {
		t.Fatal("sequence exactly one ring length old is accepted")
	}
}

func TestAuditReplayAfterSessionEviction(t *testing.T) {
	r := NewReplayGuard(64)
	for sid := uint64(1); sid <= 5; sid++ {
		r.Commit(sid, 1)
	}
	if r.Precheck(1, 1) {
		t.Fatal("previously delivered frame becomes eligible after session eviction")
	}
}
