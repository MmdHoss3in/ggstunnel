package frame

import (
	"testing"
	"time"
)

func TestReassemblyBudgetsAndCleanup(t *testing.T) {
	r := NewBoundedReassembler(time.Second, 2, 1024)
	for i := uint32(1); i < 100; i++ {
		r.Add(Header{SessionID: 1, PacketID: i, FragCount: 2}, make([]byte, 100))
	}
	count, used := r.Usage()
	if count != 2 || used > 1024 {
		t.Fatalf("usage=%d/%d", count, used)
	}
	r.Cleanup(time.Now().Add(2 * time.Second))
	count, used = r.Usage()
	if count != 0 || used != 0 {
		t.Fatalf("cleanup usage=%d/%d", count, used)
	}
}
func TestReassemblyRejectConflictingCountAndOversize(t *testing.T) {
	r := NewReassembler(time.Second)
	h := Header{SessionID: 1, PacketID: 1, FragCount: 2}
	r.Add(h, make([]byte, 40000))
	h.FragIndex = 1
	if _, ok := r.Add(h, make([]byte, 40000)); ok {
		t.Fatal("oversized IP packet accepted")
	}
	count, used := r.Usage()
	if count != 0 || used != 0 {
		t.Fatal("oversized partial retained")
	}
	h.FragIndex = 0
	r.Add(h, []byte{1})
	h.FragCount = 3
	if _, ok := r.Add(h, []byte{1}); ok {
		t.Fatal("conflict accepted")
	}
}
func TestWrongKeyAndTamperDoNotPoisonReplay(t *testing.T) {
	a, _ := NewCodec("0123456789abcdef")
	b, _ := NewCodec("0123456789abcdef")
	wrong, _ := NewCodec("fedcba9876543210")
	w, _ := a.Seal(TypeData, 1, 0, 1, []byte("hello"))
	if _, err := wrong.Open(w); err == nil {
		t.Fatal("wrong key accepted")
	}
	tampered := append([]byte(nil), w...)
	tampered[len(tampered)-1] ^= 1
	if _, err := b.Open(tampered); err == nil {
		t.Fatal("tamper accepted")
	}
	if _, err := b.Open(w); err != nil {
		t.Fatal(err)
	}
}
func TestReplayBoundaryDoesNotOverwriteNewSlot(t *testing.T) {
	r := NewReplayGuard(64)
	r.Commit(1, 136)
	r.Commit(1, 72)
	if r.Precheck(1, 136) {
		t.Fatal("new frame replay admitted")
	}
}
func FuzzFrameParser(f *testing.F) {
	f.Add([]byte("IPX1"))
	f.Add(make([]byte, 100))
	c, _ := NewCodec("0123456789abcdef")
	w, _ := c.Seal(TypeData, 1, 0, 1, []byte("seed"))
	f.Add(w)
	f.Fuzz(func(t *testing.T, b []byte) {
		c, err := NewCodec("0123456789abcdef")
		if err != nil {
			t.Fatal(err)
		}
		_, _ = c.Open(b)
	})
}
func FuzzReassemblyBounds(f *testing.F) {
	f.Add(uint16(2), uint16(1), []byte("abc"))
	f.Fuzz(func(t *testing.T, count, index uint16, p []byte) {
		r := NewBoundedReassembler(time.Second, 2, 4096)
		r.Add(Header{SessionID: 1, PacketID: 1, FragCount: count, FragIndex: index}, p)
		n, b := r.Usage()
		if n > 2 || b > 4096 {
			t.Fatal("budget exceeded")
		}
	})
}
