package frame

import (
	"bytes"
	"testing"
	"time"
)

func TestSealOpenAndReplay(t *testing.T) {
	a, _ := NewCodec("0123456789abcdef")
	b, _ := NewCodec("0123456789abcdef")
	w, err := a.Seal(TypeData, 7, 0, 1, []byte("hello"))
	if err != nil {
		t.Fatal(err)
	}
	d, err := b.Open(w)
	if err != nil {
		t.Fatal(err)
	}
	if string(d.Payload) != "hello" {
		t.Fatalf("bad payload %q", d.Payload)
	}
	if _, err := b.Open(w); err == nil {
		t.Fatal("replay was accepted")
	}
	if _, err := a.Open(w); err == nil {
		t.Fatal("reflected local frame was accepted")
	}
}

func TestReassembly(t *testing.T) {
	r := NewReassembler(time.Second)
	h := Header{SessionID: 1, PacketID: 9, FragCount: 3}
	h.FragIndex = 1
	if _, ok := r.Add(h, []byte("bb")); ok {
		t.Fatal("early")
	}
	h.FragIndex = 0
	if _, ok := r.Add(h, []byte("aa")); ok {
		t.Fatal("early")
	}
	h.FragIndex = 2
	out, ok := r.Add(h, []byte("cc"))
	if !ok || !bytes.Equal(out, []byte("aabbcc")) {
		t.Fatalf("bad %q", out)
	}
}

func TestReplayGuardWindowAndOutOfOrder(t *testing.T) {
	r := NewReplayGuard(64)
	const sid = 77
	for seq := uint64(100); seq <= 200; seq += 2 {
		if !r.Precheck(sid, seq) {
			t.Fatalf("fresh seq %d rejected", seq)
		}
		r.Commit(sid, seq)
	}
	if r.Precheck(sid, 200) {
		t.Fatal("duplicate accepted")
	}
	if r.Precheck(sid, 100) {
		t.Fatal("stale sequence accepted")
	}
	if !r.Precheck(sid, 199) {
		t.Fatal("unseen out-of-order sequence inside window rejected")
	}
	r.Commit(sid, 199)
	if r.Precheck(sid, 199) {
		t.Fatal("out-of-order duplicate accepted")
	}
}

func BenchmarkReplayGuardCommit(b *testing.B) {
	r := NewReplayGuard(4096)
	const sid = 1234
	b.ReportAllocs()
	b.ResetTimer()
	for i := 1; i <= b.N; i++ {
		seq := uint64(i)
		if !r.Precheck(sid, seq) {
			b.Fatal("unexpected replay")
		}
		r.Commit(sid, seq)
	}
}
