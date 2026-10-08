package frame

import (
	"bytes"
	"errors"
	"testing"
)

func TestOpaqueAuthenticationReplayAndFragments(t *testing.T) {
	a, err := NewOpaqueCodec("0123456789abcdef0123456789abcdef")
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewOpaqueCodec("0123456789abcdef0123456789abcdef")
	if err != nil {
		t.Fatal(err)
	}
	wire, err := a.Seal(TypeData, 91, 1, 3, []byte("payload"))
	if err != nil || len(wire) != OpaqueOverhead+7 || bytes.Contains(wire, []byte("GGS1")) {
		t.Fatal("opaque packet shape", err)
	}
	for _, offset := range []int{0, 8, 12, len(wire) - 1} {
		bad := append([]byte(nil), wire...)
		bad[offset] ^= 1
		if _, err := b.Open(bad); err == nil || len(b.replay.sessions) != 0 || b.receiverID != 0 {
			t.Fatal("forgery changed authenticated state", offset, err)
		}
	}
	d, err := b.Open(wire)
	if err != nil || d.Header.SessionID != a.SessionID() || d.Header.PacketID != 91 || d.Header.FragIndex != 1 || d.Header.FragCount != 3 || string(d.Payload) != "payload" {
		t.Fatal("authenticated metadata roundtrip", d, err)
	}
	if _, err := b.Open(wire); !errors.Is(err, ErrReplay) {
		t.Fatal("replay accepted", err)
	}
	if _, err := a.Open(wire); !errors.Is(err, ErrReflectedLocal) {
		t.Fatal("reflection accepted", err)
	}
}

func TestOpaqueKeyBoundaryAndMismatch(t *testing.T) {
	a, _ := NewOpaqueCodec("0123456789abcdef")
	b, _ := NewOpaqueCodec("0123456789abcdef")
	a.seq.Store((1 << 32) - 1)
	wire, err := a.Seal(TypeHeartbeat, 0, 0, 1, nil)
	if err != nil {
		t.Fatal(err)
	}
	d, err := b.Open(wire)
	if err != nil || d.Header.Seq != 1<<32 {
		t.Fatal("last unique nonce", err)
	}
	if _, err := a.Seal(TypeHeartbeat, 0, 0, 1, nil); !errors.Is(err, ErrKeyLifetime) {
		t.Fatal("nonce lifetime not enforced", err)
	}
	legacy, _ := NewCodec("0123456789abcdef")
	if _, err := legacy.Open(wire); err == nil {
		t.Fatal("opaque silently downgraded")
	}
}

func TestIndependentReplaySpanSurvivesPeerBinding(t *testing.T) {
	a, _ := NewCodec("0123456789abcdef")
	b, _ := NewCodec("0123456789abcdef")
	b.SetReplayWindow(16*8192 + 4096)
	early, _ := a.Seal(TypeData, 1, 0, 1, []byte("early"))
	a.seq.Store(16 * 8192)
	late, _ := a.Seal(TypeData, 2, 0, 1, []byte("late"))
	if _, err := b.OpenForSession(late, a.SessionID()); err != nil {
		t.Fatal(err)
	}
	if _, err := b.OpenForSession(early, a.SessionID()); err != nil {
		t.Fatal("valid retained frame fell outside inner replay span", err)
	}
	if _, err := b.OpenForSession(early, a.SessionID()); !errors.Is(err, ErrReplay) {
		t.Fatal("expanded history lost replay rejection", err)
	}
}

func FuzzOpaqueParser(f *testing.F) {
	a, _ := NewOpaqueCodec("0123456789abcdef")
	packet, _ := a.Seal(TypeData, 1, 0, 1, []byte("seed"))
	f.Add(packet)
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, packet []byte) {
		if len(packet) > 2048 {
			return
		}
		c, err := NewOpaqueCodec("0123456789abcdef")
		if err != nil {
			t.Fatal(err)
		}
		_, _ = c.Open(packet)
	})
}

func TestOpaqueRestartBudgetFailsClosedWithoutEvictingReplay(t *testing.T) {
	receiver, _ := NewOpaqueCodec("0123456789abcdef")
	var first []byte
	for i := 0; i < 5; i++ {
		sender, _ := NewOpaqueCodec("0123456789abcdef")
		packet, _ := sender.Seal(TypeHeartbeat, 0, 0, 1, nil)
		if i == 0 {
			first = packet
		}
		_, err := receiver.Open(packet)
		if (i < 4 && err != nil) || (i == 4 && !errors.Is(err, ErrReplay)) {
			t.Fatal("bounded restart budget violated", i, err)
		}
	}
	if _, err := receiver.Open(first); !errors.Is(err, ErrReplay) {
		t.Fatal("retired replay history was forgotten", err)
	}
}
