package frame

import (
	"errors"
	"testing"
)

func TestKeyLifetimeBoundaryRequiresFreshIdentity(t *testing.T) {
	old, _ := NewCodec("0123456789abcdef0123456789abcdef")
	old.seq.Store((1 << 32) - 1)
	if _, err := old.Seal(TypeData, 1, 0, 1, []byte("last allowed frame")); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if _, err := old.Seal(TypeData, 2, 0, 1, []byte("expired")); !errors.Is(err, ErrKeyLifetime) {
			t.Fatal("expired sender key reused", err)
		}
	}
	fresh, _ := NewCodec("0123456789abcdef0123456789abcdef")
	if old.SessionID() == fresh.SessionID() {
		t.Fatal("identity reused")
	}
	wire, err := fresh.Seal(TypeData, 1, 0, 1, []byte("fresh"))
	if err != nil {
		t.Fatal(err)
	}
	peer, _ := NewCodec("0123456789abcdef0123456789abcdef")
	if _, err := peer.Open(wire); err != nil {
		t.Fatal(err)
	}
}
