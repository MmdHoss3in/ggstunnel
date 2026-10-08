package frame

import (
	"errors"
	"testing"
)

func TestBoundOpaqueReceiverRestartRejectsOldCiphertext(t *testing.T) {
	const key = "0123456789abcdef0123456789abcdef"
	sender, _ := NewBoundOpaqueCodec(key)
	old, _ := NewBoundOpaqueCodec(key)
	if _, err := sender.Seal(TypeData, 1, 0, 1, []byte("unbound")); !errors.Is(err, ErrPeerNotBound) {
		t.Fatal("sent without receiver binding", err)
	}
	if err := sender.BindSendPeer(old.SessionID()); err != nil {
		t.Fatal(err)
	}
	packet, err := sender.Seal(TypeData, 1, 0, 1, []byte("old receiver"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sender.OpenForSession(packet, old.SessionID()); !errors.Is(err, ErrReflectedLocal) {
		t.Fatal("kernel reflection misclassified", err)
	}
	if _, err := old.OpenForSession(packet, sender.SessionID()); err != nil {
		t.Fatal(err)
	}
	fresh, _ := NewBoundOpaqueCodec(key)
	if _, err := fresh.OpenForSession(packet, sender.SessionID()); err == nil {
		t.Fatal("old ciphertext admitted after receiver restart")
	}
	if err := sender.BindSendPeer(fresh.SessionID()); err != nil {
		t.Fatal(err)
	}
	next, _ := sender.Seal(TypeData, 2, 0, 1, []byte("new receiver"))
	if _, err := fresh.OpenForSession(next, sender.SessionID()); err != nil {
		t.Fatal("fresh binding", err)
	}
	if _, err := fresh.OpenForSession(next, sender.SessionID()); !errors.Is(err, ErrReplay) {
		t.Fatal("replay after binding", err)
	}
	if _, err := old.OpenForSession(next, sender.SessionID()); err == nil {
		t.Fatal("new ciphertext accepted by retired receiver")
	}
}

func TestBoundOpaqueManyAuthenticatedSendersAndKeyLifetime(t *testing.T) {
	const key = "0123456789abcdef"
	receiver, _ := NewBoundOpaqueCodec(key)
	var first []byte
	var firstID uint64
	for i := 0; i < 20; i++ {
		sender, _ := NewBoundOpaqueCodec(key)
		_ = sender.BindSendPeer(receiver.SessionID())
		p, _ := sender.Seal(TypeHeartbeat, 0, 0, 1, nil)
		if i == 0 {
			first, firstID = p, sender.SessionID()
		}
		// The carrier's fresh challenge grants the only admissible identity.
		if _, err := receiver.OpenForSession(p, sender.SessionID()); err != nil {
			t.Fatal(i, err)
		}
	}
	if _, err := receiver.OpenForSession(first, receiver.peerSession); !errors.Is(err, ErrAuthentication) {
		t.Fatal("retired identity passed current grant", firstID, err)
	}
	sender, _ := NewBoundOpaqueCodec(key)
	_ = sender.BindSendPeer(receiver.SessionID())
	sender.seq.Store((1 << 32) - 4096)
	if !sender.RotationDue() {
		t.Fatal("key exhaustion not anticipated")
	}
	sender.seq.Store(1 << 32)
	if _, err := sender.Seal(TypeHeartbeat, 0, 0, 1, nil); !errors.Is(err, ErrKeyLifetime) {
		t.Fatal("nonce limit bypassed", err)
	}
}
