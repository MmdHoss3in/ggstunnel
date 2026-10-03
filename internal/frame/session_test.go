package frame

import "testing"

func TestAuthenticatedSessionRotationAndOldFrame(t *testing.T) {
	receiver, err := NewCodec("0123456789abcdef")
	if err != nil {
		t.Fatal(err)
	}
	var old []byte
	for i := 0; i < 10; i++ {
		sender, err := NewCodec("0123456789abcdef")
		if err != nil {
			t.Fatal(err)
		}
		wire, err := sender.Seal(TypeData, 1, 0, 1, []byte("rotation"))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := receiver.OpenForSession(wire, sender.SessionID()); err != nil {
			t.Fatal(err)
		}
		if _, err := receiver.OpenForSession(wire, sender.SessionID()); err == nil {
			t.Fatal("replay accepted")
		}
		if i > 0 {
			if _, err := receiver.OpenForSession(old, sender.SessionID()); err == nil {
				t.Fatal("retired identity accepted")
			}
		}
		old = wire
	}
	if _, err := receiver.OpenForSession(old, 0); err == nil {
		t.Fatal("unauthorized identity accepted")
	}
}
