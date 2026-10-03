package session

import (
	"bytes"
	"errors"
	"testing"
	"time"
)

func TestRotationLimitRequestsFreshIdentity(t *testing.T) {
	key := bytes.Repeat([]byte{1}, 32)
	g, e := NewGate(key, 1, 5)
	if e != nil {
		t.Fatal(e)
	}
	now := time.Now()
	for i := 0; i < 258; i++ {
		c, e := g.Issue(uint64(100+i), 1, now)
		if e != nil {
			t.Fatal(e)
		}
		e = g.Accept(c, Proof(key, c), now)
		if i < 257 && e != nil {
			t.Fatal(i, e)
		}
		if i == 257 && !errors.Is(e, ErrRotationLimit) {
			t.Fatal("missing restart signal", e)
		}
	}
}
