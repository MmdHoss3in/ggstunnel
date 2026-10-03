package session

import (
	"bytes"
	"testing"
	"time"
)

func TestChallengeAuthenticationReplayAndRestart(t *testing.T) {
	key := bytes.Repeat([]byte{7}, 32)
	g, _ := NewGate(key, 1, 3)
	now := time.Now()
	c, err := g.Issue(2, 1, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := g.Accept(c, Proof(bytes.Repeat([]byte{8}, 32), c), now); err == nil {
		t.Fatal("wrong key accepted")
	}
	changed := c
	changed.Wire++
	if err := g.Accept(changed, Proof(key, changed), now); err == nil {
		t.Fatal("altered transcript accepted")
	}
	proof := Proof(key, c)
	if err := g.Accept(c, proof, now); err != nil {
		t.Fatal(err)
	}
	if err := g.Accept(c, proof, now); err == nil {
		t.Fatal("proof replay accepted")
	}
	next, _ := g.Issue(3, 1, now)
	if err := g.Accept(next, Proof(key, next), now); err != nil {
		t.Fatal(err)
	}
	if g.Active() != 3 {
		t.Fatal("rotation failed")
	}
	if _, err := g.Issue(2, 1, now); err == nil {
		t.Fatal("retired peer reinstated")
	}
}
func TestChallengeExpiryAndBudget(t *testing.T) {
	key := bytes.Repeat([]byte{7}, 32)
	g, _ := NewGate(key, 1, 3)
	now := time.Now()
	c, _ := g.Issue(2, 1, now)
	if err := g.Accept(c, Proof(key, c), now.Add(11*time.Second)); err == nil {
		t.Fatal("expired proof accepted")
	}
	for i := 0; i < 15; i++ {
		if _, err := g.Issue(2, 1, now); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := g.Issue(2, 1, now); err == nil {
		t.Fatal("pending limit exceeded")
	}
	if _, err := g.Issue(2, 1, now.Add(11*time.Second)); err != nil {
		t.Fatal("expired slots retained")
	}
}
