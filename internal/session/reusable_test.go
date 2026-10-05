package session

import (
	"bytes"
	"testing"
	"time"
)

func TestReusableChallengeDoesNotExhaustBudgetOrExtendExpiry(t *testing.T) {
	key := bytes.Repeat([]byte{7}, 32)
	g, _ := NewGate(key, 1, 5)
	now := time.Now()
	first, err := g.IssueReusable(2, 1, now)
	if err != nil { t.Fatal(err) }
	for i := 1; i < 20; i++ {
		got, err := g.IssueReusable(2, 1, now.Add(time.Duration(i)*400*time.Millisecond))
		if err != nil || got != first { t.Fatalf("retry %d changed challenge: %v", i, err) }
	}
	if len(g.pending) != 1 { t.Fatal("retry exhausted pending slots") }
	next, err := g.IssueReusable(2, 1, now.Add(10*time.Second))
	if err != nil || next == first { t.Fatal("expired nonce was extended or reused") }
	if err := g.Accept(first, Proof(key, first), now.Add(10*time.Second)); err == nil { t.Fatal("expired proof accepted") }
	if err := g.Accept(next, Proof(key, next), now.Add(10*time.Second)); err != nil { t.Fatal(err) }
	if err := g.Accept(next, Proof(key, next), now.Add(10*time.Second)); err == nil { t.Fatal("consumed proof replayed") }
}

func TestReusableChallengePreservesPeerRoleAndRotationBounds(t *testing.T) {
	key := bytes.Repeat([]byte{7}, 32)
	g, _ := NewGate(key, 1, 5)
	now := time.Now()
	a, _ := g.IssueReusable(2, 1, now)
	b, _ := g.IssueReusable(2, 2, now)
	if a == b || a.Nonce == b.Nonce { t.Fatal("roles shared challenge") }
	for peer := uint64(3); peer < 17; peer++ {
		if _, err := g.IssueReusable(peer, 1, now); err != nil { t.Fatal(err) }
	}
	if _, err := g.IssueReusable(17, 1, now); err == nil { t.Fatal("distinct peer budget exceeded") }
	if got, err := g.IssueReusable(2, 1, now); err != nil || got != a { t.Fatal("existing retry rejected at full budget") }
	if err := g.Accept(a, Proof(key, a), now); err != nil { t.Fatal(err) }
	c, _ := g.IssueReusable(18, 1, now)
	if err := g.Accept(c, Proof(key, c), now); err != nil { t.Fatal(err) }
	if _, err := g.IssueReusable(2, 1, now); err == nil { t.Fatal("retired peer allowed back in") }
}
