package carrier

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"ggstunnel/internal/frame"
	"ggstunnel/internal/session"
)

type challengeTestCarrier struct {
	rx   chan []byte
	mu   sync.Mutex
	sent [][]byte
}

func (c *challengeTestCarrier) Start(context.Context) error { return nil }
func (c *challengeTestCarrier) Close() error                { return nil }
func (c *challengeTestCarrier) Name() string                { return "udp" }
func (c *challengeTestCarrier) Recv() <-chan []byte         { return c.rx }
func (c *challengeTestCarrier) Send(b []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.sent = append(c.sent, append([]byte(nil), b...))
	return nil
}
func (c *challengeTestCarrier) pop(t *testing.T) []byte {
	t.Helper()
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.sent) == 0 {
		t.Fatal("control not emitted")
	}
	p := c.sent[0]
	c.sent = c.sent[1:]
	return p
}
func challengeEndpoint(t *testing.T, role string, id uint64) (*authenticatedCarrier, *challengeTestCarrier) {
	t.Helper()
	cfg := simConfig(role)
	cfg.Profile = "udp"
	inner := &challengeTestCarrier{rx: make(chan []byte, 32)}
	a, err := newAuthenticatedCarrier(cfg, inner)
	if err != nil {
		t.Fatal(err)
	}
	if err := a.BindIdentity(id); err != nil {
		t.Fatal(err)
	}
	return a, inner
}
func challengeBody(t *testing.T, to *authenticatedCarrier, wire []byte) []byte {
	t.Helper()
	p, err := to.open.Open(nil, wire[:12], wire[12:], nil)
	if err != nil {
		t.Fatal(err)
	}
	return p
}
func establishChallenge(t *testing.T, receiver, sender *authenticatedCarrier, receiverWire, senderWire *challengeTestCarrier, now time.Time) []byte {
	t.Helper()
	if err := sender.control(1, 0, [32]byte{}, [32]byte{}); err != nil {
		t.Fatal(err)
	}
	if err := receiver.receiveControl(challengeBody(t, receiver, senderWire.pop(t)), now); err != nil {
		t.Fatal(err)
	}
	if err := sender.receiveControl(challengeBody(t, sender, receiverWire.pop(t)), now); err != nil {
		t.Fatal(err)
	}
	proof := challengeBody(t, receiver, senderWire.pop(t))
	if err := receiver.receiveControl(proof, now); err != nil {
		t.Fatal(err)
	}
	return proof
}
func TestAuthenticatedChallengeManyRestartsAndReplay(t *testing.T) {
	receiver, rwire := challengeEndpoint(t, "server", 111)
	now := time.Unix(100, 0)
	var original []byte
	for i := 0; i < 20; i++ {
		sender, swire := challengeEndpoint(t, "client", uint64(200+i))
		proof := establishChallenge(t, receiver, sender, rwire, swire, now)
		if receiver.PeerSession() != sender.local {
			t.Fatal("identity not granted", i)
		}
		if i == 0 {
			original = proof
		}
		if err := receiver.receiveControl(proof, now); err == nil {
			t.Fatal("consumed proof replayed")
		}
		now = now.Add(time.Second)
	}
	if err := receiver.receiveControl(original, now); err == nil || receiver.PeerSession() != 219 {
		t.Fatal("retired identity resurrected", err)
	}
	old, owire := challengeEndpoint(t, "client", 200)
	_ = old.control(1, 0, [32]byte{}, [32]byte{})
	if err := receiver.receiveControl(challengeBody(t, receiver, owire.pop(t)), now); err == nil {
		t.Fatal("retired hello admitted")
	}
}
func TestAuthenticatedChallengeForgeryBindingExpiryAndBudget(t *testing.T) {
	r, rwire := challengeEndpoint(t, "server", 111)
	s, swire := challengeEndpoint(t, "client", 222)
	now := time.Unix(100, 0)
	_ = s.control(1, 0, [32]byte{}, [32]byte{})
	if err := r.receiveControl(challengeBody(t, r, swire.pop(t)), now); err != nil {
		t.Fatal(err)
	}
	challenge := challengeBody(t, s, rwire.pop(t))
	if err := s.receiveControl(challenge, now); err != nil {
		t.Fatal(err)
	}
	proof := challengeBody(t, r, swire.pop(t))
	bad := append([]byte(nil), proof...)
	bad[82] ^= 1
	if err := r.receiveControl(bad, now); err == nil || r.PeerSession() != 0 {
		t.Fatal("forged proof changed grant")
	}
	other, _ := challengeEndpoint(t, "server", 112)
	if err := other.receiveControl(proof, now); err == nil {
		t.Fatal("proof accepted by another receiver")
	}
	bad = append([]byte(nil), proof...)
	bad[9] = 1
	if err := r.receiveControl(bad, now); err == nil {
		t.Fatal("reflection role accepted")
	}
	if err := r.receiveControl(proof, now.Add(11*time.Second)); err == nil {
		t.Fatal("expired proof accepted")
	}
	if err := r.Send([]byte("data")); !errors.Is(err, ErrPeerNotReady) {
		t.Fatal("sent before authenticated grant", err)
	}
	// Exhausted retired history requests a fresh local identity, never eviction.
	r, rwire = challengeEndpoint(t, "server", 111)
	for i := 0; i < 257; i++ {
		s, swire = challengeEndpoint(t, "client", uint64(200+i))
		establishChallenge(t, r, s, rwire, swire, now)
		now = now.Add(time.Second)
	}
	s, swire = challengeEndpoint(t, "client", 600)
	_ = s.control(1, 0, [32]byte{}, [32]byte{})
	_ = r.receiveControl(challengeBody(t, r, swire.pop(t)), now)
	_ = s.receiveControl(challengeBody(t, s, rwire.pop(t)), now)
	if err := r.receiveControl(challengeBody(t, r, swire.pop(t)), now); !errors.Is(err, session.ErrRotationLimit) {
		t.Fatal("unsafe identity eviction", err)
	}
}
func TestAuthenticatedChallengeControlDomainAndClose(t *testing.T) {
	r, rwire := challengeEndpoint(t, "server", 111)
	s, swire := challengeEndpoint(t, "client", 222)
	_ = s.control(1, 0, [32]byte{}, [32]byte{})
	p := swire.pop(t)
	for i := range p {
		bad := append([]byte(nil), p...)
		bad[i] ^= 1
		if _, err := r.open.Open(nil, bad[:12], bad[12:], nil); err == nil {
			t.Fatal("control forgery", i)
		}
	}
	cfg := simConfig("server")
	cfg.Profile = "dcpi"
	wrong, err := newAuthenticatedCarrier(cfg, rwire)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := wrong.open.Open(nil, p[:12], p[12:], nil); err == nil {
		t.Fatal("cross-carrier control accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := r.Start(ctx); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- r.SendContext(ctx, []byte("waiting")) }()
	_ = r.Close()
	select {
	case err := <-done:
		if !errors.Is(err, ErrClosed) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("close leaked waiting send")
	}
	if err := r.Start(ctx); err == nil {
		t.Fatal("restarted closed carrier")
	}
}
func TestAuthenticatedChallengeBindsDataToGrantedReceiver(t *testing.T) {
	const key = "0123456789abcdef0123456789abcdef"
	a, _ := frame.NewBoundOpaqueCodec(key)
	b, _ := frame.NewBoundOpaqueCodec(key)
	_ = a.BindSendPeer(b.SessionID())
	packet, _ := a.Seal(frame.TypeData, 1, 0, 1, []byte("data"))
	if _, err := b.OpenForSession(packet, a.SessionID()); err != nil {
		t.Fatal(err)
	}
	fresh, _ := frame.NewBoundOpaqueCodec(key)
	if _, err := fresh.OpenForSession(packet, a.SessionID()); err == nil {
		t.Fatal("old receiver binding lost")
	}
}

func TestAuthenticatedChallengePreservesBoundedQueueBackpressure(t *testing.T) {
	cfg := simConfig("server")
	cfg.Profile = "udp"
	inner := NewUDP(cfg)
	a, err := newAuthenticatedCarrier(cfg, inner)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	a.peer.Store(222) // The send queue test begins after an authenticated grant.
	for i := 0; i < cap(inner.tx); i++ {
		if err := inner.Send([]byte("queued")); err != nil {
			t.Fatal(err)
		}
	}
	done := make(chan error, 1)
	go func() { done <- a.SendContext(context.Background(), []byte("next")) }()
	select {
	case err := <-done:
		t.Fatal("full queue returned instead of applying backpressure", err)
	case <-time.After(20 * time.Millisecond):
	}
	<-inner.tx
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("send did not resume after capacity returned")
	}
	go func() { done <- a.SendContext(context.Background(), []byte("closed wait")) }()
	_ = a.Close()
	select {
	case err := <-done:
		if !errors.Is(err, ErrClosed) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("close leaked a full-queue sender")
	}
}
