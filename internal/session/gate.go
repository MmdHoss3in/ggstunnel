// Package session provides a bounded challenge gate for the next BIP wire
// revision. It is not yet connected to the baseline BIP2 data plane.
package session

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"sync"
	"time"
)

var ErrRotationLimit = errors.New("session rotation limit reached; fresh local identity required")

type Challenge struct {
	Nonce   [32]byte
	PeerID  uint64
	LocalID uint64
	Wire    uint16
	Role    byte
}
type pending struct {
	challenge Challenge
	expires   time.Time
}
type Gate struct {
	mu      sync.Mutex
	key     []byte
	localID uint64
	wire    uint16
	pending map[[32]byte]pending
	retired map[uint64]bool
	active  uint64
	ttl     time.Duration
}

func NewGate(key []byte, localID uint64, wire uint16) (*Gate, error) {
	if len(key) < 32 || localID == 0 || wire == 0 {
		return nil, errors.New("strong key, nonzero identity and wire version required")
	}
	return &Gate{key: append([]byte(nil), key...), localID: localID, wire: wire, pending: make(map[[32]byte]pending), retired: make(map[uint64]bool), ttl: 10 * time.Second}, nil
}
func (g *Gate) Issue(peerID uint64, role byte, now time.Time) (Challenge, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	for n, p := range g.pending {
		if !now.Before(p.expires) {
			delete(g.pending, n)
		}
	}
	if peerID == 0 || peerID == g.localID || (role != 1 && role != 2) || g.retired[peerID] || len(g.pending) >= 16 {
		return Challenge{}, errors.New("challenge rejected")
	}
	c := Challenge{PeerID: peerID, LocalID: g.localID, Wire: g.wire, Role: role}
	if _, err := rand.Read(c.Nonce[:]); err != nil {
		return Challenge{}, err
	}
	g.pending[c.Nonce] = pending{c, now.Add(g.ttl)}
	return c, nil
}

// Proof binds identities, role, wire version and receiver-generated randomness.
func Proof(key []byte, c Challenge) [32]byte {
	h := hmac.New(sha256.New, key)
	h.Write([]byte("ggstunnel/session-challenge/v1\x00"))
	h.Write(c.Nonce[:])
	var b [19]byte
	binary.BigEndian.PutUint64(b[:8], c.LocalID)
	binary.BigEndian.PutUint64(b[8:16], c.PeerID)
	binary.BigEndian.PutUint16(b[16:18], c.Wire)
	b[18] = c.Role
	h.Write(b[:])
	var result [32]byte
	copy(result[:], h.Sum(nil))
	return result
}
func (g *Gate) Accept(c Challenge, proof [32]byte, now time.Time) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	p, ok := g.pending[c.Nonce]
	if !ok || p.challenge != c || !now.Before(p.expires) || g.retired[c.PeerID] {
		return errors.New("stale or unknown challenge")
	}
	expected := Proof(g.key, c)
	if !hmac.Equal(expected[:], proof[:]) {
		return errors.New("authentication failed")
	}
	if g.active != 0 && g.active != c.PeerID {
		// Never forget a retired identity and silently allow replay. Rekey/restart
		// with a fresh local identity after exhausting this bounded lifecycle.
		if len(g.retired) >= 256 {
			return ErrRotationLimit
		}
		g.retired[g.active] = true
	}
	delete(g.pending, c.Nonce)
	g.active = c.PeerID
	return nil
}
func (g *Gate) Active() uint64 { g.mu.Lock(); defer g.mu.Unlock(); return g.active }
