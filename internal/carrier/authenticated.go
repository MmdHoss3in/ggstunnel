package carrier

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"sync"
	"sync/atomic"
	"time"

	"ggstunnel/internal/config"
	"ggstunnel/internal/session"
)

// This explicitly negotiated lifecycle is independent of opaque v1 data frames.
// Only a consumed, fresh receiver challenge may replace the accepted identity.
// OpenForSession in the engine keeps data from any other identity inadmissible.
const genericControlSize = 12 + 83 + 16
const genericSessionWire uint16 = 0x0601

var ErrPeerNotReady = errors.New("authenticated peer identity not yet established")

type authenticatedCarrier struct {
	inner                                      Carrier
	cfg                                        *config.Config
	key                                        []byte
	seal, open                                 cipher.AEAD
	gate                                       *session.Gate
	local                                      uint64
	role                                       byte
	rx                                         chan []byte
	errors                                     chan error
	closed                                     chan struct{}
	once                                       sync.Once
	mu                                         sync.Mutex
	started                                    bool
	workers                                    sync.WaitGroup
	startedAt                                  atomic.Int64
	peer                                       atomic.Uint64
	controlTX, controlRX, rejected, queueDrops atomic.Uint64
	reflections                                atomic.Uint64
}

func newAuthenticatedCarrier(c *config.Config, inner Carrier) (*authenticatedCarrier, error) {
	key, err := hkdf.Key(sha256.New, []byte(c.PSK), nil, "ggstunnel/generic-challenge/"+c.Profile+"/v1", 32)
	if err != nil {
		return nil, err
	}
	role := byte(1)
	if c.Role == "client" {
		role = 2
	}
	makeAEAD := func(role byte) (cipher.AEAD, error) {
		k, err := hkdf.Key(sha256.New, key, []byte{role}, "control-aead", 32)
		if err != nil {
			return nil, err
		}
		b, err := aes.NewCipher(k)
		if err != nil {
			return nil, err
		}
		return cipher.NewGCM(b)
	}
	tx, err := makeAEAD(role)
	if err != nil {
		return nil, err
	}
	rx, err := makeAEAD(3 - role)
	if err != nil {
		return nil, err
	}
	return &authenticatedCarrier{inner: inner, cfg: c, key: key, role: role, seal: tx, open: rx,
		rx: make(chan []byte, c.Performance.QueueSize), errors: make(chan error, 1), closed: make(chan struct{})}, nil
}

func (a *authenticatedCarrier) BindIdentity(id uint64) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.started || a.local != 0 {
		return errors.New("cannot change a running authenticated identity")
	}
	g, err := session.NewGate(a.key, id, genericSessionWire)
	if err != nil {
		return err
	}
	a.local, a.gate = id, g
	return nil
}
func (a *authenticatedCarrier) Name() string         { return a.inner.Name() }
func (a *authenticatedCarrier) Recv() <-chan []byte  { return a.rx }
func (a *authenticatedCarrier) Errors() <-chan error { return a.errors }
func (a *authenticatedCarrier) PeerSession() uint64 {
	return a.peer.Load()
}
func (a *authenticatedCarrier) Send(b []byte) error {
	select {
	case <-a.closed:
		return ErrClosed
	default:
	}
	if a.PeerSession() == 0 {
		return ErrPeerNotReady
	}
	return a.inner.Send(b)
}
func (a *authenticatedCarrier) SendContext(ctx context.Context, b []byte) error {
	if a.PeerSession() != 0 {
		return a.Send(b)
	}
	// A bounded wait keeps TUN pressure bounded while carrier-owned control
	// traffic independently establishes the identity. Close always cancels it.
	tick := time.NewTicker(10 * time.Millisecond)
	defer tick.Stop()
	for {
		if a.PeerSession() != 0 {
			return a.Send(b)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-a.closed:
			return ErrClosed
		case <-tick.C:
		}
	}
}
func (a *authenticatedCarrier) Start(ctx context.Context) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.started || a.gate == nil {
		return errors.New("identity must be bound once before Start")
	}
	select {
	case <-a.closed:
		return ErrClosed
	default:
	}
	if err := a.inner.Start(ctx); err != nil {
		return err
	}
	a.started = true
	a.startedAt.Store(time.Now().UnixNano())
	a.workers.Add(1)
	go func() { defer a.workers.Done(); a.loop(ctx) }()
	return nil
}
func (a *authenticatedCarrier) Close() error {
	a.once.Do(func() {
		a.mu.Lock()
		close(a.closed)
		a.mu.Unlock()
		_ = a.inner.Close()
	})
	a.workers.Wait()
	return nil
}
func (a *authenticatedCarrier) SnapshotStats() RuntimeStats {
	var s RuntimeStats
	if inner, ok := a.inner.(Statser); ok {
		s = inner.SnapshotStats()
	}
	s.WireMode, s.SessionMode = "opaque", "challenge"
	s.PeerAuthenticated = a.PeerSession() != 0
	s.ControlPacketsTx, s.ControlPacketsRx = a.controlTX.Load(), a.controlRX.Load()
	s.ControlRejected, s.ReceiveQueueDrops = a.rejected.Load(), s.ReceiveQueueDrops+a.queueDrops.Load()
	s.ReflectionsSuppressed += a.reflections.Load()
	if at := a.startedAt.Load(); !s.PeerAuthenticated && at != 0 {
		s.HandshakeWaitMS = time.Since(time.Unix(0, at)).Milliseconds()
	}
	return s
}

// kind=HELLO(1), CHALLENGE(2), PROOF(3). The entire fixed-size body is
// encrypted with direction- and carrier-specific keys and a random nonce.
func (a *authenticatedCarrier) control(kind byte, target uint64, nonce [32]byte, proof [32]byte) error {
	p := make([]byte, 83)
	p[0], p[9] = kind, a.role
	binary.BigEndian.PutUint64(p[1:9], a.local)
	binary.BigEndian.PutUint64(p[10:18], target)
	copy(p[18:50], nonce[:])
	p[50] = 3 - a.role
	copy(p[51:83], proof[:])
	w := make([]byte, a.seal.NonceSize(), genericControlSize)
	if _, err := rand.Read(w); err != nil {
		return err
	}
	w = a.seal.Seal(w, w, p, nil)
	if err := a.inner.Send(w); err != nil {
		return err
	}
	a.controlTX.Add(1)
	return nil
}
func (a *authenticatedCarrier) loop(ctx context.Context) {
	tick := time.NewTicker(250 * time.Millisecond)
	defer tick.Stop()
	var lastHello, budgetStart time.Time
	controlBudget := 0
	var carrierErrors <-chan error
	if e, ok := a.inner.(interface{ Errors() <-chan error }); ok {
		carrierErrors = e.Errors()
	}
	fail := func(err error) {
		select {
		case a.errors <- err:
		default:
		}
	}
	for {
		select {
		case <-ctx.Done():
			return
		case <-a.closed:
			return
		case err := <-carrierErrors:
			if err == nil {
				err = io.ErrUnexpectedEOF
			}
			fail(err)
			return
		case now := <-tick.C:
			interval := 500 * time.Millisecond
			if a.PeerSession() != 0 {
				interval = 5 * time.Second
			}
			if lastHello.IsZero() || now.Sub(lastHello) >= interval {
				if err := a.control(1, 0, [32]byte{}, [32]byte{}); err != nil && !errors.Is(err, ErrQueueFull) {
					fail(err)
					return
				}
				lastHello = now
			}
		case wire, ok := <-a.inner.Recv():
			if !ok {
				fail(io.ErrUnexpectedEOF)
				return
			}
			if len(wire) == genericControlSize {
				p, err := a.open.Open(nil, wire[:12], wire[12:], nil)
				if err == nil {
					now := time.Now()
					if now.Sub(budgetStart) >= time.Second {
						budgetStart = now
						controlBudget = 0
					}
					controlBudget++
					if controlBudget > 32 {
						a.rejected.Add(1)
						continue
					}
					a.controlRX.Add(1)
					if err := a.receiveControl(p, now); err != nil {
						if errors.Is(err, session.ErrRotationLimit) {
							fail(err)
							return
						}
						a.rejected.Add(1)
					}
					continue
				}
				// The kernel may echo our own ICMP control ciphertext. Recognize
				// its authenticated direction without mutating peer/replay state.
				if _, err := a.seal.Open(nil, wire[:12], wire[12:], nil); err == nil {
					a.reflections.Add(1)
					continue
				}
			}
			if a.PeerSession() == 0 {
				a.rejected.Add(1)
				continue
			}
			select {
			case a.rx <- wire:
			case <-ctx.Done():
				return
			case <-a.closed:
				return
			default:
				a.queueDrops.Add(1)
			}
		}
	}
}
func (a *authenticatedCarrier) receiveControl(p []byte, now time.Time) error {
	if len(p) != 83 || p[9] != 3-a.role {
		return errors.New("control role mismatch")
	}
	sender, target := binary.BigEndian.Uint64(p[1:9]), binary.BigEndian.Uint64(p[10:18])
	if sender == 0 || sender == a.local {
		return errors.New("invalid control identity")
	}
	var nonce [32]byte
	copy(nonce[:], p[18:50])
	var proof [32]byte
	copy(proof[:], p[51:83])
	switch p[0] {
	case 1:
		if target != 0 {
			return errors.New("bad hello target")
		}
		c, err := a.gate.IssueReusable(sender, p[9], now)
		if err != nil {
			return err
		}
		return a.control(2, sender, c.Nonce, [32]byte{})
	case 2:
		if target != a.local || p[50] != a.role {
			return errors.New("challenge target mismatch")
		}
		c := session.Challenge{Nonce: nonce, LocalID: sender, PeerID: a.local, Role: a.role, Wire: genericSessionWire}
		if err := a.control(3, sender, nonce, session.Proof(a.key, c)); err != nil {
			return err
		}
		if a.PeerSession() != sender {
			challenge, err := a.gate.IssueReusable(sender, p[9], now)
			if err != nil {
				return err
			}
			return a.control(2, sender, challenge.Nonce, [32]byte{})
		}
		return nil
	case 3:
		if target != a.local || p[50] != a.role {
			return errors.New("proof target mismatch")
		}
		c := session.Challenge{Nonce: nonce, LocalID: a.local, PeerID: sender, Role: p[9], Wire: genericSessionWire}
		if err := a.gate.Accept(c, proof, now); err != nil {
			return err
		}
		a.peer.Store(sender)
		return nil
	default:
		return errors.New("unknown control type")
	}
}
