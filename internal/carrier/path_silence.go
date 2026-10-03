package carrier

import (
	"fmt"
	"time"
)

// An entirely unresponsive path cannot provide delivery or loss evidence.
// Keep the bounded encrypted flight/backlog and continue path probes, rather
// than exhaust every frame's retry budget during an arbitrarily long blackout.
// A path that still responds but fails to deliver data remains budget-limited.
func (b *BIP) pathUnresponsive(now time.Time) bool {
	if b.lastPeerActivity.IsZero() {
		return false
	}
	quiet := time.Duration(b.cfg.Transport.BIPFastTTLMS) * time.Millisecond
	if b.tuner != nil {
		quiet = max(quiet, 3*b.tuner.rto)
	}
	return now.Sub(b.lastPeerActivity) >= quiet
}

// Called only after authentication, active-identity and replay checks. Replayed
// or reflected control packets must not keep a failed path artificially alive.
// A fresh receiver-issued challenge proof can also confirm the existing peer.
func (b *BIP) observePeerActivity(now time.Time) {
	wasSilent := b.pathUnresponsive(now)
	b.lastPeerActivity = now
	b.peerSilenceMS.Store(0)
	if wasSilent {
		b.expeditePathRetries(now)
	}
}

// HELLO uses the master key and can rediscover a peer when session controls are
// filtered or stale. A valid proof for the same identity preserves flight data,
// replay protection and key counters. Reflections never reach this confirmation.
func (b *BIP) maintainPeerLiveness(now time.Time) error {
	if b.active == 0 || b.lastPeerActivity.IsZero() {
		b.peerSilenceMS.Store(0)
		return nil
	}
	silent := max(0, now.Sub(b.lastPeerActivity))
	b.peerSilenceMS.Store(silent.Milliseconds())
	if !b.pathUnresponsive(now) {
		return nil
	}
	if silent >= time.Duration(b.cfg.Transport.BIPDeadTimeoutSec)*time.Second {
		return fmt.Errorf("%w after %s without authenticated peer response", ErrBIPPeerUnresponsive, silent.Round(time.Second))
	}
	if now.Sub(b.lastHello) >= b.cfg.RetryInterval() {
		id, tuple := b.nextTuple()
		_ = b.send(8, id, tuple, bipKindHello, 0, 0, []byte{b.localRole()}, 0)
		b.lastHello = now
		b.rehandshakeTries.Add(1)
	}
	return nil
}
