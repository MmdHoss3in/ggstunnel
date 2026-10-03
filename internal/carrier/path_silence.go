package carrier

import "time"

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
func (b *BIP) observePeerActivity(now time.Time) {
	wasSilent := b.pathUnresponsive(now)
	b.lastPeerActivity = now
	if wasSilent {
		b.expeditePathRetries(now)
	}
}
