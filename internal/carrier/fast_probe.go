package carrier

import (
	"crypto/rand"
	"encoding/binary"
	"time"
)

// Retransmit an unanswered probe at the configured probe interval, with a new
// outer tuple/counter but the same still-live token and unchanged deadline.
// Waiting an entire token TTL after one lost probe can expire a working FAST
// path and spend DATA retries on a blocked request fallback.
func (b *BIP) maintainFASTProbe(now time.Time) error {
	if now.Sub(b.lastProbe) < time.Duration(b.cfg.Transport.BIPFastProbeMS)*time.Millisecond {
		return nil
	}
	if b.fastToken == 0 || !now.Before(b.fastDeadline) {
		b.controlReply.probeAttempts = 0
		var seed [4]byte
		if _, err := rand.Read(seed[:]); err != nil {
			return err
		}
		b.fastToken = binary.BigEndian.Uint32(seed[:])
		if b.fastToken == 0 {
			b.fastToken = 1
		}
		b.fastDeadline = now.Add(time.Duration(b.cfg.Transport.BIPFastTTLMS) * time.Millisecond)
	}
	id, tuple := b.nextTuple()
	flags := byte(0)
	if b.controlReply.preferReply || b.controlReply.probeAttempts > 0 {
		flags = bipFlagReplyControl
	}
	_ = b.send(0, id, tuple, bipKindFastProbe, flags, b.fastToken, nil, b.active)
	b.controlReply.probeAttempts++
	b.lastProbe = now
	b.fastProbeTx.Add(1)
	return nil
}
