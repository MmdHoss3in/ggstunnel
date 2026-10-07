package carrier

import (
	"sync/atomic"
	"time"
)

// MORE was ignored on FAST_PROBE by legacy peers. In this kind only, its
// authenticated use asks for an additional EchoReply control return path.
// Neither the hint nor receiving a peer probe proves our outgoing FAST path.
const bipFlagReplyControl = bipFlagMore

type controlReplyPath struct {
	probeAttempts uint64
	preferReply   bool
	peerUntil     time.Time
	ackBackup     bool

	sent     atomic.Uint64
	accepted atomic.Uint64
}

func (c *controlReplyPath) reset() {
	c.probeAttempts = 0
	c.preferReply = false
	c.peerUntil = time.Time{}
	c.ackBackup = false
}

func (b *BIP) respondFASTProbe(p wirePacket, now time.Time) {
	// Always retain the traditional response, including its paired tuple on
	// stateful paths. A requested alternative uses a fresh wire counter/MAC.
	b.fastAckTx.Add(1)
	_ = b.sendResponse(p, bipKindFastAck, 0, p.token, nil, b.active)
	if p.typ != 0 || p.token == 0 {
		return
	}
	if p.flags&bipFlagReplyControl == 0 {
		b.controlReply.peerUntil = time.Time{}
		return
	}
	b.controlReply.peerUntil = now.Add(time.Duration(b.cfg.Transport.BIPFastTTLMS) * time.Millisecond)
	id, tuple := b.nextTuple()
	b.fastAckTx.Add(1)
	if b.send(0, id, tuple, bipKindFastAck, 0, p.token, nil, b.active) == nil {
		b.controlReply.sent.Add(1)
	}
}

func (b *BIP) ackReturnType(p wirePacket, now time.Time) byte {
	typ := responseType(p)
	b.controlReply.ackBackup = typ == 8 && now.Before(b.controlReply.peerUntil)
	if b.controlReply.ackBackup {
		return 0
	}
	return typ
}
