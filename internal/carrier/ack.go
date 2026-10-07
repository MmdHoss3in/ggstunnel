package carrier

import "time"

// A successfully emitted packet can carry the ACK instead of a separate
// control packet. Preserve the reply/request direction for stateful paths,
// and keep dedicated ACKs when the receiver needs the wide SACK extension.
func (b *BIP) coalesceAck(p wirePacket) {
	if b.ackDue.IsZero() || p.kind >= bipKindHello || p.kind == bipKindAck || p.typ != b.ackType || p.target != b.active {
		return
	}
	ack, sack := b.takeAckForSend()
	if p.ack != ack || p.sack&sack != sack {
		return
	}
	b.ackMu.Lock()
	for seq := range b.rxAck.seen {
		if sequenceDistance(ack, seq) > 64 {
			b.ackMu.Unlock()
			return
		}
	}
	b.ackMu.Unlock()
	b.ackDue = time.Time{}
	b.ackCount = 0
	b.lastAck = time.Now()
	b.acksCoalesced.Add(1)
}

// Retain the latest authenticated request tuple so a delayed EchoReply ACK
// remains usable through a stateful path. Flush every 16 frames or ACK interval.
// Duplicates get an immediate ACK to recover a lost acknowledgement.
func (b *BIP) scheduleAck(p wirePacket, now time.Time, immediate bool) {
	b.ackType, b.ackID, b.ackTuple = b.ackReturnType(p, now), p.id, p.tuple
	b.ackCount++
	if b.ackDue.IsZero() {
		b.ackDue = now.Add(time.Duration(b.cfg.Transport.BIPAckMS) * time.Millisecond)
	}
	if immediate || b.ackCount >= 16 {
		b.flushAck(now)
	}
}

func (b *BIP) flushAck(now time.Time) {
	if b.ackType == 8 || b.controlReply.ackBackup {
		b.ackID, b.ackTuple = b.nextTuple()
	}
	err := b.send(b.ackType, b.ackID, b.ackTuple, bipKindAck, 0, 0, nil, b.active)
	if b.controlReply.ackBackup {
		if err == nil {
			b.controlReply.sent.Add(1)
		}
		// Keep a request ACK as a safety net during a route transition. This
		// adds control only; successful DATA piggyback still avoids both ACKs.
		id, tuple := b.nextTuple()
		backupErr := b.send(8, id, tuple, bipKindAck, 0, 0, nil, b.active)
		if backupErr == nil {
			err = nil
		}
	}
	if err != nil {
		b.ackDue = now.Add(time.Duration(b.cfg.Transport.BIPAckMS) * time.Millisecond)
		return
	}
	b.ackDue = time.Time{}
	b.ackCount = 0
	b.lastAck = now
}
