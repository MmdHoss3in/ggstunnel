package carrier

import "time"

// Retain the latest authenticated request tuple so a delayed EchoReply ACK
// remains usable through a stateful path. Flush every 16 frames or ACK interval.
// Duplicates get an immediate ACK to recover a lost acknowledgement.
func (b *BIP) scheduleAck(p wirePacket, now time.Time, immediate bool) {
	b.ackType, b.ackID, b.ackTuple = responseType(p), p.id, p.tuple
	b.ackCount++
	if b.ackDue.IsZero() {
		b.ackDue = now.Add(time.Duration(b.cfg.Transport.BIPAckMS) * time.Millisecond)
	}
	if immediate || b.ackCount >= 16 {
		b.flushAck(now)
	}
}

func (b *BIP) flushAck(now time.Time) {
	if b.ackType == 8 {
		b.ackID, b.ackTuple = b.nextTuple()
	}
	if err := b.send(b.ackType, b.ackID, b.ackTuple, bipKindAck, 0, 0, nil, b.active); err != nil {
		b.ackDue = now.Add(time.Duration(b.cfg.Transport.BIPAckMS) * time.Millisecond)
		return
	}
	b.ackDue = time.Time{}
	b.ackCount = 0
	b.lastAck = now
}
