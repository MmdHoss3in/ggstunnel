package carrier

// The actor owns the bounded reorder buffer. Acceptance/SACK means the frame
// is retained, not necessarily already consumed by TUN. Preserve a slot for
// the missing next frame so a full future window cannot deadlock recovery.
// Caller of receiveOrdered holds ackMu.
func (b *BIP) receiveOrdered(seq uint32, payload []byte) bool {
	if b.rxNext == 0 {
		b.rxNext = nextSequence(b.rxAck.max)
	}
	if b.rxHold == nil {
		b.rxHold = make(map[uint32][]byte)
	}
	b.drainRX()
	limit := b.window()
	if len(b.rxHold) >= limit || (seq != b.rxNext && len(b.rxHold) >= limit-1) {
		return false
	}
	b.rxHold[seq] = append([]byte(nil), payload...)
	b.rxBuffered.Store(uint64(len(b.rxHold)))
	b.recordRXSeqLocked(seq)
	b.payloadFrameRx.Add(1)
	b.drainRX()
	return true
}

func (b *BIP) drainRX() {
	for i := 0; i < 256; i++ {
		payload, ok := b.rxHold[b.rxNext]
		if !ok {
			return
		}
		select {
		case b.rx <- payload:
			delete(b.rxHold, b.rxNext)
			b.rxBuffered.Store(uint64(len(b.rxHold)))
			b.rxNext = nextSequence(b.rxNext)
		default:
			return
		}
	}
}
