package carrier

import "encoding/binary"

// The actor owns the bounded reorder buffer. Acceptance/SACK means the frame
// is retained, not necessarily already consumed by TUN. Preserve a slot for
// the missing next frame so a full future window cannot deadlock recovery.
// Caller of receiveOrdered holds ackMu.
func (b *BIP) receiveOrdered(seq uint32, payload []byte) bool {
	return b.receiveOrderedPayload(seq, payload, false)
}

func (b *BIP) receiveOrderedPayload(seq uint32, payload []byte, packed bool) bool {
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
	if packed {
		if b.rxPacked == nil { b.rxPacked = make(map[uint32]int) }
		b.rxPacked[seq] = 1
	}
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
		offset, packed := b.rxPacked[b.rxNext]
		frame := payload
		next := len(payload)
		if packed {
			size := int(binary.BigEndian.Uint16(payload[offset:]))
			next = offset+2+size
			frame = payload[offset+2:next]
		}
		select {
		case b.rx <- frame:
			if packed && next < len(payload) { b.rxPacked[b.rxNext] = next; continue }
			delete(b.rxHold, b.rxNext)
			delete(b.rxPacked, b.rxNext)
			b.rxBuffered.Store(uint64(len(b.rxHold)))
			b.rxNext = nextSequence(b.rxNext)
		default:
			return
		}
	}
}
