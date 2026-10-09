package carrier

import (
	"bytes"
	"encoding/binary"
)

// READY's payload was ignored by older BIP5 implementations. Keep its old
// flags and shape; never send a new DATA flag until a verified active peer
// advertises or confirms receive support. Each nested frame retains its original
// independent AEAD nonce, sender identity, packet ID and replay sequence.
var packOffer = []byte("GGS-PACK1-OFFER")
var packAccept = []byte("GGS-PACK1-ACCEPT")

func (b *BIP) packOfferPayload() []byte {
	if b.allowPacking {
		return packOffer
	}
	return nil
}

func (b *BIP) handlePackReady(p wirePacket) {
	if !b.allowPacking || b.active == 0 || p.sender != b.active || p.target != b.localID {
		return
	}
	switch {
	case bytes.Equal(p.payload, packOffer):
		b.peerPackSupport = true
		b.packetPacking.Store(true)
		_ = b.sendResponse(p, bipKindReady, 0, 0, packAccept, b.active)
	case bytes.Equal(p.payload, packAccept):
		b.peerPackSupport = true
		b.packetPacking.Store(true)
	}
}

func (b *BIP) txBacklog() int {
	n := len(b.tx)
	if b.heldTXPresent.Load() {
		n++
	}
	return n
}

func (b *BIP) popTX() []byte {
	if b.heldTX != nil {
		p := b.heldTX
		b.heldTX = nil
		b.heldTXPresent.Store(false)
		return p
	}
	select {
	case p := <-b.tx:
		return p
	default:
		return nil
	}
}

func appendPackedFrame(dst, frame []byte) []byte {
	dst = binary.BigEndian.AppendUint16(dst, uint16(len(frame)))
	return append(dst, frame...)
}

// Consume only already queued frames. One lookahead preserves FIFO when the
// next frame cannot fit; the channel's bounded backlog gains at most one slot.
func (b *BIP) takeTXPayload() ([]byte, byte, int) {
	first := b.popTX()
	limit := min(1408, int(b.pathPayload.Load())+60)
	if limit == 60 {
		limit = min(1408, b.cfg.Performance.MaxFramePayload+60)
	}
	if first == nil || !b.packetPacking.Load() || len(b.tx) == 0 || len(first)+5 >= limit {
		return first, 0, 1
	}
	second := b.popTX()
	if second == nil {
		return first, 0, 1
	}
	if 5+len(first)+len(second) > limit {
		b.heldTX = second
		b.heldTXPresent.Store(true)
		return first, 0, 1
	}
	payload := make([]byte, 1, limit)
	payload = appendPackedFrame(payload, first)
	payload = appendPackedFrame(payload, second)
	count := 2
	for count < 16 && len(b.tx) > 0 {
		next := b.popTX()
		if next == nil {
			break
		}
		if len(payload)+2+len(next) > limit {
			b.heldTX = next
			b.heldTXPresent.Store(true)
			break
		}
		payload = appendPackedFrame(payload, next)
		count++
	}
	payload[0] = byte(count)
	return payload, bipFlagPacked, count
}

func validatePacked(payload []byte, limit int) (int, bool) {
	if len(payload) < 1 || len(payload) > min(1408, limit) || payload[0] < 2 || payload[0] > 16 {
		return 0, false
	}
	offset := 1
	for i := 0; i < int(payload[0]); i++ {
		if offset+2 > len(payload) {
			return 0, false
		}
		size := int(binary.BigEndian.Uint16(payload[offset:]))
		offset += 2
		if size == 0 || size > limit || size > len(payload)-offset {
			return 0, false
		}
		offset += size
	}
	return int(payload[0]), offset == len(payload)
}
