package frame

import (
	"encoding/binary"
)

// Compact preserves the original ciphertext, nonce, tag and associated data.
// The carrier supplies the authenticated sender identity on reconstruction.
// Marker zero escapes arbitrary carrier-test payloads without reinterpreting
// them as frames. It is inside the encrypted compact carrier envelope.
func Compact(b []byte, sender uint64) []byte {
	if len(b) >= HeaderLen+NonceLen+16 {
		h, err := parseHeader(b)
		if err == nil && h.SessionID == sender && h.Seq <= 1<<32 {
			out := make([]byte, 13+len(b)-HeaderLen)
			out[0] = h.Type
			binary.BigEndian.PutUint32(out[1:5], uint32(h.Seq))
			copy(out[5:13], b[24:32])
			copy(out[13:], b[HeaderLen:])
			return out
		}
	}
	return append([]byte{0}, b...)
}

func ExpandCompact(b []byte, sender uint64) ([]byte, error) {
	if len(b) == 0 { return nil, ErrMalformed }
	if b[0] == 0 { return append([]byte(nil), b[1:]...), nil }
	if sender == 0 || len(b) < 13+NonceLen+16 || (b[0] != TypeData && b[0] != TypeHeartbeat) { return nil, ErrMalformed }
	seq := uint64(binary.BigEndian.Uint32(b[1:5]))
	// The existing codec admits sequence 2^32 as its final frame.
	if seq == 0 { seq = 1<<32 }
	h := Header{Type:b[0],SessionID:sender,Seq:seq,PacketID:binary.BigEndian.Uint32(b[5:9]),FragIndex:binary.BigEndian.Uint16(b[9:11]),FragCount:binary.BigEndian.Uint16(b[11:13])}
	out := make([]byte, HeaderLen+len(b)-13)
	writeHeader(out[:HeaderLen],h)
	if _,err := parseHeader(out); err != nil { return nil, ErrMalformed }
	copy(out[HeaderLen:],b[13:])
	return out,nil
}
