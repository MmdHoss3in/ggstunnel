package frame

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
)

// Opaque v1 is an explicit, incompatible PSK packet format, not TLS/QUIC.
// Twelve bytes of alias/masked counter precede a single AEAD envelope containing
// type, packet ID, fragment indices and the IP payload. No public magic string.
// A per-session alias remains observable; this does not hide traffic patterns.
const OpaqueOverhead = 12 + 9 + 16

type opaqueState struct {
	mask          uint64
	send, receive cipher.Block
}

func NewOpaqueCodec(psk string) (*Codec, error) {
	c, err := NewCodec(psk)
	if err != nil {
		return nil, err
	}
	mask, err := hkdf.Key(sha256.New, c.master, nil, "ggstunnel/opaque/alias/v1", 8)
	if err != nil {
		return nil, err
	}
	c.opaque = &opaqueState{mask: binary.BigEndian.Uint64(mask)}
	c.aead, c.opaque.send, err = c.opaqueKeys(c.sessionID)
	return c, err
}

// The challenge lifecycle uses a separate data-key domain bound to BOTH
// endpoint identities. A local restart cannot reset replay protection for
// ciphertext addressed to an old local identity, even if the sender stays up.
func NewBoundOpaqueCodec(psk string) (*Codec, error) {
	c, err := NewOpaqueCodec(psk)
	if err != nil {
		return nil, err
	}
	c.boundOpaque = true
	return c, nil
}
func (c *Codec) BindSendPeer(id uint64) error {
	c.sendMu.Lock()
	defer c.sendMu.Unlock()
	if !c.boundOpaque || id == 0 || id == c.sessionID {
		return ErrPeerNotBound
	}
	if c.sendPeer == id {
		return nil
	}
	aead, header, err := c.boundOpaqueKeys(c.sessionID, id)
	if err != nil {
		return err
	}
	c.aead, c.opaque.send, c.sendPeer = aead, header, id
	return nil
}
func (c *Codec) boundOpaqueKeys(sender, receiver uint64) (cipher.AEAD, cipher.Block, error) {
	var salt [16]byte
	binary.BigEndian.PutUint64(salt[:8], sender)
	binary.BigEndian.PutUint64(salt[8:], receiver)
	derive := func(label string) (cipher.Block, error) {
		key, err := hkdf.Key(sha256.New, c.master, salt[:], "ggstunnel/opaque-bound/"+label+"/v2", 32)
		if err != nil {
			return nil, err
		}
		return aes.NewCipher(key)
	}
	b, err := derive("data")
	if err != nil {
		return nil, nil, err
	}
	aead, err := cipher.NewGCM(b)
	if err != nil {
		return nil, nil, err
	}
	header, err := derive("header")
	return aead, header, err
}

func (c *Codec) opaqueKeys(sid uint64) (cipher.AEAD, cipher.Block, error) {
	var salt [8]byte
	binary.BigEndian.PutUint64(salt[:], sid)
	derive := func(label string) (cipher.Block, error) {
		key, err := hkdf.Key(sha256.New, c.master, salt[:], "ggstunnel/opaque/"+label+"/v1", 32)
		if err != nil {
			return nil, err
		}
		return aes.NewCipher(key)
	}
	block, err := derive("data")
	if err != nil {
		return nil, nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, err
	}
	header, err := derive("header")
	return aead, header, err
}

func maskOpaqueCounter(header cipher.Block, packet []byte) {
	var mask [16]byte
	header.Encrypt(mask[:], packet[12:28])
	for i := 0; i < 4; i++ {
		packet[8+i] ^= mask[i]
	}
}

func (c *Codec) sealOpaque(typ byte, packetID uint32, fragIndex, fragCount uint16, payload []byte) ([]byte, error) {
	if (typ != TypeData && typ != TypeHeartbeat) || fragCount == 0 || fragCount > 128 || fragIndex >= fragCount || len(payload) > 65535 {
		return nil, ErrMalformed
	}
	seq := c.seq.Add(1)
	if seq > 1<<32 {
		return nil, ErrKeyLifetime
	}
	var nonce [12]byte
	binary.BigEndian.PutUint64(nonce[:8], c.sessionID^c.opaque.mask)
	binary.BigEndian.PutUint32(nonce[8:], uint32(seq))
	plain := make([]byte, 9+len(payload))
	plain[0] = typ
	binary.BigEndian.PutUint32(plain[1:5], packetID)
	binary.BigEndian.PutUint16(plain[5:7], fragIndex)
	binary.BigEndian.PutUint16(plain[7:9], fragCount)
	copy(plain[9:], payload)
	out := make([]byte, 12, OpaqueOverhead+len(payload))
	copy(out, nonce[:])
	out = c.aead.Seal(out, nonce[:], plain, nonce[:])
	maskOpaqueCounter(c.opaque.send, out)
	return out, nil
}

func (c *Codec) opaqueSession(b []byte) (uint64, bool) {
	if len(b) < OpaqueOverhead {
		return 0, false
	}
	sid := binary.BigEndian.Uint64(b[:8]) ^ c.opaque.mask
	return sid, sid != 0
}

func (c *Codec) openOpaque(b []byte) (*Decoded, error) {
	sid, ok := c.opaqueSession(b)
	if !ok {
		return nil, ErrMalformed
	}
	if sid == c.sessionID {
		return nil, ErrReflectedLocal
	}
	aead, header := c.receiver, c.opaque.receive
	if c.receiverID != sid {
		var err error
		if c.boundOpaque {
			aead, header, err = c.boundOpaqueKeys(sid, c.sessionID)
		} else {
			aead, header, err = c.opaqueKeys(sid)
		}
		if err != nil {
			return nil, err
		}
	}
	var nonce [12]byte
	copy(nonce[:], b[:12])
	var mask [16]byte
	header.Encrypt(mask[:], b[12:28])
	for i := 0; i < 4; i++ {
		nonce[8+i] ^= mask[i]
	}
	seq := uint64(binary.BigEndian.Uint32(nonce[8:]))
	if seq == 0 {
		seq = 1 << 32
	}
	if !c.replay.Precheck(sid, seq) {
		return nil, ErrReplay
	}
	plain, err := aead.Open(nil, nonce[:], b[12:], nonce[:])
	if err != nil {
		return nil, ErrAuthentication
	}
	h := Header{Type: plain[0], SessionID: sid, Seq: seq, PacketID: binary.BigEndian.Uint32(plain[1:5]), FragIndex: binary.BigEndian.Uint16(plain[5:7]), FragCount: binary.BigEndian.Uint16(plain[7:9])}
	if (h.Type != TypeData && h.Type != TypeHeartbeat) || h.FragCount == 0 || h.FragCount > 128 || h.FragIndex >= h.FragCount {
		return nil, fmt.Errorf("%w: opaque metadata", ErrMalformed)
	}
	c.receiver, c.receiverID, c.opaque.receive = aead, sid, header
	c.replay.Commit(sid, seq)
	return &Decoded{Header: h, Payload: plain[9:]}, nil
}
