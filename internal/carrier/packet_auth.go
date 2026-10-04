package carrier

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"hash"
)

// Actor-owned keyed state. Master/session caches are independent and replaced
// when the corresponding key changes. No wire field or MAC input changes.
type packetAuthenticator struct {
	key []byte
	mac hash.Hash
}

func (b *BIP) wireMAC(body []byte, typ byte) [16]byte {
	key := b.macKey(body[12])
	auth := &b.sessionAuth
	if body[12] >= bipKindHello {
		auth = &b.masterAuth
	}
	if auth.mac == nil || !bytes.Equal(auth.key, key) {
		auth.key = append(auth.key[:0], key...)
		auth.mac = hmac.New(sha256.New, key)
	}
	auth.mac.Reset()
	header := [2]byte{typ, body[1]}
	auth.mac.Write(header[:])
	auth.mac.Write(body[4:56])
	auth.mac.Write(body[72:])
	var full [32]byte
	var tag [16]byte
	copy(tag[:], auth.mac.Sum(full[:0]))
	return tag
}
