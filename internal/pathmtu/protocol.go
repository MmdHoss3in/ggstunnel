// Package pathmtu defines a small, authenticated-carrier-only size probe.
package pathmtu

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
)

const Header = 24

var marker = []byte{0x70, 0x6d, 0x74, 0x31}
var ErrUnsupported = errors.New("peer does not support authenticated size probes")

func Request(size int) ([]byte, error) {
	if size < Header || size > 1500 {
		return nil, errors.New("invalid path probe size")
	}
	p := make([]byte, Header)
	copy(p, marker)
	p[4] = 1
	binary.BigEndian.PutUint16(p[6:8], uint16(size))
	_, err := rand.Read(p[8:])
	return p, err
}
func Size(p []byte) (int, bool) {
	if len(p) < Header || !bytes.Equal(p[:4], marker) || p[4] != 1 || p[5] != 0 {
		return 0, false
	}
	size := int(binary.BigEndian.Uint16(p[6:8]))
	return size, size >= Header && size <= 1500
}
func Reply(p []byte) []byte {
	if _, ok := Size(p); !ok {
		return nil
	}
	r := append([]byte(nil), p[:Header]...)
	r[4] = 2
	return r
}
func Matches(request, reply []byte) bool {
	if len(request) < Header || len(reply) != Header {
		return false
	}
	return reply[4] == 2 && bytes.Equal(reply[:4], request[:4]) && bytes.Equal(reply[5:], request[5:Header])
}
