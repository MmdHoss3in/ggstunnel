package frame

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"
)

const (
	Version       byte = 1
	TypeData      byte = 1
	TypeHeartbeat byte = 2
	HeaderLen          = 32
	NonceLen           = 12
)

var (
	magic             = [4]byte{'G', 'G', 'S', '1'}
	ErrKeyLifetime    = errors.New("data key lifetime exceeded; fresh identity required")
	ErrMalformed      = errors.New("malformed frame")
	ErrReflectedLocal = errors.New("reflected local frame")
	ErrReplay         = errors.New("replayed or stale frame")
	ErrAuthentication = errors.New("authentication failed")
)

type Header struct {
	Type      byte
	Flags     byte
	SessionID uint64
	Seq       uint64
	PacketID  uint32
	FragIndex uint16
	FragCount uint16
}

type Decoded struct {
	Header  Header
	Payload []byte
}

type Codec struct {
	master      []byte
	receiverID  uint64
	receiver    cipher.AEAD
	aead        cipher.AEAD
	sessionID   uint64
	seq         atomic.Uint64
	packetID    atomic.Uint32
	replay      *ReplayGuard
	peerSession uint64
}

func NewCodec(psk string) (*Codec, error) {
	if len(psk) < 12 {
		return nil, errors.New("PSK must be at least 12 bytes")
	}
	master, err := hkdf.Key(sha256.New, []byte(psk), nil, "ggstunnel/frame/master", 32)
	if err != nil {
		return nil, err
	}
	var sid [8]byte
	if _, err := rand.Read(sid[:]); err != nil {
		return nil, err
	}
	c := &Codec{master: master, sessionID: binary.BigEndian.Uint64(sid[:]), replay: NewReplayGuard(4096)}
	if c.sessionID == 0 {
		c.sessionID = 1
	}
	aead, err := c.dataAEAD(c.sessionID)
	if err != nil {
		return nil, err
	}
	c.aead = aead
	c.seq.Store(1)
	c.packetID.Store(1)
	return c, nil
}

func (c *Codec) dataAEAD(sid uint64) (cipher.AEAD, error) {
	var salt [8]byte
	binary.BigEndian.PutUint64(salt[:], sid)
	key, err := hkdf.Key(sha256.New, c.master, salt[:], "ggstunnel/sender-data/v1", 32)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func (c *Codec) NextPacketID() uint32 { return c.packetID.Add(1) }
func (c *Codec) SessionID() uint64    { return c.sessionID }

func (c *Codec) Seal(typ byte, packetID uint32, fragIndex, fragCount uint16, payload []byte) ([]byte, error) {
	if (typ != TypeData && typ != TypeHeartbeat) || fragCount == 0 || fragCount > 128 || fragIndex >= fragCount || len(payload) > 65535 {
		return nil, ErrMalformed
	}
	h := Header{Type: typ, SessionID: c.sessionID, Seq: c.seq.Add(1), PacketID: packetID, FragIndex: fragIndex, FragCount: fragCount}
	if h.Seq > 1<<32 {
		return nil, ErrKeyLifetime
	}
	hb := marshalHeader(h)
	nonce := make([]byte, c.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	ct := c.aead.Seal(nil, nonce, payload, hb)
	out := make([]byte, 0, len(hb)+len(nonce)+len(ct))
	out = append(out, hb...)
	out = append(out, nonce...)
	out = append(out, ct...)
	return out, nil
}

func (c *Codec) Open(b []byte) (*Decoded, error) {
	if len(b) < HeaderLen+NonceLen+c.aead.Overhead() {
		return nil, fmt.Errorf("%w: frame too short", ErrMalformed)
	}
	h, err := parseHeader(b[:HeaderLen])
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMalformed, err)
	}
	// Raw ICMP can reflect the process's own encrypted frame. Reject it before
	// touching AEAD/replay state. BIP v0.1.2 also suppresses the common case in
	// the carrier, but this remains a carrier-independent safety check.
	if h.SessionID == c.sessionID {
		return nil, ErrReflectedLocal
	}
	if !c.replay.Precheck(h.SessionID, h.Seq) {
		return nil, ErrReplay
	}
	nonce := b[HeaderLen : HeaderLen+NonceLen]
	receiver := c.receiver
	if c.receiverID != h.SessionID {
		receiver, err = c.dataAEAD(h.SessionID)
		if err != nil {
			return nil, err
		}
	}
	pt, err := receiver.Open(nil, nonce, b[HeaderLen+NonceLen:], b[:HeaderLen])
	if err != nil {
		return nil, ErrAuthentication
	}
	c.receiver = receiver
	c.receiverID = h.SessionID
	c.replay.Commit(h.SessionID, h.Seq)
	return &Decoded{Header: h, Payload: pt}, nil
}

// OpenForSession admits only the identity authorized by the carrier handshake.
func (c *Codec) OpenForSession(b []byte, sid uint64) (*Decoded, error) {
	if sid == 0 {
		return nil, ErrAuthentication
	}
	got, ok := PeekSessionID(b)
	if !ok || got != sid {
		return nil, ErrAuthentication
	}
	if c.peerSession != sid {
		c.replay = NewReplayGuard(4096)
		c.peerSession = sid
	}
	return c.Open(b)
}

func marshalHeader(h Header) []byte {
	b := make([]byte, HeaderLen)
	copy(b[0:4], magic[:])
	b[4] = Version
	b[5] = h.Type
	b[6] = h.Flags
	b[7] = 0
	binary.BigEndian.PutUint64(b[8:16], h.SessionID)
	binary.BigEndian.PutUint64(b[16:24], h.Seq)
	binary.BigEndian.PutUint32(b[24:28], h.PacketID)
	binary.BigEndian.PutUint16(b[28:30], h.FragIndex)
	binary.BigEndian.PutUint16(b[30:32], h.FragCount)
	return b
}

func parseHeader(b []byte) (Header, error) {
	var h Header
	if len(b) < HeaderLen {
		return h, errors.New("short header")
	}
	if string(b[:4]) != string(magic[:]) {
		return h, errors.New("bad magic")
	}
	if b[4] != Version {
		return h, fmt.Errorf("unsupported wire version %d", b[4])
	}
	h.Type = b[5]
	h.Flags = b[6]
	h.SessionID = binary.BigEndian.Uint64(b[8:16])
	h.Seq = binary.BigEndian.Uint64(b[16:24])
	h.PacketID = binary.BigEndian.Uint32(b[24:28])
	h.FragIndex = binary.BigEndian.Uint16(b[28:30])
	h.FragCount = binary.BigEndian.Uint16(b[30:32])
	if h.SessionID == 0 || h.Seq == 0 || (h.Type != TypeData && h.Type != TypeHeartbeat) || h.Flags != 0 || b[7] != 0 {
		return h, errors.New("invalid frame header")
	}
	if h.FragCount == 0 || h.FragCount > 128 || h.FragIndex >= h.FragCount {
		return h, errors.New("invalid fragment metadata")
	}
	return h, nil
}

// PeekSessionID is intentionally lightweight and does not authenticate a frame.
// BIP uses it only to suppress obvious kernel reflections of frames created by
// this process. Security decisions still happen in Codec.Open.
func PeekSessionID(b []byte) (uint64, bool) {
	if len(b) < HeaderLen || string(b[:4]) != string(magic[:]) || b[4] != Version {
		return 0, false
	}
	return binary.BigEndian.Uint64(b[8:16]), true
}

type replayState struct {
	max     uint64
	slots   []uint64
	touched uint64
}

// ReplayGuard is a point-to-point anti-replay window optimized for the hot path.
// Each sequence number maps to one ring slot storing the exact sequence value,
// so duplicate/stale checks are O(1) with no per-packet map scan. The engine has
// a single receive owner, therefore this type intentionally has no mutex.
type ReplayGuard struct {
	window   uint64
	sessions map[uint64]*replayState
	tick     uint64
	maxSID   int
}

func NewReplayGuard(window uint64) *ReplayGuard {
	if window < 64 {
		window = 64
	}
	return &ReplayGuard{window: window, sessions: make(map[uint64]*replayState), maxSID: 4}
}

func (r *ReplayGuard) Precheck(sid, seq uint64) bool {
	if sid == 0 || seq == 0 {
		return false
	}
	s := r.sessions[sid]
	if s == nil {
		return len(r.sessions) < r.maxSID
	}
	if seq < s.max && s.max-seq >= r.window {
		return false
	}
	return s.slots[seq%r.window] != seq
}

func (r *ReplayGuard) Commit(sid, seq uint64) {
	if !r.Precheck(sid, seq) {
		return
	}
	s := r.sessions[sid]
	if s == nil {
		// Fail closed instead of evicting a replay window. New sessions require
		// an authenticated lifecycle transition (wired into BIP in the next stage).
		if len(r.sessions) >= r.maxSID {
			return
		}

		s = &replayState{slots: make([]uint64, r.window)}
		r.sessions[sid] = s
	}
	if seq > s.max {
		s.max = seq
	}
	s.slots[seq%r.window] = seq
	r.tick++
	s.touched = r.tick
}

// Memory accounting includes fragment slots, payload and a conservative
// fixed per-entry allowance. Count and per-packet limits are separate.
type packetKey struct {
	SessionID uint64
	PacketID  uint32
}
type partial struct {
	count      uint16
	parts      [][]byte
	got, bytes int
	created    time.Time
}
type Reassembler struct {
	mu                              sync.Mutex
	packets                         map[packetKey]*partial
	ttl                             time.Duration
	nextSweep                       time.Time
	maxPackets, maxBytes, usedBytes int
}

func NewReassembler(ttl time.Duration) *Reassembler {
	return NewBoundedReassembler(ttl, 1024, 8<<20)
}
func NewBoundedReassembler(ttl time.Duration, maxPackets, maxBytes int) *Reassembler {
	if ttl <= 0 {
		ttl = time.Second
	}
	if maxPackets < 1 {
		maxPackets = 1
	}
	if maxBytes < 1 {
		maxBytes = 1
	}
	return &Reassembler{packets: make(map[packetKey]*partial), ttl: ttl, maxPackets: maxPackets, maxBytes: maxBytes}
}
func (r *Reassembler) remove(k packetKey) {
	if p := r.packets[k]; p != nil {
		r.usedBytes -= 128 + int(p.count)*24 + p.bytes
		delete(r.packets, k)
	}
}
func (r *Reassembler) sweep(now time.Time) {
	for k, p := range r.packets {
		if now.Sub(p.created) >= r.ttl {
			r.remove(k)
		}
	}
	interval := r.ttl / 2
	if interval > time.Second {
		interval = time.Second
	}
	r.nextSweep = now.Add(interval)
}
func (r *Reassembler) Cleanup(now time.Time) { r.mu.Lock(); defer r.mu.Unlock(); r.sweep(now) }
func (r *Reassembler) Usage() (int, int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.packets), r.usedBytes
}
func (r *Reassembler) Add(h Header, payload []byte) ([]byte, bool) {
	if h.FragCount == 0 || h.FragCount > 128 || h.FragIndex >= h.FragCount || len(payload) > 65535 {
		return nil, false
	}
	if h.FragCount == 1 {
		return payload, true
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	now := time.Now()
	if !now.Before(r.nextSweep) {
		r.sweep(now)
	}
	k := packetKey{h.SessionID, h.PacketID}
	p := r.packets[k]
	if p != nil && now.Sub(p.created) >= r.ttl {
		r.remove(k)
		p = nil
	}
	if p != nil && p.count != h.FragCount {
		return nil, false
	}
	if p == nil {
		cost := 128 + int(h.FragCount)*24
		if len(r.packets) >= r.maxPackets || r.usedBytes+cost+len(payload) > r.maxBytes {
			return nil, false
		}
		p = &partial{count: h.FragCount, parts: make([][]byte, h.FragCount), created: now}
		r.packets[k] = p
		r.usedBytes += cost
	}
	if p.parts[h.FragIndex] != nil {
		return nil, false
	}
	if p.bytes+len(payload) > 65535 || r.usedBytes+len(payload) > r.maxBytes {
		r.remove(k)
		return nil, false
	}
	p.parts[h.FragIndex] = append([]byte{}, payload...)
	p.got++
	p.bytes += len(payload)
	r.usedBytes += len(payload)
	if p.got != int(p.count) {
		return nil, false
	}
	out := make([]byte, 0, p.bytes)
	for _, part := range p.parts {
		out = append(out, part...)
	}
	r.remove(k)
	return out, true
}
