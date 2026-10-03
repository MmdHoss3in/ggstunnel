package carrier

import (
	"container/heap"
	"context"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"ggstunnel/internal/config"
	"ggstunnel/internal/frame"
	"ggstunnel/internal/session"
	"log"
	mbits "math/bits"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

const (
	bipMagic              = "BIP5"
	bipICMPHeaderLen      = 72
	bipKindFastProbe byte = 1
	bipKindFastAck   byte = 2
	bipKindNeedPull  byte = 3
	bipKindPullProbe byte = 4
	bipKindData      byte = 5
	bipKindAck       byte = 6
	bipKindHello     byte = 7
	bipKindChallenge byte = 8
	bipKindProof     byte = 9
	bipKindReady     byte = 10
	bipFlagMore      byte = 1
	bipFlagPulled    byte = 2
	// MORE is ignored on legacy PROOF packets. Its authenticated use there
	// advertises wide SACK without introducing a flag old parsers reject.
	bipFlagWideSACK    byte = bipFlagMore
	bipLegacySpan           = 4096
	bipWideSpan             = 8192
	pendingModeFast    byte = 1
	pendingModePull    byte = 2
	pendingModeRequest byte = 3
)

var errBIPBadMAC = errors.New("bad MAC")
var errBIPUnknownSession = errors.New("unknown session")

// Recoverable only by creating a new authenticated identity, never by skipping
// an undelivered ordered frame or reusing an encryption counter.
var ErrBIPDeliveryTimeout = errors.New("BIP delivery timeout")

type outData struct {
	data    []byte
	seq     uint32
	retries int
}
type pendingData struct {
	item     outData
	sent     time.Time
	deadline time.Time
	mode     byte
	index    int
	sacked   int
	fast     bool
}
type sackWindow struct {
	init  bool
	max   uint32
	dirty bool
	seen  map[uint32]bool
}
type wirePacket struct {
	typ, kind, flags       byte
	id, tuple              uint16
	sender, target, number uint64
	token, ack             uint32
	sack                   uint64
	payload                []byte
}

type ackDelivery struct {
	seq  uint32
	sent time.Time
}

// The actor owns all handshake, path and delivery state.
// PacketIO is an injectable outer-packet I/O backend. Receive returns an ICMP
// body already filtered to the configured peer; Send receives a full IPv4 packet.
// Implementations must unblock Receive and Send when context/Close is signaled.
type PacketIO interface {
	Receive(context.Context) ([]byte, error)
	Send([]byte) error
	Close() error
}

type BIP struct {
	txReady                                                                                          chan struct{}
	lossFlightEnd                                                                                    uint32
	lossFlightSet                                                                                    bool
	retryHeap                                                                                        pendingHeap
	closed                                                                                           chan struct{}
	ackDue                                                                                           time.Time
	ackCount                                                                                         int
	ackType                                                                                          byte
	ackID, ackTuple                                                                                  uint16
	nextPullRetryCheck                                                                               time.Time
	pullRate                                                                                         float64
	pullSampleAt                                                                                     time.Time
	pullSampleRX                                                                                     uint64
	trace                                                                                            *bipTrace
	tuner                                                                                            *bipTuner
	tuning                                                                                           atomic.Pointer[TunerSnapshot]
	lastTuning                                                                                       time.Time
	tuningPath                                                                                       byte
	txAckBase                                                                                        uint32
	pullCredit, compatCredit                                                                         float64
	lastTick                                                                                         time.Time
	backend                                                                                          PacketIO
	cfg                                                                                              *config.Config
	local, peer                                                                                      net.IP
	localID                                                                                          uint64
	master, sessionKey                                                                               []byte
	gate                                                                                             *session.Gate
	active                                                                                           uint64
	peerSpan                                                                                         int
	peerID                                                                                           atomic.Uint64
	replay                                                                                           *frame.ReplayGuard
	tx, rx, incoming                                                                                 chan []byte
	errors                                                                                           chan error
	recv                                                                                             *net.IPConn
	rawfd                                                                                            int
	emit                                                                                             func([]byte) error
	cancel                                                                                           context.CancelFunc
	workers                                                                                          sync.WaitGroup
	closeOnce                                                                                        sync.Once
	startMu                                                                                          sync.Mutex
	started                                                                                          bool
	id, icmpSeq                                                                                      uint16
	packetNo                                                                                         uint64
	dataSeq                                                                                          uint32
	ackMu                                                                                            sync.Mutex
	rxAck                                                                                            sackWindow
	pending                                                                                          map[uint32]*pendingData
	fastToken                                                                                        uint32
	lastPeerActivity                                                                                 time.Time
	pathSuspended                                                                                    atomic.Bool
	fastDeadline, fastUntil, needPullSince, remotePullUntil, lastPull                                time.Time
	lastHello, lastProbe, lastNeedPull, lastAck, lastIdle                                            time.Time
	fastHealthy, pullActive, compatActive                                                            atomic.Bool
	wireTxBytes, wireRxBytes, fastDataTx, pullDataTx, compatDataTx                                   atomic.Uint64
	fastProbeTx, fastAckTx, fastAckRx, needPullTx, needPullRx, pullProbeTx, pullProbeRx, idleProbeTx atomic.Uint64
	reflectionsSuppressed, hmacFail, dataDuplicate, payloadFrameRx                                   atomic.Uint64
	malformedWire, unknownSession                                                                    atomic.Uint64
	pendingExpired, pendingOverflow, retransmits, txErrors, fastPromotions, fastDemotions            atomic.Uint64

	rxHold map[uint32][]byte
	rxNext uint32

	fastRetries atomic.Uint64
	rxBuffered  atomic.Uint64
}

func NewBIP(c *config.Config) (Carrier, error) {
	if c == nil {
		return nil, errors.New("nil config")
	}
	if err := c.Validate(); err != nil {
		return nil, err
	}
	l, p := net.ParseIP(c.Real.LocalIP).To4(), net.ParseIP(c.Real.PeerIP).To4()
	if l == nil || p == nil {
		return nil, errors.New("BIP requires IPv4 outer addresses")
	}
	var seed [10]byte
	if _, err := rand.Read(seed[:]); err != nil {
		return nil, err
	}
	sid := binary.BigEndian.Uint64(seed[:8])
	if sid == 0 {
		sid = 1
	}
	master, err := hkdf.Key(sha256.New, []byte(c.PSK), nil, "ggstunnel/bip5/bootstrap", 32)
	if err != nil {
		return nil, err
	}
	g, err := session.NewGate(master, sid, 5)
	if err != nil {
		return nil, err
	}
	b := &BIP{tuner: newBIPTuner(c), cfg: c, local: l, peer: p, localID: sid, master: master, gate: g, rawfd: -1, id: binary.BigEndian.Uint16(seed[8:]), tx: make(chan []byte, c.Performance.QueueSize), rx: make(chan []byte, c.Performance.QueueSize), incoming: make(chan []byte, c.Performance.QueueSize), errors: make(chan error, 1), pending: make(map[uint32]*pendingData), rxAck: sackWindow{init: true, seen: make(map[uint32]bool)}, replay: frame.NewReplayGuard(65536)}
	b.closed = make(chan struct{})
	b.txReady = make(chan struct{}, 1)
	// The retransmission window and the unsent backlog serve different
	// purposes. Keep a small unsent backlog waiting ahead of inner
	// TCP control traffic even when the flight window can reach 8192.
	b.tx = make(chan []byte, min(c.Performance.QueueSize, 64))
	b.publishTuner(time.Now())
	return b, nil
}
func (b *BIP) BindIdentity(id uint64) error {
	b.startMu.Lock()
	defer b.startMu.Unlock()
	if b.started || id == 0 {
		return errors.New("cannot bind identity")
	}
	g, err := session.NewGate(b.master, id, 5)
	if err != nil {
		return err
	}
	b.localID = id
	b.gate = g
	return nil
}
func (b *BIP) PeerSession() uint64  { return b.peerID.Load() }
func (b *BIP) Name() string         { return "bip" }
func (b *BIP) Recv() <-chan []byte  { return b.rx }
func (b *BIP) Errors() <-chan error { return b.errors }
func (b *BIP) Send(p []byte) error {
	if len(p) == 0 || len(p) > b.cfg.Performance.MaxFramePayload+60 {
		return errors.New("BIP frame too large")
	}
	select {
	case b.tx <- p:
		b.notifyTX()
		return nil
	default:
		return ErrQueueFull
	}
}

// SendContext applies bounded backpressure to the TUN reader instead of
// discarding an already-read IP packet when this reliable carrier is full.
func (b *BIP) SendContext(ctx context.Context, p []byte) error {
	if len(p) == 0 || len(p) > b.cfg.Performance.MaxFramePayload+60 {
		return errors.New("BIP frame too large")
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-b.closed:
		return errors.New("BIP closed")
	default:
	}
	select {
	case b.tx <- p:
		b.notifyTX()
		return nil
	case <-ctx.Done():
		return ctx.Err()
	case <-b.closed:
		return errors.New("BIP closed")
	}
}
func (b *BIP) Start(ctx context.Context) error {
	b.startMu.Lock()
	defer b.startMu.Unlock()
	if b.started {
		return errors.New("already started")
	}
	r, err := net.ListenIP("ip4:icmp", &net.IPAddr{IP: b.local})
	if err != nil {
		return err
	}
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_RAW)
	if err != nil {
		r.Close()
		return err
	}
	fail := func(err error) error { syscall.Close(fd); r.Close(); return err }
	if err = syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, syscall.IP_HDRINCL, 1); err != nil {
		return fail(err)
	}
	// A congested socket must not stall the actor (including ACK processing)
	// for a full second. Failed DATA sends stay pending for bounded retry.
	if err = syscall.SetNonblock(fd, true); err != nil {
		return fail(err)
	}
	_ = r.SetReadBuffer(b.cfg.Transport.SockBuf)
	_ = syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_SNDBUF, b.cfg.Transport.SockBuf)
	b.recv = r
	b.rawfd = fd
	b.emit = func(w []byte) error {
		sa := &syscall.SockaddrInet4{}
		copy(sa.Addr[:], b.peer)
		return syscall.Sendto(fd, w, 0, sa)
	}
	child := b.startActor(ctx)
	b.workers.Add(1)
	go func() { defer b.workers.Done(); b.readLoop(child) }()
	return nil
}
func (b *BIP) StartPacketIO(ctx context.Context, backend PacketIO) error {
	b.startMu.Lock()
	defer b.startMu.Unlock()
	if b.started || backend == nil {
		return errors.New("invalid packet backend")
	}
	b.backend = backend
	b.emit = backend.Send
	child := b.startActor(ctx)
	b.workers.Add(1)
	go func() {
		defer b.workers.Done()
		for {
			p, err := backend.Receive(child)
			if err != nil {
				if child.Err() == nil {
					b.fail(err)
				}
				return
			}
			select {
			case b.incoming <- p:
			case <-child.Done():
				return
			}
		}
	}()
	return nil
}

func (b *BIP) startActor(ctx context.Context) context.Context {
	if path := os.Getenv("GGSTUNNEL_BIP_TRACE"); path != "" {
		var err error
		b.trace, err = openBIPTrace(path)
		if err != nil {
			log.Printf("BIP trace unavailable: %v", err)
		}
	}
	ctx, b.cancel = context.WithCancel(ctx)
	b.started = true
	b.workers.Add(1)
	go func() { defer b.workers.Done(); b.run(ctx) }()
	return ctx
}
func (b *BIP) fail(err error) {
	select {
	case b.errors <- err:
	default:
	}
	if b.cancel != nil {
		b.cancel()
	}
}
func (b *BIP) readLoop(ctx context.Context) {
	buf := make([]byte, 65535)
	for {
		_ = b.recv.SetReadDeadline(time.Now().Add(time.Second))
		n, src, err := b.recv.ReadFromIP(buf)
		if err != nil {
			select {
			case <-ctx.Done():
				return
			default:
			}
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			b.fail(err)
			return
		}
		if n < 72 || n > 1480 || !src.IP.Equal(b.peer) || string(buf[8:12]) != bipMagic {
			continue
		}
		p := append([]byte(nil), buf[:n]...)
		select {
		case b.incoming <- p:
		case <-ctx.Done():
			return
		default:
			b.pendingOverflow.Add(1)
		}
	}
}
func (b *BIP) Close() error {
	b.closeOnce.Do(func() {
		if b.closed != nil {
			close(b.closed)
		}
		if b.cancel != nil {
			b.cancel()
		}
		if b.recv != nil {
			b.recv.Close()
		}
		if b.started && b.rawfd >= 0 {
			syscall.Close(b.rawfd)
		}
		if b.backend != nil {
			b.backend.Close()
		}
		b.workers.Wait()
		b.trace.close()
	})
	return nil
}
func nextSequence(s uint32) uint32 {
	s++
	if s == 0 {
		s = 1
	}
	return s
}

// Sequence zero is reserved and does not occupy a SACK slot at wraparound.
func sequenceDistance(base, seq uint32) uint32 {
	distance := seq - base
	if seq < base {
		distance--
	}
	return distance
}
func previousSequence(s uint32) uint32 {
	if s == 1 {
		return 0
	}
	return s - 1
}
func seqAfter(a, c uint32) bool { return int32(a-c) > 0 }
func (b *BIP) nextTuple() (uint16, uint16) {
	b.icmpSeq++
	if b.icmpSeq == 0 {
		b.id++
	}
	return b.id, b.icmpSeq
}
func (b *BIP) nextDataSeq() uint32 { b.dataSeq = nextSequence(b.dataSeq); return b.dataSeq }

// Cumulative ACK covers contiguous acceptance. SACK covers the NEXT 4096 slots on dedicated ACK packets.
func (b *BIP) recordRXSeq(seq uint32) bool {
	b.ackMu.Lock()
	defer b.ackMu.Unlock()
	return b.recordRXSeqLocked(seq)
}
func (b *BIP) recordRXSeqLocked(seq uint32) bool {
	if seq == 0 {
		return false
	}
	w := &b.rxAck
	if w.seen == nil {
		w.seen = make(map[uint32]bool)
	}
	if !w.init {
		w.init = true
		w.max = previousSequence(seq)
	}
	if !seqAfter(seq, w.max) || w.seen[seq] {
		w.dirty = true
		return false
	}
	if sequenceDistance(w.max, seq) > uint32(b.ackSpan()) {
		return false
	}
	w.seen[seq] = true
	w.dirty = true
	for {
		n := nextSequence(w.max)
		if !w.seen[n] {
			break
		}
		delete(w.seen, n)
		w.max = n
	}
	return true
}
func (b *BIP) takeAckForSend() (uint32, uint64) {
	b.ackMu.Lock()
	defer b.ackMu.Unlock()
	var bits uint64
	s := b.rxAck.max
	for i := 0; i < 64; i++ {
		s = nextSequence(s)
		if b.rxAck.seen[s] {
			bits |= uint64(1) << i
		}
	}
	return b.rxAck.max, bits
}
func (b *BIP) processPeerAck(ack uint32, bits uint64) bool {
	return b.processPeerAckAt(ack, bits, time.Now())
}
func (b *BIP) processPeerAckAt(ack uint32, bits uint64, now time.Time) bool {
	return b.processWideAckAt(ack, bits, nil, now)
}

// Additional words are authenticated ACK payload, never added to DATA headers.
func (b *BIP) ackExtension(ack uint32) []byte {
	b.ackMu.Lock()
	defer b.ackMu.Unlock()
	var words [127]uint64
	high := 0
	for seq := range b.rxAck.seen {
		d := sequenceDistance(ack, seq)
		if d > 64 && d <= uint32(b.ackSpan()) {
			i := (d-1)/64 - 1
			words[i] |= uint64(1) << ((d - 1) % 64)
			high = max(high, int(i)+1)
		}
	}
	payload := make([]byte, high*8)
	for i := 0; i < high; i++ {
		binary.BigEndian.PutUint64(payload[i*8:], words[i])
	}
	return payload
}
func (b *BIP) processWideAckAt(ack uint32, bits uint64, extra []byte, now time.Time) bool {
	b.ackMu.Lock()
	defer b.ackMu.Unlock()
	fast := false
	clean := 0
	var oldest time.Time
	var delivered []ackDelivery
	accept := func(seq uint32) {
		p := b.pending[seq]
		if p == nil {
			return
		}
		delivered = append(delivered, ackDelivery{seq: seq, sent: p.sent})
		b.traceRecord(traceEvent{At: now, Event: "ack_accept", Seq: seq, Ack: ack, Sack: bits, Mode: p.mode, Retries: p.item.retries, AgeMS: float64(now.Sub(p.sent)) / float64(time.Millisecond)})
		fast = fast || p.mode == pendingModeFast
		if b.tuner != nil {
			b.tuner.acked++
			if p.item.retries == 0 && !p.sent.IsZero() {
				clean++
				if oldest.IsZero() || p.sent.Before(oldest) {
					oldest = p.sent
				}
			}
		}
		b.removePending(p)
		delete(b.pending, seq)
	}
	if seqAfter(ack, b.txAckBase) {
		distance := sequenceDistance(b.txAckBase, ack)
		if distance <= uint32(b.window()) {
			seq := b.txAckBase
			for i := uint32(0); i < distance; i++ {
				seq = nextSequence(seq)
				accept(seq)
			}
		} else {
			// Bounded fallback for initial/wrapped state; wire handler rejects future ACKs.
			for seq := range b.pending {
				if !seqAfter(seq, ack) {
					accept(seq)
				}
			}
		}
		b.txAckBase = ack
	}
	for block := 0; block <= len(extra)/8; block++ {
		word := bits
		if block > 0 {
			word = binary.BigEndian.Uint64(extra[(block-1)*8:])
		}
		for word != 0 {
			offset := uint32(block*64 + mbits.TrailingZeros64(word) + 1)
			seq := ack + offset
			if seq < ack {
				seq++
			}
			accept(seq)
			word &= word - 1
		}
	}

	b.detectSACKLoss(delivered, now)
	if b.tuner != nil && clean > 0 {
		// Include the oldest clean packet's residence time in a cumulative
		// ACK. The newest packet alone systematically hides batching delay,
		// producing premature timeouts and repeated congestion cuts.
		b.tuner.onAck(clean, now.Sub(oldest), now)
	}
	return fast
}
func (b *BIP) queuePending(x outData, mode byte, now time.Time) {
	b.ackMu.Lock()
	defer b.ackMu.Unlock()
	if old := b.pending[x.seq]; old != nil {
		b.removePending(old)
	}
	p := &pendingData{item: x, sent: now, mode: mode, index: -1}
	if b.tuner != nil {
		p.deadline = now.Add(b.tuner.timeout(x.retries))
	} else {
		p.deadline = now.Add(time.Duration(b.cfg.Transport.BIPRTOMS) * time.Millisecond)
	}
	b.pending[x.seq] = p
	heap.Push(&b.retryHeap, p)
	if mode == pendingModeRequest && x.retries > 0 {
		b.nextPullRetryCheck = time.Time{}
	} else if b.nextPullRetryCheck.IsZero() || p.deadline.Before(b.nextPullRetryCheck) {
		b.nextPullRetryCheck = p.deadline
	}
	b.traceRecord(traceEvent{At: now, Event: "pending", Seq: x.seq, Mode: mode, Retries: x.retries, DeadlineMS: float64(p.deadline.Sub(now)) / float64(time.Millisecond), Pending: len(b.pending), Backlog: len(b.tx)})
}
func (b *BIP) takeTimedOut(now time.Time, rto time.Duration) (*pendingData, bool) {
	b.ackMu.Lock()
	defer b.ackMu.Unlock()
	if len(b.retryHeap) == 0 || now.Before(b.retryHeap[0].deadline) {
		return nil, false
	}
	oldest := b.retryHeap[0]
	b.removePending(oldest)
	return oldest, true
}

// A request-mode retry may be blocked in one direction. A subsequent
// authenticated peer PULL supplies a usable EchoReply tuple for that same data.
// Do not allocate a new data sequence or treat a kernel echo as an ACK.
func (b *BIP) retryOnPull(id, tuple uint16, now time.Time) bool {
	if now.Before(b.nextPullRetryCheck) {
		return false
	}
	if b.tuner != nil && !b.tuner.allow(now, false) {
		return false
	}
	b.ackMu.Lock()
	var oldest *pendingData
	next := now.Add(time.Second)
	for _, p := range b.pending {
		if !p.deadline.IsZero() && p.deadline.Before(next) {
			next = p.deadline
		}
		eligible := p.mode == pendingModeRequest && p.item.retries > 0
		eligible = eligible || (!p.deadline.IsZero() && !now.Before(p.deadline))
		if eligible && p.item.retries < b.cfg.Transport.BIPMaxRetries && (oldest == nil || p.sent.Before(oldest.sent)) {
			oldest = p
		}
	}
	if oldest != nil {
		b.removePending(oldest)
	} else {
		b.nextPullRetryCheck = next
	}
	b.ackMu.Unlock()
	if oldest == nil {
		return false
	}
	if b.tuner != nil {
		b.noteDeliveryLoss(oldest, now)
		b.tuner.allow(now, true)
	}
	oldest.item.retries++
	b.retransmits.Add(1)
	if oldest.fast {
		b.fastRetries.Add(1)
	}
	b.queuePending(oldest.item, pendingModePull, now)
	_ = b.send(0, id, tuple, bipKindData, bipFlagMore|bipFlagPulled, oldest.item.seq, oldest.item.data, b.active)
	return true
}
func (b *BIP) SnapshotTuner() TunerSnapshot {
	if s := b.tuning.Load(); s != nil {
		return *s
	}
	return TunerSnapshot{Mode: b.cfg.Tuner.Mode}
}
func (b *BIP) publishTuner(now time.Time) {
	if b.tuner != nil {
		s := b.tuner.snapshot()
		b.tuning.Store(&s)
		b.lastTuning = now
	}
}
func (b *BIP) resetPeer(id uint64) error {
	if id == b.active {
		return nil
	}
	if b.gate == nil || b.gate.Active() != id {
		return errors.New("unauthenticated peer reset")
	}
	a, c := b.localID, id
	if a > c {
		a, c = c, a
	}
	var salt [16]byte
	binary.BigEndian.PutUint64(salt[:8], a)
	binary.BigEndian.PutUint64(salt[8:], c)
	key, err := hkdf.Key(sha256.New, b.master, salt[:], "ggstunnel/bip5/session-control", 32)
	if err != nil {
		return err
	}
	b.ackMu.Lock()
	b.pending = make(map[uint32]*pendingData)
	b.retryHeap = nil
	b.ackDue = time.Time{}
	b.ackCount = 0
	b.rxAck = sackWindow{init: true, seen: make(map[uint32]bool)}
	b.rxHold = nil
	b.rxNext = 1
	b.rxBuffered.Store(0)
	b.ackMu.Unlock()
	b.active = id
	b.peerSpan = bipLegacySpan
	if b.tuner != nil {
		b.tuner.maxWindow = min(b.cfg.Performance.QueueSize, bipLegacySpan)
	}
	b.sessionKey = key
	b.dataSeq = 0
	b.lossFlightSet = false
	b.txAckBase = 0
	b.nextPullRetryCheck = time.Time{}
	b.pullRate = 1000
	b.pullSampleAt = time.Time{}
	b.replay = frame.NewReplayGuard(65536)
	b.fastUntil = time.Time{}
	b.lastPeerActivity = time.Time{}
	b.pathSuspended.Store(false)
	b.fastToken = 0
	b.needPullSince = time.Time{}
	b.remotePullUntil = time.Time{}
	b.lastPull = time.Time{}
	if b.tuner != nil {
		b.tuner.reset()
		b.publishTuner(time.Now())
	}
	b.peerID.Store(id)
	return nil
}
func marshalChallenge(c session.Challenge) []byte {
	p := make([]byte, 51)
	copy(p, c.Nonce[:])
	binary.BigEndian.PutUint64(p[32:40], c.PeerID)
	binary.BigEndian.PutUint64(p[40:48], c.LocalID)
	binary.BigEndian.PutUint16(p[48:50], c.Wire)
	p[50] = c.Role
	return p
}
func parseChallenge(p []byte) (session.Challenge, error) {
	var c session.Challenge
	if len(p) != 51 {
		return c, errors.New("bad challenge")
	}
	copy(c.Nonce[:], p[:32])
	c.PeerID = binary.BigEndian.Uint64(p[32:40])
	c.LocalID = binary.BigEndian.Uint64(p[40:48])
	c.Wire = binary.BigEndian.Uint16(p[48:50])
	c.Role = p[50]
	return c, nil
}
func (b *BIP) remoteRole() byte {
	if b.cfg.Role == "server" {
		return 2
	}
	return 1
}
func (b *BIP) localRole() byte {
	if b.cfg.Role == "server" {
		return 1
	}
	return 2
}
func responseType(p wirePacket) byte {
	if p.typ == 8 {
		return 0
	}
	return 8
}
func (b *BIP) issueChallenge(p wirePacket, now time.Time) {
	c, err := b.gate.Issue(p.sender, b.remoteRole(), now)
	if err == nil {
		_ = b.send(responseType(p), p.id, p.tuple, bipKindChallenge, 0, 0, marshalChallenge(c), p.sender)
	}
}
func (b *BIP) handle(body []byte, now time.Time) {
	// Kernel echo changes type/checksum but leaves the authenticated payload.
	// Recognize only a verified reflection of our own request; never ACK it.
	if len(body) >= 72 && len(body) <= 1480 && body[0] == 0 && string(body[8:12]) == bipMagic && checksum(body) == 0 && binary.BigEndian.Uint64(body[16:24]) == b.localID {
		key := b.macKey(body[12])
		if len(key) > 0 {
			original := append([]byte(nil), body...)
			original[0] = 8
			tag := packetMAC(key, original)
			if hmac.Equal(tag[:], body[56:72]) {
				b.reflectionsSuppressed.Add(1)
				return
			}
		}
	}
	p, err := b.decode(body)
	if err != nil {
		switch {
		case errors.Is(err, errBIPBadMAC):
			b.hmacFail.Add(1)
		case errors.Is(err, errBIPUnknownSession):
			b.unknownSession.Add(1)
		default:
			b.malformedWire.Add(1)
		}
		return
	}
	if p.sender == b.localID {
		b.reflectionsSuppressed.Add(1)
		return
	}
	if p.target != b.localID && !(p.kind == bipKindHello && p.target == 0) {
		return
	}
	if p.kind >= bipKindHello {
		switch p.kind {
		case bipKindHello:
			if len(p.payload) == 1 && p.payload[0] == b.remoteRole() {
				b.issueChallenge(p, now)
			}
		case bipKindChallenge:
			c, err := parseChallenge(p.payload)
			if err != nil || c.PeerID != b.localID || c.LocalID != p.sender || c.Wire != 5 || c.Role != b.localRole() {
				return
			}
			proof := session.Proof(b.master, c)
			payload := append(marshalChallenge(c), proof[:]...)
			capability := byte(0)
			if b.cfg.Performance.QueueSize >= bipWideSpan {
				capability = bipFlagWideSACK
			}
			_ = b.send(responseType(p), p.id, p.tuple, bipKindProof, capability, 0, payload, p.sender)
			if b.active != p.sender {
				b.issueChallenge(p, now)
			}
		case bipKindProof:
			if len(p.payload) != 83 {
				return
			}
			c, err := parseChallenge(p.payload[:51])
			if err != nil || c.PeerID != p.sender || c.LocalID != b.localID {
				return
			}
			var proof [32]byte
			copy(proof[:], p.payload[51:])
			if err := b.gate.Accept(c, proof, now); err != nil {
				if errors.Is(err, session.ErrRotationLimit) {
					b.fail(err)
				}
				return
			}
			if err := b.resetPeer(p.sender); err != nil {
				b.fail(err)
				return
			}
			b.lastPeerActivity = now
			// Capability is accepted only with a fresh receiver-issued challenge
			// and a verified proof. Legacy peers ignore this flag and advertise 0.
			if p.flags&bipFlagWideSACK != 0 {
				b.peerSpan = bipWideSpan
				if b.tuner != nil {
					b.tuner.resizeWindow(b.window())
					b.publishTuner(now)
				}
			}
			_ = b.send(responseType(p), p.id, p.tuple, bipKindReady, 0, 0, nil, p.sender)
		case bipKindReady: // READY never authorizes a session reset.
		}
		return
	}
	if b.active == 0 || p.sender != b.active || !b.replay.Precheck(p.sender, p.number) {
		return
	}
	b.replay.Commit(p.sender, p.number)
	if seqAfter(p.ack, b.dataSeq) {
		return
	}
	if p.kind == bipKindAck {
		b.processWideAckAt(p.ack, p.sack, p.payload, now)
	} else {
		b.processPeerAckAt(p.ack, p.sack, now)
	}
	b.observePeerActivity(now)
	b.recoverPersistentHole(p.ack, p.sack, p.payload, p.kind == bipKindAck, now)
	b.traceRecord(traceEvent{At: now, Event: "wire_rx", Seq: p.token, Ack: p.ack, Sack: p.sack, Kind: p.kind, Type: p.typ})
	switch p.kind {
	case bipKindFastProbe:
		b.fastAckTx.Add(1)
		_ = b.send(responseType(p), p.id, p.tuple, bipKindFastAck, 0, p.token, nil, b.active)
	case bipKindFastAck:
		if p.token != 0 && p.token == b.fastToken && now.Before(b.fastDeadline) {
			if !now.Before(b.fastUntil) {
				b.expeditePathRetries(now)
			}
			b.fastUntil = now.Add(time.Duration(b.cfg.Transport.BIPFastTTLMS) * time.Millisecond)
			b.fastToken = 0
			b.fastAckRx.Add(1)
		}
	case bipKindNeedPull:
		b.needPullRx.Add(1)
		b.remotePullUntil = now.Add(time.Duration(b.cfg.Transport.BIPPullHoldMS) * time.Millisecond)
		// FAST and PULL probes may both be filtered while request DATA still
		// works. Confirm this authenticated request so silence suspension does
		// not prevent the first compatibility DATA from discovering that path.
		// ACKs do not authorize a reset and never elicit another ACK.
		_ = b.send(responseType(p), p.id, p.tuple, bipKindAck, 0, 0, nil, b.active)
	case bipKindPullProbe:
		b.pullProbeRx.Add(1)
		b.lastPull = now
		b.needPullSince = time.Time{}
		if !b.retryOnPull(p.id, p.tuple, now) {
			b.deliverOne(0, p.id, p.tuple, pendingModePull, now)
		}
	case bipKindData:
		if len(p.payload) == 0 || p.token == 0 {
			return
		}
		b.ackMu.Lock()
		w := &b.rxAck
		duplicate := !seqAfter(p.token, w.max) || w.seen[p.token]
		if duplicate {
			w.dirty = true
			b.dataDuplicate.Add(1)
		} else if sequenceDistance(w.max, p.token) <= uint32(b.window()) {
			if !b.receiveOrdered(p.token, p.payload) {
				b.pendingOverflow.Add(1)
			}
		}
		b.ackMu.Unlock()
		b.scheduleAck(p, now, duplicate)
		if p.flags&bipFlagMore != 0 && p.flags&bipFlagPulled != 0 {
			b.remotePullUntil = now.Add(time.Duration(b.cfg.Transport.BIPPullHoldMS) * time.Millisecond)
		}
	case bipKindAck:
	}
}
func (b *BIP) window() int {
	n := b.cfg.Performance.QueueSize
	return min(n, b.ackSpan())
}
func (b *BIP) ackSpan() int {
	if b.peerSpan == bipWideSpan {
		return bipWideSpan
	}
	return bipLegacySpan
}
func (b *BIP) deliverOne(typ byte, id, tuple uint16, mode byte, now time.Time) {
	b.ackMu.Lock()
	full := len(b.pending) >= b.window() || sequenceDistance(b.txAckBase, nextSequence(b.dataSeq)) > uint32(b.window())
	b.ackMu.Unlock()
	b.ackMu.Lock()
	congestionFull := b.tuner != nil && b.tuner.adaptive() && len(b.pending) >= b.tuner.window()
	b.ackMu.Unlock()
	if congestionFull {
		full = true
	}
	if full {
		return
	}
	if len(b.tx) == 0 {
		return
	}
	if b.tuner != nil && !b.tuner.allow(now, true) {
		return
	}
	var p []byte
	select {
	case p = <-b.tx:
	default:
		return
	}
	x := outData{data: p, seq: b.nextDataSeq()}
	b.queuePending(x, mode, now)
	flags := byte(0)
	if mode == pendingModePull {
		flags |= bipFlagPulled
	}
	if len(b.tx) > 0 && !(mode == pendingModePull && b.fastHealthy.Load()) {
		flags |= bipFlagMore
	}
	_ = b.send(typ, id, tuple, bipKindData, flags, x.seq, x.data, b.active)
	switch mode {
	case pendingModeFast:
		b.fastDataTx.Add(1)
	case pendingModePull:
		b.pullDataTx.Add(1)
	case pendingModeRequest:
		b.compatDataTx.Add(1)
	}
}
func (b *BIP) notifyTX() {
	select {
	case b.txReady <- struct{}{}:
	default:
	}
}

// FAST reacts to producer and ACK events instead of waiting for a maintenance
// tick. Work per event remains bounded; congestion, pacing and SACK horizon
// checks remain in deliverOne. A finite backlog is not a packets-per-tick cap.
func (b *BIP) pumpFast(now time.Time) {
	if b.active == 0 || !now.Before(b.fastUntil) || b.pathUnresponsive(now) {
		return
	}
	for i := 0; i < b.cfg.Tuner.MaxBurst && len(b.tx) > 0; i++ {
		previous := b.dataSeq
		id, s := b.nextTuple()
		b.deliverOne(0, id, s, pendingModeFast, now)
		if b.dataSeq == previous {
			break
		}
	}
}
func (b *BIP) run(ctx context.Context) {
	tick := time.NewTicker(time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case p := <-b.incoming:
			b.handle(p, time.Now())
			b.pumpFast(time.Now())
		case <-b.txReady:
			b.pumpFast(time.Now())
		case <-tick.C:
			// A ticker timestamp can predate queued I/O by an entire scheduling
			// pause. Deadlines must start at actual transmission time.
			now := time.Now()
			dt := now.Sub(b.lastTick).Seconds()
			if b.lastTick.IsZero() || dt > 0.02 {
				dt = 0.001
			}
			if dt < 0 {
				dt = 0
			}
			b.lastTick = now
			if now.Sub(b.lastTuning) >= 100*time.Millisecond {
				b.publishTuner(now)
			}
			if b.active == 0 && now.Sub(b.lastHello) >= 500*time.Millisecond {
				id, s := b.nextTuple()
				_ = b.send(8, id, s, bipKindHello, 0, 0, []byte{b.localRole()}, 0)
				b.lastHello = now
			}
			if b.active == 0 {
				continue
			}
			if now.Sub(b.lastProbe) >= time.Duration(b.cfg.Transport.BIPFastProbeMS)*time.Millisecond && (b.fastToken == 0 || !now.Before(b.fastDeadline)) {
				var r [4]byte
				if _, err := rand.Read(r[:]); err != nil {
					b.fail(err)
					return
				}
				b.fastToken = binary.BigEndian.Uint32(r[:])
				if b.fastToken == 0 {
					b.fastToken = 1
				}
				b.fastDeadline = now.Add(time.Duration(b.cfg.Transport.BIPFastTTLMS) * time.Millisecond)
				id, s := b.nextTuple()
				_ = b.send(0, id, s, bipKindFastProbe, 0, b.fastToken, nil, b.active)
				b.lastProbe = now
				b.fastProbeTx.Add(1)
			}
			fast := now.Before(b.fastUntil)
			b.drainRX()
			// Keep reporting a retained hole even if its retransmission was lost
			// and no new data can cross the cumulative-ACK horizon.
			if len(b.rxHold) > 0 && b.ackDue.IsZero() && now.Sub(b.lastAck) >= 100*time.Millisecond {
				b.flushAck(now)
			}
			if fast != b.fastHealthy.Swap(fast) {
				if fast {
					b.fastPromotions.Add(1)
				} else {
					b.fastDemotions.Add(1)
				}
			}
			remotePull := now.Before(b.remotePullUntil)
			b.pullActive.Store(remotePull)
			if now.Sub(b.lastIdle) >= time.Duration(b.cfg.Transport.BIPProbeMS)*time.Millisecond {
				id, s := b.nextTuple()
				_ = b.send(8, id, s, bipKindPullProbe, 0, 0, nil, b.active)
				b.idleProbeTx.Add(1)
				b.lastIdle = now
			}
			if !remotePull {
				b.pullCredit = 0
			}
			if b.pullRate == 0 {
				b.pullRate = 1000
			}
			if b.pullSampleAt.IsZero() {
				b.pullSampleAt = now
				b.pullSampleRX = b.payloadFrameRx.Load()
			}
			if elapsed := now.Sub(b.pullSampleAt); elapsed >= 100*time.Millisecond {
				count := b.payloadFrameRx.Load()
				observed := float64(count-b.pullSampleRX) / elapsed.Seconds()
				b.pullRate = max(1000, observed*1.5)
				b.pullSampleAt = now
				b.pullSampleRX = count
			}
			if remotePull {
				pullRate := b.cfg.Transport.BIPPullPPS
				if b.tuner != nil && b.tuner.adaptive() {
					// Bound unsuccessful polling overhead independently of data rate.
					// Sustained high-PPS tuning requires separate field validation.
					if b.tuner.cfg.UnlimitedRate {
						pullRate = int(b.pullRate)
					} else {
						pullRate = min(pullRate, b.tuner.cfg.MaxPPS)
					}
				}
				b.pullCredit += float64(pullRate) * dt
				if b.pullCredit > float64(b.cfg.Transport.BIPPullBurst) {
					b.pullCredit = float64(b.cfg.Transport.BIPPullBurst)
				}
				quota := int(b.pullCredit)
				b.pullCredit -= float64(quota)

				for i := 0; i < quota; i++ {
					id, s := b.nextTuple()
					_ = b.send(8, id, s, bipKindPullProbe, 0, 0, nil, b.active)
					b.pullProbeTx.Add(1)
				}
			}
			if len(b.tx) > 0 && !fast && now.Sub(b.lastNeedPull) >= time.Duration(b.cfg.Transport.BIPNeedPullMS)*time.Millisecond {
				id, s := b.nextTuple()
				_ = b.send(8, id, s, bipKindNeedPull, 0, 0, nil, b.active)
				b.needPullTx.Add(1)
				b.lastNeedPull = now
				if b.needPullSince.IsZero() {
					b.needPullSince = now
				}
			}
			compat := !fast && !b.needPullSince.IsZero() && now.Sub(b.needPullSince) >= time.Duration(b.cfg.Transport.BIPPullTimeoutMS)*time.Millisecond && now.Sub(b.lastPull) >= time.Duration(b.cfg.Transport.BIPPullTimeoutMS)*time.Millisecond
			b.compatActive.Store(compat)
			path := byte(0)
			if fast {
				path = 1
			} else if compat {
				path = 3
			} else if !b.needPullSince.IsZero() || remotePull {
				path = 2
			}
			if path != 0 && b.tuningPath != 0 && path != b.tuningPath && b.tuner != nil {
				b.tuner.pathChanged()
			}
			if path != 0 {
				b.tuningPath = path
			}
			suspended := b.pathUnresponsive(now)
			b.pathSuspended.Store(suspended)
			for i := 0; i < 16 && !suspended; i++ {
				if b.tuner != nil && !b.tuner.allow(now, false) {
					break
				}
				pd, ok := b.takeTimedOut(now, time.Duration(b.cfg.Transport.BIPRTOMS)*time.Millisecond)
				if !ok {
					break
				}
				if pd.item.retries >= b.cfg.Transport.BIPMaxRetries {
					b.pendingExpired.Add(1)
					b.fail(fmt.Errorf("%w at %d", ErrBIPDeliveryTimeout, pd.item.seq))
					return
				}
				if b.tuner != nil {
					b.traceRecord(traceEvent{At: now, Event: "timeout", Seq: pd.item.seq, Mode: pd.mode, Retries: pd.item.retries, AgeMS: float64(now.Sub(pd.sent)) / float64(time.Millisecond), DeadlineMS: float64(now.Sub(pd.deadline)) / float64(time.Millisecond), RTOms: float64(b.tuner.rto) / float64(time.Millisecond), Window: b.tuner.window(), Cuts: b.tuner.cuts, Pending: len(b.pending), Backlog: len(b.tx)})
					b.noteDeliveryLoss(pd, now)
					b.tuner.allow(now, true)
				}
				pd.item.retries++
				b.retransmits.Add(1)
				if pd.fast {
					b.fastRetries.Add(1)
				}
				b.queuePending(pd.item, pendingModeRequest, now)
				id, s := b.nextTuple()
				// DATA loss is congestion evidence, not proof the FAST path died.
				// Path probes/TTL independently decide when to fall back.
				_ = b.send(8, id, s, bipKindData, bipFlagMore, pd.item.seq, pd.item.data, b.active)
			}
			if (fast || compat) && !suspended {
				quota := b.cfg.Tuner.MaxBurst
				if compat {
					rate := float64(b.cfg.Transport.BIPPullPPS)
					if b.tuner != nil && b.tuner.cfg.UnlimitedRate {
						rate = b.tuner.rate()
					}
					b.compatCredit += rate * dt
					if b.compatCredit > float64(b.cfg.Transport.BIPPullBurst) {
						b.compatCredit = float64(b.cfg.Transport.BIPPullBurst)
					}
					quota = int(b.compatCredit)
					b.compatCredit -= float64(quota)
				} else {
					b.compatCredit = 0
				}
				for i := 0; i < quota && len(b.tx) > 0; i++ {
					id, s := b.nextTuple()
					typ, mode := byte(0), byte(pendingModeFast)
					if compat {
						typ, mode = 8, pendingModeRequest
					}
					b.deliverOne(typ, id, s, mode, now)
				}
			}
			if !b.ackDue.IsZero() && !now.Before(b.ackDue) {
				b.flushAck(now)
			}
		}
	}
}
func (b *BIP) send(typ byte, id, tuple uint16, kind, flags byte, token uint32, payload []byte, target uint64) error {
	if b.emit == nil {
		return errors.New("carrier not started")
	}
	b.packetNo++
	if b.packetNo == 0 {
		return errors.New("packet counter exhausted")
	}
	ack, sack := b.takeAckForSend()
	if kind == bipKindAck {
		payload = b.ackExtension(ack)
	}
	p := wirePacket{typ: typ, kind: kind, flags: flags, id: id, tuple: tuple, sender: b.localID, target: target, number: b.packetNo, token: token, ack: ack, sack: sack, payload: payload}
	body, err := b.encode(p)
	if err != nil {
		return err
	}
	ip := make([]byte, 20+len(body))
	if len(ip) > 1500 {
		return syscall.EMSGSIZE
	}
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:4], uint16(len(ip)))
	binary.BigEndian.PutUint16(ip[6:8], 0x4000)
	ip[8] = 64
	ip[9] = 1
	copy(ip[12:16], b.local)
	copy(ip[16:20], b.peer)
	copy(ip[20:], body)
	binary.BigEndian.PutUint16(ip[10:12], checksum(ip[:20]))
	if err := b.emit(ip); err != nil {
		b.traceRecord(traceEvent{At: time.Now(), Event: "wire_tx", Seq: token, Ack: ack, Sack: sack, Kind: kind, Type: typ, Error: true})
		b.txErrors.Add(1)
		return err
	}
	b.wireTxBytes.Add(uint64(len(ip)))
	b.traceRecord(traceEvent{At: time.Now(), Event: "wire_tx", Seq: token, Ack: ack, Sack: sack, Kind: kind, Type: typ})
	return nil
}
func (b *BIP) macKey(kind byte) []byte {
	if kind >= bipKindHello {
		return b.master
	}
	return b.sessionKey
}
func (b *BIP) encode(p wirePacket) ([]byte, error) {
	key := b.macKey(p.kind)
	if len(key) == 0 {
		return nil, errors.New("unknown session")
	}
	body := make([]byte, 72+len(p.payload))
	body[0] = p.typ
	binary.BigEndian.PutUint16(body[4:6], p.id)
	binary.BigEndian.PutUint16(body[6:8], p.tuple)
	copy(body[8:12], bipMagic)
	body[12] = p.kind
	body[13] = p.flags
	binary.BigEndian.PutUint64(body[16:24], p.sender)
	binary.BigEndian.PutUint64(body[24:32], p.target)
	binary.BigEndian.PutUint64(body[32:40], p.number)
	binary.BigEndian.PutUint32(body[40:44], p.token)
	binary.BigEndian.PutUint32(body[44:48], p.ack)
	binary.BigEndian.PutUint64(body[48:56], p.sack)
	copy(body[72:], p.payload)
	tag := packetMAC(key, body)
	copy(body[56:72], tag[:])
	binary.BigEndian.PutUint16(body[2:4], checksum(body))
	return body, nil
}
func packetMAC(key, body []byte) [16]byte {
	h := hmac.New(sha256.New, key)
	h.Write(body[:2])
	h.Write(body[4:56])
	h.Write(body[72:])
	var tag [16]byte
	copy(tag[:], h.Sum(nil))
	return tag
}
func (b *BIP) decode(body []byte) (wirePacket, error) {
	var p wirePacket
	if len(body) < 72 || len(body) > 1480 || string(body[8:12]) != bipMagic || (body[0] != 0 && body[0] != 8) || body[1] != 0 || body[14] != 0 || body[15] != 0 || checksum(body) != 0 {
		return p, errors.New("malformed BIP5")
	}
	p.kind = body[12]
	if p.kind < 1 || p.kind > 10 || body[13]&^(bipFlagMore|bipFlagPulled) != 0 || (body[13]&bipFlagPulled != 0 && p.kind != bipKindData) {
		return p, errors.New("unknown control")
	}
	key := b.macKey(p.kind)
	if len(key) == 0 {
		return p, errBIPUnknownSession
	}
	tag := packetMAC(key, body)
	if !hmac.Equal(tag[:], body[56:72]) {
		return p, errBIPBadMAC
	}
	p.typ = body[0]
	p.flags = body[13]
	p.id = binary.BigEndian.Uint16(body[4:6])
	p.tuple = binary.BigEndian.Uint16(body[6:8])
	p.sender = binary.BigEndian.Uint64(body[16:24])
	p.target = binary.BigEndian.Uint64(body[24:32])
	p.number = binary.BigEndian.Uint64(body[32:40])
	p.token = binary.BigEndian.Uint32(body[40:44])
	p.ack = binary.BigEndian.Uint32(body[44:48])
	p.sack = binary.BigEndian.Uint64(body[48:56])
	p.payload = body[72:]
	span := bipLegacySpan
	if b.peerSpan == bipWideSpan {
		span = bipWideSpan
	}
	if p.kind == bipKindAck && (len(p.payload) > (span/64-1)*8 || len(p.payload)%8 != 0) {
		return p, errors.New("invalid extended ACK")
	}
	if p.sender == 0 || p.number == 0 {
		return p, errors.New("zero identity/counter")
	}
	b.wireRxBytes.Add(uint64(len(body) + 20))
	return p, nil
}
func (b *BIP) SnapshotStats() RuntimeStats {
	b.ackMu.Lock()
	pending := len(b.pending)
	b.ackMu.Unlock()
	return RuntimeStats{PathSuspended: b.pathSuspended.Load(), FastRetransmits: b.fastRetries.Load(), ReorderBuffered: b.rxBuffered.Load(), WireTxBytes: b.wireTxBytes.Load(), WireRxBytes: b.wireRxBytes.Load(), FastDataTx: b.fastDataTx.Load(), PullDataTx: b.pullDataTx.Load(), CompatDataTx: b.compatDataTx.Load(), IdleProbeTx: b.idleProbeTx.Load(), FastProbeTx: b.fastProbeTx.Load(), FastAckTx: b.fastAckTx.Load(), NeedPullTx: b.needPullTx.Load(), PullProbeTx: b.pullProbeTx.Load(), FastAckRx: b.fastAckRx.Load(), NeedPullRx: b.needPullRx.Load(), PullProbeRx: b.pullProbeRx.Load(), ReflectionsSuppressed: b.reflectionsSuppressed.Load(), PayloadFrameRx: b.payloadFrameRx.Load(), HMACFail: b.hmacFail.Load(), MalformedWire: b.malformedWire.Load(), UnknownSession: b.unknownSession.Load(), DataDuplicate: b.dataDuplicate.Load(), Pending: uint64(pending), Backlog: uint64(len(b.tx)), Retransmits: b.retransmits.Load(), PendingExpired: b.pendingExpired.Load(), PendingOverflow: b.pendingOverflow.Load(), FastPromotions: b.fastPromotions.Load(), FastDemotions: b.fastDemotions.Load(), FastHealthy: b.fastHealthy.Load(), PullActive: b.pullActive.Load(), CompatActive: b.compatActive.Load(), TxErrors: b.txErrors.Load()}
}
