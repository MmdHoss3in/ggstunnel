package carrier

import (
	"bytes"
	"context"
	"encoding/binary"
	"ggstunnel/internal/config"
	"ggstunnel/internal/session"
	"sync"
	"testing"
	"time"
)

type simPacket struct {
	dest *BIP
	body []byte
	due  time.Time
}
type simLink struct {
	configure        func(*config.Config)
	adaptive         bool
	delay            time.Duration
	queued           []simPacket
	scheduler        sync.Once
	schedulerWorkers sync.WaitGroup
	mu               sync.Mutex
	ends             [2]*BIP
	filter           func(int, []byte) bool
	copies           int
	dropFirst        bool
	dropped          [2]bool
	held             [2][]byte
	reorder          bool
	requests         map[[3]uint16]time.Time
	stateful         bool
}

func (l *simLink) emit(from int, w []byte) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	body := append([]byte(nil), w[20:]...)
	kind := body[12]
	id, seq := binary.BigEndian.Uint16(body[4:6]), binary.BigEndian.Uint16(body[6:8])
	if body[0] == 8 {
		l.requests[[3]uint16{uint16(from), id, seq}] = time.Now()
	}
	if l.stateful && body[0] == 0 {
		created, ok := l.requests[[3]uint16{uint16(1 - from), id, seq}]
		if !ok || time.Since(created) > time.Second {
			return nil
		}
	}
	if l.filter != nil && !l.filter(from, body) {
		return nil
	}
	if kind == bipKindData && l.dropFirst && !l.dropped[from] {
		l.dropped[from] = true
		return nil
	}
	dest := l.ends[1-from]
	if dest == nil {
		return nil
	}
	deliver := func(p []byte) {
		for i := 0; i < l.copies; i++ {
			if l.delay > 0 {
				if len(l.queued) < 32768 {
					l.queued = append(l.queued, simPacket{dest, append([]byte(nil), p...), time.Now().Add(l.delay)})
				}
				continue
			}
			select {
			case dest.incoming <- append([]byte(nil), p...):
			default:
			}
		}
	}
	if kind == bipKindData && l.reorder {
		if l.held[from] == nil {
			l.held[from] = body
			return nil
		}
		deliver(body)
		deliver(l.held[from])
		l.held[from] = nil
		return nil
	}
	deliver(body)
	return nil
}
func simConfig(role string) *config.Config {
	c := &config.Config{Role: role, Profile: "bip", PSK: "0123456789abcdef0123456789abcdef", Real: config.RealConfig{LocalIP: "198.51.100.10", PeerIP: "203.0.113.20"}, TUN: config.TUNConfig{LocalAddr: "10.77.1.1", RemoteAddr: "10.77.1.2"}}
	c.ApplyDefaults()
	c.Performance.QueueSize = 512
	c.Transport.BIPMaxRetries = 12
	c.Transport.BIPRTOMS = 80
	c.Transport.BIPFastProbeMS = 30
	c.Transport.BIPFastTTLMS = 200
	c.Transport.BIPProbeMS = 30
	c.Transport.BIPPullTimeoutMS = 50
	c.Transport.BIPPullPPS = 2000
	c.Transport.BIPPullBurst = 4
	return c
}
func (l *simLink) start(t *testing.T, index int, ctx context.Context) *BIP {
	t.Helper()
	role := "server"
	if index == 1 {
		role = "client"
	}
	cfg := simConfig(role)
	if l.adaptive {
		cfg.Tuner.Mode = "adaptive"
	}
	if l.configure != nil {
		l.configure(cfg)
	}
	ca, err := NewBIP(cfg)
	if err != nil {
		t.Fatal(err)
	}
	b := ca.(*BIP)
	b.emit = func(w []byte) error { return l.emit(index, w) }
	l.mu.Lock()
	l.ends[index] = b
	l.mu.Unlock()
	if l.delay > 0 {
		l.scheduler.Do(func() { l.schedulerWorkers.Add(1); go l.runScheduler(ctx) })
	}
	b.startActor(ctx)
	t.Cleanup(func() { b.Close() })
	return b
}
func (l *simLink) runScheduler(ctx context.Context) {
	defer l.schedulerWorkers.Done()
	tick := time.NewTicker(time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-tick.C:
			l.mu.Lock()
			kept := l.queued[:0]
			for _, p := range l.queued {
				if now.Before(p.due) {
					kept = append(kept, p)
					continue
				}
				select {
				case p.dest.incoming <- p.body:
				default:
				}
			}
			// Clear references in unused backing slots.
			for i := len(kept); i < len(l.queued); i++ {
				l.queued[i] = simPacket{}
			}
			l.queued = kept
			l.mu.Unlock()
		}
	}
}
func waitFor(t *testing.T, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for !condition() {
		if time.Now().After(deadline) {
			t.Fatal("condition timed out")
		}
		time.Sleep(time.Millisecond)
	}
}
func TestBIPWirePathsLossDuplicateReorder(t *testing.T) {
	for _, adaptive := range []bool{false, true} {
		mode := "manual"
		if adaptive {
			mode = "adaptive"
		}
		for _, name := range []string{"fast", "pull", "compat", "asymmetric", "loss-duplicate-reorder"} {
			t.Run(mode+"/"+name, func(t *testing.T) {
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				l := &simLink{adaptive: adaptive, copies: 1, requests: make(map[[3]uint16]time.Time)}
				switch name {
				case "pull":
					l.stateful = true
				case "compat":
					l.filter = func(_ int, p []byte) bool { return p[12] != bipKindPullProbe && p[12] != bipKindFastProbe }
				case "asymmetric":
					l.filter = func(from int, p []byte) bool { return from != 1 || p[0] != 8 }
				case "loss-duplicate-reorder":
					l.copies = 2
					l.dropFirst = true
					l.reorder = true
				}
				a := l.start(t, 0, ctx)
				b := l.start(t, 1, ctx)
				waitFor(t, func() bool { return a.PeerSession() == b.localID && b.PeerSession() == a.localID })
				if name == "fast" {
					waitFor(t, func() bool { return a.SnapshotStats().FastHealthy && b.SnapshotStats().FastHealthy })
				}
				const count = 100
				for i := 0; i < count; i++ {
					payload := make([]byte, 8)
					binary.BigEndian.PutUint64(payload, uint64(i+1))
					if err := a.Send(payload); err != nil {
						t.Fatal(err)
					}
					if err := b.Send(append([]byte(nil), payload...)); err != nil {
						t.Fatal(err)
					}
				}
				for _, receiver := range []*BIP{a, b} {
					seen := make(map[uint64]bool)
					deadline := time.After(4 * time.Second)
					for len(seen) < count {
						select {
						case p := <-receiver.rx:
							if len(p) != 8 {
								t.Fatal("corrupt payload")
							}
							n := binary.BigEndian.Uint64(p)
							if seen[n] {
								t.Fatalf("duplicate delivery %d", n)
							}
							seen[n] = true
						case err := <-receiver.errors:
							t.Fatal(err)
						case <-deadline:
							t.Fatalf("%s received %d/%d, stats=%+v", name, len(seen), count, receiver.SnapshotStats())
						}
					}
				}
				waitFor(t, func() bool { return a.SnapshotStats().Pending == 0 && b.SnapshotStats().Pending == 0 })
				if name == "fast" && a.fastDataTx.Load() == 0 {
					t.Fatal("FAST never used")
				}
				if name == "pull" && a.pullDataTx.Load() == 0 {
					t.Fatal("PULL never used")
				}
				if name == "compat" && a.compatDataTx.Load() == 0 {
					t.Fatal("COMPAT never used")
				}
				t.Logf("%s a=%+v b=%+v", name, a.SnapshotStats(), b.SnapshotStats())
			})
		}
	}
}

func TestBIPAuthenticatedRestartAndOldProof(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	l := &simLink{copies: 1, requests: make(map[[3]uint16]time.Time)}
	a := l.start(t, 0, ctx)
	b := l.start(t, 1, ctx)
	waitFor(t, func() bool { return a.PeerSession() == b.localID && b.PeerSession() == a.localID })
	oldID := b.localID
	b.Close()
	fresh := l.start(t, 1, ctx)
	waitFor(t, func() bool { return a.PeerSession() == fresh.localID && fresh.PeerSession() == a.localID })
	if fresh.localID == oldID {
		t.Fatal("restart reused identity")
	}
	a.Send([]byte("after restart"))
	select {
	case p := <-fresh.rx:
		if !bytes.Equal(p, []byte("after restart")) {
			t.Fatal("wrong payload")
		}
	case <-time.After(time.Second):
		t.Fatal("restart delivery failed")
	}
	a.Close()
	if err := a.resetPeer(oldID); err == nil {
		t.Fatal("retired identity reset accepted")
	}
}
func authorizeForTest(t *testing.T, b *BIP, peer uint64) {
	t.Helper()
	g, err := session.NewGate(b.master, b.localID, 3)
	if err != nil {
		t.Fatal(err)
	}
	b.gate = g
	c, err := g.Issue(peer, 1, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if err = g.Accept(c, session.Proof(b.master, c), time.Now()); err != nil {
		t.Fatal(err)
	}
	if err = b.resetPeer(peer); err != nil {
		t.Fatal(err)
	}
}
func TestBIPQueueAcceptanceAndReflection(t *testing.T) {
	receiver := testBIP(t)
	sender := testBIP(t)
	sender.localID = 8
	authorizeForTest(t, receiver, 8)
	authorizeForTest(t, sender, 7)
	receiver.rx = make(chan []byte, 1)
	receiver.rx <- []byte("occupied")
	receiver.emit = func([]byte) error { return nil }
	p := wirePacket{typ: 8, kind: bipKindData, sender: 8, target: 7, number: 1, token: 1, payload: []byte("real")}
	body, _ := sender.encode(p)
	receiver.handle(body, time.Now())
	ack, _ := receiver.takeAckForSend()
	if ack != 0 {
		t.Fatal("full queue incorrectly acknowledged")
	}
	<-receiver.rx
	p.number = 2
	body, _ = sender.encode(p)
	receiver.handle(body, time.Now())
	if got := <-receiver.rx; string(got) != "real" {
		t.Fatal("retry not delivered")
	}
	ack, _ = receiver.takeAckForSend()
	if ack != 1 {
		t.Fatal("accepted packet not acknowledged")
	}
	reflected := append([]byte(nil), body...)
	reflected[0] = 0
	binary.BigEndian.PutUint16(reflected[2:4], 0)
	binary.BigEndian.PutUint16(reflected[2:4], checksum(reflected))
	sender.queuePending(outData{seq: 1}, pendingModeRequest, time.Now())
	sender.handle(reflected, time.Now())
	if sender.SnapshotStats().Pending != 1 {
		t.Fatal("kernel reflection confirmed delivery")
	}
}
func TestBIPSACKKeepsHoles(t *testing.T) {
	b := testBIP(t)
	b.rxAck = sackWindow{init: true}
	b.recordRXSeq(2)
	ack, bits := b.takeAckForSend()
	if ack != 0 || bits != 2 {
		t.Fatalf("gap ACK=%d bits=%x", ack, bits)
	}
	b.recordRXSeq(1)
	ack, bits = b.takeAckForSend()
	if ack != 2 || bits != 0 {
		t.Fatal("gap did not close")
	}
}
func FuzzBIPWireParser(f *testing.F) {
	b := testBIP(&testing.T{})
	body, _ := b.encode(wirePacket{typ: 8, kind: bipKindData, sender: 7, target: 8, number: 1, payload: []byte("seed")})
	f.Add(body)
	f.Add([]byte("BIP3"))
	f.Fuzz(func(t *testing.T, p []byte) { b := testBIP(t); _, _ = b.decode(p) })
}
