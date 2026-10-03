package carrier

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"ggstunnel/internal/config"
	"testing"
	"time"
)

func TestWideACKAuthenticationAndRecovery(t *testing.T) {
	b := testBIP(t)
	b.rxAck.init = true
	b.rxAck.max = 4135
	for s := uint32(4137); s <= 8231; s++ {
		b.recordRXSeq(s)
		b.pending[s] = &pendingData{}
	}
	b.pending[4136] = &pendingData{}
	ack, bits := b.takeAckForSend()
	extra := b.ackExtension(ack)
	if len(extra) != 504 {
		t.Fatal(len(extra))
	}
	body, err := b.encode(wirePacket{typ: 8, kind: bipKindAck, sender: 8, number: 1, ack: ack, sack: bits, payload: extra})
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := b.decode(body)
	if err != nil {
		t.Fatal(err)
	}
	b.processWideAckAt(decoded.ack, decoded.sack, decoded.payload, time.Now())
	if len(b.pending) != 1 || b.pending[4136] == nil {
		t.Fatal("SACK lost hole or failed to cover full window")
	}
	for i := 72; i < len(body); i++ {
		bad := append([]byte(nil), body...)
		bad[i] ^= 1
		bad[2] = 0
		bad[3] = 0
		binary.BigEndian.PutUint16(bad[2:4], checksum(bad))
		if _, err = b.decode(bad); !errors.Is(err, errBIPBadMAC) {
			t.Fatal("unprotected extension", i, err)
		}
	}
	b.recordRXSeq(4136)
	ack, bits = b.takeAckForSend()
	b.processWideAckAt(ack, bits, b.ackExtension(ack), time.Now())
	if len(b.pending) != 0 || ack != 8231 {
		t.Fatal("hole recovery")
	}
	// No extension overhead at all on ordered data/ACK traffic.
	if len(b.ackExtension(ack)) != 0 {
		t.Fatal("unneeded ACK payload")
	}
}
func TestWideACKRejectsMalformedLength(t *testing.T) {
	b := testBIP(t)
	for _, n := range []int{1, 7, 505, 512} {
		p, _ := b.encode(wirePacket{typ: 8, kind: bipKindAck, sender: 8, number: 1, payload: make([]byte, n)})
		if _, err := b.decode(p); err == nil {
			t.Fatal("accepted length", n)
		}
	}
}
func TestUnlimitedTunerHasNoTenThousandPPSCeiling(t *testing.T) {
	x := adaptiveTuner()
	x.cfg.UnlimitedRate = true
	x.maxWindow = 4096
	x.cwnd = 4096
	x.srtt = 80 * time.Millisecond
	if x.rate() != 51200 {
		t.Fatal(x.rate())
	}
	x.cfg.UnlimitedRate = false
	if x.rate() > float64(x.cfg.MaxPPS) {
		t.Fatal("explicit limit ignored")
	}
}
func TestWideACKDelayedBulk(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	l := &simLink{adaptive: true, delay: 40 * time.Millisecond, copies: 1, requests: make(map[[3]uint16]time.Time)}
	defer func() { cancel(); l.schedulerWorkers.Wait() }()
	l.configure = func(c *config.Config) {
		c.Performance.QueueSize = 8192
		c.Tuner.UnlimitedRate = true
		c.Tuner.MaxBurst = 128
		c.Transport.BIPPullBurst = 128
		c.Transport.BIPRTOMS = 300
		c.Transport.BIPFastTTLMS = 1000
	}
	a := l.start(t, 0, ctx)
	b := l.start(t, 1, ctx)
	waitFor(t, func() bool { return a.PeerSession() != 0 && b.PeerSession() != 0 })
	peakWindow := 0
	const count = 6000
	started := time.Now()
	for i := 0; i < count; i++ {
		p := bytes.Repeat([]byte{byte(i)}, 1280)
		binary.BigEndian.PutUint32(p, uint32(i))
		if err := a.Send(p); err != nil {
			t.Fatal(err)
		}
	}
	seen := make(map[uint32]bool)
	deadline := time.After(30 * time.Second)
	for len(seen) < count {
		select {
		case p := <-b.Recv():
			id := binary.BigEndian.Uint32(p)
			if len(p) != 1280 || id >= count || seen[id] || !bytes.Equal(p[4:], bytes.Repeat([]byte{byte(id)}, 1276)) {
				t.Fatal("corrupt/duplicate")
			}
			seen[id] = true
			peakWindow = max(peakWindow, a.SnapshotTuner().Window)
		case err := <-a.Errors():
			t.Fatal(err)
		case <-deadline:
			t.Fatalf("received %d", len(seen))
		}
	}
	waitFor(t, func() bool { return a.SnapshotStats().Pending == 0 })
	t.Logf("simulated 80ms RTT: %.2f Mbps incl ramp-up; tuner=%+v", count*1280*8/time.Since(started).Seconds()/1e6, a.SnapshotTuner())
	if peakWindow <= 64 {
		t.Fatal("remained at legacy window")
	}
}
func BenchmarkWideACKCumulative(b *testing.B) {
	x := &BIP{pending: make(map[uint32]*pendingData)}
	now := time.Now()
	for i := 0; i < b.N; i++ {
		seq := uint32(i%1000000 + 1)
		if seq == 1 {
			x.txAckBase = 0
		}
		x.pending[seq] = &pendingData{}
		x.processPeerAckAt(seq, 0, now)
	}
}

func TestBIP5SustainedSimulation(t *testing.T) {
	if testing.Short() {
		t.Skip("sustained simulator")
	}
	for _, stateful := range []bool{false, true} {
		t.Run(map[bool]string{false: "fast", true: "pull"}[stateful], func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			l := &simLink{adaptive: true, delay: 40 * time.Millisecond, copies: 1, stateful: stateful, requests: make(map[[3]uint16]time.Time)}
			defer func() { cancel(); l.schedulerWorkers.Wait() }()
			l.configure = func(c *config.Config) {
				c.Performance.QueueSize = 8192
				c.Tuner.UnlimitedRate = true
				c.Tuner.MaxBurst = 128
				c.Transport.BIPPullBurst = 128
				c.Transport.BIPRTOMS = 300
				c.Transport.BIPFastTTLMS = 1000
				c.Transport.BIPMaxRetries = 12
			}
			a := l.start(t, 0, ctx)
			b := l.start(t, 1, ctx)
			waitFor(t, func() bool { return a.PeerSession() != 0 && b.PeerSession() != 0 })
			const count = 30000
			const warmup = 5000
			sent := make(chan error, 1)
			go func() {
				for i := 0; i < count; i++ {
					p := make([]byte, 1280)
					binary.BigEndian.PutUint32(p, uint32(i))
					for {
						err := a.Send(p)
						if err == nil {
							break
						}
						if !errors.Is(err, ErrQueueFull) {
							sent <- err
							return
						}
						select {
						case <-ctx.Done():
							sent <- ctx.Err()
							return
						case <-time.After(time.Millisecond):
						}
					}
				}
				sent <- nil
			}()
			seen := make(map[uint32]bool)
			deadline := time.After(45 * time.Second)
			var warm time.Time
			for len(seen) < count {
				select {
				case p := <-b.Recv():
					id := binary.BigEndian.Uint32(p)
					if len(p) != 1280 || id >= count || seen[id] {
						t.Fatal("bad delivery")
					}
					seen[id] = true
					if len(seen) == warmup {
						warm = time.Now()
					}
				case err := <-a.Errors():
					t.Fatal(err)
				case <-deadline:
					t.Fatalf("only %d", len(seen))
				}
			}
			if err := <-sent; err != nil {
				t.Fatal(err)
			}
			t.Logf("80ms carrier simulation, steady receive %.2f Mbps; %+v", (count-warmup)*1280*8/time.Since(warm).Seconds()/1e6, a.SnapshotTuner())
		})
	}
}

func TestNineBIP5Peers(t *testing.T) {
	for i := 0; i < 9; i++ {
		t.Run(string(rune('A'+i)), func(t *testing.T) { t.Parallel(); TestWideACKDelayedBulk(t) })
	}
}
