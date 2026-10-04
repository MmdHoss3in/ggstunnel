package carrier

import (
	"context"
	"encoding/binary"
	"sync"
	"testing"
	"time"

	"ggstunnel/internal/config"
	"ggstunnel/internal/frame"
)

func TestPullFeedbackDoesNotFollowFASTOrCOMPAT(t *testing.T) {
	b := testBIP(t)
	b.cfg.Tuner.Mode = "adaptive"
	b.cfg.Tuner.UnlimitedRate = true
	b.tuner = newBIPTuner(b.cfg)
	now := time.Now()
	b.pollingRate(now, true)
	for i := 1; i <= 25; i++ {
		// Incoming non-PULL DATA must not fund thousands of unanswered polls.
		b.payloadFrameRx.Add(10_000)
		b.pollingRate(now.Add(time.Duration(i)*100*time.Millisecond), true)
	}
	if s := b.SnapshotStats(); s.PullBudgetPPS > 50 || s.PulledDataRx != 0 {
		t.Fatalf("unanswered polling follows unrelated DATA: %+v", s)
	}
	// A correlated response restores growth despite local FAST being healthy.
	b.fastHealthy.Store(true)
	b.poll.requests = map[uint32]time.Time{pullTuple(9, 1): now.Add(2500 * time.Millisecond)}
	if !b.poll.reply(9, 1, now.Add(2510*time.Millisecond)) {
		t.Fatal("valid return rejected")
	}
	b.poll.accepted += 100
	if rate := b.pollingRate(now.Add(2600*time.Millisecond), true); rate < 1000 {
		t.Fatalf("PULL did not rediscover the returning direction: %f", rate)
	}
	if b.poll.reply(9, 1, now.Add(2610*time.Millisecond)) || b.poll.reply(9, 2, now) {
		t.Fatal("duplicate or unsolicited feedback accepted")
	}
}

func TestPullFeedbackRequestMemoryAndExpiryBound(t *testing.T) {
	b := testBIP(t)
	b.active = 8
	b.cfg.Transport.BIPPullPPS = 1000
	b.emit = func([]byte) error { return nil }
	now := time.Now()
	b.pollingRate(now, true)
	for i := 0; i < 10000; i++ {
		b.sendPullProbe(now)
	}
	if len(b.poll.requests) != 512 {
		t.Fatal("poll tuples are not bounded to four 128-frame windows")
	}
	b.pollingRate(now.Add(2*time.Second), true)
	if len(b.poll.requests) != 0 || b.SnapshotStats().PullRequestsExpired != 512 {
		t.Fatal("unanswered requests retained")
	}
	if !b.sendPullProbe(now.Add(2 * time.Second)) {
		t.Fatal("expiry blocked rediscovery")
	}
}

func TestPullFeedbackRequiresAuthenticatedCorrelatedUniqueDATA(t *testing.T) {
	b := testBIP(t)
	b.active = 8
	b.replay = frame.NewReplayGuard(65536)
	b.rxAck.init = true
	now := time.Now()
	b.poll.requests = map[uint32]time.Time{pullTuple(9, 1): now, pullTuple(9, 2): now}
	p := wirePacket{typ: 0, kind: bipKindData, flags: bipFlagPulled, id: 9, tuple: 1, sender: 8, target: b.localID, number: 1, token: 1, payload: []byte("first")}
	body, err := b.encode(p)
	if err != nil {
		t.Fatal(err)
	}
	bad := append([]byte(nil), body...)
	bad[len(bad)-1] ^= 1
	binary.BigEndian.PutUint16(bad[2:4], 0)
	binary.BigEndian.PutUint16(bad[2:4], checksum(bad))
	b.handle(bad, now)
	if b.poll.accepted != 0 || len(b.poll.requests) != 2 {
		t.Fatal("unauthenticated DATA consumed poll feedback")
	}
	b.handle(body, now.Add(time.Millisecond))
	b.handle(body, now.Add(2*time.Millisecond))
	p.number = 2
	body, _ = b.encode(p)
	b.handle(body, now.Add(3*time.Millisecond))
	// FAST with a coincident tuple is DATA, not a PULL response.
	p.number, p.token, p.tuple, p.flags = 3, 2, 2, 0
	body, _ = b.encode(p)
	b.handle(body, now.Add(4*time.Millisecond))
	// A late/unmatched pulled frame must still be delivered normally.
	p.number, p.token, p.tuple, p.flags = 4, 3, 99, bipFlagPulled
	body, _ = b.encode(p)
	b.handle(body, now.Add(5*time.Millisecond))
	s := b.SnapshotStats()
	if b.poll.accepted != 1 || s.PullRepliesRx != 1 || s.PulledDataRx != 2 || s.PayloadFrameRx != 3 || len(b.poll.requests) != 1 {
		t.Fatalf("feedback bypassed authentication, correlation or unique retention: %+v", s)
	}
	for i := 0; i < 3; i++ {
		select {
		case <-b.Recv():
		default:
			t.Fatal("late or unmatched DATA was lost")
		}
	}
}

func TestPullFeedbackAsymmetricContinuousTraffic(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	l := &simLink{adaptive: true, delay: time.Millisecond, copies: 1, requests: make(map[[3]uint16]time.Time)}
	l.configure = func(c *config.Config) { c.Tuner.UnlimitedRate = true; c.Transport.BIPPullBurst = 128 }
	var latePolls, lateData int
	began := time.Now()
	l.filter = func(from int, p []byte) bool {
		if from == 0 && time.Since(began) > 2*time.Second {
			if p[12] == bipKindPullProbe {
				latePolls++
			}
			if p[12] == bipKindData {
				lateData++
			}
		}
		return from != 0 || p[0] != 8 || p[12] >= bipKindHello
	}
	a, b := l.start(t, 0, ctx), l.start(t, 1, ctx)
	waitFor(t, func() bool { return a.PeerSession() == b.localID && b.PeerSession() == a.localID })
	var workers sync.WaitGroup
	var counts [2]int
	for i, endpoint := range []*BIP{a, b} {
		workers.Add(2)
		go func(e *BIP) {
			defer workers.Done()
			tick := time.NewTicker(time.Millisecond)
			defer tick.Stop()
			seq := uint32(1)
			for {
				select {
				case <-ctx.Done():
					return
				case <-tick.C:
					for batch := 0; batch < 2; batch++ {
						packet := make([]byte, 1200)
						binary.BigEndian.PutUint32(packet, seq)
						if e.SendContext(ctx, packet) != nil {
							return
						}
						seq++
					}
				}
			}
		}(endpoint)
		go func(i int, e *BIP) {
			defer workers.Done()
			var previous uint32
			for {
				select {
				case packet := <-e.Recv():
					seq := binary.BigEndian.Uint32(packet)
					if seq != previous+1 {
						t.Errorf("direction %d reordered or corrupted DATA: %d after %d", i, seq, previous)
						return
					}
					previous = seq
					counts[i]++
				case <-ctx.Done():
					return
				}
			}
		}(i, endpoint)
	}
	time.Sleep(4 * time.Second)
	cancel()
	workers.Wait()
	a.Close()
	b.Close()
	l.mu.Lock()
	polls, data := latePolls, lateData
	l.mu.Unlock()
	if counts[0] < 500 || counts[1] < 500 || data < 500 || polls > 250 {
		t.Fatalf("asymmetric progress/poll budget: delivered=%v late_data=%d late_polls=%d", counts, data, polls)
	}
	if a.SnapshotStats().PulledDataRx != 0 || a.SnapshotStats().PullRepliesRx != 0 {
		t.Fatal("COMPAT counted as useful PULL feedback")
	}
	t.Logf("delivered=%v late_data=%d late_polls=%d", counts, data, polls)
}
