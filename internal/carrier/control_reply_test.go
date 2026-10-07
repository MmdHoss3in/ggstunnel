package carrier

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"syscall"
	"testing"
	"time"

	"ggstunnel/internal/config"
)

func replyControlPeers(t *testing.T, wire string) (*BIP, *BIP) {
	t.Helper()
	newPeer := func(role string) *BIP {
		c := simConfig(role)
		c.Transport.BIPWireMode = wire
		c.Transport.BIPFastProbeMS = 1000
		c.Transport.BIPFastTTLMS = 3500
		carrier, err := NewBIP(c)
		if err != nil {
			t.Fatal(err)
		}
		b := carrier.(*BIP)
		t.Cleanup(func() { b.Close() })
		return b
	}
	a, b := newPeer("server"), newPeer("client")
	a.active, b.active = b.localID, a.localID
	a.peerID.Store(b.localID)
	b.peerID.Store(a.localID)
	a.sessionKey = bytes.Repeat([]byte{17}, 32)
	b.sessionKey = append([]byte(nil), a.sessionKey...)
	return a, b
}

func TestReplyControlNegotiatesWithoutChangingLiveProbeDeadline(t *testing.T) {
	for _, wire := range []string{"legacy", "compact"} {
		t.Run(wire, func(t *testing.T) {
			a, b := replyControlPeers(t, wire)
			var probes, replies [][]byte
			a.emit = func(p []byte) error {
				probes = append(probes, p[20:])
				return nil
			}
			b.emit = func(p []byte) error {
				replies = append(replies, p[20:])
				return nil
			}
			now := time.Unix(100, 0)
			if err := a.maintainFASTProbe(now); err != nil {
				t.Fatal(err)
			}
			token, deadline := a.fastToken, a.fastDeadline
			b.handle(probes[0], now.Add(40*time.Millisecond))
			if len(replies) != 1 || replies[0][0] != 8 {
				t.Fatal("ordinary probe changed the traditional response")
			}
			// Drop the type-8 return, exactly as observed in the field pcap.
			if err := a.maintainFASTProbe(now.Add(time.Second)); err != nil {
				t.Fatal(err)
			}
			if a.fastToken != token || a.fastDeadline != deadline {
				t.Fatal("alternative response request extended or replaced the token")
			}
			b.handle(probes[1], now.Add(1040*time.Millisecond))
			if len(replies) != 3 || replies[1][0] != 8 || replies[2][0] != 0 {
				t.Fatal("requested alternative lost the traditional response or reply")
			}
			p, err := a.decode(replies[2])
			if err != nil || p.token != token || p.sender != b.localID || p.target != a.localID {
				t.Fatalf("alternative is not an authenticated peer response: %v", err)
			}
			accepted := now.Add(1080 * time.Millisecond)
			a.handle(replies[2], accepted)
			if a.fastToken != 0 || !a.fastUntil.After(accepted) || a.controlReply.accepted.Load() != 1 || !a.controlReply.preferReply {
				t.Fatal("fresh response did not validate FAST")
			}
			a.handle(replies[2], accepted.Add(time.Millisecond))
			if a.controlReply.accepted.Load() != 1 {
				t.Fatal("replay counted as fresh path evidence")
			}
			// No application traffic returns from b: its control ACK alone
			// must retire a's complete flight on the blocked request path.
			a.dataSeq = 1
			a.queuePending(outData{seq: 1, data: []byte("one-way")}, pendingModeFast, accepted)
			if !b.recordRXSeq(1) {
				t.Fatal("could not record receiver delivery")
			}
			replies = nil
			b.scheduleAck(wirePacket{typ: 0, id: 9, tuple: 11}, accepted, true)
			if len(replies) != 2 || replies[0][0] != 0 || replies[1][0] != 8 {
				t.Fatal("one-way ACK lacks reply and traditional backup")
			}
			a.handle(replies[0], accepted.Add(40*time.Millisecond))
			if len(a.pending) != 0 {
				t.Fatal("one-way flight did not receive its standalone ACK")
			}
			// A working traditional response switches the next probe back.
			if err := a.maintainFASTProbe(now.Add(2 * time.Second)); err != nil {
				t.Fatal(err)
			}
			replies = nil
			b.handle(probes[2], now.Add(2040*time.Millisecond))
			a.handle(replies[0], now.Add(2080*time.Millisecond))
			if a.controlReply.preferReply {
				t.Fatal("traditional return path cannot recover")
			}
			b.scheduleAck(wirePacket{typ: 8, id: 71, tuple: 72}, accepted, false)
			if b.ackType != 0 || b.ackID != 71 || b.ackTuple != 72 || b.controlReply.ackBackup {
				t.Fatal("paired stateful request ACK was changed")
			}
		})
	}
}

func TestReplyControlACKExpiryAndSendFailures(t *testing.T) {
	for _, failedType := range []int{-1, 0, 8, 9} {
		t.Run(fmt.Sprint(failedType), func(t *testing.T) {
			b := testBIP(t)
			b.active = 9
			b.cfg.Transport.BIPAckMS = 10
			now := time.Unix(100, 0)
			b.controlReply.peerUntil = now.Add(time.Second)
			var types []byte
			b.emit = func(p []byte) error {
				types = append(types, p[20])
				if int(p[20]) == failedType || failedType == 9 {
					return syscall.EAGAIN
				}
				return nil
			}
			b.scheduleAck(wirePacket{typ: 0}, now, true)
			if len(types) != 2 || types[0] != 0 || types[1] != 8 || b.ackDue.IsZero() != (failedType != 9) {
				t.Fatal("ACK success/retention does not reflect both send results")
			}
			b.scheduleAck(wirePacket{typ: 0}, now.Add(time.Second), false)
			if b.ackType != 8 || b.controlReply.ackBackup {
				t.Fatal("expired request changed future ACK routing")
			}
		})
	}
}

func TestReplyControlSuccessfulDATAStillCoalescesACK(t *testing.T) {
	b := testBIP(t)
	b.active = 9
	now := time.Now()
	b.controlReply.peerUntil = now.Add(time.Second)
	var emitted int
	b.emit = func([]byte) error {
		emitted++
		return nil
	}
	if !b.recordRXSeq(1) {
		t.Fatal("could not record receiver delivery")
	}
	b.scheduleAck(wirePacket{typ: 0}, now, false)
	if err := b.send(0, 1, 2, bipKindData, 0, 1, []byte("return DATA"), b.active); err != nil {
		t.Fatal(err)
	}
	if !b.ackDue.IsZero() || emitted != 1 || b.acksCoalesced.Load() != 1 || b.controlReply.sent.Load() != 0 {
		t.Fatal("alternative control path added ACKs despite successful DATA piggyback")
	}
}

func TestReplyControlStaleOrForgedResponseCannotPromoteFAST(t *testing.T) {
	for _, wire := range []string{"legacy", "compact"} {
		t.Run(wire, func(t *testing.T) {
			a, b := replyControlPeers(t, wire)
			a.emit = func([]byte) error { return nil }
			now := time.Unix(100, 0)
			a.fastToken, a.fastDeadline = 17, now.Add(time.Second)
			for i, tc := range []struct {
				token uint32
				at    time.Time
			}{
				{18, now}, {17, now.Add(time.Second)},
			} {
				p, err := b.encode(wirePacket{typ: 0, kind: bipKindFastAck, sender: b.localID, target: a.localID, number: uint64(i + 1), token: tc.token})
				if err != nil {
					t.Fatal(err)
				}
				a.handle(p, tc.at)
				if !a.fastUntil.IsZero() || a.controlReply.accepted.Load() != 0 {
					t.Fatal("mismatched or expired response promoted FAST")
				}
			}
			p, err := b.encode(wirePacket{typ: 0, kind: bipKindFastProbe, flags: bipFlagReplyControl, sender: b.localID, target: a.localID, number: 3, token: 99})
			if err != nil {
				t.Fatal(err)
			}
			p[len(p)-1] ^= 1
			binary.BigEndian.PutUint16(p[2:4], 0)
			binary.BigEndian.PutUint16(p[2:4], checksum(p))
			a.handle(p, now)
			if !a.controlReply.peerUntil.IsZero() || !a.fastUntil.IsZero() {
				t.Fatal("unauthenticated hint changed control routing")
			}
			a.controlReply.preferReply = true
			a.controlReply.peerUntil = now.Add(time.Second)
			a.controlReply.reset()
			if a.controlReply.preferReply || !a.controlReply.peerUntil.IsZero() {
				t.Fatal("new identity retained old path preference")
			}
		})
	}
}

func TestReplyControlDirectionalBlockOneWayDelivery(t *testing.T) {
	for _, wire := range []string{"legacy", "compact"} {
		for blocked := 0; blocked < 2; blocked++ {
			t.Run(fmt.Sprintf("%s/blocked%d", wire, blocked), func(t *testing.T) {
				ctx, cancel := context.WithCancel(context.Background())
				l := &simLink{adaptive: true, delay: 20 * time.Millisecond, copies: 1, requests: make(map[[3]uint16]time.Time)}
				defer func() {
					cancel()
					l.schedulerWorkers.Wait()
				}()
				l.configure = func(c *config.Config) {
					c.Transport.BIPWireMode = wire
					c.Transport.BIPFastTTLMS = 1000
					c.Tuner.UnlimitedRate = true
				}
				l.filter = func(from int, p []byte) bool { return from != blocked || p[0] != 8 }
				a, b := l.start(t, 0, ctx), l.start(t, 1, ctx)
				waitFor(t, func() bool { return a.SnapshotStats().FastHealthy && b.SnapshotStats().FastHealthy })
				for from, sender := range []*BIP{a, b} {
					receiver := []*BIP{b, a}[from]
					const count = 128
					for seq := 1; seq <= count; seq++ {
						payload := make([]byte, 1200)
						binary.BigEndian.PutUint32(payload, uint32(seq))
						if err := sender.SendContext(ctx, payload); err != nil {
							t.Fatal(err)
						}
					}
					deadline := time.After(3 * time.Second)
					for seq := 1; seq <= count; seq++ {
						select {
						case payload := <-receiver.Recv():
							if len(payload) != 1200 || binary.BigEndian.Uint32(payload) != uint32(seq) {
								t.Fatal("one-way DATA lost order or integrity")
							}
						case err := <-sender.Errors():
							t.Fatal(err)
						case <-deadline:
							t.Fatal("one-way DATA stalled")
						}
					}
					waitFor(t, func() bool { return sender.SnapshotStats().Pending == 0 })
				}
				if a.SnapshotStats().PendingExpired != 0 || b.SnapshotStats().PendingExpired != 0 {
					t.Fatal("working directional path exhausted delivery retries")
				}
			})
		}
	}
}

func TestReplyControlUnansweredPullBackoffAndRediscovery(t *testing.T) {
	b := testBIP(t)
	b.cfg.Tuner.Mode = "adaptive"
	b.cfg.Tuner.UnlimitedRate = true
	b.tuner = newBIPTuner(b.cfg)
	now := time.Unix(100, 0)
	for i := 0; i <= 80; i++ {
		b.pollingRate(now.Add(time.Duration(i)*100*time.Millisecond), true)
	}
	if rate := b.pollingRate(now.Add(8100*time.Millisecond), true); rate != 5 {
		t.Fatalf("stale PULL did not reach bounded discovery: %f", rate)
	}
	b.poll.requests = map[uint32]time.Time{pullTuple(9, 1): now.Add(8100 * time.Millisecond)}
	if !b.poll.reply(9, 1, now.Add(8110*time.Millisecond)) {
		t.Fatal("late discovery reply rejected")
	}
	b.poll.accepted++
	if rate := b.pollingRate(now.Add(8200*time.Millisecond), true); rate < 1000 {
		t.Fatal("useful correlated DATA failed to restore polling capacity")
	}
}
