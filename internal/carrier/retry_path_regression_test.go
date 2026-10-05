package carrier

import (
	"testing"
	"time"
)

func TestFASTLostProbeRetriesLiveTokenWithoutExtendingDeadline(t *testing.T) {
	c := simConfig("server")
	c.Transport.BIPFastProbeMS = 1000
	c.Transport.BIPFastTTLMS = 3500
	x, err := NewBIP(c)
	if err != nil {
		t.Fatal(err)
	}
	b := x.(*BIP)
	defer b.Close()
	if err := b.BindIdentity(7); err != nil {
		t.Fatal(err)
	}
	b.active = 9
	b.sessionKey = []byte("test-key")
	var packets [][]byte
	b.emit = func(packet []byte) error {
		packets = append(packets, append([]byte(nil), packet[20:]...))
		return nil
	}
	now := time.Unix(100, 0)
	if err := b.maintainFASTProbe(now); err != nil {
		t.Fatal(err)
	}
	token, deadline, counter := b.fastToken, b.fastDeadline, b.packetNo
	if err := b.maintainFASTProbe(now.Add(500 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	if len(packets) != 1 {
		t.Fatal("pending probe exceeded configured interval")
	}
	if err := b.maintainFASTProbe(now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if len(packets) != 2 || token == 0 || b.fastToken != token || b.fastDeadline != deadline || b.packetNo != counter+1 {
		t.Fatal("lost probe did not retry its live token with fresh outer counter and fixed deadline")
	}
	if packets[0][4] == packets[1][4] && packets[0][5] == packets[1][5] && packets[0][6] == packets[1][6] && packets[0][7] == packets[1][7] {
		t.Fatal("probe retry reused an outer tuple")
	}
	peer := testBIP(t)
	peer.localID = 9
	ack, err := peer.encode(wirePacket{typ: 8, kind: bipKindFastAck, sender: 9, target: 7, number: 1, token: token})
	if err != nil {
		t.Fatal(err)
	}
	accepted := now.Add(1080 * time.Millisecond)
	b.handle(ack, accepted)
	if b.fastToken != 0 || b.fastUntil != accepted.Add(3500*time.Millisecond) || b.fastAckRx.Load() != 1 {
		t.Fatal("authenticated response to retransmitted probe did not preserve FAST health")
	}
	// A response at/after the token deadline must never validate a stale probe.
	if err := b.maintainFASTProbe(now.Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	token = b.fastToken
	deadline = b.fastDeadline
	ack, err = peer.encode(wirePacket{typ: 8, kind: bipKindFastAck, sender: 9, target: 7, number: 2, token: token})
	if err != nil {
		t.Fatal(err)
	}
	before := b.fastUntil
	b.handle(ack, deadline)
	if b.fastUntil != before || b.fastAckRx.Load() != 1 {
		t.Fatal("expired probe extended path health")
	}
}

func TestBlockedRequestSACKDoesNotSpendRetryBudgetBeforeBackoff(t *testing.T) {
	b := testBIP(t)
	b.tuner = adaptiveTuner()
	b.tuner.srtt = 80 * time.Millisecond
	now := time.Unix(100, 0)
	b.queuePending(outData{seq: 1, retries: 5}, pendingModeRequest, now)
	deadline := b.pending[1].deadline
	for seq := uint32(2); seq <= 5; seq++ {
		b.queuePending(outData{seq: seq}, pendingModeFast, now.Add(10*time.Millisecond))
	}
	b.processPeerAckAt(0, 0b11110, now.Add(100*time.Millisecond))
	for i := 0; i < 20; i++ {
		b.recoverPersistentHole(0, 0b11110, nil, false, now.Add(300*time.Millisecond))
	}
	if b.requestPathProven || b.pending[1].deadline != deadline || b.pending[1].fast || b.pending[1].item.retries != 5 {
		t.Fatal("working FAST SACKs accelerated an unproven blocked request carrier")
	}
	if _, ok := b.takeTimedOut(now.Add(time.Second), time.Second); ok {
		t.Fatal("blocked fallback consumed an early attempt")
	}
	// A returned peer PULL remains usable immediately, including before the
	// request backoff expires, without replacing the data sequence or budget.
	b.cfg.Transport.BIPMaxRetries = 8
	b.active = 9
	b.emit = func([]byte) error { return nil }
	if !b.retryOnPull(3, 4, now.Add(301*time.Millisecond)) {
		t.Fatal("retained blocked request was not returned on a usable peer tuple")
	}
	if b.pending[1].mode != pendingModePull || b.pending[1].item.retries != 6 || b.dataSeq != 0 {
		t.Fatal("PULL recovery changed identity/sequence or discarded retry budget")
	}
}

func TestRequestCarrierProofRequiresCleanDeliveryAndEnablesRecovery(t *testing.T) {
	b := testBIP(t)
	b.tuner = adaptiveTuner()
	now := time.Unix(100, 0)
	b.queuePending(outData{seq: 1, retries: 1}, pendingModeRequest, now)
	b.processPeerAckAt(1, 0, now.Add(80*time.Millisecond))
	if b.requestPathProven {
		t.Fatal("ambiguous retry ACK proved the request route")
	}
	b.queuePending(outData{seq: 2}, pendingModeRequest, now)
	b.processPeerAckAt(2, 0, now.Add(80*time.Millisecond))
	if !b.requestPathProven {
		t.Fatal("clean request delivery failed to prove the carrier")
	}
	for seq := uint32(3); seq <= 7; seq++ {
		b.queuePending(outData{seq: seq}, pendingModeRequest, now.Add(time.Second))
	}
	deadline := b.pending[3].deadline
	b.processPeerAckAt(2, 0b11110, now.Add(1080*time.Millisecond))
	if !b.pending[3].fast || !b.pending[3].deadline.Before(deadline) {
		t.Fatal("proven compatibility route lost normal SACK recovery")
	}
}
