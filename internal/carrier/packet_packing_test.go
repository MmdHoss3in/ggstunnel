package carrier

import (
	"bytes"
	"errors"
	"testing"
	"time"

	"ggstunnel/internal/frame"
)

func packingFixture(t *testing.T) *BIP {
	b := testBIP(t)
	b.cfg.Performance.MaxFramePayload = 1280
	b.cfg.Transport.BIPRTOMS = 100
	b.active = 8
	b.allowPacking = true
	b.peerPackSupport = true
	b.packetPacking.Store(true)
	b.tx = make(chan []byte, 64)
	return b
}

func TestPacketPackingPreservesFIFOAndDoesNotWait(t *testing.T) {
	b := packingFixture(t)
	input := [][]byte{bytes.Repeat([]byte{1}, 80), bytes.Repeat([]byte{2}, 80), bytes.Repeat([]byte{3}, 1340), []byte{4}}
	for _, p := range input {
		b.tx <- p
	}
	p, flags, count := b.takeTXPayload()
	if flags != bipFlagPacked || count != 2 || b.txBacklog() != 2 {
		t.Fatal("small frames not packed with bounded lookahead")
	}
	if _, ok := validatePacked(p, 1340); !ok {
		t.Fatal("generated invalid bundle")
	}
	b.rx = make(chan []byte, 8)
	if !b.receiveOrderedPayload(1, p, true) {
		t.Fatal("packed frame not retained")
	}
	for i := 0; i < 2; i++ {
		if !bytes.Equal(<-b.rx, input[i]) {
			t.Fatal("packed FIFO changed")
		}
	}
	for i := 2; i < len(input); i++ {
		got, flag, n := b.takeTXPayload()
		if flag != 0 || n != 1 || !bytes.Equal(got, input[i]) {
			t.Fatal("lookahead reordered or delayed a single frame")
		}
	}
	if b.txBacklog() != 0 {
		t.Fatal("lookahead leaked")
	}
}

func TestPacketPackingPartialReceiveRetainsEveryFrameOnce(t *testing.T) {
	b := packingFixture(t)
	for i := 1; i <= 16; i++ {
		b.tx <- []byte{byte(i)}
	}
	p, _, count := b.takeTXPayload()
	if count != 16 {
		t.Fatal("packing count bound changed")
	}
	b.rx = make(chan []byte, 1)
	if !b.receiveOrderedPayload(1, p, true) || !b.receiveOrdered(2, []byte{17}) {
		t.Fatal("bounded receive did not retain flight")
	}
	for i := 1; i <= 17; i++ {
		select {
		case got := <-b.rx:
			if len(got) != 1 || got[0] != byte(i) {
				t.Fatal("partial packed delivery duplicated/reordered")
			}
		default:
			t.Fatal("partial packed delivery lost progress")
		}
		b.drainRX()
	}
	if len(b.rxHold) != 0 || len(b.rxPacked) != 0 || b.rxNext != 3 {
		t.Fatal("packed receive references retained after drain")
	}
}

func TestPacketPackingRequiresCurrentPeerCapability(t *testing.T) {
	b := packingFixture(t)
	b.packetPacking.Store(false)
	b.peerPackSupport = false
	b.emit = func([]byte) error { return nil }
	for _, p := range []wirePacket{{sender: 9, target: b.localID, payload: packAccept}, {sender: 8, target: 99, payload: packAccept}, {sender: 8, target: b.localID}} {
		b.handlePackReady(p)
	}
	if b.packetPacking.Load() {
		t.Fatal("stale/legacy READY enabled new wire format")
	}
	b.handlePackReady(wirePacket{typ: 8, sender: 8, target: b.localID, payload: packOffer})
	if !b.packetPacking.Load() || !b.peerPackSupport {
		t.Fatal("verified peer receive capability was not enabled")
	}
	b.handlePackReady(wirePacket{typ: 0, sender: 8, target: b.localID, payload: packAccept})
	if !b.packetPacking.Load() {
		t.Fatal("verified current peer capability not enabled")
	}
	legacy := packingFixture(t)
	legacy.packetPacking.Store(false)
	legacy.tx <- []byte{1}
	legacy.tx <- []byte{2}
	p, flags, n := legacy.takeTXPayload()
	if flags != 0 || n != 1 || !bytes.Equal(p, []byte{1}) {
		t.Fatal("legacy peer received packed DATA")
	}
}

func TestPackedFramesKeepIndependentAEADAndReplayState(t *testing.T) {
	b := packingFixture(t)
	sender, err := frame.NewCodec("test-only-packing-key")
	if err != nil {
		t.Fatal(err)
	}
	receiver, err := frame.NewCodec("test-only-packing-key")
	if err != nil {
		t.Fatal(err)
	}
	var sealed [][]byte
	for i := 0; i < 4; i++ {
		p, err := sender.Seal(frame.TypeData, sender.NextPacketID(), 0, 1, []byte{byte(i)})
		if err != nil {
			t.Fatal(err)
		}
		sealed = append(sealed, p)
		b.tx <- p
	}
	p, _, _ := b.takeTXPayload()
	b.rx = make(chan []byte, 4)
	b.receiveOrderedPayload(1, p, true)
	for i := 0; i < 4; i++ {
		wire := <-b.rx
		if !bytes.Equal(wire, sealed[i]) {
			t.Fatal("packing altered sealed frame or nonce")
		}
		d, err := receiver.OpenForSession(wire, sender.SessionID())
		if err != nil || !bytes.Equal(d.Payload, []byte{byte(i)}) {
			t.Fatal("independent frame authentication failed")
		}
	}
	if _, err := receiver.OpenForSession(sealed[0], sender.SessionID()); !errors.Is(err, frame.ErrReplay) {
		t.Fatal("packing weakened inner replay protection")
	}
}

func TestPullRetryRetainsPackedPayloadFlag(t *testing.T) {
	b := packingFixture(t)
	b.tx <- []byte{1}
	b.tx <- []byte{2}
	p, flags, _ := b.takeTXPayload()
	var sent []byte
	b.emit = func(w []byte) error { sent = append([]byte(nil), w[20:]...); return nil }
	now := time.Unix(100, 0)
	b.queuePending(outData{seq: 1, data: p, flags: flags}, pendingModePull, now)
	if !b.retryOnPull(31, 5, now.Add(time.Second)) {
		t.Fatal("packed flight not retried")
	}
	w, err := b.decode(sent)
	if err != nil || w.flags&bipFlagPacked == 0 || !bytes.Equal(w.payload, p) {
		t.Fatal("retry lost packed format or ciphertext")
	}
}

func TestMalformedPackedDATADoesNotACKOrConsumePullRequest(t *testing.T) {
	b := packingFixture(t)
	b.replay = frame.NewReplayGuard(65536)
	now := time.Now()
	b.poll.requests = map[uint32]time.Time{pullTuple(31, 5): now}
	invalid := [][]byte{{17}, {2, 0, 1, 7, 0, 0}, {2, 0, 1, 7}, {2, 255, 255}}
	for i, payload := range invalid {
		wire, err := b.encode(wirePacket{typ: 0, kind: bipKindData, flags: bipFlagPacked | bipFlagPulled, sender: 8, target: b.localID, number: uint64(i + 1), id: 31, tuple: 5, token: 1, payload: payload})
		if err != nil {
			t.Fatal(err)
		}
		b.handle(wire, now)
	}
	if len(b.poll.requests) != 1 || b.rxAck.max != 0 || len(b.rxHold) != 0 || b.payloadFrameRx.Load() != 0 || b.malformedWire.Load() != uint64(len(invalid)) {
		t.Fatal("authenticated malformed bundle committed delivery or polling feedback")
	}
}

func TestPackedReceiveAcrossSequenceWrap(t *testing.T) {
	b := packingFixture(t)
	b.rxAck = sackWindow{init: true, max: 0xfffffffd, seen: make(map[uint32]bool)}
	b.rxNext = 0xfffffffe
	b.rx = make(chan []byte, 4)
	b.tx <- []byte{1}
	b.tx <- []byte{2}
	payload, _, _ := b.takeTXPayload()
	if !b.receiveOrderedPayload(0xfffffffe, payload, true) || !b.receiveOrdered(0xffffffff, []byte{3}) || !b.receiveOrdered(1, []byte{4}) {
		t.Fatal("packed receive stalled across sequence zero")
	}
	for i := byte(1); i <= 4; i++ {
		if got := <-b.rx; len(got) != 1 || got[0] != i {
			t.Fatal("packed receive reordered across wrap")
		}
	}
	if b.rxNext != 2 || len(b.rxPacked) != 0 {
		t.Fatal("packed wrap retained stale metadata")
	}
}

func TestPacketPackingCapabilityWithOneRequestDirectionBlocked(t *testing.T) {
	for _, from := range []int{0, 1} {
		a, b := packingFixture(t), packingFixture(t)
		a.localID, a.active = 7, 8
		b.localID, b.active = 8, 7
		a.packetPacking.Store(false)
		b.packetPacking.Store(false)
		a.peerPackSupport = false
		b.peerPackSupport = false
		now := time.Now()
		a.emit = func(w []byte) error {
			if w[20] != 8 {
				b.handle(append([]byte(nil), w[20:]...), now)
			}
			return nil
		}
		b.emit = func(w []byte) error {
			a.handle(append([]byte(nil), w[20:]...), now)
			return nil
		}
		if from == 0 {
			_ = a.send(0, 31, 5, bipKindReady, 0, 0, packOffer, b.localID)
		} else {
			_ = b.send(8, 31, 5, bipKindReady, 0, 0, packOffer, a.localID)
		}
		if !a.packetPacking.Load() || !b.packetPacking.Load() {
			t.Fatal("packing capability required a blocked originated request")
		}
	}
}

func TestPackedDATAOvertakesReverseCapability(t *testing.T) {
	for _, enabled := range []bool{true, false} {
		b := packingFixture(t)
		b.tx <- []byte{1}
		b.tx <- []byte{2}
		payload, flags, _ := b.takeTXPayload()
		b.allowPacking = enabled
		b.packetPacking.Store(false)
		b.peerPackSupport = false
		b.replay = frame.NewReplayGuard(65536)
		b.emit = func([]byte) error { return nil }
		wire, err := b.encode(wirePacket{typ: 8, kind: bipKindData, flags: flags, sender: b.active, target: b.localID, number: 1, id: 31, tuple: 5, token: 1, payload: payload})
		if err != nil {
			t.Fatal(err)
		}
		b.handle(wire, time.Now())
		if enabled {
			if len(b.rx) != 2 || b.rxAck.max != 1 || b.packedFramesRx.Load() != 2 || b.packetPacking.Load() {
				t.Fatal("DATA overtaking READY was dropped or enabled unadvertised TX")
			}
		} else if len(b.rx) != 0 || b.rxAck.max != 0 || b.malformedWire.Load() != 1 {
			t.Fatal("local packing opt-out accepted packed DATA")
		}
	}
}

func FuzzPackedFrameBounds(f *testing.F) {
	f.Add([]byte{2, 0, 1, 7, 0, 1, 8})
	f.Add([]byte{16, 255, 255})
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, p []byte) {
		n, valid := validatePacked(p, 1340)
		if valid && (n < 2 || n > 16 || len(p) > 1340) {
			t.Fatal("unbounded packed payload")
		}
	})
}
