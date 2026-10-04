package carrier

import (
	"bytes"
	"encoding/binary"
	"testing"
	"time"
)

func TestCachedPacketMACMatchesWireAcrossKeysAndTypes(t *testing.T) {
	b := testBIP(t)
	for rotation := 0; rotation < 4; rotation++ {
		b.sessionKey = bytes.Repeat([]byte{byte(rotation + 1)}, 32)
		b.master = bytes.Repeat([]byte{byte(rotation + 17)}, 32)
		for _, kind := range []byte{bipKindData, bipKindAck, bipKindHello, bipKindProof} {
			for _, typ := range []byte{0, 8} {
				for _, length := range []int{0, 64, 1200} {
					p := wirePacket{kind: kind, typ: typ, sender: 8, target: b.localID, number: 1, token: 1, payload: bytes.Repeat([]byte{31}, length)}
					body, err := b.encode(p)
					if err != nil {
						t.Fatal(err)
					}
					want := packetMAC(b.macKey(kind), body)
					if !bytes.Equal(want[:], body[56:72]) || b.wireMAC(body, typ) != want {
						t.Fatal("wire MAC changed")
					}
					other := append([]byte(nil), body...)
					other[0] = typ ^ 8
					if b.wireMAC(body, typ^8) != packetMAC(b.macKey(kind), other) {
						t.Fatal("reflection MAC changed")
					}
					body[72-1] ^= 1
					binary.BigEndian.PutUint16(body[2:4], 0)
					binary.BigEndian.PutUint16(body[2:4], checksum(body))
					if _, err = b.decode(body); err == nil {
						t.Fatal("MAC tamper accepted")
					}
				}
			}
		}
	}
}

func TestSingleBufferIPEncodingRetainsAuthenticatedPayload(t *testing.T) {
	b := testBIP(t)
	b.active = 8
	b.emit = func(packet []byte) error {
		if checksum(packet[:20]) != 0 || int(binary.BigEndian.Uint16(packet[2:4])) != len(packet) {
			t.Fatal("IPv4 header changed")
		}
		p, err := b.decode(packet[20:])
		if err != nil || !bytes.Equal(p.payload, []byte("retained DATA")) || p.token != 17 {
			t.Fatalf("packet invalid: %v", err)
		}
		return nil
	}
	if err := b.send(0, 9, 10, bipKindData, bipFlagPulled, 17, []byte("retained DATA"), 8); err != nil {
		t.Fatal(err)
	}
}

func TestPartialDataBatchRetainsUnsentFlightForRetry(t *testing.T) {
	b := testBIP(t)
	b.active = 8
	b.tx = make(chan []byte, 3)
	b.emit = func([]byte) error { return nil }
	b.batchEmit = func(packets [][]byte) (int, error) { return 1, nil }
	b.collectDATA = true
	now := time.Now()
	for i := 0; i < 3; i++ {
		b.tx <- []byte{byte(i+1)}
		b.deliverOne(0, 9, uint16(i+1), pendingModeFast, now)
	}
	if len(b.pending) != 3 || len(b.dataBatch) != 3 || b.wireTxBytes.Load() != 0 { t.Fatal("DATA not retained before batch emission") }
	b.flushDataBatch()
	if len(b.pending) != 3 || len(b.dataBatch) != 0 || b.wireTxBytes.Load() != 93 || b.txErrors.Load() != 2 { t.Fatal("unsent DATA flight lost or accounted as success") }
	b.processPeerAckAt(1, 0, now.Add(time.Millisecond))
	if len(b.pending) != 2 { t.Fatal("unacknowledged suffix removed") }
	retry, ok := b.takeTimedOut(now.Add(time.Second), 250*time.Millisecond)
	if !ok || retry.item.seq < 2 || !bytes.Equal(retry.item.data, []byte{byte(retry.item.seq)}) { t.Fatal("unsent suffix not eligible for ordinary retry") }
}
