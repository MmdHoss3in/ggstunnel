package carrier

import (
	"context"
	"testing"

	"ggstunnel/internal/frame"
)

func TestNativeReceiveBatchKeepsPulledRepliesInOneEvent(t *testing.T) {
	b := testBIP(t)
	b.active = 8
	b.replay = frame.NewReplayGuard(65536)
	b.tx = make(chan []byte, 3)
	b.collectDATA = true
	b.emit = func([]byte) error { t.Fatal("native DATA escaped scalar path"); return nil }
	var batches [][]byte
	b.batchEmit = func(packets [][]byte) (int, error) {
		batches = append(batches, packets...)
		return len(packets), nil
	}
	var requests [][]byte
	for i := 1; i <= 3; i++ {
		b.tx <- []byte{byte(i)}
		p, err := b.encode(wirePacket{typ: 8, kind: bipKindPullProbe, sender: 8, target: b.localID, number: uint64(i), id: 31, tuple: uint16(i)})
		if err != nil { t.Fatal(err) }
		requests = append(requests, p)
	}
	b.processNativeBatch(context.Background(), requests)
	if len(batches) != 0 || len(b.dataBatch) != 3 || len(b.pending) != 3 {
		t.Fatal("completed receive batch did not retain one bounded DATA event")
	}
	b.flushDataBatch()
	if len(batches) != 3 || b.SnapshotStats().TxErrors != 0 { t.Fatal("native response batch did not send completely") }
	for i, packet := range batches {
		if packet[20] != 0 || packet[len(packet)-1] != byte(i+1) { t.Fatal("DATA response order/payload changed") }
	}
}
