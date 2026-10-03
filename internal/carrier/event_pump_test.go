package carrier

import (
	"context"
	"testing"
	"time"
)

func TestFASTEventPumpHonorsWindowPacingAndPath(t *testing.T) {
	b := spanSender(t, 0)
	b.cfg.Tuner.MaxBurst = 128
	b.tuner = adaptiveTuner()
	b.tuner.maxWindow = 8192
	b.tuner.cwnd = 512
	b.tuner.cfg.MaxBurst = 128
	b.tuner.credit = 128
	now := time.Now()
	b.fastUntil = now.Add(time.Second)
	b.pumpFast(now)
	if b.dataSeq != 128 { t.Fatal("producer event did not send bounded burst", b.dataSeq) }
	b.pumpFast(now)
	if b.dataSeq != 128 { t.Fatal("event bypassed pacing") }
	b.tuner.credit = 128
	b.pumpFast(now)
	if b.dataSeq != 256 { t.Fatal("same tick unnecessarily limited throughput") }
	b.tuner.cwnd = 256
	b.tuner.credit = 128
	b.pumpFast(now)
	if b.dataSeq != 256 { t.Fatal("event bypassed flight window") }
	b.processPeerAckAt(256, 0, now.Add(time.Millisecond))
	b.fastUntil = now
	b.pumpFast(now)
	if b.dataSeq != 256 { t.Fatal("unverified path accepted FAST data") }
}

func TestSendContextCoalescesActorWakeups(t *testing.T) {
	b := testBIP(t)
	b.cfg.Performance.MaxFramePayload = 1280
	b.tx = make(chan []byte, 64)
	b.txReady = make(chan struct{}, 1)
	b.closed = make(chan struct{})
	for i := 0; i < 64; i++ {
		if err := b.SendContext(context.Background(), []byte("data")); err != nil { t.Fatal(err) }
	}
	if len(b.txReady) != 1 { t.Fatal("lost or unbounded notification") }
	if err := b.Send([]byte("extra")); err != ErrQueueFull { t.Fatal("unbounded data backlog", err) }
	ctx,cancel := context.WithCancel(context.Background()); cancel()
	if err := b.SendContext(ctx, []byte("extra")); err != context.Canceled { t.Fatal(err) }
}
