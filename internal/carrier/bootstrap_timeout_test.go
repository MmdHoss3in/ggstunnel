package carrier

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestBIPHandshakeDeadlineAndTelemetry(t *testing.T) {
	b := testBIP(t)
	b.cfg.ApplyDefaults()
	now := time.Now()
	b.startedAt = now
	if err := b.maintainPeerLiveness(now.Add(89 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if b.SnapshotStats().HandshakeWaitMS != 89000 {
		t.Fatal("initial wait is invisible")
	}
	if err := b.maintainPeerLiveness(now.Add(90 * time.Second)); !errors.Is(err, ErrBIPHandshakeTimeout) {
		t.Fatalf("no bounded recovery: %v", err)
	}
	b.active = 9
	b.observePeerActivity(now.Add(91 * time.Second))
	if err := b.maintainPeerLiveness(now.Add(91 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if b.SnapshotStats().HandshakeWaitMS != 0 {
		t.Fatal("authenticated peer retains initial wait")
	}
}

func TestBIPActorSignalsInitialHandshakeTimeout(t *testing.T) {
	c:=simConfig("client")
	c.Transport.BIPHandshakeTimeoutSec=1
	b,err:=NewBIP(c)
	if err!=nil{t.Fatal(err)}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err:=b.StartPacketIO(ctx,silentBootstrapIO{});err!=nil{t.Fatal(err)}
	defer b.Close()
	select {
	case err := <-b.Errors():
		if !errors.Is(err, ErrBIPHandshakeTimeout) {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("bootstrap actor stuck indefinitely")
	}
	done := make(chan struct{})
	go func() { defer close(done); b.Close() }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("actor leaked")
	}
}

type silentBootstrapIO struct{}
func (silentBootstrapIO)Send([]byte)error{return nil}
func (silentBootstrapIO)Receive(ctx context.Context)([]byte,error){<-ctx.Done();return nil,ctx.Err()}
func (silentBootstrapIO)Close()error{return nil}
