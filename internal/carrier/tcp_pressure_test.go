package carrier

import (
	"context"
	"testing"
	"time"
)

func TestTCPBackpressureWaitsAndPreservesFrame(t *testing.T) {
	c := simConfig("server")
	c.Performance.QueueSize = 1
	x := NewTCP(c)
	defer x.Close()
	if err := x.Send([]byte("first")); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- x.SendContext(ctx, []byte("second")) }()
	select {
	case err := <-done:
		t.Fatalf("full reliable queue did not wait: %v", err)
	case <-time.After(10 * time.Millisecond):
	}
	if string(<-x.tx) != "first" {
		t.Fatal("first frame lost")
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("producer remained blocked")
	}
	if string(<-x.tx) != "second" {
		t.Fatal("waiting frame lost")
	}
	x.Send([]byte("full"))
	go func() { done <- x.SendContext(ctx, []byte("cancelled")) }()
	cancel()
	select {
	case err := <-done:
		if err != context.Canceled {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("cancellation did not release producer")
	}
}
