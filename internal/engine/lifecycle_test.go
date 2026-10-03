package engine

import (
	"context"
	"errors"
	"ggstunnel/internal/config"
	"ggstunnel/internal/frame"
	"io"
	"sync"
	"testing"
	"time"
)

type fakeDevice struct {
	closed chan struct{}
	once   sync.Once
}

func (d *fakeDevice) Read([]byte) (int, error)    { <-d.closed; return 0, io.EOF }
func (d *fakeDevice) Write(b []byte) (int, error) { return len(b), nil }
func (d *fakeDevice) Close() error                { d.once.Do(func() { close(d.closed) }); return nil }

type fakeCarrier struct {
	rx   chan []byte
	errs chan error
}

func (c *fakeCarrier) Start(context.Context) error { return nil }
func (c *fakeCarrier) Send([]byte) error           { return nil }
func (c *fakeCarrier) Recv() <-chan []byte         { return c.rx }
func (c *fakeCarrier) Errors() <-chan error        { return c.errs }
func (c *fakeCarrier) Close() error                { return nil }
func (c *fakeCarrier) Name() string                { return "fake" }
func TestWorkerShutdownAndFatalError(t *testing.T) {
	for _, fatal := range []bool{false, true} {
		t.Run(map[bool]string{false: "cancel", true: "fatal"}[fatal], func(t *testing.T) {
			c := &config.Config{}
			c.Transport.HeartbeatSec = 1
			co, _ := frame.NewCodec("0123456789abcdef")
			carrier := &fakeCarrier{rx: make(chan []byte), errs: make(chan error, 1)}
			e := &Engine{cfg: c, tun: &fakeDevice{closed: make(chan struct{})}, carrier: carrier, codec: co, reasm: frame.NewReassembler(time.Second)}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			done := make(chan error, 1)
			go func() { done <- e.runWorkers(ctx) }()
			sentinel := errors.New("fatal carrier read")
			if fatal {
				carrier.errs <- sentinel
			} else {
				cancel()
			}
			select {
			case err := <-done:
				if fatal && !errors.Is(err, sentinel) {
					t.Fatal(err)
				}
				if !fatal && err != nil {
					t.Fatal(err)
				}
			case <-time.After(time.Second):
				t.Fatal("workers failed to stop")
			}
		})
	}
}
