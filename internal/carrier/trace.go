package carrier

import (
	"encoding/json"
	"os"
	"sync/atomic"
	"time"
)

// Fixed metadata only: no packet contents, addresses, MACs or keys.
type traceEvent struct {
	At         time.Time `json:"at"`
	Event      string    `json:"event"`
	Session    uint64    `json:"session"`
	Seq        uint32    `json:"seq,omitempty"`
	Ack        uint32    `json:"ack,omitempty"`
	Sack       uint64    `json:"sack,omitempty"`
	Kind       byte      `json:"kind,omitempty"`
	Type       byte      `json:"icmp_type"`
	Mode       byte      `json:"mode,omitempty"`
	Retries    int       `json:"retries,omitempty"`
	AgeMS      float64   `json:"age_ms,omitempty"`
	DeadlineMS float64   `json:"deadline_ms,omitempty"`
	Pending    int       `json:"pending,omitempty"`
	Backlog    int       `json:"backlog,omitempty"`
	RTOms      float64   `json:"rto_ms,omitempty"`
	Window     int       `json:"window,omitempty"`
	Cuts       uint64    `json:"cuts,omitempty"`
	Error      bool      `json:"send_error,omitempty"`
	Dropped    uint64    `json:"dropped,omitempty"`
}

type bipTrace struct {
	events  chan traceEvent
	done    chan struct{}
	dropped atomic.Uint64
	lossOnly bool
}

func openBIPTrace(path string) (*bipTrace, error) {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return nil, err
	}
	t := &bipTrace{events: make(chan traceEvent, 8192), done: make(chan struct{}), lossOnly: os.Getenv("GGSTUNNEL_BIP_TRACE_LOSS_ONLY") == "1"}
	go func() {
		defer close(t.done)
		defer f.Close()
		size := 0
		for e := range t.events {
			data, _ := json.Marshal(e)
			data = append(data, '\n')
			if size+len(data) > 64<<20 {
				t.dropped.Add(1)
				continue
			}
			n, err := f.Write(data)
			size += n
			if err != nil {
				t.dropped.Add(1)
			}
		}
		data, _ := json.Marshal(traceEvent{At: time.Now().UTC(), Event: "trace_end", Dropped: t.dropped.Load()})
		_, _ = f.Write(append(data, '\n'))
	}()
	return t, nil
}

func (t *bipTrace) record(e traceEvent) {
	if t == nil {
		return
	}
	select {
	case t.events <- e:
	default:
		t.dropped.Add(1)
	}
}
func (t *bipTrace) close() {
	if t == nil {
		return
	}
	close(t.events)
	<-t.done
}
func (b *BIP) traceRecord(e traceEvent) {
	if b.trace == nil {
		return
	}
	if b.trace.lossOnly && e.Event != "timeout" && e.Event != "delivery_exhausted" && !(e.Event == "pending" && e.Retries > 0) && !(e.Event == "ack_accept" && e.Retries > 0) {
		return
	}
	e.At = e.At.UTC()
	e.Session = b.localID
	b.trace.record(e)
}
