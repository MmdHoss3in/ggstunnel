package carrier

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestDiagnosticTracePrivateMetadataAndDrain(t *testing.T) {
	path := filepath.Join(t.TempDir(), "trace.jsonl")
	tr, err := openBIPTrace(path)
	if err != nil {
		t.Fatal(err)
	}
	tr.record(traceEvent{At: time.Now().UTC(), Event: "timeout", Seq: 7, AgeMS: 200})
	tr.close()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 2 {
		t.Fatalf("events not drained: %s", data)
	}
	var e traceEvent
	if json.Unmarshal([]byte(lines[0]), &e) != nil || e.Seq != 7 || e.Event != "timeout" {
		t.Fatal("event mismatch")
	}
	st, _ := os.Stat(path)
	if st.Mode().Perm() != 0600 {
		t.Fatal("trace not private")
	}
	if _, err := openBIPTrace(path); err == nil {
		t.Fatal("existing trace overwritten")
	}
}

func TestDiagnosticTraceNeverBlocksActor(t *testing.T) {
	tr := &bipTrace{events: make(chan traceEvent, 1)}
	tr.record(traceEvent{})
	done := make(chan struct{})
	go func() { tr.record(traceEvent{}); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("full trace blocked actor")
	}
	if tr.dropped.Load() != 1 {
		t.Fatal("trace drop unreported")
	}
}
