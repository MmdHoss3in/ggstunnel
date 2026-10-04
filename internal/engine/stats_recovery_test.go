package engine

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"ggstunnel/internal/config"
)

type statsLogSink struct{ lines chan string }

func (s *statsLogSink) Write(p []byte) (int, error) {
	select {
	case s.lines <- string(p):
	default:
	}
	return len(p), nil
}

func TestStatsRecoveryDoesNotCountHistoricalTrafficAsRate(t *testing.T) {
	e := &Engine{cfg: &config.Config{}}
	e.cfg.Telemetry.IntervalSec = 1
	e.txBytes.Store(8 << 30)
	e.rxBytes.Store(70 << 30)
	e.txPackets.Store(54_000_000)
	e.rxPackets.Store(76_000_000)
	sink := &statsLogSink{lines: make(chan string, 8)}
	old := log.Writer()
	log.SetOutput(sink)
	defer log.SetOutput(old)
	for epoch := 0; epoch < 2; epoch++ {
		e.cfg.Telemetry.StatsFile = filepath.Join(t.TempDir(), "stats.json")
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan struct{})
		go func() { defer close(done); e.statsLoop(ctx) }()
		deadline := time.Now().Add(time.Second)
		for {
			if _, err := os.Stat(e.cfg.Telemetry.StatsFile); err == nil {
				break
			}
			if time.Now().After(deadline) {
				cancel()
				<-done
				t.Fatal("initial telemetry not written")
			}
			time.Sleep(time.Millisecond)
		}
		e.txBytes.Add(1_000_000)
		e.rxBytes.Add(2_000_000)
		e.txPackets.Add(100)
		e.rxPackets.Add(200)
		select {
		case line := <-sink.lines:
			cancel()
			<-done
			at := strings.Index(line, "rate{tx=")
			if at < 0 {
				t.Fatal(line)
			}
			var tx, tp, rx, rp float64
			rates := strings.NewReplacer("rate{tx=", "", "Mbps/", " ", "pps rx=", " ", "pps}", " ").Replace(line[at:])
			_, err := fmt.Sscanf(rates, "%f %f %f %f", &tx, &tp, &rx, &rp)
			if err != nil || tx < 7.5 || tx > 8.5 || rx < 15 || rx > 17 || tp < 95 || tp > 105 || rp < 190 || rp > 210 {
				t.Fatalf("epoch %d counted historical traffic or wrong interval: %s (%v)", epoch, line, err)
			}
		case <-time.After(3 * time.Second):
			cancel()
			<-done
			t.Fatal("no stats sample")
		}
	}
}
