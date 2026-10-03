package engine

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"ggstunnel/internal/config"
)

func TestTelemetryAtomicPrivateAndNoSecrets(t *testing.T) {
	e := &Engine{cfg: &config.Config{Role: "server", Profile: "bip", PSK: "never-export-this-secret"}}
	e.txPackets.Store(7)
	e.drops.Store(2)
	p := filepath.Join(t.TempDir(), "stats.json")
	for i := 0; i < 2; i++ {
		if err := writeTelemetry(p, e.SnapshotTelemetry(time.Now())); err != nil {
			t.Fatal(err)
		}
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		var s Telemetry
		if err = json.Unmarshal(b, &s); err != nil {
			t.Fatal(err)
		}
		if s.TxReadPackets != 7 || s.EnqueueDrops != 2 || s.SchemaVersion != 1 {
			t.Fatal("wrong counters")
		}
		if strings.Contains(string(b), e.cfg.PSK) {
			t.Fatal("secret exported")
		}
		fi, _ := os.Stat(p)
		if fi.Mode().Perm() != 0600 {
			t.Fatal("stats file is not private")
		}
	}
	target := filepath.Join(t.TempDir(), "target")
	os.WriteFile(target, []byte("keep"), 0600)
	link := filepath.Join(t.TempDir(), "symlink")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if err := writeTelemetry(link, e.SnapshotTelemetry(time.Now())); err == nil {
		t.Fatal("symlink accepted")
	}
	b, _ := os.ReadFile(target)
	if string(b) != "keep" {
		t.Fatal("symlink target overwritten")
	}
}
