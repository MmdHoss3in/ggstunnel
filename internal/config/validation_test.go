package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadRejectsTrailingJSONAndPreservesExplicitPreset(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	body := `{"role":"server","profile":"bip","psk":"0123456789abcdef","real":{"local_ip":"198.51.100.10","peer_ip":"203.0.113.20"},"tun":{"local_addr":"10.77.1.1","remote_addr":"10.77.1.2","mtu":1280},"performance":{"profile":"speed"}}`
	if err := os.WriteFile(path, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	c, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if c.TUN.MTU != 1280 || c.Performance.QueueSize != 8192 {
		t.Fatalf("defaults=%+v", c)
	}
	os.WriteFile(path, []byte(body+` {}`), 0600)
	if _, err := Load(path); err == nil {
		t.Fatal("trailing JSON accepted")
	}
}
