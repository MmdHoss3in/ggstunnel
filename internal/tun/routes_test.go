package tun

import (
	"encoding/json"
	"errors"
	"ggstunnel/internal/config"
	"strings"
	"testing"
)

type routeMock struct {
	routes map[string]map[string]any
	calls  [][]string
}

func (m *routeMock) run(args ...string) ([]byte, error) {
	m.calls = append(m.calls, append([]string(nil), args...))
	joined := strings.Join(args, " ")
	if strings.Contains(joined, "route get") {
		return []byte(`[{"dev":"eth0","gateway":"192.0.2.1","prefsrc":"198.51.100.10","table":200}]`), nil
	}
	if len(args) > 7 && args[0] == "-j" {
		prefix := args[len(args)-1]
		rows := []map[string]any{}
		if r := m.routes[prefix]; r != nil {
			rows = append(rows, r)
		}
		return json.Marshal(rows)
	}
	if len(args) > 8 && args[2] == "add" {
		prefix := args[3]
		if m.routes[prefix] != nil {
			return nil, errors.New("exists")
		}
		m.routes[prefix] = map[string]any{"dev": args[7], "protocol": "186"}
		for j := 10; j+1 < len(args); j += 2 {
			key := args[j]
			if key == "via" {
				key = "gateway"
			}
			if key == "src" {
				key = "prefsrc"
			}
			m.routes[prefix][key] = args[j+1]
		}
		return nil, nil
	}
	if len(args) > 8 && args[2] == "del" {
		delete(m.routes, args[3])
		return nil, nil
	}
	return nil, errors.New("unexpected ip command: " + joined)
}
func TestRouteConflictRollbackPreservesExisting(t *testing.T) {
	m := &routeMock{routes: map[string]map[string]any{"10.99.0.0/24": {"dev": "other0", "protocol": "static"}}}
	tr := newRouteTransaction(m.run)
	c := &config.Config{Real: config.RealConfig{PeerIP: "203.0.113.20"}}
	if err := tr.protectPeer(c, "ggs0"); err != nil {
		t.Fatal(err)
	}
	if err := tr.addTUN("10.98.0.0/24", "ggs0"); err != nil {
		t.Fatal(err)
	}
	if err := tr.addTUN("10.99.0.0/24", "ggs0"); err == nil {
		t.Fatal("existing route overwritten")
	}
	if err := tr.rollback(); err != nil {
		t.Fatal(err)
	}
	if len(m.routes) != 1 || m.routes["10.99.0.0/24"]["dev"] != "other0" {
		t.Fatal("unrelated route changed")
	}
	found := false
	for _, args := range m.calls {
		if strings.Contains(strings.Join(args, " "), "203.0.113.20/32 table 200") {
			found = true
		}
	}
	if !found {
		t.Fatal("selected FIB table ignored")
	}
}
func TestRouteRollbackPreservesExternallyChangedRoute(t *testing.T) {
	m := &routeMock{routes: map[string]map[string]any{}}
	tr := newRouteTransaction(m.run)
	if err := tr.addTUN("2001:db8:1::/64", "ggs0"); err != nil {
		t.Fatal(err)
	}
	m.routes["2001:db8:1::/64"] = map[string]any{"dev": "manual0", "protocol": "static"}
	if err := tr.rollback(); err == nil {
		t.Fatal("external change not reported")
	}
	if len(m.routes) != 1 {
		t.Fatal("external route deleted")
	}
}

func TestRouteRollbackPreservesChangedGateway(t *testing.T) {
	m := &routeMock{routes: map[string]map[string]any{}}
	tr := newRouteTransaction(m.run)
	if err := tr.protectPeer(&config.Config{Real: config.RealConfig{PeerIP: "203.0.113.20"}}, "ggs0"); err != nil {
		t.Fatal(err)
	}
	m.routes["203.0.113.20/32"]["gateway"] = "192.0.2.2"
	if err := tr.rollback(); err == nil {
		t.Fatal("changed gateway not reported")
	}
	if len(m.routes) != 1 {
		t.Fatal("changed gateway removed")
	}
}
