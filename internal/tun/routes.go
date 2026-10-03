//go:build linux

package tun

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"ggstunnel/internal/config"
	"net"
	"os/exec"
	"strings"
	"time"
)

type routeRunner func(...string) ([]byte, error)

func systemIP(args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	p, err := exec.CommandContext(ctx, "ip", args...).CombinedOutput()
	if err != nil {
		return p, fmt.Errorf("ip %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(string(p)))
	}
	return p, nil
}

type ownedRoute struct {
	family, prefix, table, dev string
	args                       []string
}
type routeTransaction struct {
	run   routeRunner
	owned []ownedRoute
}

func newRouteTransaction(run routeRunner) *routeTransaction { return &routeTransaction{run: run} }
func (t *routeTransaction) show(family, prefix, table string) ([]map[string]any, error) {
	p, err := t.run("-j", family, "route", "show", "table", table, "exact", prefix)
	if err != nil {
		return nil, err
	}
	var rows []map[string]any
	if err = json.Unmarshal(p, &rows); err != nil {
		return nil, err
	}
	return rows, nil
}
func (t *routeTransaction) add(family, prefix, table, dev string, extra ...string) error {
	rows, err := t.show(family, prefix, table)
	if err != nil {
		return err
	}
	if len(rows) > 0 {
		return fmt.Errorf("route %s in table %s already exists; preserved", prefix, table)
	}
	args := []string{family, "route", "add", prefix, "table", table, "dev", dev, "proto", "186"}
	args = append(args, extra...)
	if _, err = t.run(args...); err != nil {
		return err
	}
	t.owned = append(t.owned, ownedRoute{family, prefix, table, dev, args})
	return nil
}
func (t *routeTransaction) protectPeer(c *config.Config, tunName string) error {
	peer := c.Real.PeerIP
	if peer == "" {
		h, _, err := net.SplitHostPort(c.Real.PeerAddr)
		if err != nil {
			return err
		}
		peer = h
	}
	ip := net.ParseIP(peer)
	if ip == nil {
		return errors.New("peer protection needs a numeric outer IP")
	}
	family, prefix := "-4", peer+"/32"
	if ip.To4() == nil {
		family, prefix = "-6", peer+"/128"
	}
	lookup := []string{"-j", family, "route", "get", peer}
	if c.Real.Interface != "" {
		lookup = append(lookup, "oif", c.Real.Interface)
	}
	p, err := t.run(lookup...)
	if err != nil {
		return err
	}
	var rows []map[string]any
	if err = json.Unmarshal(p, &rows); err != nil || len(rows) != 1 {
		return errors.New("ambiguous peer FIB lookup")
	}
	row := rows[0]
	dev, _ := row["dev"].(string)
	if dev == "" || dev == tunName {
		return errors.New("physical peer route is missing or points into this TUN")
	}
	table := "main"
	if v, ok := row["table"]; ok {
		table = fmt.Sprint(v)
	}
	exact, err := t.show(family, prefix, table)
	if err != nil {
		return err
	}
	if len(exact) > 0 {
		return nil
	} // Existing selected host route stays untouched.
	var extra []string
	if via, ok := row["gateway"].(string); ok && via != "" {
		extra = append(extra, "via", via)
	}
	if src, ok := row["prefsrc"].(string); ok && src != "" {
		extra = append(extra, "src", src)
	}
	return t.add(family, prefix, table, dev, extra...)
}
func (t *routeTransaction) addTUN(prefix, dev string) error {
	_, n, err := net.ParseCIDR(prefix)
	if err != nil {
		return err
	}
	family := "-4"
	if n.IP.To4() == nil {
		family = "-6"
	}
	return t.add(family, n.String(), "main", dev)
}
func (t *routeTransaction) rollback() error {
	var errs []error
	for i := len(t.owned) - 1; i >= 0; i-- {
		r := t.owned[i]
		rows, err := t.show(r.family, r.prefix, r.table)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		if len(rows) == 0 {
			continue
		}
		owned := false
		for _, row := range rows {
			if row["dev"] == r.dev && fmt.Sprint(row["protocol"]) == "186" {
				owned = true
				for j := 10; j+1 < len(r.args); j += 2 {
					key := r.args[j]
					if key == "via" {
						key = "gateway"
					}
					if key == "src" {
						key = "prefsrc"
					}
					if row[key] != r.args[j+1] {
						owned = false
					}
				}
			}
		}
		if !owned {
			errs = append(errs, fmt.Errorf("route %s changed externally; preserved", r.prefix))
			continue
		}
		args := append([]string(nil), r.args...)
		args[2] = "del"
		if _, err = t.run(args...); err != nil {
			errs = append(errs, err)
		}
	}
	t.owned = nil
	return errors.Join(errs...)
}
