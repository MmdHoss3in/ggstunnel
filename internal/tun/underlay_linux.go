//go:build linux

package tun

import (
	"encoding/json"
	"errors"
	"net"

	"ggstunnel/internal/config"
)

func UnderlayMTU(c *config.Config) (int, error) {
	peer := c.Real.PeerIP
	if peer == "" && c.Real.PeerAddr != "" {
		peer, _, _ = net.SplitHostPort(c.Real.PeerAddr)
	}
	if net.ParseIP(peer).To4() == nil {
		return 0, errors.New("no IPv4 peer for MTU lookup")
	}
	result, err := systemIP("-j", "-4", "route", "get", peer)
	if err != nil {
		return 0, err
	}
	var rows []struct {
		Dev     string          `json:"dev"`
		MTU     int             `json:"mtu"`
		Metrics json.RawMessage `json:"metrics"`
	}
	if err := json.Unmarshal(result, &rows); err != nil {
		return 0, err
	}
	if len(rows) == 0 || rows[0].Dev == "" || rows[0].Dev == c.TUN.Name {
		return 0, errors.New("no external underlay route")
	}
	device, err := net.InterfaceByName(rows[0].Dev)
	if err != nil {
		return 0, err
	}
	mtu := device.MTU
	if rows[0].MTU > 0 {
		mtu = min(mtu, rows[0].MTU)
	}
	var metrics []struct {
		MTU int `json:"mtu"`
	}
	if len(rows[0].Metrics) > 0 {
		if err := json.Unmarshal(rows[0].Metrics, &metrics); err != nil {
			var metric struct {
				MTU int `json:"mtu"`
			}
			if err := json.Unmarshal(rows[0].Metrics, &metric); err != nil {
				return 0, err
			}
			metrics = append(metrics, metric)
		}
	}
	for _, metric := range metrics {
		if metric.MTU > 0 {
			mtu = min(mtu, metric.MTU)
		}
	}
	return mtu, nil
}
