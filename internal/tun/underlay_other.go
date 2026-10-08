//go:build !linux

package tun

import (
	"errors"
	"ggstunnel/internal/config"
)

func UnderlayMTU(_ *config.Config) (int, error) {
	return 0, errors.New("underlay MTU lookup requires Linux")
}
