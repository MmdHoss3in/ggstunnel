package engine

import (
	"bytes"
	"context"
	"fmt"
	"ggstunnel/internal/config"
	"net"
	"testing"
	"time"
)

func TestNineEncryptedPeers(t *testing.T) {
	for _, profile := range []string{"tcp", "udp"} {
		t.Run(profile, func(t *testing.T) {
			for i := 0; i < 9; i++ {
				t.Run(fmt.Sprint(i), func(t *testing.T) {
					t.Parallel()
					endpoints := make([]string, 2)
					for side := range endpoints {
						if profile == "tcp" {
							l, e := net.Listen("tcp4", "127.0.0.1:0")
							if e != nil {
								t.Fatal(e)
							}
							endpoints[side] = l.Addr().String()
							l.Close()
						} else {
							c, e := net.ListenPacket("udp4", "127.0.0.1:0")
							if e != nil {
								t.Fatal(e)
							}
							endpoints[side] = c.LocalAddr().String()
							c.Close()
						}
					}
					ctx, cancel := context.WithCancel(context.Background())
					defer cancel()
					done := make(chan error, 2)
					var devices [2]*packetDeviceFake
					for side := 0; side < 2; side++ {
						role := "server"
						if side == 1 {
							role = "client"
						}
						c := &config.Config{Role: role, Profile: profile, PSK: fmt.Sprintf("unique-peer-secret-%03d", i), Real: config.RealConfig{LocalIP: "127.0.0.1", PeerIP: "127.0.0.1", ListenAddr: endpoints[side], PeerAddr: endpoints[1-side]}, TUN: config.TUNConfig{LocalAddr: "10.88.1.1", RemoteAddr: "10.88.1.2"}}
						c.ApplyDefaults()
						e, err := New(c)
						if err != nil {
							t.Fatal(err)
						}
						d := &packetDeviceFake{in: make(chan []byte, 32), out: make(chan []byte, 32), closed: make(chan struct{})}
						devices[side] = d
						e.tun = d
						if err = e.carrier.Start(ctx); err != nil {
							t.Fatal(err)
						}
						go func() { done <- e.runWorkers(ctx) }()
					}
					for j := 0; j < 64; j++ {
						for side := 0; side < 2; side++ {
							payload := bytes.Repeat([]byte{byte(i + 1), byte(j + 1), byte(side)}, 420)
							devices[side].in <- payload
							select {
							case got := <-devices[1-side].out:
								if !bytes.Equal(got, payload) {
									t.Fatal("cross-peer delivery or corruption")
								}
							case <-time.After(5 * time.Second):
								t.Fatal("encrypted delivery timeout")
							}
						}
					}
					cancel()
					for side := 0; side < 2; side++ {
						select {
						case err := <-done:
							if err != nil {
								t.Fatal(err)
							}
						case <-time.After(time.Second):
							t.Fatal("engine shutdown stuck")
						}
					}
				})
			}
		})
	}
}
