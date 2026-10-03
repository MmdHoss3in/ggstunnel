// Package forward provides bounded TCP/UDP forwarding over a tunnel address.
package forward

import (
	"context"
	"io"
	"net"
	"sync"
	"time"
)

type Rule struct {
	Protocol string `json:"protocol"`
	Listen   string `json:"listen"`
	Target   string `json:"target"`
}
type Group struct {
	cancel  context.CancelFunc
	closers []io.Closer
	wg      sync.WaitGroup
}

func Start(parent context.Context, rules []Rule) (*Group, error) {
	ctx, cancel := context.WithCancel(parent)
	g := &Group{cancel: cancel}
	for _, r := range rules {
		if r.Protocol == "tcp" {
			ln, e := net.Listen("tcp4", r.Listen)
			if e != nil {
				g.Close()
				return nil, e
			}
			g.closers = append(g.closers, ln)
			g.wg.Add(1)
			go func(r Rule) {
				defer g.wg.Done()
				slots := make(chan struct{}, 1024)
				var workers sync.WaitGroup
				defer workers.Wait()
				for {
					a, e := ln.Accept()
					if e != nil {
						return
					}
					select {
					case slots <- struct{}{}:
					default:
						a.Close()
						continue
					}
					workers.Add(1)
					go func() {
						defer workers.Done()
						defer func() { <-slots }()
						defer a.Close()
						b, e := (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "tcp4", r.Target)
						if e != nil {
							return
						}
						defer b.Close()
						done := make(chan struct{})
						go func() {
							select {
							case <-ctx.Done():
								a.Close()
								b.Close()
							case <-done:
							}
						}()
						defer close(done)
						var w sync.WaitGroup
						w.Add(1)
						go func() { defer w.Done(); io.Copy(b, a); b.(*net.TCPConn).CloseWrite() }()
						io.Copy(a, b)
						a.(*net.TCPConn).CloseWrite()
						w.Wait()
					}()
				}
			}(r)
		} else {
			la, e := net.ResolveUDPAddr("udp4", r.Listen)
			if e != nil {
				g.Close()
				return nil, e
			}
			c, e := net.ListenUDP("udp4", la)
			if e != nil {
				g.Close()
				return nil, e
			}
			target, e := net.ResolveUDPAddr("udp4", r.Target)
			if e != nil {
				c.Close()
				g.Close()
				return nil, e
			}
			g.closers = append(g.closers, c)
			g.wg.Add(1)
			go func() { defer g.wg.Done(); udp(ctx, c, target) }()
		}
	}
	return g, nil
}
func (g *Group) Close() error {
	g.cancel()
	for _, c := range g.closers {
		c.Close()
	}
	g.wg.Wait()
	return nil
}
func udp(ctx context.Context, c *net.UDPConn, target *net.UDPAddr) {
	var mu sync.Mutex
	peers := map[string]*net.UDPConn{}
	var wg sync.WaitGroup
	defer func() {
		mu.Lock()
		for _, p := range peers {
			p.Close()
		}
		mu.Unlock()
		wg.Wait()
	}()
	buf := make([]byte, 65535)
	for {
		n, addr, err := c.ReadFromUDP(buf)
		if err != nil {
			return
		}
		key := addr.String()
		mu.Lock()
		p := peers[key]
		if p == nil && len(peers) < 1024 {
			p, err = net.DialUDP("udp4", nil, target)
			if err == nil {
				peers[key] = p
				wg.Add(1)
				go func(p *net.UDPConn, a *net.UDPAddr) {
					defer wg.Done()
					defer p.Close()
					defer func() {
						mu.Lock()
						if peers[key] == p {
							delete(peers, key)
						}
						mu.Unlock()
					}()
					b := make([]byte, 65535)
					for {
						p.SetReadDeadline(time.Now().Add(60 * time.Second))
						n, e := p.Read(b)
						if e != nil {
							return
						}
						c.SetWriteDeadline(time.Now().Add(5 * time.Second))
						if _, e = c.WriteToUDP(b[:n], a); e != nil {
							return
						}
					}
				}(p, addr)
			}
		}
		mu.Unlock()
		if p != nil {
			p.SetWriteDeadline(time.Now().Add(5 * time.Second))
			p.Write(buf[:n])
		}
		select {
		case <-ctx.Done():
			return
		default:
		}
	}
}
