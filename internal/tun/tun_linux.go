//go:build linux

package tun

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"ggstunnel/internal/config"
)

const (
	iffTUN    = 0x0001
	iffNoPI   = 0x1000
	tunSetIFF = 0x400454ca
)

type Device struct {
	routes    *routeTransaction
	closeOnce sync.Once
	closeErr  error
	File      *os.File
	Name      string
}

func Open(name string) (*Device, error) {
	if len(name) == 0 || len(name) > 15 {
		return nil, errors.New("tun name must be 1..15 chars")
	}
	fd, err := syscall.Open("/dev/net/tun", syscall.O_RDWR|syscall.O_CLOEXEC|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, fmt.Errorf("open /dev/net/tun: %w", err)
	}
	var ifr [40]byte
	copy(ifr[:16], []byte(name))
	binary.LittleEndian.PutUint16(ifr[16:18], uint16(iffTUN|iffNoPI))
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), uintptr(tunSetIFF), uintptr(unsafe.Pointer(&ifr[0])))
	if errno != 0 {
		_ = syscall.Close(fd)
		return nil, fmt.Errorf("TUNSETIFF: %w", errno)
	}
	// TUNSETIFF must precede runtime poll registration. An unattached clone
	// descriptor cannot be registered successfully with epoll.
	f := os.NewFile(uintptr(fd), "/dev/net/tun")
	if f == nil {
		_ = syscall.Close(fd)
		return nil, errors.New("wrap /dev/net/tun file descriptor")
	}
	// Detect failed poll registration at Open, rather than on the first Read.
	if err := f.SetReadDeadline(time.Time{}); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("TUN runtime poll registration: %w", err)
	}
	actual := string(ifr[:16])
	if i := strings.IndexByte(actual, 0); i >= 0 {
		actual = actual[:i]
	}
	return &Device{File: f, Name: actual}, nil
}

func (d *Device) Configure(c *config.Config) (result error) {
	d.routes = newRouteTransaction(systemIP)
	defer func() {
		if result != nil {
			result = errors.Join(result, d.routes.rollback())
		}
	}()
	if err := d.routes.protectPeer(c, d.Name); err != nil {
		return err
	}
	if err := runIP("link", "set", "dev", d.Name, "mtu", fmt.Sprint(c.TUN.MTU), "txqueuelen", fmt.Sprint(c.TUN.TxQueueLen), "up"); err != nil {
		return err
	}
	if net.ParseIP(c.TUN.LocalAddr).To4() != nil {
		if err := runIP("addr", "replace", c.TUN.LocalAddr+"/"+fmt.Sprint(c.TUN.Prefix), "peer", c.TUN.RemoteAddr, "dev", d.Name); err != nil {
			return err
		}
	} else {
		if err := runIP("-6", "addr", "replace", c.TUN.LocalAddr+"/"+fmt.Sprint(c.TUN.Prefix), "peer", c.TUN.RemoteAddr, "dev", d.Name); err != nil {
			return err
		}
	}
	for _, r := range c.TUN.Routes {
		if strings.TrimSpace(r) == "" {
			continue
		}
		if err := d.routes.addTUN(r, d.Name); err != nil {
			return fmt.Errorf("route %s: %w", r, err)
		}
	}
	return nil
}
func (d *Device) Close() error {
	d.closeOnce.Do(func() {
		d.closeErr = d.File.Close()
		if d.routes != nil {
			d.closeErr = errors.Join(d.closeErr, d.routes.rollback())
		}
	})
	return d.closeErr
}
func (d *Device) Read(p []byte) (int, error)  { return d.File.Read(p) }
func (d *Device) Write(p []byte) (int, error) { return d.File.Write(p) }

func runIP(args ...string) error {
	out, err := systemIP(args...)
	if err != nil {
		return fmt.Errorf("ip %s: %v: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}
