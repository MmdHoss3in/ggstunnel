//go:build linux

package tun

import (
	"errors"
	"os"
	"testing"
	"time"
)

// Opt in on a disposable Linux host with CAP_NET_ADMIN. This test creates a TUN.
func TestKernelTUNReadCancellation(t *testing.T) {
	if os.Getenv("GGS_KERNEL_TEST") != "1" {
		t.Skip("set GGS_KERNEL_TEST=1 on a disposable privileged Linux host")
	}
	d, err := Open("ggstest0")
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	// Actually wait for an empty TUN read, so immediate Close cannot conceal
	// a broken poll registration. Old code fails here with "not pollable".
	if err := d.File.SetReadDeadline(time.Now().Add(100 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	_, err = d.Read(make([]byte, 1500))
	if !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("empty TUN read: want deadline, got %v", err)
	}
	if err := d.File.SetReadDeadline(time.Time{}); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { _, err := d.Read(make([]byte, 1500)); done <- err }()
	select {
	case err := <-done:
		t.Fatalf("empty read returned before Close: %v", err)
	case <-time.After(50 * time.Millisecond):
	}
	if err := d.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("closed device read succeeded")
		}
	case <-time.After(time.Second):
		t.Fatal("TUN read did not unblock after Close")
	}
}
