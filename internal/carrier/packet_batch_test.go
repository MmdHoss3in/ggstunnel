//go:build linux && (amd64 || arm64)

package carrier

import (
	"bytes"
	"errors"
	"syscall"
	"testing"
	"unsafe"
)

func TestReceiveBatchDrainsAvailableDatagramsWithoutWaiting(t *testing.T) {
	if unsafe.Sizeof(bipMessage{}) != 64 { t.Fatal("unexpected Linux mmsghdr layout") }
	fd, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_DGRAM|syscall.SOCK_NONBLOCK, 0)
	if err != nil { t.Fatal(err) }
	defer syscall.Close(fd[0]); defer syscall.Close(fd[1])
	batch := newBIPSocketBatch()
	if _, err = batch.read(uintptr(fd[0])); !errors.Is(err, syscall.EAGAIN) { t.Fatalf("empty receive did not return EAGAIN: %v", err) }
	for i := 0; i < 5; i++ {
		if err = syscall.Sendto(fd[1], bytes.Repeat([]byte{byte(i+1)}, 100+i), 0, nil); err != nil { t.Fatal(err) }
	}
	n, err := batch.read(uintptr(fd[0]))
	if err != nil || n != 5 { t.Fatalf("partial batch: %d %v", n, err) }
	for i := 0; i < n; i++ {
		if batch.msg[i].length != uint32(100+i) || !bytes.Equal(batch.data[i][:100+i], bytes.Repeat([]byte{byte(i+1)}, 100+i)) { t.Fatal("datagram boundary/order changed") }
	}
	if err = syscall.Sendto(fd[1], make([]byte, 3000), 0, nil); err != nil { t.Fatal(err) }
	if n, err = batch.read(uintptr(fd[0])); err != nil || n != 1 || batch.msg[0].header.Flags&syscall.MSG_TRUNC == 0 { t.Fatal("oversized packet not marked truncated") }
	if err = syscall.Sendto(fd[1], []byte("next"), 0, nil); err != nil { t.Fatal(err) }
	if n, err = batch.read(uintptr(fd[0])); err != nil || n != 1 || batch.msg[0].header.Flags&syscall.MSG_TRUNC != 0 || !bytes.Equal(batch.data[0][:batch.msg[0].length], []byte("next")) { t.Fatal("batch metadata not reset after truncation") }
}
