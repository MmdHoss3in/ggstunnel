package carrier

import (
	"net"
	"syscall"
)

// DF without trusting the kernel's cached path MTU: only authenticated probes
// raise the engine payload. ICMP PTB messages need not reach this socket.
func enableUDPPathMTU(conn *net.UDPConn) error {
	raw, err := conn.SyscallConn()
	if err != nil {
		return err
	}
	var optionErr error
	err = raw.Control(func(fd uintptr) {
		optionErr = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, syscall.IP_MTU_DISCOVER, syscall.IP_PMTUDISC_PROBE)
	})
	if err != nil {
		return err
	}
	return optionErr
}
