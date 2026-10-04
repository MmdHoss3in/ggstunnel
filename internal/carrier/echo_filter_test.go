package carrier

import (
	"errors"
	"reflect"
	"strings"
	"testing"
)

func TestKernelEchoFilterInstallsAndRemovesOnlyItsExactRule(t *testing.T) {
	for _, exists := range []bool{false, true} {
		var calls [][]string
		cleanup, err := installBIPReflectionFilter("192.0.2.1", "198.51.100.1", "ggs01", func(args []string) error {
			calls = append(calls, args)
			if args[2] == "-C" && !exists { return errors.New("missing rule") }
			return nil
		})
		if err != nil { t.Fatal(err) }
		cleanup()
		want := 3; if exists { want = 2 }
		if len(calls) != want { t.Fatal("unexpected firewall mutation") }
		first, last := calls[0], calls[len(calls)-1]
		if first[2] != "-C" || last[2] != "-D" || !reflect.DeepEqual(first[3:], last[3:]) { t.Fatal("cleanup does not match exact owned rule") }
		joined := strings.Join(first, " ")
		for _, term := range []string{"OUTPUT", "-s 192.0.2.1", "-d 198.51.100.1", "echo-reply", "0x42495035", "=2:3,7", "ggstunnel-bip-echo-ggs01"} {
			if !strings.Contains(joined, term) { t.Fatal("filter scope incomplete") }
		}
	}
}

func TestUnavailableEchoFilterDoesNotInstallCleanup(t *testing.T) {
	cleanup, err := installBIPReflectionFilter("192.0.2.1", "198.51.100.1", "ggs01", func([]string) error { return errors.New("iptables unavailable") })
	if err == nil || cleanup != nil { t.Fatal("failed filter reported installed") }
}
