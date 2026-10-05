package carrier

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"
	"time"

	"ggstunnel/internal/config"
)

// These kinds are only originated as EchoRequests. Their kernel EchoReply
// copies are redundant. Scope the rule to the outer pair, BIP5 magic, exact
// kinds and a managed instance tag. DATA/ACK/FAST and ordinary ping pass.
func bipEchoRule(local, peer, instance, action string) []string {
	return []string{"-w", "3", action, "OUTPUT", "-s", local, "-d", peer, "-p", "icmp", "--icmp-type", "echo-reply",
		"-m", "u32", "--u32", fmt.Sprintf("0>>22&0x3C@8=0x42495035&&0>>22&0x3C@12>>24=%d,%d,%d", bipKindNeedPull, bipKindPullProbe, bipKindHello),
		"-m", "comment", "--comment", "ggstunnel-bip-echo-" + instance, "-j", "DROP"}
}

func installBIPReflectionFilter(local, peer, instance string, run func([]string) error) (func(), error) {
	if err := run(bipEchoRule(local, peer, instance, "-C")); err != nil {
		if err := run(bipEchoRule(local, peer, instance, "-I")); err != nil {
			return nil, err
		}
	}
	return func() {
		if err := run(bipEchoRule(local, peer, instance, "-D")); err != nil {
			log.Printf("BIP kernel echo filter cleanup: %v", err)
		}
	}, nil
}

// systemd's best-effort ExecStopPost also runs after an abnormal exit. Reuse
// the exact rule specification; never flush chains or remove unrelated rules.
func CleanupBIPReflectionFilter(c *config.Config) error {
	// The config may have been replaced before systemd stops the old process.
	// Stored records retain its exact pair; only this instance/netns is cleaned.
	namespace, nsErr := os.Readlink("/proc/self/ns/net")
	var compactErr error
	if nsErr == nil {
		compactErr = cleanupCompactEchoRecords(compactEchoDirectory, c.TUN.Name, namespace, runEchoRule)
	} else {
		compactErr = nsErr
	}
	if c.Profile != "bip" {
		return compactErr
	}
	err := runEchoRule(bipEchoRule(c.Real.LocalIP, c.Real.PeerIP, c.TUN.Name, "-C"))
	if err == nil {
		err = runEchoRule(bipEchoRule(c.Real.LocalIP, c.Real.PeerIP, c.TUN.Name, "-D"))
	}
	if errors.Is(err, errEchoRuleMissing) {
		err = nil
	}
	return errors.Join(compactErr, err)
}

var errEchoRuleMissing = errors.New("echo filter rule absent")

func runEchoRule(args []string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, "iptables", args...)
	command.Env = append(os.Environ(), "LC_ALL=C")
	output, err := command.CombinedOutput()
	if err != nil {
		var exit *exec.ExitError
		if len(args) > 2 && args[2] == "-C" && errors.As(err, &exit) && exit.ExitCode() == 1 && strings.Contains(string(output), "does a matching rule exist") {
			return errEchoRuleMissing
		}
		return fmt.Errorf("iptables: %w: %s", err, output)
	}
	return nil
}
