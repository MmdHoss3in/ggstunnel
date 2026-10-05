package carrier

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"ggstunnel/internal/session"
)

func TestBIPCloseWaitsForActorBeforeRemovingEchoFilter(t *testing.T) {
	b := testBIP(t)
	ctx, cancel := context.WithCancel(context.Background())
	b.cancel = cancel
	b.kernelEchoFilter.Store(true)
	actorStopped := make(chan struct{})
	b.workers.Add(1)
	go func() {
		defer b.workers.Done()
		<-ctx.Done()
		close(actorStopped)
	}()
	calls := 0
	b.echoFilterCleanup = func() {
		select {
		case <-actorStopped:
		default:
			t.Error("echo rule removed while actor still running")
		}
		calls++
	}
	if err := b.Close(); err != nil {
		t.Fatal(err)
	}
	if err := b.Close(); err != nil {
		t.Fatal(err)
	}
	if calls != 1 || b.SnapshotStats().KernelEchoFilter {
		t.Fatal("close did not clear filter telemetry exactly once")
	}
}

func TestKernelEchoFilterInstallsAndRemovesOnlyItsExactRule(t *testing.T) {
	for _, exists := range []bool{false, true} {
		var calls [][]string
		cleanup, err := installBIPReflectionFilter("192.0.2.1", "198.51.100.1", "ggs01", func(args []string) error {
			calls = append(calls, args)
			if args[2] == "-C" && !exists {
				return errors.New("missing rule")
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
		cleanup()
		want := 3
		if exists {
			want = 2
		}
		if len(calls) != want {
			t.Fatal("unexpected firewall mutation")
		}
		first, last := calls[0], calls[len(calls)-1]
		if first[2] != "-C" || last[2] != "-D" || !reflect.DeepEqual(first[3:], last[3:]) {
			t.Fatal("cleanup does not match exact owned rule")
		}
		joined := strings.Join(first, " ")
		for _, term := range []string{"OUTPUT", "-s 192.0.2.1", "-d 198.51.100.1", "echo-reply", "0x42495035", "=3,4,7", "ggstunnel-bip-echo-ggs01"} {
			if !strings.Contains(joined, term) {
				t.Fatal("filter scope incomplete")
			}
		}
	}
}

func TestUnavailableEchoFilterDoesNotInstallCleanup(t *testing.T) {
	cleanup, err := installBIPReflectionFilter("192.0.2.1", "198.51.100.1", "ggs01", func([]string) error { return errors.New("iptables unavailable") })
	if err == nil || cleanup != nil {
		t.Fatal("failed filter reported installed")
	}
}

func compactFilterForTest(t *testing.T, dir, namespace string, run func([]string) error) *compactEchoFilter {
	t.Helper()
	f, err := newCompactEchoFilter(dir, "192.0.2.1", "198.51.100.1", "ggs01", namespace, run)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func TestCompactEchoFilterExactAliasScopeRotationAndCleanup(t *testing.T) {
	dir := t.TempDir()
	rules := make(map[string]bool)
	var calls [][]string
	run := func(args []string) error {
		calls = append(calls, append([]string(nil), args...))
		key := strings.Join(args[3:], " ")
		switch args[2] {
		case "-C":
			if !rules[key] {
				return errEchoRuleMissing
			}
		case "-I":
			files, _ := filepath.Glob(filepath.Join(dir, "compact-echo-*.json"))
			if len(files) != 1 {
				t.Fatal("rule inserted without durable cleanup recipe")
			}
			r, err := readCompactEchoRecord(files[0])
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(r.rule("-I"), args) {
				t.Fatal("metadata differs from rule")
			}
			if info, _ := os.Stat(files[0]); info.Mode().Perm() != 0600 {
				t.Fatal("metadata is not private")
			}
			rules[key] = true
		case "-D":
			delete(rules, key)
		default:
			t.Fatal("unexpected firewall command")
		}
		return nil
	}
	f := compactFilterForTest(t, dir, "net:[10]", run)
	now := time.Now()
	if ok, err := f.update(0x1122334455667788, 0x8877665544332211, now); err != nil || !ok {
		t.Fatal(err)
	}
	first := f.current.rule("-I")
	for _, term := range []string{"OUTPUT", "-s 192.0.2.1", "-d 198.51.100.1", "echo-reply", "@8=0x11223344&&0>>22&0x3C@12=0x55667788", "ggstunnel-bip-compact-echo-ggs01"} {
		if !strings.Contains(strings.Join(first, " "), term) {
			t.Fatal("missing exact compact scope", term)
		}
	}
	count := len(calls)
	for i := 0; i < 100; i++ {
		if ok, err := f.update(0x1122334455667788, 0x8877665544332211, now); err != nil || !ok {
			t.Fatal(err)
		}
	}
	if len(calls) != count {
		t.Fatal("firewall invoked on packet/tick instead of session change")
	}
	if ok, err := f.update(0xaabbccdd12345678, 0x8877665544332211, now); err != nil || !ok {
		t.Fatal(err)
	}
	if len(rules) != 1 || rules[strings.Join(first[3:], " ")] {
		t.Fatal("old peer alias survived rotation")
	}
	if err := f.close(); err != nil {
		t.Fatal(err)
	}
	if len(rules) != 0 {
		t.Fatal("rule survived normal close")
	}
	if err := f.close(); err != nil {
		t.Fatal("close not idempotent", err)
	}
	files, _ := filepath.Glob(filepath.Join(dir, "compact-echo-*.json"))
	if len(files) != 0 {
		t.Fatal("metadata survived successful cleanup")
	}
}

func TestCompactEchoFilterRetainsFailedCleanupAndBacksOff(t *testing.T) {
	dir := t.TempDir()
	unavailable := true
	calls := 0
	run := func(args []string) error {
		calls++
		if unavailable {
			return errors.New("firewall unavailable")
		}
		if args[2] == "-C" {
			return errEchoRuleMissing
		}
		return nil
	}
	f := compactFilterForTest(t, dir, "net:[11]", run)
	now := time.Now()
	if ok, err := f.update(33, 44, now); err == nil || ok {
		t.Fatal("failed insertion reported installed")
	}
	count := calls
	for i := 0; i < 100; i++ {
		f.update(33, 44, now.Add(time.Second))
	}
	if calls != count {
		t.Fatal("unavailable firewall retried without backoff")
	}
	if err := f.close(); err == nil {
		t.Fatal("failed cleanup ignored")
	}
	files, _ := filepath.Glob(filepath.Join(dir, "compact-echo-*.json"))
	if len(files) != 1 {
		t.Fatal("lost ambiguous insertion recipe")
	}
	unavailable = false
	if ok, err := f.update(33, 44, now.Add(31*time.Second)); err != nil || !ok {
		t.Fatal("filter did not recover", err)
	}
	if err := f.close(); err != nil {
		t.Fatal(err)
	}
}

func TestCompactEchoFilterCleanupScopesNamespaceAndSurvivesChangedConfig(t *testing.T) {
	dir := t.TempDir()
	r := compactEchoRecord{Schema: 1, Namespace: "net:[12]", Local: "192.0.2.1", Peer: "198.51.100.1", Instance: "ggs01", Alias: 55}
	other := r
	other.Namespace = "net:[13]"
	for _, record := range []compactEchoRecord{r, other} {
		if err := writeCompactEchoRecord(dir, record); err != nil {
			t.Fatal(err)
		}
	}
	var deleted [][]string
	if err := cleanupCompactEchoRecords(dir, "ggs01", "net:[12]", func(args []string) error {
		if args[2] == "-D" {
			deleted = append(deleted, args)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if len(deleted) != 1 || !reflect.DeepEqual(deleted[0], r.rule("-D")) {
		t.Fatal("crash cleanup did not use original stored pair")
	}
	if _, err := os.Stat(filepath.Join(dir, other.filename())); err != nil {
		t.Fatal("cleanup removed another network namespace recipe")
	}
}

func TestCompactEchoFilterRejectsOwnOrZeroAlias(t *testing.T) {
	for _, alias := range []uint64{0, 77} {
		calls := 0
		f := compactFilterForTest(t, t.TempDir(), "net:[14]", func([]string) error { calls++; return nil })
		if ok, err := f.update(alias, 77, time.Now()); ok || err == nil || calls != 0 {
			t.Fatal("unsafe alias installed")
		}
	}
}

func TestCompactEchoFilterCannotRotateWithoutFreshProof(t *testing.T) {
	b, _ := compactPair(t)
	b.emit = func([]byte) error { return nil }
	t.Cleanup(func() { b.Close() })
	calls := 0
	b.compactEchoFilter = compactFilterForTest(t, t.TempDir(), "net:[15]", func(args []string) error {
		calls++
		if args[2] == "-C" {
			return errEchoRuleMissing
		}
		return nil
	})
	b.active = 123
	b.issueChallenge(wirePacket{sender: 456, typ: 8}, time.Now())
	if calls != 0 || b.compactEchoFilter.current != nil {
		t.Fatal("unproven rotation changed active echo filter")
	}
}

func TestCompactEchoFilterOnlyFollowsAuthenticatedHandshake(t *testing.T) {
	a, b := compactPair(t)
	b.emit = func([]byte) error { return nil }
	t.Cleanup(func() { a.Close(); b.Close() })
	calls := 0
	b.compactEchoFilter = compactFilterForTest(t, t.TempDir(), "net:[16]", func(args []string) error {
		calls++
		if args[2] == "-C" {
			return errEchoRuleMissing
		}
		return nil
	})
	now := time.Now()
	hello := wirePacket{typ: 8, kind: bipKindHello, sender: a.localID, number: 1, id: 10, tuple: 20, payload: []byte{a.localRole()}}
	wire, err := a.encode(hello)
	if err != nil {
		t.Fatal(err)
	}
	bad := append([]byte(nil), wire...)
	bad[len(bad)-1] ^= 1
	b.handle(bad, now)
	if calls != 0 {
		t.Fatal("unauthenticated packet installed a filter")
	}
	wrong := hello
	wrong.number = 2
	wrong.payload = []byte{b.localRole()}
	wrongWire, err := a.encode(wrong)
	if err != nil {
		t.Fatal(err)
	}
	b.handle(wrongWire, now)
	if calls != 0 {
		t.Fatal("wrong-role HELLO installed a filter")
	}
	b.handle(wire, now)
	remoteMask, _ := b.aliasMask(b.remoteRole())
	if !b.kernelEchoFilter.Load() || b.compactEchoFilter.current == nil || b.compactEchoFilter.current.Alias != a.localID^remoteMask {
		t.Fatal("authenticated bootstrap did not install the remote alias")
	}
	accept := func(peer *BIP) {
		t.Helper()
		c, err := b.gate.IssueReusable(peer.localID, b.remoteRole(), now)
		if err != nil {
			t.Fatal(err)
		}
		proof := session.Proof(b.master, c)
		p := wirePacket{typ: 8, kind: bipKindProof, sender: peer.localID, target: b.localID, number: 3, id: 10, tuple: 21, payload: append(marshalChallenge(c), proof[:]...)}
		body, err := peer.encode(p)
		if err != nil {
			t.Fatal(err)
		}
		b.handle(body, now)
		if b.active != peer.localID {
			t.Fatal("valid fresh proof did not activate peer")
		}
	}
	accept(a)
	other, spare := compactPair(t)
	t.Cleanup(func() { other.Close(); spare.Close() })
	old := b.compactEchoFilter.current.Alias
	count := calls
	hello.sender = other.localID
	wire, err = other.encode(hello)
	if err != nil {
		t.Fatal(err)
	}
	b.handle(wire, now)
	if calls != count || b.compactEchoFilter.current.Alias != old {
		t.Fatal("unproven candidate rotated the active filter")
	}
	accept(other)
	if b.compactEchoFilter.current.Alias != other.localID^remoteMask || b.compactEchoFilter.current.Alias == old {
		t.Fatal("fresh proof did not rotate the alias")
	}
	count = calls
	hello.sender = a.localID
	hello.number = 4
	wire, err = a.encode(hello)
	if err != nil {
		t.Fatal(err)
	}
	b.handle(wire, now)
	if calls != count || b.compactEchoFilter.current.Alias != other.localID^remoteMask {
		t.Fatal("retired peer replay changed the filter")
	}
}

func TestCompactEchoFilterFailedRotationKeepsOldCleanupRecipe(t *testing.T) {
	dir := t.TempDir()
	denyDelete := false
	inserts := 0
	run := func(args []string) error {
		if args[2] == "-I" {
			inserts++
		}
		if args[2] == "-D" && denyDelete {
			return errors.New("firewall lock unavailable")
		}
		return nil
	}
	f := compactFilterForTest(t, dir, "net:[17]", run)
	now := time.Now()
	if ok, err := f.update(88, 99, now); !ok || err != nil {
		t.Fatal(err)
	}
	denyDelete = true
	if ok, err := f.update(111, 99, now); ok || err == nil {
		t.Fatal("failed old-rule deletion allowed rotation")
	}
	r, err := readCompactEchoRecord(filepath.Join(dir, f.base.filename()))
	if err != nil || r.Alias != 88 || inserts != 1 {
		t.Fatal("failed rotation lost the old exact rule recipe", err)
	}
	denyDelete = false
	if ok, err := f.update(111, 99, now.Add(31*time.Second)); !ok || err != nil {
		t.Fatal("rotation did not recover", err)
	}
	if inserts != 2 || f.current.Alias != 111 {
		t.Fatal("recovered rotation did not replace the rule")
	}
	if err := f.close(); err != nil {
		t.Fatal(err)
	}
}

func TestCompactEchoFilterRejectsInvalidStoredScope(t *testing.T) {
	dir := t.TempDir()
	r := compactEchoRecord{Schema: 1, Namespace: "net:[18]", Local: "192.0.2.1", Peer: "198.51.100.1", Instance: "ggs01", Alias: 66}
	path := filepath.Join(dir, r.filename())
	if err := os.WriteFile(path, []byte(`{"schema":1,"namespace":"net:[18]","local":"0.0.0.0/0","peer":"198.51.100.1","instance":"ggs01","alias":66}`), 0600); err != nil {
		t.Fatal(err)
	}
	calls := 0
	err := cleanupCompactEchoRecords(dir, "ggs01", "net:[18]", func([]string) error { calls++; return nil })
	if err == nil || calls != 0 {
		t.Fatal("invalid stored scope reached the firewall")
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatal("invalid recipe was silently discarded")
	}
}
