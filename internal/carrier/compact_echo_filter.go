package carrier

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const compactEchoDirectory = "/run/ggstunnel"

// Only kernel copies of the authenticated peer's opaque alias are dropped.
// Actual replies carry our alias. There is no plaintext protocol marker.
type compactEchoRecord struct {
	Schema    int    `json:"schema"`
	Namespace string `json:"namespace"`
	Local     string `json:"local"`
	Peer      string `json:"peer"`
	Instance  string `json:"instance"`
	Alias     uint64 `json:"alias"`
}

func (r compactEchoRecord) rule(action string) []string {
	return []string{"-w", "3", action, "OUTPUT", "-s", r.Local, "-d", r.Peer, "-p", "icmp", "--icmp-type", "echo-reply",
		"-m", "u32", "--u32", fmt.Sprintf("0>>22&0x3C@8=0x%08x&&0>>22&0x3C@12=0x%08x", uint32(r.Alias>>32), uint32(r.Alias)),
		"-m", "comment", "--comment", "ggstunnel-bip-compact-echo-" + r.Instance, "-j", "DROP"}
}

func (r compactEchoRecord) filename() string {
	// Include the network namespace and direction: disposable tests may run
	// identical instance names in multiple namespaces on the same filesystem.
	h := sha256.Sum256([]byte(r.Namespace + "|" + r.Instance + "|" + r.Local + "|" + r.Peer))
	return fmt.Sprintf("compact-echo-%s-%x.json", r.Instance, h[:16])
}

func (r compactEchoRecord) valid() bool {
	local, peer := net.ParseIP(r.Local), net.ParseIP(r.Peer)
	return r.Schema == 1 && r.Namespace != "" && len(r.Namespace) < 100 &&
		local != nil && local.To4() != nil && peer != nil && peer.To4() != nil &&
		r.Local == local.String() && r.Peer == peer.String() && r.Alias != 0 &&
		len(r.Instance) > 0 && len(r.Instance) <= 15 && !strings.ContainsAny(r.Instance, "/\\\x00\t\r\n ")
}

func writeCompactEchoRecord(dir string, r compactEchoRecord) error {
	if !r.valid() {
		return errors.New("invalid compact echo filter scope")
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, ".compact-echo-")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	data, err := json.Marshal(r)
	if err == nil {
		_, err = f.Write(data)
	}
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	return os.Rename(f.Name(), filepath.Join(dir, r.filename()))
}

func readCompactEchoRecord(path string) (compactEchoRecord, error) {
	var r compactEchoRecord
	info, err := os.Lstat(path)
	if err != nil {
		return r, err
	}
	if !info.Mode().IsRegular() || info.Size() > 2048 {
		return r, errors.New("invalid compact echo metadata file")
	}
	f, err := os.Open(path)
	if err != nil {
		return r, err
	}
	defer f.Close()
	d := json.NewDecoder(io.LimitReader(f, 2049))
	d.DisallowUnknownFields()
	if err = d.Decode(&r); err != nil {
		return r, err
	}
	if !r.valid() || filepath.Base(path) != r.filename() {
		return r, errors.New("invalid compact echo metadata scope")
	}
	return r, nil
}

func removeCompactEchoRecord(dir string, r compactEchoRecord, run func([]string) error) error {
	err := run(r.rule("-C"))
	if err == nil {
		if err = run(r.rule("-D")); err != nil {
			return err
		}
	} else if !errors.Is(err, errEchoRuleMissing) {
		return err // Keep the durable recipe when the firewall is unavailable.
	}
	err = os.Remove(filepath.Join(dir, r.filename()))
	if os.IsNotExist(err) {
		return nil
	}
	return err
}

func cleanupCompactEchoRecords(dir, instance, namespace string, run func([]string) error) error {
	entries, err := os.ReadDir(dir)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	var failures []error
	for _, entry := range entries {
		if !strings.HasPrefix(entry.Name(), "compact-echo-"+instance+"-") || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		r, err := readCompactEchoRecord(filepath.Join(dir, entry.Name()))
		if err != nil {
			failures = append(failures, err)
			continue
		}
		if r.Instance != instance || r.Namespace != namespace {
			continue
		}
		if err := removeCompactEchoRecord(dir, r, run); err != nil {
			failures = append(failures, err)
		}
	}
	return errors.Join(failures...)
}

// Actor-owned; Close runs only after its worker has joined. Metadata is saved
// before insertion so ExecStopPost can recover every SIGKILL interruption point.
type compactEchoFilter struct {
	dir       string
	base      compactEchoRecord
	run       func([]string) error
	current   *compactEchoRecord
	installed bool
	lastAlias uint64
	retryAt   time.Time
}

func newCompactEchoFilter(dir, local, peer, instance, namespace string, run func([]string) error) (*compactEchoFilter, error) {
	f := &compactEchoFilter{dir: dir, base: compactEchoRecord{Schema: 1, Namespace: namespace, Local: local, Peer: peer, Instance: instance}, run: run}
	check := f.base
	check.Alias = 1
	if !check.valid() {
		return nil, errors.New("invalid compact echo filter scope")
	}
	if err := cleanupCompactEchoRecords(dir, instance, namespace, run); err != nil {
		return nil, err
	}
	return f, nil
}

func (f *compactEchoFilter) update(alias, ownAlias uint64, now time.Time) (bool, error) {
	if f.current != nil && f.current.Alias == alias && f.installed {
		return true, nil
	}
	if f.lastAlias == alias && now.Before(f.retryAt) {
		return false, nil
	}
	f.lastAlias, f.retryAt = alias, now.Add(30*time.Second)
	if alias == 0 || alias == ownAlias {
		return false, errors.New("unsafe compact echo alias collision")
	}
	if f.current != nil {
		if err := removeCompactEchoRecord(f.dir, *f.current, f.run); err != nil {
			return false, err
		}
		f.current, f.installed = nil, false
	}
	r := f.base
	r.Alias = alias
	if err := writeCompactEchoRecord(f.dir, r); err != nil {
		return false, err
	}
	f.current = &r
	if err := f.run(r.rule("-I")); err != nil {
		// The insertion result may be ambiguous (command timeout). Retain the
		// recipe until an exact check confirms the rule is absent or removes it.
		return false, err
	}
	f.installed = true
	return true, nil
}

func (f *compactEchoFilter) close() error {
	if f.current == nil {
		return nil
	}
	if err := removeCompactEchoRecord(f.dir, *f.current, f.run); err != nil {
		return err
	}
	f.current, f.installed = nil, false
	return nil
}
