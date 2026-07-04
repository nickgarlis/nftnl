package integration_test

import (
	"os"
	"os/exec"
	"runtime"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/nickgarlis/nftnl"
	"github.com/vishvananda/netns"
)

func isRoot() bool {
	return os.Geteuid() == 0
}

func OpenSystemConn(t *testing.T) (*nftnl.Conn, netns.NsHandle, func()) {
	t.Helper()

	if !isRoot() {
		t.Skip("skipping: not running as root")
	}

	runtime.LockOSThread()
	ns, err := netns.New()
	if err != nil {
		t.Fatalf("get current network namespace: %v", err)
	}
	conn, err := nftnl.Open(&nftnl.Config{
		NetNS: int(ns),
	})
	if err != nil {
		t.Fatalf("create nftnl connection: %v", err)
	}
	closer := func() {
		defer runtime.UnlockOSThread()
		if err := conn.Close(); err != nil {
			t.Errorf("close nftnl connection: %v", err)
		}
		if err := ns.Close(); err != nil {
			t.Errorf("close network namespace handle: %v", err)
		}
	}
	return conn, ns, closer
}

// AssertRuleset runs "nft list ruleset" and compares the output to want.
// It relies on the goroutine being pinned (via LockOSThread in OpenSystemConn)
// to the OS thread that netns.New() already switched into the test namespace.
func AssertRuleset(t *testing.T, want string) {
	t.Helper()
	out, err := exec.Command("nft", "list", "ruleset").Output()
	if err != nil {
		t.Fatalf("nft list ruleset: %v", err)
	}
	got := strings.TrimSpace(string(out))
	want = strings.TrimSpace(want)
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("ruleset mismatch (-want +got):\n%s", diff)
	}
}
