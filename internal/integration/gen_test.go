package integration_test

import (
	"errors"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/mdlayher/netlink"
	"github.com/nickgarlis/nftnl"
	"golang.org/x/sys/unix"
)

func TestGen(t *testing.T) {
	conn, _, closer := OpenSystemConn(t)
	defer closer()

	msgs, err := conn.Send(nftnl.Msg{
		Type:  nftnl.MsgGetGen,
		Flags: netlink.Request,
	})
	if err != nil {
		t.Fatalf("get gen: %v", err)
	}
	if len(msgs) != 1 {
		t.Fatalf("expected 1 gen message, got %d", len(msgs))
	}
	gen, ok := nftnl.As[*nftnl.Gen](msgs[0].Attrs)
	if !ok {
		t.Fatalf("expected *GenAttrs, got %T", msgs[0].Attrs)
	}
	initialID := gen.ID

	batch := nftnl.NewBatch()
	batch.Add(nftnl.Msg{
		Type:   nftnl.MsgNewTable,
		Family: nftnl.FamilyInet,
		Flags:  netlink.Request,
		Attrs:  &nftnl.Table{Name: "test"},
	})
	if _, err := conn.SendBatch(batch); err != nil {
		t.Fatalf("create table: %v", err)
	}

	msgs, err = conn.Send(nftnl.Msg{
		Type:  nftnl.MsgGetGen,
		Flags: netlink.Request,
	})
	if err != nil {
		t.Fatalf("get gen after commit: %v", err)
	}
	gen, ok = nftnl.As[*nftnl.Gen](msgs[0].Attrs)
	if !ok {
		t.Fatalf("expected *GenAttrs, got %T", msgs[0].Attrs)
	}
	if diff := cmp.Diff(initialID+1, gen.ID); diff != "" {
		t.Errorf("gen ID mismatch (-want +got):\n%s", diff)
	}
	currentID := gen.ID

	// A batch with a stale gen ID is rejected with ERESTART.
	stale := nftnl.NewBatchWithGenID(initialID)
	stale.Add(nftnl.Msg{
		Type:   nftnl.MsgNewTable,
		Family: nftnl.FamilyInet,
		Flags:  netlink.Request,
		Attrs:  &nftnl.Table{Name: "test2"},
	})
	if _, err := conn.SendBatch(stale); !errors.Is(err, unix.ERESTART) {
		t.Errorf("expected ERESTART with stale gen ID, got %v", err)
	}

	// A batch with the current gen ID succeeds.
	current := nftnl.NewBatchWithGenID(currentID)
	current.Add(nftnl.Msg{
		Type:   nftnl.MsgNewTable,
		Family: nftnl.FamilyInet,
		Flags:  netlink.Request,
		Attrs:  &nftnl.Table{Name: "test2"},
	})
	if _, err := conn.SendBatch(current); err != nil {
		t.Fatalf("batch with current gen ID: %v", err)
	}
}
