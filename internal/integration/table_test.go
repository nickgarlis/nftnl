package integration_test

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/mdlayher/netlink"
	"github.com/nickgarlis/nftnl"
)

func TestTable(t *testing.T) {
	conn, _, closer := OpenSystemConn(t)
	defer closer()

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

	msgs, err := conn.Send(nftnl.Msg{
		Type:   nftnl.MsgGetTable,
		Family: nftnl.FamilyInet,
		Flags:  netlink.Request | netlink.Dump,
	})
	if err != nil {
		t.Fatalf("get tables: %v", err)
	}

	if len(msgs) != 1 {
		t.Fatalf("expected 1 table, got %d", len(msgs))
	}
	attrs, ok := nftnl.As[*nftnl.Table](msgs[0].Attrs)
	if !ok {
		t.Fatalf("expected *TableAttrs, got %T", msgs[0].Attrs)
	}
	if diff := cmp.Diff("test", attrs.Name); diff != "" {
		t.Errorf("table name mismatch (-want +got):\n%s", diff)
	}

	del := nftnl.NewBatch()
	del.Add(nftnl.Msg{
		Type:   nftnl.MsgDelTable,
		Family: nftnl.FamilyInet,
		Flags:  netlink.Request,
		Attrs:  &nftnl.Table{Name: "test"},
	})
	if _, err := conn.SendBatch(del); err != nil {
		t.Fatalf("delete table: %v", err)
	}
	msgs, err = conn.Send(nftnl.Msg{
		Type:   nftnl.MsgGetTable,
		Family: nftnl.FamilyInet,
		Flags:  netlink.Request | netlink.Dump,
	})
	if err != nil {
		t.Fatalf("get tables after delete: %v", err)
	}
	if len(msgs) != 0 {
		t.Errorf("expected 0 tables after delete, got %d", len(msgs))
	}

	destroy := nftnl.NewBatch()
	destroy.Add(nftnl.Msg{
		Type:   nftnl.MsgDestroyTable,
		Family: nftnl.FamilyInet,
		Flags:  netlink.Request,
		Attrs:  &nftnl.Table{Name: "test"},
	})
	if _, err := conn.SendBatch(destroy); err != nil {
		t.Fatalf("destroy table (idempotent): %v", err)
	}
}
