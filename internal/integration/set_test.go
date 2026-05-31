package integration_test

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/mdlayher/netlink"
	"github.com/nickgarlis/nftnl"
)

func TestSet(t *testing.T) {
	conn, _, closer := OpenSystemConn(t)
	defer closer()

	batch := nftnl.NewBatch()
	batch.Add(nftnl.Msg{
		Type:   nftnl.MsgNewTable,
		Family: nftnl.FamilyInet,
		Flags:  netlink.Request,
		Attrs:  &nftnl.Table{Name: "test"},
	})
	batch.Add(nftnl.Msg{
		Type:   nftnl.MsgNewSet,
		Family: nftnl.FamilyInet,
		Flags:  netlink.Request | netlink.Create,
		Attrs: &nftnl.Set{
			ID:      new(uint32(1)),
			Table:   "test",
			Name:    new("testset"),
			KeyType: new(nftnl.DataTypeIPAddr),
			KeyLen:  new(uint32(4)),
		},
	})
	if _, err := conn.SendBatch(batch); err != nil {
		t.Fatalf("create set: %v", err)
	}

	msgs, err := conn.Send(nftnl.Msg{
		Type:   nftnl.MsgGetSet,
		Family: nftnl.FamilyInet,
		Flags:  netlink.Request | netlink.Dump,
		Attrs:  &nftnl.Set{Table: "test"},
	})
	if err != nil {
		t.Fatalf("get sets: %v", err)
	}
	if len(msgs) != 1 {
		t.Fatalf("expected 1 set, got %d", len(msgs))
	}
	attrs, ok := nftnl.As[*nftnl.Set](msgs[0].Attrs)
	if !ok {
		t.Fatalf("expected *SetAttrs, got %T", msgs[0].Attrs)
	}
	if diff := cmp.Diff(new("testset"), attrs.Name); diff != "" {
		t.Errorf("set name mismatch (-want +got):\n%s", diff)
	}

	del := nftnl.NewBatch()
	del.Add(nftnl.Msg{
		Type:   nftnl.MsgDelSet,
		Family: nftnl.FamilyInet,
		Flags:  netlink.Request,
		Attrs:  &nftnl.Set{Table: "test", Name: new("testset")},
	})
	if _, err := conn.SendBatch(del); err != nil {
		t.Fatalf("delete set: %v", err)
	}
	msgs, err = conn.Send(nftnl.Msg{
		Type:   nftnl.MsgGetSet,
		Family: nftnl.FamilyInet,
		Flags:  netlink.Request | netlink.Dump,
		Attrs:  &nftnl.Set{Table: "test"},
	})
	if err != nil {
		t.Fatalf("get sets after delete: %v", err)
	}
	if len(msgs) != 0 {
		t.Errorf("expected 0 sets after delete, got %d", len(msgs))
	}

	destroy := nftnl.NewBatch()
	destroy.Add(nftnl.Msg{
		Type:   nftnl.MsgDestroySet,
		Family: nftnl.FamilyInet,
		Flags:  netlink.Request,
		Attrs:  &nftnl.Set{Table: "test", Name: new("testset")},
	})
	if _, err := conn.SendBatch(destroy); err != nil {
		t.Fatalf("destroy set (idempotent): %v", err)
	}
}
