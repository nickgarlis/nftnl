package integration_test

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/mdlayher/netlink"
	"github.com/nickgarlis/nftnl"
)

func TestFlowtable(t *testing.T) {
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
		Type:   nftnl.MsgNewFlowtable,
		Family: nftnl.FamilyInet,
		Flags:  netlink.Request | netlink.Create,
		Attrs: &nftnl.Flowtable{
			Table: "test",
			Name:  "ft",
			Hook: &nftnl.FlowtableHook{
				HookNum:  new(nftnl.HookNum(0)), // NF_NETDEV_INGRESS
				Priority: new(int32(0)),
				Devs:     []string{"lo"},
			},
		},
	})
	if _, err := conn.SendBatch(batch); err != nil {
		t.Fatalf("create flowtable: %v", err)
	}

	msgs, err := conn.Send(nftnl.Msg{
		Type:   nftnl.MsgGetFlowtable,
		Family: nftnl.FamilyInet,
		Flags:  netlink.Request | netlink.Dump,
		Attrs:  &nftnl.Flowtable{Table: "test"},
	})
	if err != nil {
		t.Fatalf("get flowtables: %v", err)
	}
	if len(msgs) != 1 {
		t.Fatalf("expected 1 flowtable, got %d", len(msgs))
	}
	attrs, ok := nftnl.As[*nftnl.Flowtable](msgs[0].Attrs)
	if !ok {
		t.Fatalf("expected *FlowtableAttrs, got %T", msgs[0].Attrs)
	}
	if diff := cmp.Diff("ft", attrs.Name); diff != "" {
		t.Errorf("flowtable name mismatch (-want +got):\n%s", diff)
	}
	if attrs.Hook == nil {
		t.Fatal("flowtable has no hook")
	}
	if diff := cmp.Diff([]string{"lo"}, attrs.Hook.Devs); diff != "" {
		t.Errorf("flowtable devs mismatch (-want +got):\n%s", diff)
	}

	AssertRuleset(t, `
table inet test {
	flowtable ft {
		hook ingress priority filter
		devices = { "lo" }
	}
}`)

	del := nftnl.NewBatch()
	del.Add(nftnl.Msg{
		Type:   nftnl.MsgDelFlowtable,
		Family: nftnl.FamilyInet,
		Flags:  netlink.Request,
		Attrs:  &nftnl.Flowtable{Table: "test", Name: "ft"},
	})
	if _, err := conn.SendBatch(del); err != nil {
		t.Fatalf("delete flowtable: %v", err)
	}
	msgs, err = conn.Send(nftnl.Msg{
		Type:   nftnl.MsgGetFlowtable,
		Family: nftnl.FamilyInet,
		Flags:  netlink.Request | netlink.Dump,
		Attrs:  &nftnl.Flowtable{Table: "test"},
	})
	if err != nil {
		t.Fatalf("get flowtables after delete: %v", err)
	}
	if len(msgs) != 0 {
		t.Errorf("expected 0 flowtables after delete, got %d", len(msgs))
	}

	destroy := nftnl.NewBatch()
	destroy.Add(nftnl.Msg{
		Type:   nftnl.MsgDestroyFlowtable,
		Family: nftnl.FamilyInet,
		Flags:  netlink.Request,
		Attrs:  &nftnl.Flowtable{Table: "test", Name: "ft"},
	})
	if _, err := conn.SendBatch(destroy); err != nil {
		t.Fatalf("destroy flowtable (idempotent): %v", err)
	}
}
