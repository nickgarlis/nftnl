package integration_test

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/mdlayher/netlink"
	"github.com/nickgarlis/nftnl"
)

func TestChain(t *testing.T) {
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
		Type:   nftnl.MsgNewChain,
		Family: nftnl.FamilyInet,
		Flags:  netlink.Request | netlink.Create,
		Attrs: &nftnl.Chain{
			Table:  "test",
			Name:   "input",
			Type:   "filter",
			Hook:   &nftnl.Hook{HookNum: nftnl.HookLocalIn, Priority: nftnl.PriorityFilter},
			Policy: new(nftnl.ChainPolicyAccept),
		},
	})
	if _, err := conn.SendBatch(batch); err != nil {
		t.Fatalf("create chain: %v", err)
	}

	msgs, err := conn.Send(nftnl.Msg{
		Type:   nftnl.MsgGetChain,
		Family: nftnl.FamilyInet,
		Flags:  netlink.Request | netlink.Dump,
		Attrs:  &nftnl.Chain{Table: "test"},
	})
	if err != nil {
		t.Fatalf("get chains: %v", err)
	}
	if len(msgs) != 1 {
		t.Fatalf("expected 1 chain, got %d", len(msgs))
	}
	attrs, ok := nftnl.As[*nftnl.Chain](msgs[0].Attrs)
	if !ok {
		t.Fatalf("expected *ChainAttrs, got %T", msgs[0].Attrs)
	}
	if diff := cmp.Diff("input", attrs.Name); diff != "" {
		t.Errorf("chain name mismatch (-want +got):\n%s", diff)
	}
	if attrs.Hook == nil {
		t.Fatal("chain has no hook")
	}
	if diff := cmp.Diff(nftnl.HookLocalIn, attrs.Hook.HookNum); diff != "" {
		t.Errorf("hook number mismatch (-want +got):\n%s", diff)
	}
	if attrs.Policy == nil {
		t.Fatal("chain has no policy")
	}
	if diff := cmp.Diff(nftnl.ChainPolicyAccept, *attrs.Policy); diff != "" {
		t.Errorf("chain policy mismatch (-want +got):\n%s", diff)
	}

	AssertRuleset(t, `
table inet test {
	chain input {
		type filter hook input priority filter; policy accept;
	}
}`)

	del := nftnl.NewBatch()
	del.Add(nftnl.Msg{
		Type:   nftnl.MsgDelChain,
		Family: nftnl.FamilyInet,
		Flags:  netlink.Request,
		Attrs:  &nftnl.Chain{Table: "test", Name: "input"},
	})
	if _, err := conn.SendBatch(del); err != nil {
		t.Fatalf("delete chain: %v", err)
	}
	msgs, err = conn.Send(nftnl.Msg{
		Type:   nftnl.MsgGetChain,
		Family: nftnl.FamilyInet,
		Flags:  netlink.Request | netlink.Dump,
		Attrs:  &nftnl.Chain{Table: "test"},
	})
	if err != nil {
		t.Fatalf("get chains after delete: %v", err)
	}
	if len(msgs) != 0 {
		t.Errorf("expected 0 chains after delete, got %d", len(msgs))
	}

	destroy := nftnl.NewBatch()
	destroy.Add(nftnl.Msg{
		Type:   nftnl.MsgDestroyChain,
		Family: nftnl.FamilyInet,
		Flags:  netlink.Request,
		Attrs:  &nftnl.Chain{Table: "test", Name: "input"},
	})
	if _, err := conn.SendBatch(destroy); err != nil {
		t.Fatalf("destroy chain (idempotent): %v", err)
	}
}
