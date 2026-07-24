package integration_test

import (
	"math"
	"testing"

	"github.com/mdlayher/netlink"
	"github.com/nickgarlis/nftnl"
)

func TestLargeDump(t *testing.T) {
	const count = math.MaxUint16

	conn, ns, closer := OpenSystemConn(t)
	defer closer()

	batch := nftnl.NewBatch()
	batch.Add(nftnl.Msg{
		Type:   nftnl.MsgNewTable,
		Family: nftnl.FamilyInet,
		Flags:  netlink.Request | netlink.Create,
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
	for range count {
		batch.Add(nftnl.Msg{
			Type:   nftnl.MsgNewRule,
			Family: nftnl.FamilyInet,
			Flags:  netlink.Request | netlink.Create,
			Attrs: &nftnl.Rule{
				Table: "test",
				Chain: new("input"),
				Expressions: []nftnl.Expr{
					&nftnl.ExprImmediate{
						DReg: nftnl.RegVerdict,
						Data: &nftnl.ExprData{Verdict: &nftnl.ExprVerdict{Code: nftnl.VerdictAccept}},
					},
				},
			},
		})
	}
	if _, err := conn.SendBatch(batch); err != nil {
		t.Fatalf("send batch of %d rules: %v", count, err)
	}

	// Dump via a second connection to verify the streaming receive loop works
	// on a fresh socket with no prior SO_RCVBUF tuning.
	conn2, err := nftnl.Open(&nftnl.Config{NetNS: int(ns)})
	if err != nil {
		t.Fatalf("open second connection: %v", err)
	}
	defer conn2.Close()

	msgs, err := conn2.Send(nftnl.Msg{
		Type:   nftnl.MsgGetRule,
		Family: nftnl.FamilyInet,
		Flags:  netlink.Request | netlink.Dump,
		Attrs:  &nftnl.Rule{Table: "test", Chain: new("input")},
	})
	if err != nil {
		t.Fatalf("dump rules: %v", err)
	}
	if len(msgs) != count {
		t.Errorf("expected %d rules, got %d", count, len(msgs))
	}
}

func TestLargeRuleset(t *testing.T) {
	const count = math.MaxUint16

	conn, _, closer := OpenSystemConn(t)
	defer closer()

	batch := nftnl.NewBatch()
	batch.Add(nftnl.Msg{
		Type:   nftnl.MsgNewTable,
		Family: nftnl.FamilyInet,
		Flags:  netlink.Request | netlink.Create,
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

	for range count {
		batch.Add(nftnl.Msg{
			Type:   nftnl.MsgNewRule,
			Family: nftnl.FamilyInet,
			Flags:  netlink.Request | netlink.Create,
			Attrs: &nftnl.Rule{
				Table: "test",
				Chain: new("input"),
				Expressions: []nftnl.Expr{
					&nftnl.ExprImmediate{
						DReg: nftnl.RegVerdict,
						Data: &nftnl.ExprData{Verdict: &nftnl.ExprVerdict{Code: nftnl.VerdictAccept}},
					},
				},
			},
		})
	}

	if _, err := conn.SendBatch(batch); err != nil {
		t.Fatalf("send batch of %d rules: %v", count, err)
	}

	msgs, err := conn.Send(nftnl.Msg{
		Type:   nftnl.MsgGetRule,
		Family: nftnl.FamilyInet,
		Flags:  netlink.Request | netlink.Dump,
		Attrs:  &nftnl.Rule{Table: "test", Chain: new("input")},
	})
	if err != nil {
		t.Fatalf("get rules: %v", err)
	}
	if len(msgs) != count {
		t.Errorf("expected %d rules, got %d", count, len(msgs))
	}
}
