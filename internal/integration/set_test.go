package integration_test

import (
	"strings"
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

func TestAnonSet(t *testing.T) {
	conn, _, closer := OpenSystemConn(t)
	defer closer()

	setID := uint32(1)
	flags := nftnl.SetAnonymous | nftnl.SetConstant

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
	batch.Add(nftnl.Msg{
		Type:   nftnl.MsgNewSet,
		Family: nftnl.FamilyInet,
		Flags:  netlink.Request | netlink.Create,
		Attrs: &nftnl.Set{
			Table:   "test",
			Name:    new(nftnl.SetAnonTemplate),
			Flags:   &flags,
			KeyType: new(nftnl.DataTypeInetService),
			KeyLen:  new(uint32(2)),
			ID:      &setID,
		},
	})
	batch.Add(nftnl.Msg{
		Type:   nftnl.MsgNewSetElem,
		Family: nftnl.FamilyInet,
		Flags:  netlink.Request | netlink.Create,
		Attrs: &nftnl.SetElemList{
			Table: "test",
			Set:   new(nftnl.SetAnonTemplate),
			SetID: &setID,
			Elements: []nftnl.SetElem{
				{Key: &nftnl.ExprData{Value: []byte{0x00, 0x50}}}, // 80
				{Key: &nftnl.ExprData{Value: []byte{0x01, 0xbb}}}, // 443
			},
		},
	})
	batch.Add(nftnl.Msg{
		Type:   nftnl.MsgNewRule,
		Family: nftnl.FamilyInet,
		Flags:  netlink.Request | netlink.Create,
		Attrs: &nftnl.Rule{
			Table: "test",
			Chain: new("input"),
			Expressions: []nftnl.Expr{
				&nftnl.ExprPayload{
					Base:   nftnl.PayloadBaseTransport,
					Offset: 2,
					Len:    2,
					DReg:   new(nftnl.Reg1),
				},
				&nftnl.ExprLookup{
					SReg:  nftnl.Reg1,
					Set:   nftnl.SetAnonTemplate,
					SetID: &setID,
				},
				&nftnl.ExprImmediate{
					DReg: nftnl.RegVerdict,
					Data: &nftnl.ExprData{Verdict: &nftnl.ExprVerdict{Code: nftnl.VerdictAccept}},
				},
			},
		},
	})
	if _, err := conn.SendBatch(batch); err != nil {
		t.Fatalf("create anon set and rule: %v", err)
	}

	// Rule must exist and reference the anonymous set via lookup.
	msgs, err := conn.Send(nftnl.Msg{
		Type:   nftnl.MsgGetRule,
		Family: nftnl.FamilyInet,
		Flags:  netlink.Request | netlink.Dump,
		Attrs:  &nftnl.Rule{Table: "test", Chain: new("input")},
	})
	if err != nil {
		t.Fatalf("get rules: %v", err)
	}
	if len(msgs) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(msgs))
	}
	ruleAttrs, ok := nftnl.As[*nftnl.Rule](msgs[0].Attrs)
	if !ok {
		t.Fatalf("expected *Rule, got %T", msgs[0].Attrs)
	}

	// After commit the lookup expression must carry the resolved name, not the template.
	var lookup *nftnl.ExprLookup
	for _, e := range ruleAttrs.Expressions {
		if l, ok := e.(*nftnl.ExprLookup); ok {
			lookup = l
			break
		}
	}
	if lookup == nil {
		t.Fatal("rule has no lookup expression")
	}
	if lookup.Set == nftnl.SetAnonTemplate {
		t.Errorf("lookup Set still holds template %q; kernel should have resolved it to a real name", nftnl.SetAnonTemplate)
	}
	if !strings.HasPrefix(lookup.Set, "__set") {
		t.Errorf("lookup Set %q does not have expected __set prefix", lookup.Set)
	}

	// The anonymous set must be visible while the rule holds a reference.
	setMsgs, err := conn.Send(nftnl.Msg{
		Type:   nftnl.MsgGetSet,
		Family: nftnl.FamilyInet,
		Flags:  netlink.Request | netlink.Dump,
		Attrs:  &nftnl.Set{Table: "test"},
	})
	if err != nil {
		t.Fatalf("get sets: %v", err)
	}
	if len(setMsgs) != 1 {
		t.Fatalf("expected 1 anonymous set, got %d", len(setMsgs))
	}
	setAttrs, ok := nftnl.As[*nftnl.Set](setMsgs[0].Attrs)
	if !ok {
		t.Fatalf("expected *Set, got %T", setMsgs[0].Attrs)
	}
	if setAttrs.Name == nil || *setAttrs.Name == nftnl.SetAnonTemplate {
		t.Errorf("set name %v: kernel should have substituted the %%d template", setAttrs.Name)
	}

	AssertRuleset(t, `
table inet test {
	chain input {
		type filter hook input priority filter; policy accept;
		th dport { 80, 443 } accept
	}
}`)

	// Deleting the rule must automatically destroy the anonymous set.
	del := nftnl.NewBatch()
	del.Add(nftnl.Msg{
		Type:   nftnl.MsgDelRule,
		Family: nftnl.FamilyInet,
		Flags:  netlink.Request,
		Attrs:  &nftnl.Rule{Table: "test", Chain: new("input"), Handle: ruleAttrs.Handle},
	})
	if _, err := conn.SendBatch(del); err != nil {
		t.Fatalf("delete rule: %v", err)
	}

	setMsgs, err = conn.Send(nftnl.Msg{
		Type:   nftnl.MsgGetSet,
		Family: nftnl.FamilyInet,
		Flags:  netlink.Request | netlink.Dump,
		Attrs:  &nftnl.Set{Table: "test"},
	})
	if err != nil {
		t.Fatalf("get sets after rule delete: %v", err)
	}
	if len(setMsgs) != 0 {
		t.Errorf("expected anonymous set to be cleaned up after rule delete, got %d sets", len(setMsgs))
	}
}
