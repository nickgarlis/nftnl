package integration_test

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/mdlayher/netlink"
	"github.com/nickgarlis/nftnl"
	"golang.org/x/sys/unix"
)

func TestRule(t *testing.T) {
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

	rule := nftnl.Rule{
		Table: "test",
		Chain: new("input"),
		Expressions: []nftnl.Expr{
			&nftnl.ExprMeta{
				Key:  nftnl.MetaKeyNFProto,
				DReg: new(nftnl.Reg1),
			},
			&nftnl.ExprCmp{
				SReg: nftnl.Reg1,
				Op:   nftnl.CmpEq,
				Data: &nftnl.ExprData{Value: []byte{nftnl.FamilyIPv4}},
			},
			&nftnl.ExprPayload{
				Base:   nftnl.PayloadBaseNetwork,
				Offset: 9,
				Len:    1,
				DReg:   new(nftnl.Reg1),
			},
			&nftnl.ExprCmp{
				SReg: nftnl.Reg1,
				Op:   nftnl.CmpEq,
				Data: &nftnl.ExprData{Value: []byte{unix.IPPROTO_TCP}},
			},
			&nftnl.ExprPayload{
				Base:   nftnl.PayloadBaseTransport,
				Offset: 2,
				Len:    2,
				DReg:   new(nftnl.Reg1),
			},
			&nftnl.ExprCmp{
				SReg: nftnl.Reg1,
				Op:   nftnl.CmpEq,
				Data: &nftnl.ExprData{Value: []byte{0x00, 0x50}}, // port 80, big-endian
			},
			&nftnl.ExprImmediate{
				DReg: nftnl.RegVerdict,
				Data: &nftnl.ExprData{Verdict: &nftnl.ExprVerdict{Code: nftnl.VerdictAccept}},
			},
		},
	}
	rule.UserData.SetString(nftnl.RuleUDComment, "http accept")

	batch.Add(nftnl.Msg{
		Type:   nftnl.MsgNewRule,
		Family: nftnl.FamilyInet,
		Flags:  netlink.Request | netlink.Create,
		Attrs:  &rule,
	})
	if _, err := conn.SendBatch(batch); err != nil {
		t.Fatalf("create rule: %v", err)
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
	if len(msgs) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(msgs))
	}
	attrs, ok := nftnl.As[*nftnl.Rule](msgs[0].Attrs)
	if !ok {
		t.Fatalf("expected *RuleAttrs, got %T", msgs[0].Attrs)
	}

	gotComment, ok := attrs.UserData.GetString(nftnl.RuleUDComment)
	if !ok {
		t.Fatal("rule has no comment in userdata")
	}
	if diff := cmp.Diff("http accept", gotComment); diff != "" {
		t.Errorf("rule comment mismatch (-want +got):\n%s", diff)
	}

	AssertRuleset(t, `
table inet test {
	chain input {
		type filter hook input priority filter; policy accept;
		ip protocol tcp tcp dport 80 accept comment "http accept"
	}
}`)

	msgs, err = conn.Send(nftnl.Msg{
		Type:   nftnl.MsgGetRuleReset,
		Family: nftnl.FamilyInet,
		Flags:  netlink.Request | netlink.Dump,
		Attrs:  &nftnl.Rule{Table: "test", Chain: new("input")},
	})
	if err != nil {
		t.Fatalf("get rule reset: %v", err)
	}
	if len(msgs) != 1 {
		t.Fatalf("expected 1 rule from reset, got %d", len(msgs))
	}
	resetAttrs, ok := nftnl.As[*nftnl.Rule](msgs[0].Attrs)
	if !ok {
		t.Fatalf("expected *RuleAttrs, got %T", msgs[0].Attrs)
	}
	if diff := cmp.Diff(attrs.Handle, resetAttrs.Handle); diff != "" {
		t.Errorf("reset rule handle mismatch (-want +got):\n%s", diff)
	}

	del := nftnl.NewBatch()
	del.Add(nftnl.Msg{
		Type:   nftnl.MsgDelRule,
		Family: nftnl.FamilyInet,
		Flags:  netlink.Request,
		Attrs:  &nftnl.Rule{Table: "test", Chain: new("input"), Handle: attrs.Handle},
	})
	if _, err := conn.SendBatch(del); err != nil {
		t.Fatalf("delete rule: %v", err)
	}
	msgs, err = conn.Send(nftnl.Msg{
		Type:   nftnl.MsgGetRule,
		Family: nftnl.FamilyInet,
		Flags:  netlink.Request | netlink.Dump,
		Attrs:  &nftnl.Rule{Table: "test", Chain: new("input")},
	})
	if err != nil {
		t.Fatalf("get rules after delete: %v", err)
	}
	if len(msgs) != 0 {
		t.Errorf("expected 0 rules after delete, got %d", len(msgs))
	}

	destroy := nftnl.NewBatch()
	destroy.Add(nftnl.Msg{
		Type:   nftnl.MsgDestroyRule,
		Family: nftnl.FamilyInet,
		Flags:  netlink.Request,
		Attrs:  &nftnl.Rule{Table: "test", Chain: new("input"), Handle: attrs.Handle},
	})
	if _, err := conn.SendBatch(destroy); err != nil {
		t.Fatalf("destroy rule (idempotent): %v", err)
	}
}
