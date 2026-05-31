package integration_test

import (
	"net"
	"net/netip"
	"testing"

	"github.com/mdlayher/netlink"
	"github.com/nickgarlis/nftnl"
	"golang.org/x/sys/unix"
)

func addr4(s string) []byte { b := netip.MustParseAddr(s).As4(); return b[:] }

func TestExpressions(t *testing.T) {
	iifNameLo := make([]byte, 16)
	copy(iifNameLo, "lo")

	ctStateMask := (nftnl.CTStateEstablished | nftnl.CTStateRelated).Bytes()
	ctStateZero := []byte{0, 0, 0, 0}

	setID1 := uint32(1)

	ipv4Daddr127 := netip.MustParseAddr("127.0.0.1").As4()
	ipv4Saddr10 := netip.MustParsePrefix("10.0.0.0/8").Masked().Addr().As4()
	ipv6Saddr1 := netip.MustParseAddr("::1").As16()
	ipv6Saddr2001 := netip.MustParsePrefix("2001:db8::/32").Masked().Addr().As16()

	rules := [][]nftnl.Expr{
		// iifname "lo" accept
		{
			&nftnl.ExprMeta{Key: nftnl.MetaKeyIIFName, DReg: new(nftnl.Reg1)},
			&nftnl.ExprCmp{SReg: nftnl.Reg1, Op: nftnl.CmpEq, Data: &nftnl.ExprData{Value: iifNameLo}},
			&nftnl.ExprImmediate{DReg: nftnl.RegVerdict, Data: &nftnl.ExprData{Verdict: &nftnl.ExprVerdict{Code: nftnl.VerdictAccept}}},
		},
		// ip protocol tcp tcp dport 80 accept
		{
			&nftnl.ExprMeta{Key: nftnl.MetaKeyNFProto, DReg: new(nftnl.Reg1)},
			&nftnl.ExprCmp{SReg: nftnl.Reg1, Op: nftnl.CmpEq, Data: &nftnl.ExprData{Value: []byte{nftnl.FamilyIPv4}}},
			&nftnl.ExprPayload{Base: nftnl.PayloadBaseNetwork, Offset: 9, Len: 1, DReg: new(nftnl.Reg1)},
			&nftnl.ExprCmp{SReg: nftnl.Reg1, Op: nftnl.CmpEq, Data: &nftnl.ExprData{Value: []byte{unix.IPPROTO_TCP}}},
			&nftnl.ExprPayload{Base: nftnl.PayloadBaseTransport, Offset: 2, Len: 2, DReg: new(nftnl.Reg1)},
			&nftnl.ExprCmp{SReg: nftnl.Reg1, Op: nftnl.CmpEq, Data: &nftnl.ExprData{Value: []byte{0, 80}}},
			&nftnl.ExprImmediate{DReg: nftnl.RegVerdict, Data: &nftnl.ExprData{Verdict: &nftnl.ExprVerdict{Code: nftnl.VerdictAccept}}},
		},
		// ct state established,related accept
		{
			&nftnl.ExprCt{Key: nftnl.CTKeyState, DReg: new(nftnl.Reg1)},
			&nftnl.ExprBitwise{
				SReg: nftnl.Reg1, DReg: nftnl.Reg1, Len: 4,
				Mask: &nftnl.ExprData{Value: ctStateMask},
				Xor:  &nftnl.ExprData{Value: ctStateZero},
			},
			&nftnl.ExprCmp{SReg: nftnl.Reg1, Op: nftnl.CmpNeq, Data: &nftnl.ExprData{Value: ctStateZero}},
			&nftnl.ExprImmediate{DReg: nftnl.RegVerdict, Data: &nftnl.ExprData{Verdict: &nftnl.ExprVerdict{Code: nftnl.VerdictAccept}}},
		},
		// ip saddr @test_set accept
		{
			&nftnl.ExprMeta{Key: nftnl.MetaKeyNFProto, DReg: new(nftnl.Reg1)},
			&nftnl.ExprCmp{SReg: nftnl.Reg1, Op: nftnl.CmpEq, Data: &nftnl.ExprData{Value: []byte{nftnl.FamilyIPv4}}},
			&nftnl.ExprPayload{Base: nftnl.PayloadBaseNetwork, Offset: 12, Len: 4, DReg: new(nftnl.Reg1)},
			&nftnl.ExprLookup{SReg: nftnl.Reg1, Set: "test_set", SetID: &setID1},
			&nftnl.ExprImmediate{DReg: nftnl.RegVerdict, Data: &nftnl.ExprData{Verdict: &nftnl.ExprVerdict{Code: nftnl.VerdictAccept}}},
		},
		// log prefix "drop: " drop
		{
			&nftnl.ExprLog{Prefix: "drop: "},
			&nftnl.ExprImmediate{DReg: nftnl.RegVerdict, Data: &nftnl.ExprData{Verdict: &nftnl.ExprVerdict{Code: nftnl.VerdictDrop}}},
		},
		// ip daddr 127.0.0.1 drop
		{
			&nftnl.ExprMeta{Key: nftnl.MetaKeyNFProto, DReg: new(nftnl.Reg1)},
			&nftnl.ExprCmp{SReg: nftnl.Reg1, Op: nftnl.CmpEq, Data: &nftnl.ExprData{Value: []byte{nftnl.FamilyIPv4}}},
			&nftnl.ExprPayload{Base: nftnl.PayloadBaseNetwork, Offset: 16, Len: 4, DReg: new(nftnl.Reg1)},
			&nftnl.ExprCmp{SReg: nftnl.Reg1, Op: nftnl.CmpEq, Data: &nftnl.ExprData{Value: ipv4Daddr127[:]}},
			&nftnl.ExprImmediate{DReg: nftnl.RegVerdict, Data: &nftnl.ExprData{Verdict: &nftnl.ExprVerdict{Code: nftnl.VerdictDrop}}},
		},
		// ip saddr 10.0.0.0/8 accept
		{
			&nftnl.ExprMeta{Key: nftnl.MetaKeyNFProto, DReg: new(nftnl.Reg1)},
			&nftnl.ExprCmp{SReg: nftnl.Reg1, Op: nftnl.CmpEq, Data: &nftnl.ExprData{Value: []byte{nftnl.FamilyIPv4}}},
			&nftnl.ExprPayload{Base: nftnl.PayloadBaseNetwork, Offset: 12, Len: 4, DReg: new(nftnl.Reg1)},
			&nftnl.ExprBitwise{
				SReg: nftnl.Reg1, DReg: nftnl.Reg1, Len: 4,
				Mask: &nftnl.ExprData{Value: net.CIDRMask(8, 32)},
				Xor:  &nftnl.ExprData{Value: []byte{0, 0, 0, 0}},
			},
			&nftnl.ExprCmp{SReg: nftnl.Reg1, Op: nftnl.CmpEq, Data: &nftnl.ExprData{Value: ipv4Saddr10[:]}},
			&nftnl.ExprImmediate{DReg: nftnl.RegVerdict, Data: &nftnl.ExprData{Verdict: &nftnl.ExprVerdict{Code: nftnl.VerdictAccept}}},
		},
		// ip6 saddr ::1 accept
		{
			&nftnl.ExprMeta{Key: nftnl.MetaKeyNFProto, DReg: new(nftnl.Reg1)},
			&nftnl.ExprCmp{SReg: nftnl.Reg1, Op: nftnl.CmpEq, Data: &nftnl.ExprData{Value: []byte{nftnl.FamilyIPv6}}},
			&nftnl.ExprPayload{Base: nftnl.PayloadBaseNetwork, Offset: 8, Len: 16, DReg: new(nftnl.Reg1)},
			&nftnl.ExprCmp{SReg: nftnl.Reg1, Op: nftnl.CmpEq, Data: &nftnl.ExprData{Value: ipv6Saddr1[:]}},
			&nftnl.ExprImmediate{DReg: nftnl.RegVerdict, Data: &nftnl.ExprData{Verdict: &nftnl.ExprVerdict{Code: nftnl.VerdictAccept}}},
		},
		// ip6 saddr 2001:db8::/32 accept
		{
			&nftnl.ExprMeta{Key: nftnl.MetaKeyNFProto, DReg: new(nftnl.Reg1)},
			&nftnl.ExprCmp{SReg: nftnl.Reg1, Op: nftnl.CmpEq, Data: &nftnl.ExprData{Value: []byte{nftnl.FamilyIPv6}}},
			&nftnl.ExprPayload{Base: nftnl.PayloadBaseNetwork, Offset: 8, Len: 16, DReg: new(nftnl.Reg1)},
			&nftnl.ExprBitwise{
				SReg: nftnl.Reg1, DReg: nftnl.Reg1, Len: 16,
				Mask: &nftnl.ExprData{Value: net.CIDRMask(32, 128)},
				Xor:  &nftnl.ExprData{Value: make([]byte, 16)},
			},
			&nftnl.ExprCmp{SReg: nftnl.Reg1, Op: nftnl.CmpEq, Data: &nftnl.ExprData{Value: ipv6Saddr2001[:]}},
			&nftnl.ExprImmediate{DReg: nftnl.RegVerdict, Data: &nftnl.ExprData{Verdict: &nftnl.ExprVerdict{Code: nftnl.VerdictAccept}}},
		},
	}
	want := `
table inet test {
	set test_set {
		type ipv4_addr
		flags interval
		elements = { 172.16.0.0/12, 192.168.1.0/24 }
	}

	chain input {
		type filter hook input priority filter; policy accept;
		iifname "lo" accept
		ip protocol tcp tcp dport 80 accept
		ct state established,related accept
		ip saddr @test_set accept
		log prefix "drop: " drop
		ip daddr 127.0.0.1 drop
		ip saddr 10.0.0.0/8 accept
		ip6 saddr ::1 accept
		ip6 saddr 2001:db8::/32 accept
	}
}`
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
			Name:    new("test_set"),
			KeyType: new(nftnl.DataTypeIPAddr),
			KeyLen:  new(uint32(4)),
			Flags:   new(nftnl.SetInterval),
		},
	})
	batch.Add(nftnl.Msg{
		Type:   nftnl.MsgNewSetElem,
		Family: nftnl.FamilyInet,
		Flags:  netlink.Request | netlink.Create,
		Attrs: &nftnl.SetElemList{
			Table: "test",
			Set:   new("test_set"),
			SetID: new(uint32(1)),
			Elements: []nftnl.SetElem{
				// 172.16.0.0/12
				{Key: &nftnl.ExprData{Value: addr4("172.16.0.0")}},
				{Key: &nftnl.ExprData{Value: addr4("172.32.0.0")}, Flags: new(nftnl.SetElemIntervalEnd)},
				// 192.168.1.0/24
				{Key: &nftnl.ExprData{Value: addr4("192.168.1.0")}},
				{Key: &nftnl.ExprData{Value: addr4("192.168.2.0")}, Flags: new(nftnl.SetElemIntervalEnd)},
			},
		},
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

	for _, exprs := range rules {
		batch.Add(nftnl.Msg{
			Type:   nftnl.MsgNewRule,
			Family: nftnl.FamilyInet,
			Flags:  netlink.Request | netlink.Create | netlink.Append,
			Attrs: &nftnl.Rule{
				Table:       "test",
				Chain:       new("input"),
				Expressions: exprs,
			},
		})
	}

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
	if len(msgs) != len(rules) {
		t.Fatalf("expected %d rules, got %d", len(rules), len(msgs))
	}

	AssertRuleset(t, want)
}
