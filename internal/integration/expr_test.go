package integration_test

import (
	"net/netip"
	"testing"

	"github.com/mdlayher/netlink"
	"github.com/nickgarlis/nftnl"
	"github.com/nickgarlis/nftnl/util"
	"golang.org/x/sys/unix"
)

func addr4(s string) []byte { b := netip.MustParseAddr(s).As4(); return b[:] }

func TestExpressions(t *testing.T) {
	rules := [][]nftnl.Expr{
		util.Exprs(util.IIFName("lo"), util.Accept()),
		util.Exprs(util.NFProtoIPv4(), util.IPv4Proto(unix.IPPROTO_TCP), util.TCPDport(80), util.Accept()),
		util.Exprs(util.CTState(nftnl.CTStateEstablished|nftnl.CTStateRelated), util.Accept()),
		util.Exprs(util.NFProtoIPv4(), util.IPv4SaddrInSet("test_set", 1), util.Accept()),
		util.Exprs(util.Log("drop: "), util.Drop()),
		util.Exprs(util.NFProtoIPv4(), util.IPv4Daddr(netip.MustParseAddr("127.0.0.1")), util.Drop()),
		util.Exprs(util.NFProtoIPv4(), util.IPv4SaddrPrefix(netip.MustParsePrefix("10.0.0.0/8")), util.Accept()),
		util.Exprs(util.NFProtoIPv6(), util.IPv6Saddr(netip.MustParseAddr("::1")), util.Accept()),
		util.Exprs(util.NFProtoIPv6(), util.IPv6SaddrPrefix(netip.MustParsePrefix("2001:db8::/32")), util.Accept()),
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
