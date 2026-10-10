package integration_test

import (
	"net/netip"
	"testing"

	"github.com/mdlayher/netlink"
	"github.com/nickgarlis/nftnl"
	"github.com/nickgarlis/nftnl/exprutil"
	"github.com/nickgarlis/nftnl/setelemutil"
	"github.com/nickgarlis/nftnl/setutil"
)

func TestIntervalElems(t *testing.T) {
	t.Run("IPv4Prefix", func(t *testing.T) {
		conn, _, closer := OpenSystemConn(t)
		defer closer()

		set := setutil.IPv4Interval("test", "v4", 1)
		batch := nftnl.NewBatch()
		batch.Add(nftnl.Msg{
			Type:   nftnl.MsgNewTable,
			Family: nftnl.FamilyInet,
			Flags:  netlink.Request,
			Attrs:  &nftnl.Table{Name: new("test")},
		})
		batch.Add(nftnl.Msg{
			Type:   nftnl.MsgNewSet,
			Family: nftnl.FamilyInet,
			Flags:  netlink.Request | netlink.Create,
			Attrs:  &set,
		})
		batch.Add(nftnl.Msg{
			Type:   nftnl.MsgNewSetElem,
			Family: nftnl.FamilyInet,
			Flags:  netlink.Request | netlink.Create,
			Attrs: &nftnl.SetElemList{
				Table:    new("test"),
				Set:      new("v4"),
				Elements: mustElems(t)(setelemutil.IPPrefix(netip.MustParsePrefix("10.0.0.0/24"), nil)),
			},
		})
		if _, err := conn.SendBatch(batch); err != nil {
			t.Fatalf("SendBatch: %v", err)
		}

		AssertRuleset(t, `
table inet test {
	set v4 {
		type ipv4_addr
		flags interval
		elements = { 10.0.0.0/24 }
	}
}`)
	})

	t.Run("IPv4Range", func(t *testing.T) {
		conn, _, closer := OpenSystemConn(t)
		defer closer()

		set := setutil.IPv4Interval("test", "v4", 1)
		batch := nftnl.NewBatch()
		batch.Add(nftnl.Msg{
			Type:   nftnl.MsgNewTable,
			Family: nftnl.FamilyInet,
			Flags:  netlink.Request,
			Attrs:  &nftnl.Table{Name: new("test")},
		})
		batch.Add(nftnl.Msg{
			Type:   nftnl.MsgNewSet,
			Family: nftnl.FamilyInet,
			Flags:  netlink.Request | netlink.Create,
			Attrs:  &set,
		})
		elems, err := setelemutil.IPRange(netip.MustParseAddr("10.0.0.1"), netip.MustParseAddr("10.0.0.5"), nil)
		if err != nil {
			t.Fatalf("IPRange: %v", err)
		}
		batch.Add(nftnl.Msg{
			Type:   nftnl.MsgNewSetElem,
			Family: nftnl.FamilyInet,
			Flags:  netlink.Request | netlink.Create,
			Attrs:  &nftnl.SetElemList{Table: new("test"), Set: new("v4"), Elements: elems},
		})
		if _, err := conn.SendBatch(batch); err != nil {
			t.Fatalf("SendBatch: %v", err)
		}

		AssertRuleset(t, `
table inet test {
	set v4 {
		type ipv4_addr
		flags interval
		elements = { 10.0.0.1-10.0.0.5 }
	}
}`)
	})

	t.Run("IPv6Prefix", func(t *testing.T) {
		conn, _, closer := OpenSystemConn(t)
		defer closer()

		set := setutil.IPv6Interval("test", "v6", 1)
		batch := nftnl.NewBatch()
		batch.Add(nftnl.Msg{
			Type:   nftnl.MsgNewTable,
			Family: nftnl.FamilyInet,
			Flags:  netlink.Request,
			Attrs:  &nftnl.Table{Name: new("test")},
		})
		batch.Add(nftnl.Msg{
			Type:   nftnl.MsgNewSet,
			Family: nftnl.FamilyInet,
			Flags:  netlink.Request | netlink.Create,
			Attrs:  &set,
		})
		batch.Add(nftnl.Msg{
			Type:   nftnl.MsgNewSetElem,
			Family: nftnl.FamilyInet,
			Flags:  netlink.Request | netlink.Create,
			Attrs: &nftnl.SetElemList{
				Table:    new("test"),
				Set:      new("v6"),
				Elements: mustElems(t)(setelemutil.IPPrefix(netip.MustParsePrefix("2001:db8::/32"), nil)),
			},
		})
		if _, err := conn.SendBatch(batch); err != nil {
			t.Fatalf("SendBatch: %v", err)
		}

		AssertRuleset(t, `
table inet test {
	set v6 {
		type ipv6_addr
		flags interval
		elements = { 2001:db8::/32 }
	}
}`)
	})

	t.Run("PortRange", func(t *testing.T) {
		conn, _, closer := OpenSystemConn(t)
		defer closer()

		set := setutil.PortInterval("test", "ports", 1)
		batch := nftnl.NewBatch()
		batch.Add(nftnl.Msg{
			Type:   nftnl.MsgNewTable,
			Family: nftnl.FamilyInet,
			Flags:  netlink.Request,
			Attrs:  &nftnl.Table{Name: new("test")},
		})
		batch.Add(nftnl.Msg{
			Type:   nftnl.MsgNewSet,
			Family: nftnl.FamilyInet,
			Flags:  netlink.Request | netlink.Create,
			Attrs:  &set,
		})
		batch.Add(nftnl.Msg{
			Type:   nftnl.MsgNewSetElem,
			Family: nftnl.FamilyInet,
			Flags:  netlink.Request | netlink.Create,
			Attrs: &nftnl.SetElemList{
				Table:    new("test"),
				Set:      new("ports"),
				Elements: mustElems(t)(setelemutil.PortRange(80, 443, nil)),
			},
		})
		if _, err := conn.SendBatch(batch); err != nil {
			t.Fatalf("SendBatch: %v", err)
		}

		AssertRuleset(t, `
table inet test {
	set ports {
		type inet_service
		flags interval
		elements = { 80-443 }
	}
}`)
	})
}

func mustElems(t *testing.T) func([]nftnl.SetElem, error) []nftnl.SetElem {
	return func(elems []nftnl.SetElem, err error) []nftnl.SetElem {
		t.Helper()
		if err != nil {
			t.Fatalf("building elements: %v", err)
		}
		return elems
	}
}

func addSet(t *testing.T, set nftnl.Set, elems []nftnl.SetElem) {
	t.Helper()
	conn, _, closer := OpenSystemConn(t)
	t.Cleanup(closer)

	batch := nftnl.NewBatch()
	batch.Add(nftnl.Msg{
		Type:   nftnl.MsgNewTable,
		Family: nftnl.FamilyInet,
		Flags:  netlink.Request,
		Attrs:  &nftnl.Table{Name: new("test")},
	})
	batch.Add(nftnl.Msg{
		Type:   nftnl.MsgNewSet,
		Family: nftnl.FamilyInet,
		Flags:  netlink.Request | netlink.Create,
		Attrs:  &set,
	})
	batch.Add(nftnl.Msg{
		Type:   nftnl.MsgNewSetElem,
		Family: nftnl.FamilyInet,
		Flags:  netlink.Request | netlink.Create,
		Attrs:  &nftnl.SetElemList{Table: set.Table, Set: set.Name, Elements: elems},
	})
	if _, err := conn.SendBatch(batch); err != nil {
		t.Fatalf("SendBatch: %v", err)
	}
}

// Ranges ending at the top of the key space are sent without an end element.
func TestIntervalElemsToTheTop(t *testing.T) {
	t.Run("IPv4", func(t *testing.T) {
		addSet(t, setutil.IPv4Interval("test", "v4", 1),
			mustElems(t)(setelemutil.IPPrefix(netip.MustParsePrefix("240.0.0.0/4"), nil)))

		AssertRuleset(t, `
table inet test {
	set v4 {
		type ipv4_addr
		flags interval
		elements = { 240.0.0.0/4 }
	}
}`)
	})

	t.Run("IPv6", func(t *testing.T) {
		addSet(t, setutil.IPv6Interval("test", "v6", 1),
			mustElems(t)(setelemutil.IPPrefix(netip.MustParsePrefix("ff00::/8"), nil)))

		AssertRuleset(t, `
table inet test {
	set v6 {
		type ipv6_addr
		flags interval
		elements = { ff00::/8 }
	}
}`)
	})

	t.Run("Ports", func(t *testing.T) {
		addSet(t, setutil.PortInterval("test", "ports", 1),
			mustElems(t)(setelemutil.PortRange(60000, 65535, nil)))

		AssertRuleset(t, `
table inet test {
	set ports {
		type inet_service
		flags interval
		elements = { 60000-65535 }
	}
}`)
	})
}

func TestAnonSetHelpers(t *testing.T) {
	for _, tt := range []struct {
		name  string
		set   nftnl.Set
		elems []nftnl.SetElem
		proto []nftnl.Expr // nfproto guard for ip/ip6 matches in an inet table
		match func(name string, setID ...uint32) []nftnl.Expr
		want  string
	}{
		{
			name: "Port",
			set:  setutil.AnonPort("test", 1),
			elems: []nftnl.SetElem{
				{Key: &nftnl.ExprData{Value: []byte{0x00, 0x50}}},
				{Key: &nftnl.ExprData{Value: []byte{0x01, 0xbb}}},
			},
			match: exprutil.DPortInSet,
			want:  "th dport { 80, 443 } accept",
		},
		{
			name: "IPv4",
			set:  setutil.AnonIPv4("test", 1),
			elems: []nftnl.SetElem{
				{Key: &nftnl.ExprData{Value: []byte{10, 0, 0, 1}}},
				{Key: &nftnl.ExprData{Value: []byte{10, 0, 0, 2}}},
			},
			proto: exprutil.NFProtoIPv4(),
			match: exprutil.IPv4SaddrInSet,
			want:  "ip saddr { 10.0.0.1, 10.0.0.2 } accept",
		},
		{
			name: "IPv6",
			set:  setutil.AnonIPv6("test", 1),
			elems: []nftnl.SetElem{
				{Key: &nftnl.ExprData{Value: netip.MustParseAddr("2001:db8::1").AsSlice()}},
			},
			proto: exprutil.NFProtoIPv6(),
			match: exprutil.IPv6SaddrInSet,
			want:  "ip6 saddr { 2001:db8::1 } accept",
		},
		{
			name:  "PortInterval",
			set:   setutil.AnonPortInterval("test", 1),
			elems: mustElems(t)(setelemutil.PortRange(1000, 2000, nil)),
			match: exprutil.DPortInSet,
			want:  "th dport { 1000-2000 } accept",
		},
		{
			name:  "IPv4Interval",
			set:   setutil.AnonIPv4Interval("test", 1),
			elems: mustElems(t)(setelemutil.IPPrefix(netip.MustParsePrefix("10.0.0.0/24"), nil)),
			proto: exprutil.NFProtoIPv4(),
			match: exprutil.IPv4SaddrInSet,
			want:  "ip saddr { 10.0.0.0/24 } accept",
		},
		{
			name:  "IPv6Interval",
			set:   setutil.AnonIPv6Interval("test", 1),
			elems: mustElems(t)(setelemutil.IPPrefix(netip.MustParsePrefix("2001:db8::/32"), nil)),
			proto: exprutil.NFProtoIPv6(),
			match: exprutil.IPv6SaddrInSet,
			want:  "ip6 saddr { 2001:db8::/32 } accept",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			conn, _, closer := OpenSystemConn(t)
			defer closer()

			batch := nftnl.NewBatch()
			batch.Add(nftnl.Msg{
				Type:   nftnl.MsgNewTable,
				Family: nftnl.FamilyInet,
				Flags:  netlink.Request,
				Attrs:  &nftnl.Table{Name: new("test")},
			})
			batch.Add(nftnl.Msg{
				Type:   nftnl.MsgNewChain,
				Family: nftnl.FamilyInet,
				Flags:  netlink.Request | netlink.Create,
				Attrs:  &nftnl.Chain{Table: new("test"), Name: new("input")},
			})
			batch.Add(nftnl.Msg{
				Type:   nftnl.MsgNewSet,
				Family: nftnl.FamilyInet,
				Flags:  netlink.Request | netlink.Create,
				Attrs:  &tt.set,
			})
			batch.Add(nftnl.Msg{
				Type:   nftnl.MsgNewSetElem,
				Family: nftnl.FamilyInet,
				Flags:  netlink.Request | netlink.Create,
				Attrs:  &nftnl.SetElemList{Table: tt.set.Table, Set: tt.set.Name, SetID: tt.set.ID, Elements: tt.elems},
			})
			batch.Add(nftnl.Msg{
				Type:   nftnl.MsgNewRule,
				Family: nftnl.FamilyInet,
				Flags:  netlink.Request | netlink.Create,
				Attrs: &nftnl.Rule{
					Table:       new("test"),
					Chain:       new("input"),
					Expressions: exprutil.Concat(tt.proto, tt.match(*tt.set.Name, *tt.set.ID), exprutil.Accept()),
				},
			})
			if _, err := conn.SendBatch(batch); err != nil {
				t.Fatalf("SendBatch: %v", err)
			}

			AssertRuleset(t, `
table inet test {
	chain input {
		`+tt.want+`
	}
}`)
		})
	}
}

func TestNamedSetHelpers(t *testing.T) {
	t.Run("IPv4", func(t *testing.T) {
		addSet(t, setutil.IPv4("test", "v4", 1), []nftnl.SetElem{
			{Key: &nftnl.ExprData{Value: []byte{10, 0, 0, 1}}},
			{Key: &nftnl.ExprData{Value: []byte{10, 0, 0, 2}}},
		})

		AssertRuleset(t, `
table inet test {
	set v4 {
		type ipv4_addr
		elements = { 10.0.0.1, 10.0.0.2 }
	}
}`)
	})

	t.Run("IPv6", func(t *testing.T) {
		addSet(t, setutil.IPv6("test", "v6", 1), []nftnl.SetElem{
			{Key: &nftnl.ExprData{Value: netip.MustParseAddr("2001:db8::1").AsSlice()}},
		})

		AssertRuleset(t, `
table inet test {
	set v6 {
		type ipv6_addr
		elements = { 2001:db8::1 }
	}
}`)
	})

	t.Run("Port", func(t *testing.T) {
		addSet(t, setutil.Port("test", "ports", 1), []nftnl.SetElem{
			{Key: &nftnl.ExprData{Value: []byte{0x00, 0x50}}},
			{Key: &nftnl.ExprData{Value: []byte{0x01, 0xbb}}},
		})

		AssertRuleset(t, `
table inet test {
	set ports {
		type inet_service
		elements = { 80, 443 }
	}
}`)
	})
}
