package integration_test

import (
	"net/netip"
	"testing"

	"github.com/mdlayher/netlink"
	"github.com/nickgarlis/nftnl"
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

func addIntervalSet(t *testing.T, set nftnl.Set, elems []nftnl.SetElem) {
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
		addIntervalSet(t, setutil.IPv4Interval("test", "v4", 1),
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
		addIntervalSet(t, setutil.IPv6Interval("test", "v6", 1),
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
		addIntervalSet(t, setutil.PortInterval("test", "ports", 1),
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
