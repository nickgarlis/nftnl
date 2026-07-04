package integration_test

import (
	"net"
	"sort"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/mdlayher/netlink"
	"github.com/nickgarlis/nftnl"
)

func TestSetElem(t *testing.T) {
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

	wantIPs := []string{
		"10.0.0.1",
		"172.16.0.1",
		"192.168.1.1",
	}
	elems := make([]nftnl.SetElem, len(wantIPs))
	for i, s := range wantIPs {
		elems[i] = nftnl.SetElem{
			Key: &nftnl.ExprData{Value: net.ParseIP(s).To4()},
		}
	}
	batch.Add(nftnl.Msg{
		Type:   nftnl.MsgNewSetElem,
		Family: nftnl.FamilyInet,
		Flags:  netlink.Request,
		Attrs: &nftnl.SetElemList{
			Table:    "test",
			Set:      new("testset"),
			Elements: elems,
		},
	})
	if _, err := conn.SendBatch(batch); err != nil {
		t.Fatalf("create set and elements: %v", err)
	}

	msgs, err := conn.Send(nftnl.Msg{
		Type:   nftnl.MsgGetSetElem,
		Family: nftnl.FamilyInet,
		Flags:  netlink.Request | netlink.Dump,
		Attrs:  &nftnl.SetElemList{Table: "test", Set: new("testset")},
	})
	if err != nil {
		t.Fatalf("get set elements: %v", err)
	}

	var gotIPs []string
	for _, msg := range msgs {
		list, ok := nftnl.As[*nftnl.SetElemList](msg.Attrs)
		if !ok {
			t.Fatalf("expected *SetElemListAttrs, got %T", msg.Attrs)
		}
		for _, elem := range list.Elements {
			if elem.Key == nil {
				t.Error("element missing key")
				continue
			}
			gotIPs = append(gotIPs, net.IP(elem.Key.Value).String())
		}
	}
	sort.Strings(gotIPs)

	if diff := cmp.Diff(wantIPs, gotIPs); diff != "" {
		t.Errorf("set elements mismatch (-want +got):\n%s", diff)
	}

	msgs, err = conn.Send(nftnl.Msg{
		Type:   nftnl.MsgGetSetElemReset,
		Family: nftnl.FamilyInet,
		Flags:  netlink.Request | netlink.Dump,
		Attrs:  &nftnl.SetElemList{Table: "test", Set: new("testset")},
	})
	if err != nil {
		t.Fatalf("get set elem reset: %v", err)
	}
	var resetIPs []string
	for _, msg := range msgs {
		list, ok := nftnl.As[*nftnl.SetElemList](msg.Attrs)
		if !ok {
			t.Fatalf("expected *SetElemListAttrs, got %T", msg.Attrs)
		}
		for _, elem := range list.Elements {
			if elem.Key == nil {
				t.Error("element missing key after reset")
				continue
			}
			resetIPs = append(resetIPs, net.IP(elem.Key.Value).String())
		}
	}
	sort.Strings(resetIPs)
	if diff := cmp.Diff(wantIPs, resetIPs); diff != "" {
		t.Errorf("set elements after reset mismatch (-want +got):\n%s", diff)
	}

	del := nftnl.NewBatch()
	del.Add(nftnl.Msg{
		Type:   nftnl.MsgDelSetElem,
		Family: nftnl.FamilyInet,
		Flags:  netlink.Request,
		Attrs: &nftnl.SetElemList{
			Table:    "test",
			Set:      new("testset"),
			Elements: elems,
		},
	})
	if _, err := conn.SendBatch(del); err != nil {
		t.Fatalf("delete set elements: %v", err)
	}
	msgs, err = conn.Send(nftnl.Msg{
		Type:   nftnl.MsgGetSetElem,
		Family: nftnl.FamilyInet,
		Flags:  netlink.Request | netlink.Dump,
		Attrs:  &nftnl.SetElemList{Table: "test", Set: new("testset")},
	})
	if err != nil {
		t.Fatalf("get elements after delete: %v", err)
	}
	var remaining int
	for _, msg := range msgs {
		if list, ok := nftnl.As[*nftnl.SetElemList](msg.Attrs); ok {
			remaining += len(list.Elements)
		}
	}
	if remaining != 0 {
		t.Errorf("expected 0 elements after delete, got %d", remaining)
	}

	destroy := nftnl.NewBatch()
	destroy.Add(nftnl.Msg{
		Type:   nftnl.MsgDestroySetElem,
		Family: nftnl.FamilyInet,
		Flags:  netlink.Request,
		Attrs: &nftnl.SetElemList{
			Table:    "test",
			Set:      new("testset"),
			Elements: elems,
		},
	})
	if _, err := conn.SendBatch(destroy); err != nil {
		t.Fatalf("destroy set elements (idempotent): %v", err)
	}
}
