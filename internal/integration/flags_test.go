package integration_test

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/mdlayher/netlink"
	"github.com/nickgarlis/nftnl"
)

func TestFlags(t *testing.T) {
	t.Run("Echo", func(t *testing.T) {
		conn, _, closer := OpenSystemConn(t)
		defer closer()

		batch := nftnl.NewBatch()
		batch.Add(nftnl.Msg{
			Type:   nftnl.MsgNewTable,
			Family: nftnl.FamilyInet,
			Flags:  netlink.Request | netlink.Create | netlink.Echo,
			Attrs:  &nftnl.Table{Name: "test"},
		})
		msgs, err := conn.SendBatch(batch)
		if err != nil {
			t.Fatalf("create table with echo: %v", err)
		}
		// echoed MsgNewTable + MsgNewGen notification
		if len(msgs) != 2 {
			t.Fatalf("expected 2 messages, got %d", len(msgs))
		}
		attrs, ok := nftnl.As[*nftnl.Table](msgs[0].Attrs)
		if !ok {
			t.Fatalf("msgs[0]: expected *TableAttrs, got %T", msgs[0].Attrs)
		}
		if diff := cmp.Diff("test", attrs.Name); diff != "" {
			t.Errorf("echoed table name mismatch (-want +got):\n%s", diff)
		}
		if attrs.Handle == nil {
			t.Error("echoed table missing kernel-assigned handle")
		}
		if diff := cmp.Diff(nftnl.MsgNewGen, msgs[1].Type); diff != "" {
			t.Errorf("msgs[1] type mismatch (-want +got):\n%s", diff)
		}
	})

	t.Run("Acknowledge", func(t *testing.T) {
		conn, _, closer := OpenSystemConn(t)
		defer closer()

		setup := nftnl.NewBatch()
		setup.Add(nftnl.Msg{
			Type:   nftnl.MsgNewTable,
			Family: nftnl.FamilyInet,
			Flags:  netlink.Request | netlink.Create | netlink.Acknowledge,
			Attrs:  &nftnl.Table{Name: "test"},
		})
		if _, err := conn.SendBatch(setup); err != nil {
			t.Fatalf("create table: %v", err)
		}

		msgs, err := conn.Send(nftnl.Msg{
			Type:   nftnl.MsgGetTable,
			Family: nftnl.FamilyInet,
			Flags:  netlink.Request | netlink.Dump | netlink.Acknowledge,
			Attrs:  &nftnl.Table{},
		})
		if err != nil {
			t.Fatalf("get tables with ack: %v", err)
		}
		// NLMSG_ERROR(0) is filtered — same result as without Acknowledge
		if len(msgs) != 1 {
			t.Fatalf("expected 1 table, got %d", len(msgs))
		}
		attrs, ok := nftnl.As[*nftnl.Table](msgs[0].Attrs)
		if !ok {
			t.Fatalf("expected *TableAttrs, got %T", msgs[0].Attrs)
		}
		if diff := cmp.Diff("test", attrs.Name); diff != "" {
			t.Errorf("table name mismatch (-want +got):\n%s", diff)
		}
	})

	t.Run("EchoAndAcknowledge", func(t *testing.T) {
		conn, _, closer := OpenSystemConn(t)
		defer closer()

		batch := nftnl.NewBatch()
		batch.Add(nftnl.Msg{
			Type:   nftnl.MsgNewTable,
			Family: nftnl.FamilyInet,
			Flags:  netlink.Request | netlink.Create | netlink.Echo | netlink.Acknowledge,
			Attrs:  &nftnl.Table{Name: "test"},
		})
		msgs, err := conn.SendBatch(batch)
		if err != nil {
			t.Fatalf("create table with echo+ack: %v", err)
		}
		if len(msgs) != 2 {
			t.Fatalf("expected 2 messages, got %d", len(msgs))
		}
		attrs, ok := nftnl.As[*nftnl.Table](msgs[0].Attrs)
		if !ok {
			t.Fatalf("msgs[0]: expected *TableAttrs, got %T", msgs[0].Attrs)
		}
		if attrs.Handle == nil {
			t.Error("echoed table missing kernel-assigned handle")
		}
		if diff := cmp.Diff(nftnl.MsgNewGen, msgs[1].Type); diff != "" {
			t.Errorf("msgs[1] type mismatch (-want +got):\n%s", diff)
		}
	})
}
