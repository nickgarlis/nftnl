package integration_test

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/mdlayher/netlink"
	"github.com/nickgarlis/nftnl"
)

func TestObj(t *testing.T) {
	conn, _, closer := OpenSystemConn(t)
	defer closer()

	batch := nftnl.NewBatch()
	batch.Add(nftnl.Msg{
		Type:   nftnl.MsgNewTable,
		Family: nftnl.FamilyInet,
		Flags:  netlink.Request,
		Attrs:  &nftnl.Table{Name: "test"},
	})

	obj := nftnl.Obj{
		Table: "test",
		Name:  "mycounter",
		Data:  &nftnl.ObjCounter{},
	}
	obj.UserData.SetString(nftnl.RuleUDComment, "test counter")

	batch.Add(nftnl.Msg{
		Type:   nftnl.MsgNewObj,
		Family: nftnl.FamilyInet,
		Flags:  netlink.Request | netlink.Create,
		Attrs:  &obj,
	})
	if _, err := conn.SendBatch(batch); err != nil {
		t.Fatalf("create obj: %v", err)
	}

	msgs, err := conn.Send(nftnl.Msg{
		Type:   nftnl.MsgGetObj,
		Family: nftnl.FamilyInet,
		Flags:  netlink.Request | netlink.Dump,
		Attrs:  &nftnl.Obj{Table: "test"},
	})
	if err != nil {
		t.Fatalf("get objs: %v", err)
	}
	if len(msgs) != 1 {
		t.Fatalf("expected 1 obj, got %d", len(msgs))
	}
	attrs, ok := nftnl.As[*nftnl.Obj](msgs[0].Attrs)
	if !ok {
		t.Fatalf("expected *ObjAttrs, got %T", msgs[0].Attrs)
	}
	if diff := cmp.Diff("mycounter", attrs.Name); diff != "" {
		t.Errorf("obj name mismatch (-want +got):\n%s", diff)
	}
	if _, ok := attrs.Data.(*nftnl.ObjCounter); !ok {
		t.Errorf("expected *ObjCounter, got %T", attrs.Data)
	}

	gotComment, ok := attrs.UserData.GetString(nftnl.RuleUDComment)
	if !ok {
		t.Fatal("obj has no comment in userdata")
	}
	if diff := cmp.Diff("test counter", gotComment); diff != "" {
		t.Errorf("obj comment mismatch (-want +got):\n%s", diff)
	}

	AssertRuleset(t, `
table inet test {
	counter mycounter {
		comment "test counter"
		packets 0 bytes 0
	}
}`)

	msgs, err = conn.Send(nftnl.Msg{
		Type:   nftnl.MsgGetObjReset,
		Family: nftnl.FamilyInet,
		Flags:  netlink.Request | netlink.Dump,
		Attrs:  &nftnl.Obj{Table: "test"},
	})
	if err != nil {
		t.Fatalf("get obj reset: %v", err)
	}
	if len(msgs) != 1 {
		t.Fatalf("expected 1 obj from reset, got %d", len(msgs))
	}
	resetAttrs, ok := nftnl.As[*nftnl.Obj](msgs[0].Attrs)
	if !ok {
		t.Fatalf("expected *ObjAttrs, got %T", msgs[0].Attrs)
	}
	counter, ok := resetAttrs.Data.(*nftnl.ObjCounter)
	if !ok {
		t.Fatalf("expected *ObjCounter after reset, got %T", resetAttrs.Data)
	}
	if diff := cmp.Diff(&nftnl.ObjCounter{}, counter); diff != "" {
		t.Errorf("counter mismatch after reset (-want +got):\n%s", diff)
	}

	del := nftnl.NewBatch()
	del.Add(nftnl.Msg{
		Type:   nftnl.MsgDelObj,
		Family: nftnl.FamilyInet,
		Flags:  netlink.Request,
		// Data is required: objects are keyed by name+type, so the kernel
		// needs NFTA_OBJ_TYPE to locate the right one.
		Attrs: &nftnl.Obj{Table: "test", Name: "mycounter", Data: &nftnl.ObjCounter{}},
	})
	if _, err := conn.SendBatch(del); err != nil {
		t.Fatalf("delete obj: %v", err)
	}
	msgs, err = conn.Send(nftnl.Msg{
		Type:   nftnl.MsgGetObj,
		Family: nftnl.FamilyInet,
		Flags:  netlink.Request | netlink.Dump,
		Attrs:  &nftnl.Obj{Table: "test"},
	})
	if err != nil {
		t.Fatalf("get objs after delete: %v", err)
	}
	if len(msgs) != 0 {
		t.Errorf("expected 0 objs after delete, got %d", len(msgs))
	}

	destroy := nftnl.NewBatch()
	destroy.Add(nftnl.Msg{
		Type:   nftnl.MsgDestroyObj,
		Family: nftnl.FamilyInet,
		Flags:  netlink.Request,
		Attrs:  &nftnl.Obj{Table: "test", Name: "mycounter", Data: &nftnl.ObjCounter{}},
	})
	if _, err := conn.SendBatch(destroy); err != nil {
		t.Fatalf("destroy obj (idempotent): %v", err)
	}
}
