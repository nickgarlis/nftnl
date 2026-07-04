# nftnl

A low-level Go library for interacting with [nftables](https://nftables.org) via
netlink. It can be used directly or as a building block for higher-level
libraries.

## Example

The following builds this ruleset and queries the tables back:

```
table inet mytable {
    chain input {
        type filter hook input priority filter; policy accept;
    }
}
```

```go
package main

import (
	"fmt"

	"github.com/mdlayher/netlink"
	"github.com/nickgarlis/nftnl"
)

func main() {
	conn, err := nftnl.Open(&nftnl.Config{})
	if err != nil {
		panic(err)
	}
	defer conn.Close()

	batch := nftnl.NewBatch()
	batch.Add(nftnl.Msg{
		Type:   nftnl.MsgNewTable,
		Family: nftnl.FamilyInet,
		Flags:  netlink.Request | netlink.Create,
		Attrs:  &nftnl.Table{Name: "mytable"},
	})
	batch.Add(nftnl.Msg{
		Type:   nftnl.MsgNewChain,
		Family: nftnl.FamilyInet,
		Flags:  netlink.Request | netlink.Create,
		Attrs: &nftnl.Chain{
			Table:  "mytable",
			Name:   "input",
			Type:   "filter",
			Hook:   &nftnl.Hook{HookNum: nftnl.HookLocalIn, Priority: nftnl.PriorityFilter},
			Policy: new(nftnl.ChainPolicyAccept),
		},
	})
	if _, err := conn.SendBatch(batch); err != nil {
		panic(err)
	}

	// Read back all tables.
	msgs, err := conn.Send(nftnl.Msg{
		Type:   nftnl.MsgGetTable,
		Family: nftnl.FamilyInet,
		Flags:  netlink.Request | netlink.Dump,
	})
	if err != nil {
		panic(err)
	}
	for _, msg := range msgs {
		if t, ok := nftnl.As[*nftnl.Table](msg.Attrs); ok {
			fmt.Println(t.Name)
		}
	}
}
```

## Flags

netlink flags go directly on each `Msg`. Use `netlink.Echo` to get the committed
object back in the response, useful when you need the kernel-assigned handle
without a separate get query:

```go
msgs, err := conn.Send(nftnl.Msg{
	Type:   nftnl.MsgNewRule,
	Family: nftnl.FamilyInet,
	Flags:  netlink.Request | netlink.Create | netlink.Append | netlink.Echo,
	Attrs: &nftnl.Rule{
		Table:       "mytable",
		Chain:       new("input"),
		Expressions: []nftnl.Expr{ /* ... */ },
	},
})
if err != nil {
	panic(err)
}
// The response contains the committed rule with its kernel-assigned handle.
if rule, ok := nftnl.As[*nftnl.Rule](msgs[0].Attrs); ok {
	// Use rule.Handle to insert another rule after this one via Position.
	fmt.Println("handle:", *rule.Handle)
}
```

## Design

**One struct per object type.** The kernel uses the same attribute set for
new/get/delete operations on any given object. `Chain`, `Rule`, `Set`, etc.
work for creating, querying, and deleting alike.

**Pointer fields mean optional.** A `*T` field is sent only when set. A plain
`T` field is always sent. Which fields are required for a given operation is
for the caller to know. When in doubt, check `nf_tables.h`.

## License

MIT, see [LICENSE](https://github.com/nickgarlis/nftnl/blob/main/LICENSE).
