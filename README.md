# nftnl

[![PkgGoDev](https://img.shields.io/badge/-reference-blue?logo=go&logoColor=white&labelColor=505050)](https://pkg.go.dev/github.com/nickgarlis/nftnl)
[![GitHub](https://img.shields.io/github/license/nickgarlis/nftnl)](https://img.shields.io/github/license/nickgarlis/nftnl)
[![Go Report Card](https://goreportcard.com/badge/github.com/nickgarlis/nftnl)](https://goreportcard.com/report/github.com/nickgarlis/nftnl)

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
		Attrs:  &nftnl.Table{Name: new("mytable")},
	})
	batch.Add(nftnl.Msg{
		Type:   nftnl.MsgNewChain,
		Family: nftnl.FamilyInet,
		Flags:  netlink.Request | netlink.Create,
		Attrs: &nftnl.Chain{
			Table:  new("mytable"),
			Name:   new("input"),
			Type:   new("filter"),
			Hook:   &nftnl.Hook{HookNum: new(nftnl.HookLocalIn), Priority: new(nftnl.Priority(nftnl.PriorityFilter))},
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
			fmt.Println(*t.Name)
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
		Table:       new("mytable"),
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

## Helpers

Helpers are optional shorthand on top of the API: everything they return can
be written with the `nftnl` types directly. Each kind of object has its own
`<kind>util` package.

`nftnl/exprutil` builds common rule expressions:

```go
import "github.com/nickgarlis/nftnl/exprutil"

exprs := exprutil.Concat(
    exprutil.NFProtoIPv4(),
    exprutil.IPv4SaddrPrefix(netip.MustParsePrefix("10.0.0.0/8")),
    exprutil.Accept(),
)

exprs := exprutil.Concat(
    exprutil.CTState(nftnl.CTStateEstablished | nftnl.CTStateRelated),
    exprutil.Accept(),
)

exprs := exprutil.Concat(exprutil.IIFName("eth0"), exprutil.Drop())
```

`nftnl/setutil` builds sets, and `nftnl/setelemutil` the elements that go in
them:

```go
import (
    "github.com/nickgarlis/nftnl/setelemutil"
    "github.com/nickgarlis/nftnl/setutil"
)

set := setutil.IPv4Interval("filter", "allow", 1)

// Attrs is optional; its timeout is converted to the kernel's milliseconds.
elems, err := setelemutil.IPPrefix(netip.MustParsePrefix("10.0.0.0/8"),
    &setelemutil.Attrs{Comment: "office", Timeout: 24 * time.Hour})

// A range that runs to the top of its key space is sent as a start element
// alone; the kernel reads it as extending to the end.
elems, err := setelemutil.PortRange(60000, 65535, nil)
```

## Design

**One struct per object type.** The kernel uses the same attribute set for
new/get/delete operations on any given object. `Chain`, `Rule`, `Set`, etc.
work for creating, querying, and deleting alike.

**Every attribute field is nullable.** Presence has to be explicit: a field is
only included on the wire when it is non-nil. Which fields are required for a
given operation is for the caller to know.

## License

MIT, see [LICENSE](https://github.com/nickgarlis/nftnl/blob/main/LICENSE).
