// Package util provides helper functions for working with nftables expressions,
// addresses, and other common constructs.
package util

import (
	"net"
	"net/netip"

	"github.com/nickgarlis/nftnl"
)

// Exprs concatenates expression slices into a single []nftnl.Expr.
func Exprs(parts ...[]nftnl.Expr) []nftnl.Expr {
	var out []nftnl.Expr
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

// Accept returns a verdict accept expression.
func Accept() []nftnl.Expr {
	return []nftnl.Expr{
		&nftnl.ExprImmediate{DReg: nftnl.RegVerdict, Data: &nftnl.ExprData{Verdict: &nftnl.ExprVerdict{Code: nftnl.VerdictAccept}}},
	}
}

// Drop returns a verdict drop expression.
func Drop() []nftnl.Expr {
	return []nftnl.Expr{
		&nftnl.ExprImmediate{DReg: nftnl.RegVerdict, Data: &nftnl.ExprData{Verdict: &nftnl.ExprVerdict{Code: nftnl.VerdictDrop}}},
	}
}

// Log returns a log expression with the given prefix.
func Log(prefix string) []nftnl.Expr {
	return []nftnl.Expr{&nftnl.ExprLog{Prefix: prefix}}
}

// IIFName matches the input interface name (padded to IFNAMSIZ).
func IIFName(name string) []nftnl.Expr {
	b := make([]byte, 16)
	copy(b, name)
	return []nftnl.Expr{
		&nftnl.ExprMeta{Key: nftnl.MetaKeyIIFName, DReg: new(nftnl.Reg1)},
		&nftnl.ExprCmp{SReg: nftnl.Reg1, Op: nftnl.CmpEq, Data: &nftnl.ExprData{Value: b}},
	}
}

// OIFName matches the output interface name (padded to IFNAMSIZ).
func OIFName(name string) []nftnl.Expr {
	b := make([]byte, 16)
	copy(b, name)
	return []nftnl.Expr{
		&nftnl.ExprMeta{Key: nftnl.MetaKeyOIFName, DReg: new(nftnl.Reg1)},
		&nftnl.ExprCmp{SReg: nftnl.Reg1, Op: nftnl.CmpEq, Data: &nftnl.ExprData{Value: b}},
	}
}

// NFProtoIPv4 matches packets in an inet table as IPv4.
// Not needed in ip tables where the family is implicit.
func NFProtoIPv4() []nftnl.Expr {
	return []nftnl.Expr{
		&nftnl.ExprMeta{Key: nftnl.MetaKeyNFProto, DReg: new(nftnl.Reg1)},
		&nftnl.ExprCmp{SReg: nftnl.Reg1, Op: nftnl.CmpEq, Data: &nftnl.ExprData{Value: []byte{nftnl.FamilyIPv4}}},
	}
}

// NFProtoIPv6 matches packets in an inet table as IPv6.
// Not needed in ip6 tables where the family is implicit.
func NFProtoIPv6() []nftnl.Expr {
	return []nftnl.Expr{
		&nftnl.ExprMeta{Key: nftnl.MetaKeyNFProto, DReg: new(nftnl.Reg1)},
		&nftnl.ExprCmp{SReg: nftnl.Reg1, Op: nftnl.CmpEq, Data: &nftnl.ExprData{Value: []byte{nftnl.FamilyIPv6}}},
	}
}

// IPv4Proto matches the IPv4 network-layer protocol field (offset 9).
func IPv4Proto(proto uint8) []nftnl.Expr {
	return []nftnl.Expr{
		&nftnl.ExprPayload{Base: nftnl.PayloadBaseNetwork, Offset: 9, Len: 1, DReg: new(nftnl.Reg1)},
		&nftnl.ExprCmp{SReg: nftnl.Reg1, Op: nftnl.CmpEq, Data: &nftnl.ExprData{Value: []byte{proto}}},
	}
}

// IPv6Proto matches the IPv6 Next Header field (offset 6).
func IPv6Proto(proto uint8) []nftnl.Expr {
	return []nftnl.Expr{
		&nftnl.ExprPayload{Base: nftnl.PayloadBaseNetwork, Offset: 6, Len: 1, DReg: new(nftnl.Reg1)},
		&nftnl.ExprCmp{SReg: nftnl.Reg1, Op: nftnl.CmpEq, Data: &nftnl.ExprData{Value: []byte{proto}}},
	}
}

// SPort matches the L4 source port (transport-layer offset 0, big-endian).
// Works for TCP, UDP, and any protocol that places sport at offset 0.
func SPort(port uint16) []nftnl.Expr {
	return []nftnl.Expr{
		&nftnl.ExprPayload{Base: nftnl.PayloadBaseTransport, Offset: 0, Len: 2, DReg: new(nftnl.Reg1)},
		&nftnl.ExprCmp{SReg: nftnl.Reg1, Op: nftnl.CmpEq, Data: &nftnl.ExprData{Value: []byte{byte(port >> 8), byte(port)}}},
	}
}

// DPort matches the L4 destination port (transport-layer offset 2, big-endian).
// Works for TCP, UDP, and any protocol that places dport at offset 2.
func DPort(port uint16) []nftnl.Expr {
	return []nftnl.Expr{
		&nftnl.ExprPayload{Base: nftnl.PayloadBaseTransport, Offset: 2, Len: 2, DReg: new(nftnl.Reg1)},
		&nftnl.ExprCmp{SReg: nftnl.Reg1, Op: nftnl.CmpEq, Data: &nftnl.ExprData{Value: []byte{byte(port >> 8), byte(port)}}},
	}
}

// SPortInSet matches the L4 source port against a named set.
// Pass setID when the set was created in the same batch (transaction-local ID).
func SPortInSet(name string, setID ...uint32) []nftnl.Expr {
	lookup := &nftnl.ExprLookup{SReg: nftnl.Reg1, Set: name}
	if len(setID) > 0 {
		id := setID[0]
		lookup.SetID = &id
	}
	return []nftnl.Expr{
		&nftnl.ExprPayload{Base: nftnl.PayloadBaseTransport, Offset: 0, Len: 2, DReg: new(nftnl.Reg1)},
		lookup,
	}
}

// DPortInSet matches the L4 destination port against a named set.
// Pass setID when the set was created in the same batch (transaction-local ID).
func DPortInSet(name string, setID ...uint32) []nftnl.Expr {
	lookup := &nftnl.ExprLookup{SReg: nftnl.Reg1, Set: name}
	if len(setID) > 0 {
		id := setID[0]
		lookup.SetID = &id
	}
	return []nftnl.Expr{
		&nftnl.ExprPayload{Base: nftnl.PayloadBaseTransport, Offset: 2, Len: 2, DReg: new(nftnl.Reg1)},
		lookup,
	}
}

// CTState matches conntrack state bits using a bitwise-AND mask.
func CTState(state nftnl.CTState) []nftnl.Expr {
	zero := []byte{0, 0, 0, 0}
	return []nftnl.Expr{
		&nftnl.ExprCt{Key: nftnl.CTKeyState, DReg: new(nftnl.Reg1)},
		&nftnl.ExprBitwise{
			SReg: nftnl.Reg1, DReg: nftnl.Reg1, Len: 4,
			Mask: &nftnl.ExprData{Value: state.Bytes()},
			Xor:  &nftnl.ExprData{Value: zero},
		},
		&nftnl.ExprCmp{SReg: nftnl.Reg1, Op: nftnl.CmpNeq, Data: &nftnl.ExprData{Value: zero}},
	}
}

// IPv4Saddr matches an exact IPv4 source address.
func IPv4Saddr(addr netip.Addr) []nftnl.Expr {
	b := addr.As4()
	return []nftnl.Expr{
		&nftnl.ExprPayload{Base: nftnl.PayloadBaseNetwork, Offset: 12, Len: 4, DReg: new(nftnl.Reg1)},
		&nftnl.ExprCmp{SReg: nftnl.Reg1, Op: nftnl.CmpEq, Data: &nftnl.ExprData{Value: b[:]}},
	}
}

// IPv4SaddrPrefix matches an IPv4 source address against a CIDR prefix.
func IPv4SaddrPrefix(p netip.Prefix) []nftnl.Expr {
	b := p.Masked().Addr().As4()
	return []nftnl.Expr{
		&nftnl.ExprPayload{Base: nftnl.PayloadBaseNetwork, Offset: 12, Len: 4, DReg: new(nftnl.Reg1)},
		&nftnl.ExprBitwise{
			SReg: nftnl.Reg1, DReg: nftnl.Reg1, Len: 4,
			Mask: &nftnl.ExprData{Value: net.CIDRMask(p.Bits(), 32)},
			Xor:  &nftnl.ExprData{Value: []byte{0, 0, 0, 0}},
		},
		&nftnl.ExprCmp{SReg: nftnl.Reg1, Op: nftnl.CmpEq, Data: &nftnl.ExprData{Value: b[:]}},
	}
}

// IPv4Daddr matches an exact IPv4 destination address.
func IPv4Daddr(addr netip.Addr) []nftnl.Expr {
	b := addr.As4()
	return []nftnl.Expr{
		&nftnl.ExprPayload{Base: nftnl.PayloadBaseNetwork, Offset: 16, Len: 4, DReg: new(nftnl.Reg1)},
		&nftnl.ExprCmp{SReg: nftnl.Reg1, Op: nftnl.CmpEq, Data: &nftnl.ExprData{Value: b[:]}},
	}
}

// IPv4SaddrInSet matches the IPv4 source address against a named set.
// Pass setID when the set was created in the same batch (transaction-local ID).
func IPv4SaddrInSet(name string, setID ...uint32) []nftnl.Expr {
	lookup := &nftnl.ExprLookup{SReg: nftnl.Reg1, Set: name}
	if len(setID) > 0 {
		id := setID[0]
		lookup.SetID = &id
	}
	return []nftnl.Expr{
		&nftnl.ExprPayload{Base: nftnl.PayloadBaseNetwork, Offset: 12, Len: 4, DReg: new(nftnl.Reg1)},
		lookup,
	}
}

// IPv6Saddr matches an exact IPv6 source address.
func IPv6Saddr(addr netip.Addr) []nftnl.Expr {
	b := addr.As16()
	return []nftnl.Expr{
		&nftnl.ExprPayload{Base: nftnl.PayloadBaseNetwork, Offset: 8, Len: 16, DReg: new(nftnl.Reg1)},
		&nftnl.ExprCmp{SReg: nftnl.Reg1, Op: nftnl.CmpEq, Data: &nftnl.ExprData{Value: b[:]}},
	}
}

// IPv6SaddrPrefix matches an IPv6 source address against a CIDR prefix.
func IPv6SaddrPrefix(p netip.Prefix) []nftnl.Expr {
	b := p.Masked().Addr().As16()
	return []nftnl.Expr{
		&nftnl.ExprPayload{Base: nftnl.PayloadBaseNetwork, Offset: 8, Len: 16, DReg: new(nftnl.Reg1)},
		&nftnl.ExprBitwise{
			SReg: nftnl.Reg1, DReg: nftnl.Reg1, Len: 16,
			Mask: &nftnl.ExprData{Value: net.CIDRMask(p.Bits(), 128)},
			Xor:  &nftnl.ExprData{Value: make([]byte, 16)},
		},
		&nftnl.ExprCmp{SReg: nftnl.Reg1, Op: nftnl.CmpEq, Data: &nftnl.ExprData{Value: b[:]}},
	}
}

// IPv6Daddr matches an exact IPv6 destination address.
func IPv6Daddr(addr netip.Addr) []nftnl.Expr {
	b := addr.As16()
	return []nftnl.Expr{
		&nftnl.ExprPayload{Base: nftnl.PayloadBaseNetwork, Offset: 24, Len: 16, DReg: new(nftnl.Reg1)},
		&nftnl.ExprCmp{SReg: nftnl.Reg1, Op: nftnl.CmpEq, Data: &nftnl.ExprData{Value: b[:]}},
	}
}

// IPv6SaddrInSet matches the IPv6 source address against a named set.
// Pass setID when the set was created in the same batch (transaction-local ID).
func IPv6SaddrInSet(name string, setID ...uint32) []nftnl.Expr {
	lookup := &nftnl.ExprLookup{SReg: nftnl.Reg1, Set: name}
	if len(setID) > 0 {
		id := setID[0]
		lookup.SetID = &id
	}
	return []nftnl.Expr{
		&nftnl.ExprPayload{Base: nftnl.PayloadBaseNetwork, Offset: 8, Len: 16, DReg: new(nftnl.Reg1)},
		lookup,
	}
}
