// Package setutil provides shorthand for building common nftnl.Set values.
// Each set's id must be unique within its batch.
package setutil

import (
	"github.com/nickgarlis/nftnl"
)

var keyLens = map[nftnl.DataType]uint32{
	nftnl.DataTypeIPAddr:      4,
	nftnl.DataTypeIP6Addr:     16,
	nftnl.DataTypeInetService: 2,
}

// IPv4 returns a nftnl.Set pre-configured for an IPv4 address set.
func IPv4(table, name string, id uint32) nftnl.Set {
	return newSet(table, name, id, 0, nftnl.DataTypeIPAddr)
}

// IPv6 returns a nftnl.Set pre-configured for an IPv6 address set.
func IPv6(table, name string, id uint32) nftnl.Set {
	return newSet(table, name, id, 0, nftnl.DataTypeIP6Addr)
}

// Port returns a nftnl.Set pre-configured for a port (inet_service) set.
func Port(table, name string, id uint32) nftnl.Set {
	return newSet(table, name, id, 0, nftnl.DataTypeInetService)
}

// IPv4Interval returns a nftnl.Set pre-configured for an IPv4 address interval set.
func IPv4Interval(table, name string, id uint32) nftnl.Set {
	return newSet(table, name, id, nftnl.SetInterval, nftnl.DataTypeIPAddr)
}

// IPv6Interval returns a nftnl.Set pre-configured for an IPv6 address interval set.
func IPv6Interval(table, name string, id uint32) nftnl.Set {
	return newSet(table, name, id, nftnl.SetInterval, nftnl.DataTypeIP6Addr)
}

// PortInterval returns a nftnl.Set pre-configured for a port (inet_service) interval set.
func PortInterval(table, name string, id uint32) nftnl.Set {
	return newSet(table, name, id, nftnl.SetInterval, nftnl.DataTypeInetService)
}

// AnonIPv4 returns a nftnl.Set pre-configured for an anonymous IPv4 address set.
func AnonIPv4(table string, id uint32) nftnl.Set {
	return newAnon(table, id, 0, nftnl.DataTypeIPAddr)
}

// AnonIPv6 returns a nftnl.Set pre-configured for an anonymous IPv6 address set.
func AnonIPv6(table string, id uint32) nftnl.Set {
	return newAnon(table, id, 0, nftnl.DataTypeIP6Addr)
}

// AnonPort returns a nftnl.Set pre-configured for an anonymous port (inet_service) set.
func AnonPort(table string, id uint32) nftnl.Set {
	return newAnon(table, id, 0, nftnl.DataTypeInetService)
}

// AnonIPv4Interval returns a nftnl.Set pre-configured for an anonymous IPv4 address interval set.
func AnonIPv4Interval(table string, id uint32) nftnl.Set {
	return newAnon(table, id, nftnl.SetInterval, nftnl.DataTypeIPAddr)
}

// AnonIPv6Interval returns a nftnl.Set pre-configured for an anonymous IPv6 address interval set.
func AnonIPv6Interval(table string, id uint32) nftnl.Set {
	return newAnon(table, id, nftnl.SetInterval, nftnl.DataTypeIP6Addr)
}

// AnonPortInterval returns a nftnl.Set pre-configured for an anonymous port (inet_service) interval set.
func AnonPortInterval(table string, id uint32) nftnl.Set {
	return newAnon(table, id, nftnl.SetInterval, nftnl.DataTypeInetService)
}

func newAnon(table string, id uint32, flags nftnl.SetFlags, keyType nftnl.DataType) nftnl.Set {
	return newSet(table, nftnl.SetAnonTemplate, id, nftnl.SetAnonymous|nftnl.SetConstant|flags, keyType)
}

func newSet(table, name string, id uint32, flags nftnl.SetFlags, keyType nftnl.DataType) nftnl.Set {
	keyLen := keyLens[keyType]
	return nftnl.Set{
		ID:      &id,
		Table:   &table,
		Name:    &name,
		Flags:   &flags,
		KeyType: &keyType,
		KeyLen:  &keyLen,
	}
}
