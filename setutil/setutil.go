// Package setutil provides shorthand for building nftnl.Set values.
package setutil

import (
	"github.com/nickgarlis/nftnl"
)

// IPv4Interval returns a nftnl.Set pre-configured for an IPv4 address interval set.
// id must be unique within the batch transaction.
func IPv4Interval(table, name string, id uint32) nftnl.Set {
	flags := nftnl.SetInterval
	keyType := nftnl.DataTypeIPAddr
	keyLen := uint32(4)
	return nftnl.Set{
		ID:      &id,
		Table:   &table,
		Name:    &name,
		Flags:   &flags,
		KeyType: &keyType,
		KeyLen:  &keyLen,
	}
}

// IPv6Interval returns a nftnl.Set pre-configured for an IPv6 address interval set.
// id must be unique within the batch transaction.
func IPv6Interval(table, name string, id uint32) nftnl.Set {
	flags := nftnl.SetInterval
	keyType := nftnl.DataTypeIP6Addr
	keyLen := uint32(16)
	return nftnl.Set{
		ID:      &id,
		Table:   &table,
		Name:    &name,
		Flags:   &flags,
		KeyType: &keyType,
		KeyLen:  &keyLen,
	}
}

// PortInterval returns a nftnl.Set pre-configured for a port (inet_service) interval set.
// id must be unique within the batch transaction.
func PortInterval(table, name string, id uint32) nftnl.Set {
	flags := nftnl.SetInterval
	keyType := nftnl.DataTypeInetService
	keyLen := uint32(2)
	return nftnl.Set{
		ID:      &id,
		Table:   &table,
		Name:    &name,
		Flags:   &flags,
		KeyType: &keyType,
		KeyLen:  &keyLen,
	}
}
