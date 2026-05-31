package nftnl

import (
	"golang.org/x/sys/unix"
)

// https://github.com/torvalds/linux/blob/v7.1/include/uapi/linux/netfilter/nf_tables.h#L199
const (
	nftaTableName     = unix.NFTA_TABLE_NAME
	nftaTableFlags    = unix.NFTA_TABLE_FLAGS
	nftaTableUse      = unix.NFTA_TABLE_USE
	nftaTableHandle   = 0x04
	nftaTableUserdata = 0x06
	nftaTableOwner    = 0x07
)

// Table Flags
//
// https://github.com/torvalds/linux/blob/v7.1/include/uapi/linux/netfilter/nf_tables.h#L183
type TableFlags uint32

const (
	// This table is not active
	TableDormant TableFlags = 1 << 0
	// This table is owned by a process
	TableOwner TableFlags = 1 << 1
	// This table shall outlive its owner
	TablePersist TableFlags = 1 << 2
)

// Table attributes
//
// https://github.com/torvalds/linux/blob/v7.1/include/uapi/linux/netfilter/nf_tables.h#L199
type Table struct {
	// Name of the table
	Name string
	// Bitmask of table flags
	Flags *TableFlags
	// Number of chains in this table
	Use    *uint32
	Handle *uint64
	// Userdata binary
	UserData UserData
	// Owner of this table through netlink portID
	Owner *uint32
}

func (a *Table) marshal() ([]byte, error) {
	ae := newAttributeEncoder()
	ae.String(nftaTableName, a.Name)
	if a.Flags != nil {
		ae.Uint32(nftaTableFlags, uint32(*a.Flags))
	}
	if a.Use != nil {
		ae.Uint32(nftaTableUse, *a.Use)
	}
	if a.Handle != nil {
		ae.Uint64(nftaTableHandle, *a.Handle)
	}
	if b := a.UserData.marshal(); b != nil {
		ae.Bytes(nftaTableUserdata, b)
	}
	if a.Owner != nil {
		ae.Uint32(nftaTableOwner, *a.Owner)
	}
	return ae.Encode()
}

func (a *Table) unmarshal(data []byte) error {
	ad, err := newAttributeDecoder(data)
	if err != nil {
		return err
	}
	for ad.Next() {
		switch ad.Type() {
		case nftaTableName:
			a.Name = ad.String()
		case nftaTableFlags:
			v := ad.Uint32()
			a.Flags = new(TableFlags(v))
		case nftaTableUse:
			v := ad.Uint32()
			a.Use = &v
		case nftaTableHandle:
			v := ad.Uint64()
			a.Handle = &v
		case nftaTableUserdata:
			if err := a.UserData.unmarshal(ad.Bytes()); err != nil {
				return err
			}
		case nftaTableOwner:
			v := ad.Uint32()
			a.Owner = &v
		}
	}
	return ad.Err()
}
