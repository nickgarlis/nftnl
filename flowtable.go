package nftnl

import (
	"golang.org/x/sys/unix"
)

// https://github.com/torvalds/linux/blob/f83a4f2a4d8c485922fba3018a64fc8f4cfd315f/include/uapi/linux/netfilter/nf_tables.h#L1710
const (
	nftaFlowtableHookNum      = 0x01
	nftaFlowtableHookPriority = 0x02
	nftaFlowtableHookDevs     = 0x03
)

// https://github.com/torvalds/linux/blob/f83a4f2a4d8c485922fba3018a64fc8f4cfd315f/include/uapi/linux/netfilter/nf_tables.h#L1710
type FlowtableHook struct {
	HookNum  *HookNum
	Priority *int32
	Devs     []string
}

func (a *FlowtableHook) marshal() ([]byte, error) {
	ae := newAttributeEncoder()
	if a.HookNum != nil {
		ae.Uint32(nftaFlowtableHookNum, uint32(*a.HookNum))
	}
	if a.Priority != nil {
		ae.Uint32(nftaFlowtableHookPriority, uint32(*a.Priority))
	}
	if len(a.Devs) > 0 {
		inner := newAttributeEncoder()
		for _, dev := range a.Devs {
			inner.String(nftaDeviceName, dev)
		}
		b, err := inner.Encode()
		if err != nil {
			return nil, err
		}
		ae.Bytes(unix.NLA_F_NESTED|nftaFlowtableHookDevs, b)
	}
	return ae.Encode()
}

func (a *FlowtableHook) unmarshal(data []byte) error {
	ad, err := newAttributeDecoder(data)
	if err != nil {
		return err
	}
	for ad.Next() {
		switch ad.Type() {
		case nftaFlowtableHookNum:
			v := HookNum(ad.Uint32())
			a.HookNum = &v
		case nftaFlowtableHookPriority:
			v := int32(ad.Uint32())
			a.Priority = &v
		case nftaFlowtableHookDevs:
			inner, err := newAttributeDecoder(ad.Bytes())
			if err != nil {
				return err
			}
			for inner.Next() {
				if inner.Type() == nftaDeviceName {
					a.Devs = append(a.Devs, inner.String())
				}
			}
			if err := inner.Err(); err != nil {
				return err
			}
		}
	}
	return ad.Err()
}

// https://github.com/torvalds/linux/blob/v7.1/include/uapi/linux/netfilter/nf_tables.h#L1702
type FlowtableFlags uint32

const (
	FlowtableHWOffload FlowtableFlags = 1 << 0
	FlowtableCounter   FlowtableFlags = 1 << 1
)

// https://github.com/torvalds/linux/blob/v7.1/include/uapi/linux/netfilter/nf_tables.h#L1715
const (
	nftaFlowtableTable  = 0x01
	nftaFlowtableName   = 0x02
	nftaFlowtableHook   = 0x03
	nftaFlowtableUse    = 0x04
	nftaFlowtableHandle = 0x05
	nftaFlowtableFlags  = 0x07
)

// https://github.com/torvalds/linux/blob/v7.1/include/uapi/linux/netfilter/nf_tables.h#L1715
type Flowtable struct {
	Table  string
	Name   string
	Hook   *FlowtableHook
	Use    *uint32
	Handle *uint64
	Flags  *FlowtableFlags
}

func (a *Flowtable) marshal() ([]byte, error) {
	ae := newAttributeEncoder()
	ae.String(nftaFlowtableTable, a.Table)
	ae.String(nftaFlowtableName, a.Name)
	if a.Hook != nil {
		b, err := a.Hook.marshal()
		if err != nil {
			return nil, err
		}
		ae.Bytes(unix.NLA_F_NESTED|nftaFlowtableHook, b)
	}
	if a.Use != nil {
		ae.Uint32(nftaFlowtableUse, *a.Use)
	}
	if a.Handle != nil {
		ae.Uint64(nftaFlowtableHandle, *a.Handle)
	}
	if a.Flags != nil {
		ae.Uint32(nftaFlowtableFlags, uint32(*a.Flags))
	}
	return ae.Encode()
}

func (a *Flowtable) unmarshal(data []byte) error {
	ad, err := newAttributeDecoder(data)
	if err != nil {
		return err
	}
	for ad.Next() {
		switch ad.Type() {
		case nftaFlowtableTable:
			a.Table = ad.String()
		case nftaFlowtableName:
			a.Name = ad.String()
		case nftaFlowtableHook:
			a.Hook = &FlowtableHook{}
			if err := a.Hook.unmarshal(ad.Bytes()); err != nil {
				return err
			}
		case nftaFlowtableUse:
			v := ad.Uint32()
			a.Use = &v
		case nftaFlowtableHandle:
			v := ad.Uint64()
			a.Handle = &v
		case nftaFlowtableFlags:
			v := FlowtableFlags(ad.Uint32())
			a.Flags = &v
		}
	}
	return ad.Err()
}
