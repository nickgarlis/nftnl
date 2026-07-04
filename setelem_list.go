package nftnl

import (
	"golang.org/x/sys/unix"
)

// https://github.com/torvalds/linux/blob/v7.1/include/uapi/linux/netfilter/nf_tables.h#L473
const (
	nftaSetElemListTable    = unix.NFTA_SET_ELEM_LIST_TABLE
	nftaSetElemListSet      = unix.NFTA_SET_ELEM_LIST_SET
	nftaSetElemListElements = unix.NFTA_SET_ELEM_LIST_ELEMENTS
	nftaSetElemListSetID    = unix.NFTA_SET_ELEM_LIST_SET_ID
)

// https://github.com/torvalds/linux/blob/v7.1/include/uapi/linux/netfilter/nf_tables.h#L473
type SetElemList struct {
	Table    string
	Set      *string
	Elements []SetElem
	SetID    *uint32
}

func (a *SetElemList) marshal() ([]byte, error) {
	ae := newAttributeEncoder()
	ae.String(nftaSetElemListTable, a.Table)
	if a.Set != nil {
		ae.String(nftaSetElemListSet, *a.Set)
	}
	if a.SetID != nil {
		ae.Uint32(nftaSetElemListSetID, *a.SetID)
	}
	if len(a.Elements) > 0 {
		inner := newAttributeEncoder()
		for _, elem := range a.Elements {
			b, err := elem.marshal()
			if err != nil {
				return nil, err
			}
			inner.Bytes(unix.NLA_F_NESTED|nftaListElem, b)
		}
		b, err := inner.Encode()
		if err != nil {
			return nil, err
		}
		ae.Bytes(unix.NLA_F_NESTED|nftaSetElemListElements, b)
	}
	return ae.Encode()
}

func (a *SetElemList) unmarshal(data []byte) error {
	ad, err := newAttributeDecoder(data)
	if err != nil {
		return err
	}
	for ad.Next() {
		switch ad.Type() {
		case nftaSetElemListTable:
			a.Table = ad.String()
		case nftaSetElemListSet:
			v := ad.String()
			a.Set = &v
		case nftaSetElemListSetID:
			v := ad.Uint32()
			a.SetID = &v
		case nftaSetElemListElements:
			inner, err := newAttributeDecoder(ad.Bytes())
			if err != nil {
				return err
			}
			for inner.Next() {
				if inner.Type() == nftaListElem {
					elem := SetElem{}
					if err := elem.unmarshal(inner.Bytes()); err != nil {
						return err
					}
					a.Elements = append(a.Elements, elem)
				}
			}
			if err := inner.Err(); err != nil {
				return err
			}
		}
	}
	return ad.Err()
}
