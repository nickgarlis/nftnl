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

func (a *SetElemList) marshalWithElements(elemBytes []byte) ([]byte, error) {
	ae := newAttributeEncoder()
	ae.String(nftaSetElemListTable, a.Table)
	if a.Set != nil {
		ae.String(nftaSetElemListSet, *a.Set)
	}
	if a.SetID != nil {
		ae.Uint32(nftaSetElemListSetID, *a.SetID)
	}
	if len(elemBytes) > 0 {
		ae.Bytes(unix.NLA_F_NESTED|nftaSetElemListElements, elemBytes)
	}
	return ae.Encode()
}

func (a *SetElemList) marshalChunks() ([][]byte, error) {
	var results [][]byte
	inner := newAttributeEncoder()

	for _, elem := range a.Elements {
		b, err := elem.marshal()
		if err != nil {
			return nil, err
		}
		if inner.Len() > 0 && inner.Len()+nlaHdrLen+len(b) > nlaMax {
			elemBytes, err := inner.Encode()
			if err != nil {
				return nil, err
			}
			chunk, err := a.marshalWithElements(elemBytes)
			if err != nil {
				return nil, err
			}
			results = append(results, chunk)
			inner = newAttributeEncoder()
		}
		inner.Bytes(unix.NLA_F_NESTED|nftaListElem, b)
	}

	elemBytes, err := inner.Encode()
	if err != nil {
		return nil, err
	}
	chunk, err := a.marshalWithElements(elemBytes)
	if err != nil {
		return nil, err
	}
	return append(results, chunk), nil
}

func (a *SetElemList) marshal() ([]byte, error) {
	inner := newAttributeEncoder()
	for _, elem := range a.Elements {
		b, err := elem.marshal()
		if err != nil {
			return nil, err
		}
		inner.Bytes(unix.NLA_F_NESTED|nftaListElem, b)
	}
	elemBytes, err := inner.Encode()
	if err != nil {
		return nil, err
	}
	return a.marshalWithElements(elemBytes)
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
