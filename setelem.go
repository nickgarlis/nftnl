package nftnl

import (
	"golang.org/x/sys/unix"
)

// Set element flags for SetElem.Flags
//
// https://github.com/torvalds/linux/blob/v7.1/include/uapi/linux/netfilter/nf_tables.h#L431
type SetElemFlags uint32

const (
	SetElemIntervalEnd SetElemFlags = 1 << 0
	SetElemCatchAll    SetElemFlags = 1 << 1
)

// https://github.com/torvalds/linux/blob/v7.1/include/uapi/linux/netfilter/nf_tables.h#L442
const (
	nftaSetElemKey         = unix.NFTA_SET_ELEM_KEY
	nftaSetElemData        = unix.NFTA_SET_ELEM_DATA
	nftaSetElemFlags       = unix.NFTA_SET_ELEM_FLAGS
	nftaSetElemTimeout     = unix.NFTA_SET_ELEM_TIMEOUT
	nftaSetElemExpiration  = unix.NFTA_SET_ELEM_EXPIRATION
	nftaSetElemUserdata    = unix.NFTA_SET_ELEM_USERDATA
	nftaSetElemExpr        = unix.NFTA_SET_ELEM_EXPR
	nftaSetElemObjref      = unix.NFTA_SET_ELEM_OBJREF
	nftaSetElemKeyEnd      = 0x0a
	nftaSetElemExpressions = 0x0b
)

// Set element attributes
//
// https://github.com/torvalds/linux/blob/v7.1/include/uapi/linux/netfilter/nf_tables.h#L442
type SetElem struct {
	// Key value
	Key *ExprData
	// Data value of mapping
	Data *ExprData
	// Bitmask of set element flags
	Flags *SetElemFlags
	// Timeout value, zero means never times out
	Timeout *uint64
	// Expiration time
	Expiration *uint64
	// User data
	UserData UserData
	// Expression
	Expr Expr
	// Stateful object reference
	ObjRef *string
	// Closing key value
	KeyEnd *ExprData
	// List of expressions
	Expressions []Expr
}

func (a *SetElem) marshal() ([]byte, error) {
	ae := newAttributeEncoder()
	if a.Key != nil {
		b, err := a.Key.marshal()
		if err != nil {
			return nil, err
		}
		ae.Bytes(unix.NLA_F_NESTED|nftaSetElemKey, b)
	}
	if a.Data != nil {
		b, err := a.Data.marshal()
		if err != nil {
			return nil, err
		}
		ae.Bytes(unix.NLA_F_NESTED|nftaSetElemData, b)
	}
	if a.Flags != nil {
		ae.Uint32(nftaSetElemFlags, uint32(*a.Flags))
	}
	if a.Timeout != nil {
		ae.Uint64(nftaSetElemTimeout, *a.Timeout)
	}
	if a.Expiration != nil {
		ae.Uint64(nftaSetElemExpiration, *a.Expiration)
	}
	if b := a.UserData.marshal(); b != nil {
		ae.Bytes(nftaSetElemUserdata, b)
	}
	if a.Expr != nil {
		b, err := marshalExpr(a.Expr)
		if err != nil {
			return nil, err
		}
		ae.Bytes(unix.NLA_F_NESTED|nftaSetElemExpr, b)
	}
	if a.ObjRef != nil {
		ae.String(nftaSetElemObjref, *a.ObjRef)
	}
	if a.KeyEnd != nil {
		b, err := a.KeyEnd.marshal()
		if err != nil {
			return nil, err
		}
		ae.Bytes(unix.NLA_F_NESTED|nftaSetElemKeyEnd, b)
	}
	if len(a.Expressions) > 0 {
		inner := newAttributeEncoder()
		for _, expr := range a.Expressions {
			b, err := expr.marshal()
			if err != nil {
				return nil, err
			}
			inner.Bytes(unix.NLA_F_NESTED|nftaListElem, b)
		}
		b, err := inner.Encode()
		if err != nil {
			return nil, err
		}
		ae.Bytes(unix.NLA_F_NESTED|nftaSetElemExpressions, b)
	}
	return ae.Encode()
}

func (a *SetElem) unmarshal(data []byte) error {
	ad, err := newAttributeDecoder(data)
	if err != nil {
		return err
	}
	for ad.Next() {
		switch ad.Type() {
		case nftaSetElemKey:
			a.Key = &ExprData{}
			if err := a.Key.unmarshal(ad.Bytes()); err != nil {
				return err
			}
		case nftaSetElemData:
			a.Data = &ExprData{}
			if err := a.Data.unmarshal(ad.Bytes()); err != nil {
				return err
			}
		case nftaSetElemFlags:
			v := ad.Uint32()
			a.Flags = new(SetElemFlags(v))
		case nftaSetElemTimeout:
			v := ad.Uint64()
			a.Timeout = &v
		case nftaSetElemExpiration:
			v := ad.Uint64()
			a.Expiration = &v
		case nftaSetElemUserdata:
			if err := a.UserData.unmarshal(ad.Bytes()); err != nil {
				return err
			}
		case nftaSetElemExpr:
			e, err := unmarshalExpr(ad.Bytes())
			if err != nil {
				return err
			}
			a.Expr = e
		case nftaSetElemObjref:
			v := ad.String()
			a.ObjRef = &v
		case nftaSetElemKeyEnd:
			a.KeyEnd = &ExprData{}
			if err := a.KeyEnd.unmarshal(ad.Bytes()); err != nil {
				return err
			}
		case nftaSetElemExpressions:
			inner, err := newAttributeDecoder(ad.Bytes())
			if err != nil {
				return err
			}
			for inner.Next() {
				if inner.Type() == nftaListElem {
					expr, err := unmarshalExpr(inner.Bytes())
					if err != nil {
						return err
					}
					a.Expressions = append(a.Expressions, expr)
				}
			}
			if err := inner.Err(); err != nil {
				return err
			}
		}
	}
	return ad.Err()
}
