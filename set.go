package nftnl

import (
	"golang.org/x/sys/unix"
)

// https://git.netfilter.org/nftables/tree/include/datatype.h?id=a20aa2e21c0d9e6aaf37566ceac2ea1e0bd0eb87#n7
type DataType uint32

const (
	DataTypeVerdict DataType = iota + 1
	DataTypeNFProto
	DataTypeBitmask
	DataTypeInteger
	DataTypeString
	DataTypeLLAddr
	DataTypeIPAddr
	DataTypeIP6Addr
	DataTypeEtherAddr
	DataTypeEtherType
	DataTypeARPOp
	DataTypeInetProtocol
	DataTypeInetService
	DataTypeICMPType
	DataTypeTCPFlag
	DataTypeDCCPPktType
	DataTypeMHType
	DataTypeTime
	DataTypeMark
	DataTypeIfIndex
	DataTypeARPHRD
	DataTypeRealm
	DataTypeClassID
	DataTypeUID
	DataTypeGID
	DataTypeCTState
	DataTypeCTDir
	DataTypeCTStatus
	DataTypeICMP6Type
	DataTypeCTLabel
	DataTypePktType
	DataTypeICMPCode
	DataTypeICMPv6Code
	DataTypeICMPXCode
	DataTypeDevGroup
	DataTypeDSCP
	DataTypeECN
	DataTypeFIBAddr
	DataTypeBoolean
	DataTypeCTEventBit
	DataTypeIfName
	DataTypeIGMPType
	DataTypeTimeDate
	DataTypeTimeHour
	DataTypeTimeDay
	DataTypeCGroupV2
)

// Name templates for anonymous sets, maps, and object maps. The kernel
// substitutes %d with the next unused integer, guaranteeing uniqueness within
// the table. Pass as NFTA_SET_NAME / NFTA_LOOKUP_SET / NFTA_SET_ELEM_LIST_SET.
//
// https://git.netfilter.org/nftables/tree/src/evaluate.c?id=3e93d847#n2944
// https://git.netfilter.org/nftables/tree/src/evaluate.c?id=3e93d847#n2267
// https://git.netfilter.org/nftables/tree/src/evaluate.c?id=3e93d847#n4948
const (
	SetAnonTemplate       = "__set%d"
	SetMapAnonTemplate    = "__map%d"
	SetObjMapAnonTemplate = "__objmap%d"
)

// Set flags for Set.Flags
// https://github.com/torvalds/linux/blob/v7.1/include/uapi/linux/netfilter/nf_tables.h#L356
type SetFlags uint32

const (
	SetAnonymous SetFlags = 1 << 0
	SetConstant  SetFlags = 1 << 1
	SetInterval  SetFlags = 1 << 2
	SetMap       SetFlags = 1 << 3
	SetTimeout   SetFlags = 1 << 4
	SetEval      SetFlags = 1 << 5
	SetObject    SetFlags = 1 << 6
	SetConcat    SetFlags = 1 << 7
	SetExpr      SetFlags = 1 << 8
)

// https://github.com/torvalds/linux/blob/v7.1/include/uapi/linux/netfilter/nf_tables.h#L378
type SetPol uint32

const (
	// Prefer high performance over low memory use
	SetPolPerformance SetPol = iota
	// Prefer low memory use over high performance
	SetPolMemory
)

// https://github.com/torvalds/linux/blob/v7.1/include/uapi/linux/netfilter/nf_tables.h#L382
const (
	nftaSetTable       = unix.NFTA_SET_TABLE
	nftaSetName        = unix.NFTA_SET_NAME
	nftaSetFlags       = unix.NFTA_SET_FLAGS
	nftaSetKeyType     = unix.NFTA_SET_KEY_TYPE
	nftaSetKeyLen      = unix.NFTA_SET_KEY_LEN
	nftaSetDataType    = unix.NFTA_SET_DATA_TYPE
	nftaSetDataLen     = unix.NFTA_SET_DATA_LEN
	nftaSetPolicy      = unix.NFTA_SET_POLICY
	nftaSetDesc        = unix.NFTA_SET_DESC
	nftaSetID          = unix.NFTA_SET_ID
	nftaSetTimeout     = unix.NFTA_SET_TIMEOUT
	nftaSetGcInterval  = unix.NFTA_SET_GC_INTERVAL
	nftaSetUserdata    = unix.NFTA_SET_USERDATA
	nftaSetObjType     = unix.NFTA_SET_OBJ_TYPE
	nftaSetHandle      = 0x10
	nftaSetExpr        = 0x11
	nftaSetExpressions = 0x12
	nftaSetType        = 0x13
	nftaSetCount       = 0x14
)

// https://github.com/torvalds/linux/blob/v7.1/include/uapi/linux/netfilter/nf_tables.h#L356
const (
	nftaSetDescSize   = unix.NFTA_SET_DESC_SIZE
	nftaSetDescConcat = 0x02
	nftaSetFieldLen   = 0x01
)

// Set description attributes
//
// https://github.com/torvalds/linux/blob/v7.1/include/uapi/linux/netfilter/nf_tables.h#L356
type SetDesc struct {
	// Number of elements in set
	Size *uint32
	// Description of field concatenation
	Concat []uint32
}

func (a *SetDesc) marshal() ([]byte, error) {
	ae := newAttributeEncoder()
	if a.Size != nil {
		ae.Uint32(nftaSetDescSize, *a.Size)
	}
	if len(a.Concat) > 0 {
		inner := newAttributeEncoder()
		for _, fieldLen := range a.Concat {
			inner.Uint32(nftaSetFieldLen, fieldLen)
		}
		b, err := inner.Encode()
		if err != nil {
			return nil, err
		}
		ae.Bytes(unix.NLA_F_NESTED|nftaSetDescConcat, b)
	}
	return ae.Encode()
}

func (a *SetDesc) unmarshal(data []byte) error {
	ad, err := newAttributeDecoder(data)
	if err != nil {
		return err
	}
	for ad.Next() {
		switch ad.Type() {
		case nftaSetDescSize:
			v := ad.Uint32()
			a.Size = &v
		case nftaSetDescConcat:
			inner, err := newAttributeDecoder(ad.Bytes())
			if err != nil {
				return err
			}
			for inner.Next() {
				if inner.Type() == nftaSetFieldLen {
					a.Concat = append(a.Concat, inner.Uint32())
				}
			}
			if err := inner.Err(); err != nil {
				return err
			}
		}
	}
	return ad.Err()
}

// Set attributes
//
// https://github.com/torvalds/linux/blob/v7.1/include/uapi/linux/netfilter/nf_tables.h#L382
type Set struct {
	// Table name
	Table string
	// Set name
	Name *string
	// Bitmask of set flags
	Flags *SetFlags
	// Key data type
	KeyType *DataType
	// Key data length
	KeyLen *uint32
	// Mapping data type
	DataType *DataType
	// Mapping data length
	DataLen *uint32
	// Selection policy
	Policy *SetPol
	// Set description
	Desc *SetDesc
	// Uniquely identifies a set in a transaction
	ID *uint32
	// Default timeout value
	Timeout *uint64
	// Garbage collection interval
	GCInterval *uint64
	// User data
	UserData UserData
	// Stateful object type
	ObjType *ObjType
	// Set handle
	Handle *uint64
	// Set expression
	Expr Expr
	// List of set expressions
	Expressions []Expr
	// Set backend type
	Type *string
	// Number of set elements
	Count *uint32
}

func (a *Set) marshal() ([]byte, error) {
	ae := newAttributeEncoder()
	ae.String(nftaSetTable, a.Table)
	if a.Name != nil {
		ae.String(nftaSetName, *a.Name)
	}
	if a.Flags != nil {
		ae.Uint32(nftaSetFlags, uint32(*a.Flags))
	}
	if a.KeyType != nil {
		ae.Uint32(nftaSetKeyType, uint32(*a.KeyType))
	}
	if a.KeyLen != nil {
		ae.Uint32(nftaSetKeyLen, *a.KeyLen)
	}
	if a.DataType != nil {
		ae.Uint32(nftaSetDataType, uint32(*a.DataType))
	}
	if a.DataLen != nil {
		ae.Uint32(nftaSetDataLen, *a.DataLen)
	}
	if a.Policy != nil {
		ae.Uint32(nftaSetPolicy, uint32(*a.Policy))
	}
	if a.Desc != nil {
		b, err := a.Desc.marshal()
		if err != nil {
			return nil, err
		}
		ae.Bytes(unix.NLA_F_NESTED|nftaSetDesc, b)
	}
	if a.ID != nil {
		ae.Uint32(nftaSetID, *a.ID)
	}
	if a.Timeout != nil {
		ae.Uint64(nftaSetTimeout, *a.Timeout)
	}
	if a.GCInterval != nil {
		ae.Uint64(nftaSetGcInterval, *a.GCInterval)
	}
	if b := a.UserData.marshal(); b != nil {
		ae.Bytes(nftaSetUserdata, b)
	}
	if a.ObjType != nil {
		ae.Uint32(nftaSetObjType, uint32(*a.ObjType))
	}
	if a.Handle != nil {
		ae.Uint64(nftaSetHandle, *a.Handle)
	}
	if a.Expr != nil {
		b, err := marshalExpr(a.Expr)
		if err != nil {
			return nil, err
		}
		ae.Bytes(unix.NLA_F_NESTED|nftaSetExpr, b)
	}
	if len(a.Expressions) > 0 {
		inner := newAttributeEncoder()
		for _, expr := range a.Expressions {
			b, err := marshalExpr(expr)
			if err != nil {
				return nil, err
			}
			inner.Bytes(unix.NLA_F_NESTED|nftaListElem, b)
		}
		b, err := inner.Encode()
		if err != nil {
			return nil, err
		}
		ae.Bytes(unix.NLA_F_NESTED|nftaSetExpressions, b)
	}
	if a.Type != nil {
		ae.String(nftaSetType, *a.Type)
	}
	if a.Count != nil {
		ae.Uint32(nftaSetCount, *a.Count)
	}
	return ae.Encode()
}

func (a *Set) unmarshal(data []byte) error {
	ad, err := newAttributeDecoder(data)
	if err != nil {
		return err
	}
	for ad.Next() {
		switch ad.Type() {
		case nftaSetTable:
			a.Table = ad.String()
		case nftaSetName:
			v := ad.String()
			a.Name = &v
		case nftaSetFlags:
			v := SetFlags(ad.Uint32())
			a.Flags = &v
		case nftaSetKeyType:
			v := DataType(ad.Uint32())
			a.KeyType = &v
		case nftaSetKeyLen:
			v := ad.Uint32()
			a.KeyLen = &v
		case nftaSetDataType:
			v := DataType(ad.Uint32())
			a.DataType = &v
		case nftaSetDataLen:
			v := ad.Uint32()
			a.DataLen = &v
		case nftaSetPolicy:
			v := ad.Uint32()
			a.Policy = new(SetPol(v))
		case nftaSetDesc:
			a.Desc = &SetDesc{}
			if err := a.Desc.unmarshal(ad.Bytes()); err != nil {
				return err
			}
		case nftaSetID:
			v := ad.Uint32()
			a.ID = &v
		case nftaSetTimeout:
			v := ad.Uint64()
			a.Timeout = &v
		case nftaSetGcInterval:
			v := ad.Uint64()
			a.GCInterval = &v
		case nftaSetUserdata:
			if err := a.UserData.unmarshal(ad.Bytes()); err != nil {
				return err
			}
		case nftaSetObjType:
			v := ObjType(ad.Uint32())
			a.ObjType = &v
		case nftaSetHandle:
			v := ad.Uint64()
			a.Handle = &v
		case nftaSetExpr:
			e, err := unmarshalExpr(ad.Bytes())
			if err != nil {
				return err
			}
			a.Expr = e
		case nftaSetExpressions:
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
		case nftaSetType:
			v := ad.String()
			a.Type = &v
		case nftaSetCount:
			v := ad.Uint32()
			a.Count = &v
		}
	}
	return ad.Err()
}
