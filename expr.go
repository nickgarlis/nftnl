package nftnl

import (
	"encoding/binary"
	"fmt"

	"golang.org/x/sys/unix"
)

// Register IDs
//
// https://github.com/torvalds/linux/blob/v7.1/include/uapi/linux/netfilter/nf_tables.h#L14
type Reg uint32

const (
	RegVerdict Reg = iota
	Reg1
	Reg2
	Reg3
	Reg4

	Reg32_00 Reg = iota + 3
	Reg32_01
	Reg32_02
	Reg32_03
	Reg32_04
	Reg32_05
	Reg32_06
	Reg32_07
	Reg32_08
	Reg32_09
	Reg32_10
	Reg32_11
	Reg32_12
	Reg32_13
	Reg32_14
	Reg32_15
)

// https://github.com/torvalds/linux/blob/v7.1/include/uapi/linux/netfilter/nf_tables.h#L545
const (
	nftaExprName = unix.NFTA_EXPR_NAME
	nftaExprData = unix.NFTA_EXPR_DATA
)

type exprName string

const (
	exprNameBitwise     exprName = "bitwise"
	exprNameByteorder   exprName = "byteorder"
	exprNameCmp         exprName = "cmp"
	exprNameConnlimit   exprName = "connlimit"
	exprNameCounter     exprName = "counter"
	exprNameCt          exprName = "ct"
	exprNameData        exprName = "data"
	exprNameDup         exprName = "dup"
	exprNameDynset      exprName = "dynset"
	exprNameExthdr      exprName = "exthdr"
	exprNameFib         exprName = "fib"
	exprNameFlowOffload exprName = "flow_offload"
	exprNameFwd         exprName = "fwd"
	exprNameHash        exprName = "hash"
	exprNameImmediate   exprName = "immediate"
	exprNameInner       exprName = "inner"
	exprNameLast        exprName = "last"
	exprNameLimit       exprName = "limit"
	exprNameLog         exprName = "log"
	exprNameLookup      exprName = "lookup"
	exprNameMasq        exprName = "masq"
	exprNameMeta        exprName = "meta"
	exprNameNat         exprName = "nat"
	exprNameNumgen      exprName = "numgen"
	exprNameObjref      exprName = "objref"
	exprNameOsf         exprName = "osf"
	exprNamePayload     exprName = "payload"
	exprNameQueue       exprName = "queue"
	exprNameQuota       exprName = "quota"
	exprNameRange       exprName = "range"
	exprNameRedir       exprName = "redir"
	exprNameReject      exprName = "reject"
	exprNameRt          exprName = "rt"
	exprNameSocket      exprName = "socket"
	exprNameSynproxy    exprName = "synproxy"
	exprNameTproxy      exprName = "tproxy"
	exprNameTunnel      exprName = "tunnel"
	exprNameVerdict     exprName = "verdict"
	exprNameXfrm        exprName = "xfrm"
)

// Expr is implemented by each expression type. The interface methods are
// unexported so only types in this package can satisfy it.
type Expr interface {
	exprName() exprName
	marshal() ([]byte, error)
	unmarshal(data []byte) error
}

func marshalExpr(a Expr) ([]byte, error) {
	ae := newAttributeEncoder()
	ae.String(nftaExprName, string(a.exprName()))
	data, err := a.marshal()
	if err != nil {
		return nil, err
	}
	ae.Bytes(unix.NLA_F_NESTED|nftaExprData, data)
	return ae.Encode()
}

func unmarshalExpr(data []byte) (Expr, error) {
	ad, err := newAttributeDecoder(data)
	if err != nil {
		return nil, err
	}
	var name exprName
	var result Expr
	for ad.Next() {
		switch ad.Type() {
		case nftaExprName:
			name = exprName(ad.String())
		case nftaExprData:
			e, err := exprDataFactory(name)
			if err != nil {
				return nil, err
			}
			if err := e.unmarshal(ad.Bytes()); err != nil {
				return nil, err
			}
			result = e
		}
	}
	if err := ad.Err(); err != nil {
		return nil, err
	}
	return result, nil
}

func exprDataFactory(name exprName) (Expr, error) {
	switch name {
	case exprNameBitwise:
		return &ExprBitwise{}, nil
	case exprNameByteorder:
		return &ExprByteorder{}, nil
	case exprNameCmp:
		return &ExprCmp{}, nil
	case exprNameConnlimit:
		return &ExprConnlimit{}, nil
	case exprNameCounter:
		return &ExprCounter{}, nil
	case exprNameCt:
		return &ExprCt{}, nil
	case exprNameData:
		return &ExprData{}, nil
	case exprNameDup:
		return &ExprDup{}, nil
	case exprNameDynset:
		return &ExprDynset{}, nil
	case exprNameExthdr:
		return &ExprExthdr{}, nil
	case exprNameFib:
		return &ExprFib{}, nil
	case exprNameFlowOffload:
		return &ExprFlowOffload{}, nil
	case exprNameFwd:
		return &ExprFwd{}, nil
	case exprNameHash:
		return &ExprHash{}, nil
	case exprNameImmediate:
		return &ExprImmediate{}, nil
	case exprNameInner:
		return &ExprInner{}, nil
	case exprNameLast:
		return &ExprLast{}, nil
	case exprNameLimit:
		return &ExprLimit{}, nil
	case exprNameLog:
		return &ExprLog{}, nil
	case exprNameLookup:
		return &ExprLookup{}, nil
	case exprNameMasq:
		return &ExprMasq{}, nil
	case exprNameMeta:
		return &ExprMeta{}, nil
	case exprNameNat:
		return &ExprNat{}, nil
	case exprNameNumgen:
		return &ExprNumgen{}, nil
	case exprNameObjref:
		return &ExprObjref{}, nil
	case exprNameOsf:
		return &ExprOsf{}, nil
	case exprNamePayload:
		return &ExprPayload{}, nil
	case exprNameQueue:
		return &ExprQueue{}, nil
	case exprNameQuota:
		return &ExprQuota{}, nil
	case exprNameRange:
		return &ExprRange{}, nil
	case exprNameRedir:
		return &ExprRedir{}, nil
	case exprNameReject:
		return &ExprReject{}, nil
	case exprNameRt:
		return &ExprRt{}, nil
	case exprNameSocket:
		return &ExprSocket{}, nil
	case exprNameSynproxy:
		return &ExprSynproxy{}, nil
	case exprNameTproxy:
		return &ExprTproxy{}, nil
	case exprNameTunnel:
		return &ExprTunnel{}, nil
	case exprNameVerdict:
		return &ExprVerdict{}, nil
	case exprNameXfrm:
		return &ExprXfrm{}, nil
	default:
		return nil, fmt.Errorf("unknown expr name %q", name)
	}
}

// https://github.com/torvalds/linux/blob/v7.1/include/uapi/linux/netfilter/nf_tables.h#L597
const (
	nftaBitwiseSreg  = unix.NFTA_BITWISE_SREG
	nftaBitwiseDreg  = unix.NFTA_BITWISE_DREG
	nftaBitwiseLen   = unix.NFTA_BITWISE_LEN
	nftaBitwiseMask  = unix.NFTA_BITWISE_MASK
	nftaBitwiseXor   = unix.NFTA_BITWISE_XOR
	nftaBitwiseOp    = 0x06
	nftaBitwiseData  = 0x07
	nftaBitwiseSreg2 = 0x08
)

// Bitwise operations for ExprBitwise.Op
//
// https://github.com/torvalds/linux/blob/v7.1/include/uapi/linux/netfilter/nf_tables.h#L573
type BitwiseOp uint32

const (
	BitwiseMaskXor BitwiseOp = iota
	BitwiseLshift
	BitwiseRshift
	BitwiseAnd
	BitwiseOr
	BitwiseXor
)

// Bitwise expression attributes
//
// https://github.com/torvalds/linux/blob/v7.1/include/uapi/linux/netfilter/nf_tables.h#L597
type ExprBitwise struct {
	// Source register
	SReg Reg
	// Destination register
	DReg Reg
	// Length of operants
	Len uint32
	// Mask value
	Mask *ExprData
	// XOR value
	Xor *ExprData
	// Type of operation
	Op *BitwiseOp
	// Argument for non-boolean operations
	Data *ExprData
	// Second source register
	Sreg2 *Reg
}

func (ExprBitwise) exprName() exprName { return exprNameBitwise }

func (a *ExprBitwise) marshal() ([]byte, error) {
	ae := newAttributeEncoder()
	ae.Uint32(nftaBitwiseSreg, uint32(a.SReg))
	ae.Uint32(nftaBitwiseDreg, uint32(a.DReg))
	ae.Uint32(nftaBitwiseLen, a.Len)
	if a.Mask != nil {
		b, err := a.Mask.marshal()
		if err != nil {
			return nil, err
		}
		ae.Bytes(unix.NLA_F_NESTED|nftaBitwiseMask, b)
	}
	if a.Xor != nil {
		b, err := a.Xor.marshal()
		if err != nil {
			return nil, err
		}
		ae.Bytes(unix.NLA_F_NESTED|nftaBitwiseXor, b)
	}
	if a.Op != nil {
		ae.Uint32(nftaBitwiseOp, uint32(*a.Op))
	}
	if a.Data != nil {
		b, err := a.Data.marshal()
		if err != nil {
			return nil, err
		}
		ae.Bytes(unix.NLA_F_NESTED|nftaBitwiseData, b)
	}
	if a.Sreg2 != nil {
		ae.Uint32(nftaBitwiseSreg2, uint32(*a.Sreg2))
	}
	return ae.Encode()
}

func (a *ExprBitwise) unmarshal(data []byte) error {
	ad, err := newAttributeDecoder(data)
	if err != nil {
		return err
	}
	for ad.Next() {
		switch ad.Type() {
		case nftaBitwiseSreg:
			a.SReg = Reg(ad.Uint32())
		case nftaBitwiseDreg:
			a.DReg = Reg(ad.Uint32())
		case nftaBitwiseLen:
			a.Len = ad.Uint32()
		case nftaBitwiseMask:
			a.Mask = &ExprData{}
			if err := a.Mask.unmarshal(ad.Bytes()); err != nil {
				return err
			}
		case nftaBitwiseXor:
			a.Xor = &ExprData{}
			if err := a.Xor.unmarshal(ad.Bytes()); err != nil {
				return err
			}
		case nftaBitwiseOp:
			v := BitwiseOp(ad.Uint32())
			a.Op = &v
		case nftaBitwiseData:
			a.Data = &ExprData{}
			if err := a.Data.unmarshal(ad.Bytes()); err != nil {
				return err
			}
		case nftaBitwiseSreg2:
			v := Reg(ad.Uint32())
			a.Sreg2 = &v
		}
	}
	return ad.Err()
}

// Byteorder operators for ExprByteorder.Op
//
// https://github.com/torvalds/linux/blob/v7.1/include/uapi/linux/netfilter/nf_tables.h#L637
type ByteorderOp uint32

const (
	// Network to host operator
	ByteorderNtoh ByteorderOp = iota
	// Host to network operator
	ByteorderHton
)

// https://github.com/torvalds/linux/blob/v7.1/include/uapi/linux/netfilter/nf_tables.h#L648
const (
	nftaByteorderSreg = unix.NFTA_BYTEORDER_SREG
	nftaByteorderDreg = unix.NFTA_BYTEORDER_DREG
	nftaByteorderOp   = unix.NFTA_BYTEORDER_OP
	nftaByteorderLen  = unix.NFTA_BYTEORDER_LEN
	nftaByteorderSize = unix.NFTA_BYTEORDER_SIZE
)

// Byte order expression attributes
//
// https://github.com/torvalds/linux/blob/v7.1/include/uapi/linux/netfilter/nf_tables.h#L648
type ExprByteorder struct {
	// Source register
	SReg Reg
	// Destination register
	DReg Reg
	// Byteorder operators
	Op ByteorderOp
	// Length of the data
	Len uint32
	// Data size in bytes, 2 or 4
	Size uint32
}

func (ExprByteorder) exprName() exprName { return exprNameByteorder }

func (a *ExprByteorder) marshal() ([]byte, error) {
	ae := newAttributeEncoder()
	ae.Uint32(nftaByteorderSreg, uint32(a.SReg))
	ae.Uint32(nftaByteorderDreg, uint32(a.DReg))
	ae.Uint32(nftaByteorderOp, uint32(a.Op))
	ae.Uint32(nftaByteorderLen, a.Len)
	ae.Uint32(nftaByteorderSize, a.Size)
	return ae.Encode()
}

func (a *ExprByteorder) unmarshal(data []byte) error {
	ad, err := newAttributeDecoder(data)
	if err != nil {
		return err
	}
	for ad.Next() {
		switch ad.Type() {
		case nftaByteorderSreg:
			a.SReg = Reg(ad.Uint32())
		case nftaByteorderDreg:
			a.DReg = Reg(ad.Uint32())
		case nftaByteorderOp:
			a.Op = ByteorderOp(ad.Uint32())
		case nftaByteorderLen:
			a.Len = ad.Uint32()
		case nftaByteorderSize:
			a.Size = ad.Uint32()
		}
	}
	return ad.Err()
}

// https://github.com/torvalds/linux/blob/v7.1/include/uapi/linux/netfilter/nf_tables.h#L668
type CmpOp uint32

// https://github.com/torvalds/linux/blob/v7.1/include/uapi/linux/netfilter/nf_tables.h#L668
const (
	CmpEq CmpOp = iota
	CmpNeq
	CmpLt
	CmpLte
	CmpGt
	CmpGte
)

// https://github.com/torvalds/linux/blob/v7.1/include/uapi/linux/netfilter/nf_tables.h#L687
const (
	nftaCmpSreg = unix.NFTA_CMP_SREG
	nftaCmpOp   = unix.NFTA_CMP_OP
	nftaCmpData = unix.NFTA_CMP_DATA
)

// https://github.com/torvalds/linux/blob/v7.1/include/uapi/linux/netfilter/nf_tables.h#L687
type ExprCmp struct {
	SReg Reg
	Op   CmpOp
	Data *ExprData
}

func (ExprCmp) exprName() exprName { return exprNameCmp }

func (a *ExprCmp) marshal() ([]byte, error) {
	ae := newAttributeEncoder()
	ae.Uint32(nftaCmpSreg, uint32(a.SReg))
	ae.Uint32(nftaCmpOp, uint32(a.Op))
	if a.Data != nil {
		b, err := a.Data.marshal()
		if err != nil {
			return nil, err
		}
		ae.Bytes(unix.NLA_F_NESTED|nftaCmpData, b)
	}
	return ae.Encode()
}

func (a *ExprCmp) unmarshal(data []byte) error {
	ad, err := newAttributeDecoder(data)
	if err != nil {
		return err
	}
	for ad.Next() {
		switch ad.Type() {
		case nftaCmpSreg:
			a.SReg = Reg(ad.Uint32())
		case nftaCmpOp:
			a.Op = CmpOp(ad.Uint32())
		case nftaCmpData:
			a.Data = &ExprData{}
			if err := a.Data.unmarshal(ad.Bytes()); err != nil {
				return err
			}
		}
	}
	return ad.Err()
}

// https://github.com/torvalds/linux/blob/v7.1/include/uapi/linux/netfilter/nf_tables.h#L1222
type ConnlimitFlags uint32

// https://github.com/torvalds/linux/blob/v7.1/include/uapi/linux/netfilter/nf_tables.h#L1222
const (
	ConnlimitInv ConnlimitFlags = 1 << 0
)

// https://github.com/torvalds/linux/blob/v7.1/include/uapi/linux/netfilter/nf_tables.h#L1227
const (
	nftaConnlimitCount = 0x01
	nftaConnlimitFlags = 0x02
)

// https://github.com/torvalds/linux/blob/v7.1/include/uapi/linux/netfilter/nf_tables.h#L1227
type ExprConnlimit struct {
	Count *uint32
	Flags *ConnlimitFlags
}

func (ExprConnlimit) exprName() exprName { return exprNameConnlimit }

func (a *ExprConnlimit) marshal() ([]byte, error) {
	ae := newAttributeEncoder()
	if a.Count != nil {
		ae.Uint32(nftaConnlimitCount, *a.Count)
	}
	if a.Flags != nil {
		ae.Uint32(nftaConnlimitFlags, uint32(*a.Flags))
	}
	return ae.Encode()
}

func (a *ExprConnlimit) unmarshal(data []byte) error {
	ad, err := newAttributeDecoder(data)
	if err != nil {
		return err
	}
	for ad.Next() {
		switch ad.Type() {
		case nftaConnlimitCount:
			v := ad.Uint32()
			a.Count = &v
		case nftaConnlimitFlags:
			v := ConnlimitFlags(ad.Uint32())
			a.Flags = &v
		}
	}
	return ad.Err()
}

// https://github.com/torvalds/linux/blob/v7.1/include/uapi/linux/netfilter/nf_tables.h#L1266
const (
	nftaCounterBytes   = unix.NFTA_COUNTER_BYTES
	nftaCounterPackets = unix.NFTA_COUNTER_PACKETS
)

// https://github.com/torvalds/linux/blob/v7.1/include/uapi/linux/netfilter/nf_tables.h#L1266
type ExprCounter struct {
	Bytes   uint64
	Packets uint64
}

func (ExprCounter) exprName() exprName { return exprNameCounter }

func (a *ExprCounter) marshal() ([]byte, error) {
	ae := newAttributeEncoder()
	ae.Uint64(nftaCounterBytes, a.Bytes)
	ae.Uint64(nftaCounterPackets, a.Packets)
	return ae.Encode()
}

func (a *ExprCounter) unmarshal(data []byte) error {
	ad, err := newAttributeDecoder(data)
	if err != nil {
		return err
	}
	for ad.Next() {
		switch ad.Type() {
		case nftaCounterBytes:
			a.Bytes = ad.Uint64()
		case nftaCounterPackets:
			a.Packets = ad.Uint64()
		}
	}
	return ad.Err()
}

// Pre-computed conntrack state bits for use with NFT_CT_STATE key.
// https://github.com/torvalds/linux/blob/v7.1/include/uapi/linux/netfilter/nf_conntrack_common.h#L7
type CTState uint32

const (
	CTStateInvalid     CTState = 1 << 0 // NF_CT_STATE_INVALID_BIT
	CTStateEstablished CTState = 1 << 1 // NfCtStateBit(IP_CT_ESTABLISHED)
	CTStateRelated     CTState = 1 << 2 // NfCtStateBit(IP_CT_RELATED)
	CTStateNew         CTState = 1 << 3 // NfCtStateBit(IP_CT_NEW)
	CTStateUntracked   CTState = 1 << 6 // NF_CT_STATE_UNTRACKED_BIT
)

// Bytes encodes the CTState bitmask as native-endian bytes for use in ExprData.Value.
func (s CTState) Bytes() []byte {
	b := make([]byte, 4)
	binary.NativeEndian.PutUint32(b, uint32(s))
	return b
}

// https://github.com/torvalds/linux/blob/v7.1/include/uapi/linux/netfilter/nf_tables.h#L1132
type CTKey uint32

const (
	CTKeyState CTKey = iota
	CTKeyDirection
	CTKeyStatus
	CTKeyMark
	CTKeySecmark
	CTKeyExpiration
	CTKeyHelper
	CTKeyL3Protocol
	CTKeySrc
	CTKeyDst
	CTKeyProtocol
	CTKeyProtoSrc
	CTKeyProtoDst
	CTKeyLabels
	CTKeyPkts
	CTKeyBytes
	CTKeyAvgPkt
	CTKeyZone
	CTKeyEventMask
	CTKeySrcIP
	CTKeyDstIP
	CTKeySrcIP6
	CTKeyDstIP6
	CTKeyID
)

// https://github.com/torvalds/linux/blob/v7.1/include/uapi/linux/netfilter/nf_tables.h#L1189
const (
	nftaCtDreg      = unix.NFTA_CT_DREG
	nftaCtKey       = unix.NFTA_CT_KEY
	nftaCtDirection = unix.NFTA_CT_DIRECTION
	nftaCtSreg      = unix.NFTA_CT_SREG
)

// https://github.com/torvalds/linux/blob/v7.1/include/uapi/linux/netfilter/nf_tables.h#L1189
type ExprCt struct {
	Key       CTKey
	DReg      *Reg
	SReg      *Reg
	Direction *uint8
}

func (ExprCt) exprName() exprName { return exprNameCt }

func (a *ExprCt) marshal() ([]byte, error) {
	ae := newAttributeEncoder()
	ae.Uint32(nftaCtKey, uint32(a.Key))
	if a.DReg != nil {
		ae.Uint32(nftaCtDreg, uint32(*a.DReg))
	}
	if a.SReg != nil {
		ae.Uint32(nftaCtSreg, uint32(*a.SReg))
	}
	if a.Direction != nil {
		ae.Uint8(nftaCtDirection, *a.Direction)
	}
	return ae.Encode()
}

func (a *ExprCt) unmarshal(data []byte) error {
	ad, err := newAttributeDecoder(data)
	if err != nil {
		return err
	}
	for ad.Next() {
		switch ad.Type() {
		case nftaCtKey:
			a.Key = CTKey(ad.Uint32())
		case nftaCtDreg:
			v := Reg(ad.Uint32())
			a.DReg = &v
		case nftaCtSreg:
			v := Reg(ad.Uint32())
			a.SReg = &v
		case nftaCtDirection:
			v := ad.Uint8()
			a.Direction = &v
		}
	}
	return ad.Err()
}

// https://github.com/torvalds/linux/blob/v7.1/include/uapi/linux/netfilter/nf_tables.h#L512
const (
	nftaDataValue   = unix.NFTA_DATA_VALUE
	nftaDataVerdict = unix.NFTA_DATA_VERDICT
)

// https://github.com/torvalds/linux/blob/v7.1/include/uapi/linux/netfilter/nf_tables.h#L512
type ExprData struct {
	Value   []byte
	Verdict *ExprVerdict
}

func (ExprData) exprName() exprName { return exprNameData }

func (a *ExprData) marshal() ([]byte, error) {
	ae := newAttributeEncoder()
	if len(a.Value) > 0 {
		ae.Bytes(nftaDataValue, a.Value)
	}
	if a.Verdict != nil {
		b, err := a.Verdict.marshal()
		if err != nil {
			return nil, err
		}
		ae.Bytes(unix.NLA_F_NESTED|nftaDataVerdict, b)
	}
	return ae.Encode()
}

func (a *ExprData) unmarshal(data []byte) error {
	ad, err := newAttributeDecoder(data)
	if err != nil {
		return err
	}
	for ad.Next() {
		switch ad.Type() {
		case nftaDataValue:
			a.Value = ad.Bytes()
		case nftaDataVerdict:
			a.Verdict = &ExprVerdict{}
			if err := a.Verdict.unmarshal(ad.Bytes()); err != nil {
				return err
			}
		}
	}
	return ad.Err()
}

// https://github.com/torvalds/linux/blob/v7.1/include/uapi/linux/netfilter/nf_tables.h#L1533
const (
	nftaDupSregAddr = unix.NFTA_DUP_SREG_ADDR
	nftaDupSregDev  = unix.NFTA_DUP_SREG_DEV
)

// https://github.com/torvalds/linux/blob/v7.1/include/uapi/linux/netfilter/nf_tables.h#L1533
type ExprDup struct {
	SregAddr *uint32
	SregDev  *uint32
}

func (ExprDup) exprName() exprName { return exprNameDup }

func (a *ExprDup) marshal() ([]byte, error) {
	ae := newAttributeEncoder()
	if a.SregAddr != nil {
		ae.Uint32(nftaDupSregAddr, *a.SregAddr)
	}
	if a.SregDev != nil {
		ae.Uint32(nftaDupSregDev, *a.SregDev)
	}
	return ae.Encode()
}

func (a *ExprDup) unmarshal(data []byte) error {
	ad, err := newAttributeDecoder(data)
	if err != nil {
		return err
	}
	for ad.Next() {
		switch ad.Type() {
		case nftaDupSregAddr:
			v := ad.Uint32()
			a.SregAddr = &v
		case nftaDupSregDev:
			v := ad.Uint32()
			a.SregDev = &v
		}
	}
	return ad.Err()
}

// https://github.com/torvalds/linux/blob/v7.1/include/uapi/linux/netfilter/nf_tables.h#L767
const (
	nftaDynsetSetName  = unix.NFTA_DYNSET_SET_NAME
	nftaDynsetSetID    = unix.NFTA_DYNSET_SET_ID
	nftaDynsetOp       = unix.NFTA_DYNSET_OP
	nftaDynsetSregKey  = unix.NFTA_DYNSET_SREG_KEY
	nftaDynsetSregData = unix.NFTA_DYNSET_SREG_DATA
	nftaDynsetTimeout  = unix.NFTA_DYNSET_TIMEOUT
	nftaDynsetExpr     = unix.NFTA_DYNSET_EXPR
	nftaDynsetFlags    = unix.NFTA_DYNSET_FLAGS
)

// https://github.com/torvalds/linux/blob/v7.1/include/uapi/linux/netfilter/nf_tables.h#L755
type DynsetOp uint32

const (
	DynsetAdd DynsetOp = iota
	DynsetUpdate
	DynsetDelete
)

// https://github.com/torvalds/linux/blob/v7.1/include/uapi/linux/netfilter/nf_tables.h#L761
type DynsetFlags uint32

const (
	DynsetInv  DynsetFlags = 1 << 0
	DynsetExpr DynsetFlags = 1 << 1
)

// https://github.com/torvalds/linux/blob/v7.1/include/uapi/linux/netfilter/nf_tables.h#L767
type ExprDynset struct {
	SetName  string
	Op       DynsetOp
	SregKey  uint32
	SetID    *uint32
	SregData *uint32
	Timeout  *uint64
	Flags    *DynsetFlags
	Expr     Expr
}

func (ExprDynset) exprName() exprName { return exprNameDynset }

func (a *ExprDynset) marshal() ([]byte, error) {
	ae := newAttributeEncoder()
	ae.String(nftaDynsetSetName, a.SetName)
	ae.Uint32(nftaDynsetOp, uint32(a.Op))
	ae.Uint32(nftaDynsetSregKey, a.SregKey)
	if a.SetID != nil {
		ae.Uint32(nftaDynsetSetID, *a.SetID)
	}
	if a.SregData != nil {
		ae.Uint32(nftaDynsetSregData, *a.SregData)
	}
	if a.Timeout != nil {
		ae.Uint64(nftaDynsetTimeout, *a.Timeout)
	}
	if a.Flags != nil {
		ae.Uint32(nftaDynsetFlags, uint32(*a.Flags))
	}
	if a.Expr != nil {
		b, err := marshalExpr(a.Expr)
		if err != nil {
			return nil, err
		}
		ae.Bytes(unix.NLA_F_NESTED|nftaDynsetExpr, b)
	}
	return ae.Encode()
}

func (a *ExprDynset) unmarshal(data []byte) error {
	ad, err := newAttributeDecoder(data)
	if err != nil {
		return err
	}
	for ad.Next() {
		switch ad.Type() {
		case nftaDynsetSetName:
			a.SetName = ad.String()
		case nftaDynsetOp:
			a.Op = DynsetOp(ad.Uint32())
		case nftaDynsetSregKey:
			a.SregKey = ad.Uint32()
		case nftaDynsetSetID:
			v := ad.Uint32()
			a.SetID = &v
		case nftaDynsetSregData:
			v := ad.Uint32()
			a.SregData = &v
		case nftaDynsetTimeout:
			v := ad.Uint64()
			a.Timeout = &v
		case nftaDynsetFlags:
			v := DynsetFlags(ad.Uint32())
			a.Flags = &v
		case nftaDynsetExpr:
			e, err := unmarshalExpr(ad.Bytes())
			if err != nil {
				return err
			}
			a.Expr = e
		}
	}
	return ad.Err()
}

// https://github.com/torvalds/linux/blob/v7.1/include/uapi/linux/netfilter/nf_tables.h#L880
type ExthdrFlags uint32

const (
	ExthdrPresent ExthdrFlags = 1 << 0
)

// https://github.com/torvalds/linux/blob/v7.1/include/uapi/linux/netfilter/nf_tables.h#L885
type ExthdrOp uint32

const (
	ExthdrIPv6 ExthdrOp = iota
	ExthdrTCPOpt
	ExthdrIPv4
	ExthdrSCTP
	ExthdrDCCP
)

// https://github.com/torvalds/linux/blob/v7.1/include/uapi/linux/netfilter/nf_tables.h#L904
const (
	nftaExthdrDreg   = unix.NFTA_EXTHDR_DREG
	nftaExthdrType   = unix.NFTA_EXTHDR_TYPE
	nftaExthdrOffset = unix.NFTA_EXTHDR_OFFSET
	nftaExthdrLen    = unix.NFTA_EXTHDR_LEN
	nftaExthdrFlags  = unix.NFTA_EXTHDR_FLAGS
	nftaExthdrOp     = unix.NFTA_EXTHDR_OP
	nftaExthdrSreg   = unix.NFTA_EXTHDR_SREG
)

// https://github.com/torvalds/linux/blob/v7.1/include/uapi/linux/netfilter/nf_tables.h#L904
type ExprExthdr struct {
	Type   *uint8
	Offset *uint32
	Len    *uint32
	DReg   *Reg
	Flags  *ExthdrFlags
	Op     *ExthdrOp
	SReg   *Reg
}

func (ExprExthdr) exprName() exprName { return exprNameExthdr }

func (a *ExprExthdr) marshal() ([]byte, error) {
	ae := newAttributeEncoder()
	if a.Type != nil {
		ae.Uint8(nftaExthdrType, *a.Type)
	}
	if a.Offset != nil {
		ae.Uint32(nftaExthdrOffset, *a.Offset)
	}
	if a.Len != nil {
		ae.Uint32(nftaExthdrLen, *a.Len)
	}
	if a.DReg != nil {
		ae.Uint32(nftaExthdrDreg, uint32(*a.DReg))
	}
	if a.Flags != nil {
		ae.Uint32(nftaExthdrFlags, uint32(*a.Flags))
	}
	if a.Op != nil {
		ae.Uint32(nftaExthdrOp, uint32(*a.Op))
	}
	if a.SReg != nil {
		ae.Uint32(nftaExthdrSreg, uint32(*a.SReg))
	}
	return ae.Encode()
}

func (a *ExprExthdr) unmarshal(data []byte) error {
	ad, err := newAttributeDecoder(data)
	if err != nil {
		return err
	}
	for ad.Next() {
		switch ad.Type() {
		case nftaExthdrType:
			v := ad.Uint8()
			a.Type = &v
		case nftaExthdrOffset:
			v := ad.Uint32()
			a.Offset = &v
		case nftaExthdrLen:
			v := ad.Uint32()
			a.Len = &v
		case nftaExthdrDreg:
			v := Reg(ad.Uint32())
			a.DReg = &v
		case nftaExthdrFlags:
			v := ExthdrFlags(ad.Uint32())
			a.Flags = &v
		case nftaExthdrOp:
			v := ExthdrOp(ad.Uint32())
			a.Op = &v
		case nftaExthdrSreg:
			v := Reg(ad.Uint32())
			a.SReg = &v
		}
	}
	return ad.Err()
}

// https://github.com/torvalds/linux/blob/v7.1/include/uapi/linux/netfilter/nf_tables.h#L1614
type FibResult uint32

const (
	FibResultOIF      FibResult = 1
	FibResultOIFName  FibResult = 2
	FibResultAddrType FibResult = 3
)

// https://github.com/torvalds/linux/blob/v7.1/include/uapi/linux/netfilter/nf_tables.h#L1624
type FibFlags uint32

const (
	FibSAddr   FibFlags = 1 << 0
	FibDAddr   FibFlags = 1 << 1
	FibMark    FibFlags = 1 << 2
	FibIIF     FibFlags = 1 << 3
	FibOIF     FibFlags = 1 << 4
	FibPresent FibFlags = 1 << 5
)

// https://github.com/torvalds/linux/blob/v7.1/include/uapi/linux/netfilter/nf_tables.h#L1597
const (
	nftaFibDreg   = unix.NFTA_FIB_DREG
	nftaFibResult = unix.NFTA_FIB_RESULT
	nftaFibFlags  = unix.NFTA_FIB_FLAGS
)

// https://github.com/torvalds/linux/blob/v7.1/include/uapi/linux/netfilter/nf_tables.h#L1597
type ExprFib struct {
	DReg   Reg
	Result FibResult
	Flags  FibFlags
}

func (ExprFib) exprName() exprName { return exprNameFib }

func (a *ExprFib) marshal() ([]byte, error) {
	ae := newAttributeEncoder()
	ae.Uint32(nftaFibDreg, uint32(a.DReg))
	ae.Uint32(nftaFibResult, uint32(a.Result))
	ae.Uint32(nftaFibFlags, uint32(a.Flags))
	return ae.Encode()
}

func (a *ExprFib) unmarshal(data []byte) error {
	ad, err := newAttributeDecoder(data)
	if err != nil {
		return err
	}
	for ad.Next() {
		switch ad.Type() {
		case nftaFibDreg:
			a.DReg = Reg(ad.Uint32())
		case nftaFibResult:
			a.Result = FibResult(ad.Uint32())
		case nftaFibFlags:
			a.Flags = FibFlags(ad.Uint32())
		}
	}
	return ad.Err()
}

// https://github.com/torvalds/linux/blob/f83a4f2a4d8c485922fba3018a64fc8f4cfd315f/include/uapi/linux/netfilter/nf_tables.h#L1560
const (
	nftaFlowTableName = 0x01
)

// https://github.com/torvalds/linux/blob/v7.1/include/uapi/linux/netfilter/nf_tables.h#L1207
type ExprFlowOffload struct {
	TableName string
}

func (ExprFlowOffload) exprName() exprName { return exprNameFlowOffload }

func (a *ExprFlowOffload) marshal() ([]byte, error) {
	ae := newAttributeEncoder()
	ae.String(nftaFlowTableName, a.TableName)
	return ae.Encode()
}

func (a *ExprFlowOffload) unmarshal(data []byte) error {
	ad, err := newAttributeDecoder(data)
	if err != nil {
		return err
	}
	for ad.Next() {
		switch ad.Type() {
		case nftaFlowTableName:
			a.TableName = ad.String()
		}
	}
	return ad.Err()
}

// https://github.com/torvalds/linux/blob/f83a4f2a4d8c485922fba3018a64fc8f4cfd315f/include/uapi/linux/netfilter/nf_tables.h#L1515
const (
	nftaFwdSregDev  = unix.NFTA_FWD_SREG_DEV
	nftaFwdSregAddr = 0x02
	nftaFwdNfProto  = 0x03
)

// https://github.com/torvalds/linux/blob/v7.1/include/uapi/linux/netfilter/nf_tables.h#L1547
type ExprFwd struct {
	SregDev  uint32
	SregAddr *uint32
	NfProto  *Family
}

func (ExprFwd) exprName() exprName { return exprNameFwd }

func (a *ExprFwd) marshal() ([]byte, error) {
	ae := newAttributeEncoder()
	ae.Uint32(nftaFwdSregDev, a.SregDev)
	if a.SregAddr != nil {
		ae.Uint32(nftaFwdSregAddr, *a.SregAddr)
	}
	if a.NfProto != nil {
		ae.Uint32(nftaFwdNfProto, uint32(*a.NfProto))
	}
	return ae.Encode()
}

func (a *ExprFwd) unmarshal(data []byte) error {
	ad, err := newAttributeDecoder(data)
	if err != nil {
		return err
	}
	for ad.Next() {
		switch ad.Type() {
		case nftaFwdSregDev:
			a.SregDev = ad.Uint32()
		case nftaFwdSregAddr:
			v := ad.Uint32()
			a.SregAddr = &v
		case nftaFwdNfProto:
			v := Family(ad.Uint32())
			a.NfProto = &v
		}
	}
	return ad.Err()
}

// https://github.com/torvalds/linux/blob/v7.1/include/uapi/linux/netfilter/nf_tables.h#L931
type HashType uint32

const (
	HashTypeJenkins HashType = iota
	HashTypeSym
)

// https://github.com/torvalds/linux/blob/v7.1/include/uapi/linux/netfilter/nf_tables.h#L1041
const (
	nftaHashSreg    = unix.NFTA_HASH_SREG
	nftaHashDreg    = unix.NFTA_HASH_DREG
	nftaHashLen     = unix.NFTA_HASH_LEN
	nftaHashModulus = unix.NFTA_HASH_MODULUS
	nftaHashSeed    = unix.NFTA_HASH_SEED
	nftaHashOffset  = unix.NFTA_HASH_OFFSET
	nftaHashType    = unix.NFTA_HASH_TYPE
)

// https://github.com/torvalds/linux/blob/v7.1/include/uapi/linux/netfilter/nf_tables.h#L1041
type ExprHash struct {
	SReg    Reg
	DReg    Reg
	Len     *uint32
	Modulus *uint32
	Seed    *uint32
	Offset  *uint32
	Type    *HashType
}

func (ExprHash) exprName() exprName { return exprNameHash }

func (a *ExprHash) marshal() ([]byte, error) {
	ae := newAttributeEncoder()
	ae.Uint32(nftaHashSreg, uint32(a.SReg))
	ae.Uint32(nftaHashDreg, uint32(a.DReg))
	if a.Len != nil {
		ae.Uint32(nftaHashLen, *a.Len)
	}
	if a.Modulus != nil {
		ae.Uint32(nftaHashModulus, *a.Modulus)
	}
	if a.Seed != nil {
		ae.Uint32(nftaHashSeed, *a.Seed)
	}
	if a.Offset != nil {
		ae.Uint32(nftaHashOffset, *a.Offset)
	}
	if a.Type != nil {
		ae.Uint32(nftaHashType, uint32(*a.Type))
	}
	return ae.Encode()
}

func (a *ExprHash) unmarshal(data []byte) error {
	ad, err := newAttributeDecoder(data)
	if err != nil {
		return err
	}
	for ad.Next() {
		switch ad.Type() {
		case nftaHashSreg:
			a.SReg = Reg(ad.Uint32())
		case nftaHashDreg:
			a.DReg = Reg(ad.Uint32())
		case nftaHashLen:
			v := ad.Uint32()
			a.Len = &v
		case nftaHashModulus:
			v := ad.Uint32()
			a.Modulus = &v
		case nftaHashSeed:
			v := ad.Uint32()
			a.Seed = &v
		case nftaHashOffset:
			v := ad.Uint32()
			a.Offset = &v
		case nftaHashType:
			v := HashType(ad.Uint32())
			a.Type = &v
		}
	}
	return ad.Err()
}

// https://github.com/torvalds/linux/blob/v7.1/include/uapi/linux/netfilter/nf_tables.h#L559
const (
	nftaImmediateDreg = unix.NFTA_IMMEDIATE_DREG
	nftaImmediateData = unix.NFTA_IMMEDIATE_DATA
)

// https://github.com/torvalds/linux/blob/v7.1/include/uapi/linux/netfilter/nf_tables.h#L559
type ExprImmediate struct {
	DReg Reg
	Data *ExprData
}

func (ExprImmediate) exprName() exprName { return exprNameImmediate }

func (a *ExprImmediate) marshal() ([]byte, error) {
	ae := newAttributeEncoder()
	ae.Uint32(nftaImmediateDreg, uint32(a.DReg))
	if a.Data != nil {
		b, err := a.Data.marshal()
		if err != nil {
			return nil, err
		}
		ae.Bytes(unix.NLA_F_NESTED|nftaImmediateData, b)
	}
	return ae.Encode()
}

func (a *ExprImmediate) unmarshal(data []byte) error {
	ad, err := newAttributeDecoder(data)
	if err != nil {
		return err
	}
	for ad.Next() {
		switch ad.Type() {
		case nftaImmediateDreg:
			a.DReg = Reg(ad.Uint32())
		case nftaImmediateData:
			a.Data = &ExprData{}
			if err := a.Data.unmarshal(ad.Bytes()); err != nil {
				return err
			}
		}
	}
	return ad.Err()
}

// https://github.com/torvalds/linux/blob/v7.1/include/uapi/linux/netfilter/nf_tables.h#L828
type InnerType uint32

const (
	InnerTypeUnspec InnerType = iota
	InnerTypeVXLAN
	InnerTypeGeneve
)

// https://github.com/torvalds/linux/blob/v7.1/include/uapi/linux/netfilter/nf_tables.h#L834
type InnerFlags uint32

const (
	InnerHdrsize InnerFlags = 1 << 0
	InnerLL      InnerFlags = 1 << 1
	InnerNH      InnerFlags = 1 << 2
	InnerTH      InnerFlags = 1 << 3
)

// https://github.com/torvalds/linux/blob/v7.1/include/uapi/linux/netfilter/nf_tables.h#L843
const (
	nftaInnerNum     = 0x01
	nftaInnerType    = 0x02
	nftaInnerFlags   = 0x03
	nftaInnerHdrsize = 0x04
	nftaInnerExpr    = 0x05
)

// https://github.com/torvalds/linux/blob/v7.1/include/uapi/linux/netfilter/nf_tables.h#L843
type ExprInner struct {
	Num     *uint32
	Type    *InnerType
	Flags   *InnerFlags
	Hdrsize *uint32
	Expr    Expr
}

func (ExprInner) exprName() exprName { return exprNameInner }

func (a *ExprInner) marshal() ([]byte, error) {
	ae := newAttributeEncoder()
	if a.Num != nil {
		ae.Uint32(nftaInnerNum, *a.Num)
	}
	if a.Type != nil {
		ae.Uint32(nftaInnerType, uint32(*a.Type))
	}
	if a.Flags != nil {
		ae.Uint32(nftaInnerFlags, uint32(*a.Flags))
	}
	if a.Hdrsize != nil {
		ae.Uint32(nftaInnerHdrsize, *a.Hdrsize)
	}
	if a.Expr != nil {
		b, err := marshalExpr(a.Expr)
		if err != nil {
			return nil, err
		}
		ae.Bytes(unix.NLA_F_NESTED|nftaInnerExpr, b)
	}
	return ae.Encode()
}

func (a *ExprInner) unmarshal(data []byte) error {
	ad, err := newAttributeDecoder(data)
	if err != nil {
		return err
	}
	for ad.Next() {
		switch ad.Type() {
		case nftaInnerNum:
			v := ad.Uint32()
			a.Num = &v
		case nftaInnerType:
			v := InnerType(ad.Uint32())
			a.Type = &v
		case nftaInnerFlags:
			v := InnerFlags(ad.Uint32())
			a.Flags = &v
		case nftaInnerHdrsize:
			v := ad.Uint32()
			a.Hdrsize = &v
		case nftaInnerExpr:
			e, err := unmarshalExpr(ad.Bytes())
			if err != nil {
				return err
			}
			a.Expr = e
		}
	}
	return ad.Err()
}

// https://github.com/torvalds/linux/blob/v7.1/include/uapi/linux/netfilter/nf_tables.h#L1281
const (
	nftaLastSet   = 0x01
	nftaLastMsecs = 0x02
)

// https://github.com/torvalds/linux/blob/v7.1/include/uapi/linux/netfilter/nf_tables.h#L1281
type ExprLast struct {
	Set   *uint32
	Msecs *uint64
}

func (ExprLast) exprName() exprName { return exprNameLast }

func (a *ExprLast) marshal() ([]byte, error) {
	ae := newAttributeEncoder()
	if a.Set != nil {
		ae.Uint32(nftaLastSet, *a.Set)
	}
	if a.Msecs != nil {
		ae.Uint64(nftaLastMsecs, *a.Msecs)
	}
	return ae.Encode()
}

func (a *ExprLast) unmarshal(data []byte) error {
	ad, err := newAttributeDecoder(data)
	if err != nil {
		return err
	}
	for ad.Next() {
		switch ad.Type() {
		case nftaLastSet:
			v := ad.Uint32()
			a.Set = &v
		case nftaLastMsecs:
			v := ad.Uint64()
			a.Msecs = &v
		}
	}
	return ad.Err()
}

// https://github.com/torvalds/linux/blob/v7.1/include/uapi/linux/netfilter/nf_tables.h#L1217
type LimitType uint32

const (
	LimitTypePkts LimitType = iota
	LimitTypePktBytes
)

// https://github.com/torvalds/linux/blob/v7.1/include/uapi/linux/netfilter/nf_tables.h#L1222
type LimitFlags uint32

const (
	LimitInv LimitFlags = 1 << 0
)

// https://github.com/torvalds/linux/blob/v7.1/include/uapi/linux/netfilter/nf_tables.h#L1227
const (
	nftaLimitRate  = unix.NFTA_LIMIT_RATE
	nftaLimitUnit  = unix.NFTA_LIMIT_UNIT
	nftaLimitBurst = unix.NFTA_LIMIT_BURST
	nftaLimitType  = unix.NFTA_LIMIT_TYPE
	nftaLimitFlags = unix.NFTA_LIMIT_FLAGS
)

// https://github.com/torvalds/linux/blob/v7.1/include/uapi/linux/netfilter/nf_tables.h#L1227
type ExprLimit struct {
	Rate  uint64
	Unit  *uint64
	Burst *uint32
	Type  *LimitType
	Flags *LimitFlags
}

func (ExprLimit) exprName() exprName { return exprNameLimit }

func (a *ExprLimit) marshal() ([]byte, error) {
	ae := newAttributeEncoder()
	ae.Uint64(nftaLimitRate, a.Rate)
	if a.Unit != nil {
		ae.Uint64(nftaLimitUnit, *a.Unit)
	}
	if a.Burst != nil {
		ae.Uint32(nftaLimitBurst, *a.Burst)
	}
	if a.Type != nil {
		ae.Uint32(nftaLimitType, uint32(*a.Type))
	}
	if a.Flags != nil {
		ae.Uint32(nftaLimitFlags, uint32(*a.Flags))
	}
	return ae.Encode()
}

func (a *ExprLimit) unmarshal(data []byte) error {
	ad, err := newAttributeDecoder(data)
	if err != nil {
		return err
	}
	for ad.Next() {
		switch ad.Type() {
		case nftaLimitRate:
			a.Rate = ad.Uint64()
		case nftaLimitUnit:
			v := ad.Uint64()
			a.Unit = &v
		case nftaLimitBurst:
			v := ad.Uint32()
			a.Burst = &v
		case nftaLimitType:
			v := LimitType(ad.Uint32())
			a.Type = &v
		case nftaLimitFlags:
			v := LimitFlags(ad.Uint32())
			a.Flags = &v
		}
	}
	return ad.Err()
}

// https://github.com/torvalds/linux/blob/v7.1/include/uapi/linux/netfilter.h
type LogFlags uint32

const (
	LogTCPSeq    LogFlags = 1 << 0
	LogTCPOpt    LogFlags = 1 << 1
	LogIPOpt     LogFlags = 1 << 2
	LogUID       LogFlags = 1 << 3
	LogMACDecode LogFlags = 1 << 5
)

// https://github.com/torvalds/linux/blob/v7.1/include/uapi/linux/netfilter/nf_log.h
type LogLevel uint32

const (
	LogLevelEmerg LogLevel = iota
	LogLevelAlert
	LogLevelCrit
	LogLevelErr
	LogLevelWarning
	LogLevelNotice
	LogLevelInfo
	LogLevelDebug
	LogLevelAudit
)

// https://github.com/torvalds/linux/blob/v7.1/include/uapi/linux/netfilter/nf_tables.h#L1296
const (
	nftaLogGroup      = unix.NFTA_LOG_GROUP
	nftaLogPrefix     = unix.NFTA_LOG_PREFIX
	nftaLogSnaplen    = unix.NFTA_LOG_SNAPLEN
	nftaLogQthreshold = unix.NFTA_LOG_QTHRESHOLD
	nftaLogLevel      = unix.NFTA_LOG_LEVEL
	nftaLogFlags      = unix.NFTA_LOG_FLAGS
)

// https://github.com/torvalds/linux/blob/v7.1/include/uapi/linux/netfilter/nf_tables.h#L1296
type ExprLog struct {
	Group      *uint16
	Prefix     string
	Snaplen    *uint32
	Qthreshold *uint16
	Level      *LogLevel
	Flags      *LogFlags
}

func (ExprLog) exprName() exprName { return exprNameLog }

func (a *ExprLog) marshal() ([]byte, error) {
	ae := newAttributeEncoder()
	if a.Group != nil {
		ae.Uint16(nftaLogGroup, *a.Group)
	}
	if a.Prefix != "" {
		ae.String(nftaLogPrefix, a.Prefix)
	}
	if a.Snaplen != nil {
		ae.Uint32(nftaLogSnaplen, *a.Snaplen)
	}
	if a.Qthreshold != nil {
		ae.Uint16(nftaLogQthreshold, *a.Qthreshold)
	}
	if a.Level != nil {
		ae.Uint32(nftaLogLevel, uint32(*a.Level))
	}
	if a.Flags != nil {
		ae.Uint32(nftaLogFlags, uint32(*a.Flags))
	}
	return ae.Encode()
}

func (a *ExprLog) unmarshal(data []byte) error {
	ad, err := newAttributeDecoder(data)
	if err != nil {
		return err
	}
	for ad.Next() {
		switch ad.Type() {
		case nftaLogGroup:
			v := ad.Uint16()
			a.Group = &v
		case nftaLogPrefix:
			a.Prefix = ad.String()
		case nftaLogSnaplen:
			v := ad.Uint32()
			a.Snaplen = &v
		case nftaLogQthreshold:
			v := ad.Uint16()
			a.Qthreshold = &v
		case nftaLogLevel:
			v := LogLevel(ad.Uint32())
			a.Level = &v
		case nftaLogFlags:
			v := LogFlags(ad.Uint32())
			a.Flags = &v
		}
	}
	return ad.Err()
}

// https://github.com/torvalds/linux/blob/v7.1/include/uapi/linux/netfilter/nf_tables.h#L731
type LookupFlags uint32

const (
	LookupInv LookupFlags = 1 << 0
)

// https://github.com/torvalds/linux/blob/v7.1/include/uapi/linux/netfilter/nf_tables.h#L736
const (
	nftaLookupSet   = unix.NFTA_LOOKUP_SET
	nftaLookupSreg  = unix.NFTA_LOOKUP_SREG
	nftaLookupDreg  = unix.NFTA_LOOKUP_DREG
	nftaLookupSetID = unix.NFTA_LOOKUP_SET_ID
	nftaLookupFlags = unix.NFTA_LOOKUP_FLAGS
)

// https://github.com/torvalds/linux/blob/v7.1/include/uapi/linux/netfilter/nf_tables.h#L736
type ExprLookup struct {
	Set   string
	SReg  Reg
	DReg  *Reg
	SetID *uint32
	Flags *LookupFlags
}

func (ExprLookup) exprName() exprName { return exprNameLookup }

func (a *ExprLookup) marshal() ([]byte, error) {
	ae := newAttributeEncoder()
	ae.String(nftaLookupSet, a.Set)
	ae.Uint32(nftaLookupSreg, uint32(a.SReg))
	if a.DReg != nil {
		ae.Uint32(nftaLookupDreg, uint32(*a.DReg))
	}
	if a.SetID != nil {
		ae.Uint32(nftaLookupSetID, *a.SetID)
	}
	if a.Flags != nil {
		ae.Uint32(nftaLookupFlags, uint32(*a.Flags))
	}
	return ae.Encode()
}

func (a *ExprLookup) unmarshal(data []byte) error {
	ad, err := newAttributeDecoder(data)
	if err != nil {
		return err
	}
	for ad.Next() {
		switch ad.Type() {
		case nftaLookupSet:
			a.Set = ad.String()
		case nftaLookupSreg:
			a.SReg = Reg(ad.Uint32())
		case nftaLookupDreg:
			v := Reg(ad.Uint32())
			a.DReg = &v
		case nftaLookupSetID:
			v := ad.Uint32()
			a.SetID = &v
		case nftaLookupFlags:
			v := LookupFlags(ad.Uint32())
			a.Flags = &v
		}
	}
	return ad.Err()
}

// https://github.com/torvalds/linux/blob/v7.1/include/uapi/linux/netfilter/nf_nat.h
type NatFlags uint32

const (
	NatMapIPs           NatFlags = 1 << 0
	NatProtoSpecified   NatFlags = 1 << 1
	NatProtoRandom      NatFlags = 1 << 2
	NatPersistent       NatFlags = 1 << 3
	NatProtoRandomFully NatFlags = 1 << 4
	NatProtoOffset      NatFlags = 1 << 5
	NatNetmap           NatFlags = 1 << 6
)

// https://github.com/torvalds/linux/blob/v7.1/include/uapi/linux/netfilter/nf_tables.h#L1501
const (
	nftaMasqFlags       = unix.NFTA_MASQ_FLAGS
	nftaMasqRegProtoMin = unix.NFTA_MASQ_REG_PROTO_MIN
	nftaMasqRegProtoMax = unix.NFTA_MASQ_REG_PROTO_MAX
)

// https://github.com/torvalds/linux/blob/v7.1/include/uapi/linux/netfilter/nf_tables.h#L1501
type ExprMasq struct {
	Flags       *NatFlags
	RegProtoMin *uint32
	RegProtoMax *uint32
}

func (ExprMasq) exprName() exprName { return exprNameMasq }

func (a *ExprMasq) marshal() ([]byte, error) {
	ae := newAttributeEncoder()
	if a.Flags != nil {
		ae.Uint32(nftaMasqFlags, uint32(*a.Flags))
	}
	if a.RegProtoMin != nil {
		ae.Uint32(nftaMasqRegProtoMin, *a.RegProtoMin)
	}
	if a.RegProtoMax != nil {
		ae.Uint32(nftaMasqRegProtoMax, *a.RegProtoMax)
	}
	return ae.Encode()
}

func (a *ExprMasq) unmarshal(data []byte) error {
	ad, err := newAttributeDecoder(data)
	if err != nil {
		return err
	}
	for ad.Next() {
		switch ad.Type() {
		case nftaMasqFlags:
			v := NatFlags(ad.Uint32())
			a.Flags = &v
		case nftaMasqRegProtoMin:
			v := ad.Uint32()
			a.RegProtoMin = &v
		case nftaMasqRegProtoMax:
			v := ad.Uint32()
			a.RegProtoMax = &v
		}
	}
	return ad.Err()
}

// https://github.com/torvalds/linux/blob/v7.1/include/uapi/linux/netfilter/nf_tables.h#L928
type MetaKey uint32

// MetaKey* — metadata key for ExprMeta.Key.
const (
	MetaKeyLen MetaKey = iota
	MetaKeyProtocol
	MetaKeyPriority
	MetaKeyMark
	MetaKeyIIF
	MetaKeyOIF
	MetaKeyIIFName
	MetaKeyOIFName
	MetaKeyIIFType
	MetaKeyOIFType
	MetaKeySKUID
	MetaKeySKGID
	MetaKeyNFTrace
	MetaKeyRTClassID
	MetaKeySecMark
	MetaKeyNFProto
	MetaKeyL4Proto
	MetaKeyBRIIIFName
	MetaKeyBRIOIFName
	MetaKeyPktType
	MetaKeyCPU
	MetaKeyIIFGroup
	MetaKeyOIFGroup
	MetaKeyCGroup
	MetaKeyPRandom
	MetaKeySecPath
	MetaKeyIIFKind
	MetaKeyOIFKind
	MetaKeyBRIIIFPVID
	MetaKeyBRIIIFVProto
	MetaKeyTimeNS
	MetaKeyTimeDay
	MetaKeyTimeHour
	MetaKeySDIF
	MetaKeySDIFName
	MetaKeyBRIBRoute
	metaKeyIIFType // internal
	MetaKeyBRIIIFHWAddr
)

// https://github.com/torvalds/linux/blob/f83a4f2a4d8c485922fba3018a64fc8f4cfd315f/include/uapi/linux/netfilter/nf_tables.h#L1069
const (
	nftaMetaDreg = unix.NFTA_META_DREG
	nftaMetaKey  = unix.NFTA_META_KEY
	nftaMetaSreg = unix.NFTA_META_SREG
)

// https://github.com/torvalds/linux/blob/f83a4f2a4d8c485922fba3018a64fc8f4cfd315f/include/uapi/linux/netfilter/nf_tables.h#L1069
type ExprMeta struct {
	Key  MetaKey
	DReg *Reg
	SReg *Reg
}

func (ExprMeta) exprName() exprName { return exprNameMeta }

func (a *ExprMeta) marshal() ([]byte, error) {
	ae := newAttributeEncoder()
	ae.Uint32(nftaMetaKey, uint32(a.Key))
	if a.DReg != nil {
		ae.Uint32(nftaMetaDreg, uint32(*a.DReg))
	}
	if a.SReg != nil {
		ae.Uint32(nftaMetaSreg, uint32(*a.SReg))
	}
	return ae.Encode()
}

func (a *ExprMeta) unmarshal(data []byte) error {
	ad, err := newAttributeDecoder(data)
	if err != nil {
		return err
	}
	for ad.Next() {
		switch ad.Type() {
		case nftaMetaKey:
			a.Key = MetaKey(ad.Uint32())
		case nftaMetaDreg:
			v := Reg(ad.Uint32())
			a.DReg = &v
		case nftaMetaSreg:
			v := Reg(ad.Uint32())
			a.SReg = &v
		}
	}
	return ad.Err()
}

// https://github.com/torvalds/linux/blob/v7.1/include/uapi/linux/netfilter/nf_tables.h#L1450
type NatType uint32

const (
	NatTypeSNAT NatType = iota
	NatTypeDNAT
)

// https://github.com/torvalds/linux/blob/v7.1/include/uapi/linux/netfilter/nf_tables.h#L1461
const (
	nftaNatType        = unix.NFTA_NAT_TYPE
	nftaNatFamily      = unix.NFTA_NAT_FAMILY
	nftaNatRegAddrMin  = unix.NFTA_NAT_REG_ADDR_MIN
	nftaNatRegAddrMax  = unix.NFTA_NAT_REG_ADDR_MAX
	nftaNatRegProtoMin = unix.NFTA_NAT_REG_PROTO_MIN
	nftaNatRegProtoMax = unix.NFTA_NAT_REG_PROTO_MAX
	nftaNatFlags       = unix.NFTA_NAT_FLAGS
)

// https://github.com/torvalds/linux/blob/v7.1/include/uapi/linux/netfilter/nf_tables.h#L1461
type ExprNat struct {
	Type        NatType
	Family      *Family
	RegAddrMin  *uint32
	RegAddrMax  *uint32
	RegProtoMin *uint32
	RegProtoMax *uint32
	Flags       *NatFlags
}

func (ExprNat) exprName() exprName { return exprNameNat }

func (a *ExprNat) marshal() ([]byte, error) {
	ae := newAttributeEncoder()
	ae.Uint32(nftaNatType, uint32(a.Type))
	if a.Family != nil {
		ae.Uint32(nftaNatFamily, uint32(*a.Family))
	}
	if a.RegAddrMin != nil {
		ae.Uint32(nftaNatRegAddrMin, *a.RegAddrMin)
	}
	if a.RegAddrMax != nil {
		ae.Uint32(nftaNatRegAddrMax, *a.RegAddrMax)
	}
	if a.RegProtoMin != nil {
		ae.Uint32(nftaNatRegProtoMin, *a.RegProtoMin)
	}
	if a.RegProtoMax != nil {
		ae.Uint32(nftaNatRegProtoMax, *a.RegProtoMax)
	}
	if a.Flags != nil {
		ae.Uint32(nftaNatFlags, uint32(*a.Flags))
	}
	return ae.Encode()
}

func (a *ExprNat) unmarshal(data []byte) error {
	ad, err := newAttributeDecoder(data)
	if err != nil {
		return err
	}
	for ad.Next() {
		switch ad.Type() {
		case nftaNatType:
			a.Type = NatType(ad.Uint32())
		case nftaNatFamily:
			v := Family(ad.Uint32())
			a.Family = &v
		case nftaNatRegAddrMin:
			v := ad.Uint32()
			a.RegAddrMin = &v
		case nftaNatRegAddrMax:
			v := ad.Uint32()
			a.RegAddrMax = &v
		case nftaNatRegProtoMin:
			v := ad.Uint32()
			a.RegProtoMin = &v
		case nftaNatRegProtoMax:
			v := ad.Uint32()
			a.RegProtoMax = &v
		case nftaNatFlags:
			v := NatFlags(ad.Uint32())
			a.Flags = &v
		}
	}
	return ad.Err()
}

// https://github.com/torvalds/linux/blob/v7.1/include/uapi/linux/netfilter/nf_tables.h#L1915
type NumgenType uint32

const (
	NumgenTypeIncremental NumgenType = iota
	NumgenTypeRandom
)

// https://github.com/torvalds/linux/blob/v7.1/include/uapi/linux/netfilter/nf_tables.h#L1894
const (
	nftaNgDreg    = unix.NFTA_NG_DREG
	nftaNgModulus = unix.NFTA_NG_MODULUS
	nftaNgType    = unix.NFTA_NG_TYPE
	nftaNgOffset  = unix.NFTA_NG_OFFSET
)

// https://github.com/torvalds/linux/blob/v7.1/include/uapi/linux/netfilter/nf_tables.h#L1894
type ExprNumgen struct {
	DReg    *Reg
	Modulus *uint32
	Type    *NumgenType
	Offset  *uint32
}

func (ExprNumgen) exprName() exprName { return exprNameNumgen }

func (a *ExprNumgen) marshal() ([]byte, error) {
	ae := newAttributeEncoder()
	if a.DReg != nil {
		ae.Uint32(nftaNgDreg, uint32(*a.DReg))
	}
	if a.Modulus != nil {
		ae.Uint32(nftaNgModulus, *a.Modulus)
	}
	if a.Type != nil {
		ae.Uint32(nftaNgType, uint32(*a.Type))
	}
	if a.Offset != nil {
		ae.Uint32(nftaNgOffset, *a.Offset)
	}
	return ae.Encode()
}

func (a *ExprNumgen) unmarshal(data []byte) error {
	ad, err := newAttributeDecoder(data)
	if err != nil {
		return err
	}
	for ad.Next() {
		switch ad.Type() {
		case nftaNgDreg:
			v := Reg(ad.Uint32())
			a.DReg = &v
		case nftaNgModulus:
			v := ad.Uint32()
			a.Modulus = &v
		case nftaNgType:
			v := NumgenType(ad.Uint32())
			a.Type = &v
		case nftaNgOffset:
			v := ad.Uint32()
			a.Offset = &v
		}
	}
	return ad.Err()
}

// https://github.com/torvalds/linux/blob/v7.1/include/uapi/linux/netfilter/nf_tables.h#L1563
const (
	nftaObjrefImmType = unix.NFTA_OBJREF_IMM_TYPE
	nftaObjrefImmName = unix.NFTA_OBJREF_IMM_NAME
	nftaObjrefSetSreg = unix.NFTA_OBJREF_SET_SREG
	nftaObjrefSetName = unix.NFTA_OBJREF_SET_NAME
	nftaObjrefSetID   = unix.NFTA_OBJREF_SET_ID
)

// https://github.com/torvalds/linux/blob/v7.1/include/uapi/linux/netfilter/nf_tables.h#L1563
type ExprObjref struct {
	ImmType uint32
	ImmName string
	SetSreg *uint32
	SetName string
	SetID   *uint32
}

func (ExprObjref) exprName() exprName { return exprNameObjref }

func (a *ExprObjref) marshal() ([]byte, error) {
	ae := newAttributeEncoder()
	ae.Uint32(nftaObjrefImmType, a.ImmType)
	if a.ImmName != "" {
		ae.String(nftaObjrefImmName, a.ImmName)
	}
	if a.SetSreg != nil {
		ae.Uint32(nftaObjrefSetSreg, *a.SetSreg)
	}
	if a.SetName != "" {
		ae.String(nftaObjrefSetName, a.SetName)
	}
	if a.SetID != nil {
		ae.Uint32(nftaObjrefSetID, *a.SetID)
	}
	return ae.Encode()
}

func (a *ExprObjref) unmarshal(data []byte) error {
	ad, err := newAttributeDecoder(data)
	if err != nil {
		return err
	}
	for ad.Next() {
		switch ad.Type() {
		case nftaObjrefImmType:
			a.ImmType = ad.Uint32()
		case nftaObjrefImmName:
			a.ImmName = ad.String()
		case nftaObjrefSetSreg:
			v := ad.Uint32()
			a.SetSreg = &v
		case nftaObjrefSetName:
			a.SetName = ad.String()
		case nftaObjrefSetID:
			v := ad.Uint32()
			a.SetID = &v
		}
	}
	return ad.Err()
}

// https://github.com/torvalds/linux/blob/v7.1/include/uapi/linux/netfilter/nf_tables.h#L1769
type OsfFlags uint32

const (
	OsfVersion OsfFlags = 1 << 0
)

// https://github.com/torvalds/linux/blob/v7.1/include/uapi/linux/netfilter/nf_tables.h#L1754
const (
	nftaOsfDreg  = 0x01
	nftaOsfTtl   = 0x02
	nftaOsfFlags = 0x03
)

// https://github.com/torvalds/linux/blob/v7.1/include/uapi/linux/netfilter/nf_tables.h#L1754
type ExprOsf struct {
	DReg  Reg
	TTL   *uint8
	Flags *OsfFlags
}

func (ExprOsf) exprName() exprName { return exprNameOsf }

func (a *ExprOsf) marshal() ([]byte, error) {
	ae := newAttributeEncoder()
	ae.Uint32(nftaOsfDreg, uint32(a.DReg))
	if a.TTL != nil {
		ae.Uint8(nftaOsfTtl, *a.TTL)
	}
	if a.Flags != nil {
		// nft_osf.c uses nla_put_u32 (host byte order), not nla_put_be32
		var buf [4]byte
		binary.NativeEndian.PutUint32(buf[:], uint32(*a.Flags))
		ae.Bytes(nftaOsfFlags, buf[:])
	}
	return ae.Encode()
}

func (a *ExprOsf) unmarshal(data []byte) error {
	ad, err := newAttributeDecoder(data)
	if err != nil {
		return err
	}
	for ad.Next() {
		switch ad.Type() {
		case nftaOsfDreg:
			a.DReg = Reg(ad.Uint32())
		case nftaOsfTtl:
			v := ad.Uint8()
			a.TTL = &v
		case nftaOsfFlags:
			// nft_osf.c uses nla_put_u32 (host byte order), not nla_put_be32
			b := ad.Bytes()
			if len(b) == 4 {
				v := OsfFlags(binary.NativeEndian.Uint32(b))
				a.Flags = &v
			}
		}
	}
	return ad.Err()
}

// https://github.com/torvalds/linux/blob/v7.1/include/uapi/linux/netfilter/nf_tables.h#L796
type PayloadBase uint32

const (
	PayloadBaseLL PayloadBase = iota
	PayloadBaseNetwork
	PayloadBaseTransport
	PayloadBaseInner
	PayloadBaseTunnel
)

// https://github.com/torvalds/linux/blob/v7.1/include/uapi/linux/netfilter/nf_tables.h#L803
type PayloadCsumType uint32

const (
	PayloadCsumNone PayloadCsumType = iota
	PayloadCsumInet
	PayloadCsumSCTP
)

// https://github.com/torvalds/linux/blob/v7.1/include/uapi/linux/netfilter/nf_tables.h#L812
type PayloadCsumFlags uint32

const (
	PayloadCsumL4PseudoHdr PayloadCsumFlags = 1 << 0
)

// https://github.com/torvalds/linux/blob/v7.1/include/uapi/linux/netfilter/nf_tables.h#L855
const (
	nftaPayloadDreg       = unix.NFTA_PAYLOAD_DREG
	nftaPayloadBase       = unix.NFTA_PAYLOAD_BASE
	nftaPayloadOffset     = unix.NFTA_PAYLOAD_OFFSET
	nftaPayloadLen        = unix.NFTA_PAYLOAD_LEN
	nftaPayloadSreg       = unix.NFTA_PAYLOAD_SREG
	nftaPayloadCsumType   = unix.NFTA_PAYLOAD_CSUM_TYPE
	nftaPayloadCsumOffset = unix.NFTA_PAYLOAD_CSUM_OFFSET
	nftaPayloadCsumFlags  = unix.NFTA_PAYLOAD_CSUM_FLAGS
)

// https://github.com/torvalds/linux/blob/v7.1/include/uapi/linux/netfilter/nf_tables.h#L855
type ExprPayload struct {
	Base       PayloadBase
	Offset     uint32
	Len        uint32
	DReg       *Reg
	SReg       *Reg
	CsumType   *PayloadCsumType
	CsumOffset *uint32
	CsumFlags  *PayloadCsumFlags
}

func (ExprPayload) exprName() exprName { return exprNamePayload }

func (a *ExprPayload) marshal() ([]byte, error) {
	ae := newAttributeEncoder()
	ae.Uint32(nftaPayloadBase, uint32(a.Base))
	ae.Uint32(nftaPayloadOffset, a.Offset)
	ae.Uint32(nftaPayloadLen, a.Len)
	if a.DReg != nil {
		ae.Uint32(nftaPayloadDreg, uint32(*a.DReg))
	}
	if a.SReg != nil {
		ae.Uint32(nftaPayloadSreg, uint32(*a.SReg))
	}
	if a.CsumType != nil {
		ae.Uint32(nftaPayloadCsumType, uint32(*a.CsumType))
	}
	if a.CsumOffset != nil {
		ae.Uint32(nftaPayloadCsumOffset, *a.CsumOffset)
	}
	if a.CsumFlags != nil {
		ae.Uint32(nftaPayloadCsumFlags, uint32(*a.CsumFlags))
	}
	return ae.Encode()
}

func (a *ExprPayload) unmarshal(data []byte) error {
	ad, err := newAttributeDecoder(data)
	if err != nil {
		return err
	}
	for ad.Next() {
		switch ad.Type() {
		case nftaPayloadBase:
			a.Base = PayloadBase(ad.Uint32())
		case nftaPayloadOffset:
			a.Offset = ad.Uint32()
		case nftaPayloadLen:
			a.Len = ad.Uint32()
		case nftaPayloadDreg:
			v := Reg(ad.Uint32())
			a.DReg = &v
		case nftaPayloadSreg:
			v := Reg(ad.Uint32())
			a.SReg = &v
		case nftaPayloadCsumType:
			v := PayloadCsumType(ad.Uint32())
			a.CsumType = &v
		case nftaPayloadCsumOffset:
			v := ad.Uint32()
			a.CsumOffset = &v
		case nftaPayloadCsumFlags:
			v := PayloadCsumFlags(ad.Uint32())
			a.CsumFlags = &v
		}
	}
	return ad.Err()
}

// https://github.com/torvalds/linux/blob/v7.1/include/uapi/linux/netfilter/nf_tables.h#L1366
type QueueFlags uint16

const (
	QueueBypass    QueueFlags = 1 << 0
	QueueCPUFanout QueueFlags = 1 << 1
)

// https://github.com/torvalds/linux/blob/v7.1/include/uapi/linux/netfilter/nf_tables.h#L1345
const (
	nftaQueueNum      = unix.NFTA_QUEUE_NUM
	nftaQueueTotal    = unix.NFTA_QUEUE_TOTAL
	nftaQueueFlags    = unix.NFTA_QUEUE_FLAGS
	nftaQueueSregQnum = unix.NFTA_QUEUE_SREG_QNUM
)

// https://github.com/torvalds/linux/blob/v7.1/include/uapi/linux/netfilter/nf_tables.h#L1345
type ExprQueue struct {
	Num      *uint16
	Total    *uint16
	Flags    *QueueFlags
	SregQnum *uint32
}

func (ExprQueue) exprName() exprName { return exprNameQueue }

func (a *ExprQueue) marshal() ([]byte, error) {
	ae := newAttributeEncoder()
	if a.Num != nil {
		ae.Uint16(nftaQueueNum, *a.Num)
	}
	if a.Total != nil {
		ae.Uint16(nftaQueueTotal, *a.Total)
	}
	if a.Flags != nil {
		ae.Uint16(nftaQueueFlags, uint16(*a.Flags))
	}
	if a.SregQnum != nil {
		ae.Uint32(nftaQueueSregQnum, *a.SregQnum)
	}
	return ae.Encode()
}

func (a *ExprQueue) unmarshal(data []byte) error {
	ad, err := newAttributeDecoder(data)
	if err != nil {
		return err
	}
	for ad.Next() {
		switch ad.Type() {
		case nftaQueueNum:
			v := ad.Uint16()
			a.Num = &v
		case nftaQueueTotal:
			v := ad.Uint16()
			a.Total = &v
		case nftaQueueFlags:
			v := QueueFlags(ad.Uint16())
			a.Flags = &v
		case nftaQueueSregQnum:
			v := ad.Uint32()
			a.SregQnum = &v
		}
	}
	return ad.Err()
}

// https://github.com/torvalds/linux/blob/v7.1/include/uapi/linux/netfilter/nf_tables.h#L1366
type QuotaFlags uint32

const (
	QuotaInv      QuotaFlags = 1 << 0
	QuotaDepleted QuotaFlags = 1 << 1
)

// https://github.com/torvalds/linux/blob/f83a4f2a4d8c485922fba3018a64fc8f4cfd315f/include/uapi/linux/netfilter/nf_tables.h#L1372
const (
	nftaQuotaBytes    = unix.NFTA_QUOTA_BYTES
	nftaQuotaFlags    = unix.NFTA_QUOTA_FLAGS
	nftaQuotaConsumed = unix.NFTA_QUOTA_CONSUMED
)

// https://github.com/torvalds/linux/blob/v7.1/include/uapi/linux/netfilter/nf_tables.h#L1372
type ExprQuota struct {
	Bytes    uint64
	Flags    *QuotaFlags
	Consumed *uint64
}

func (ExprQuota) exprName() exprName { return exprNameQuota }

func (a *ExprQuota) marshal() ([]byte, error) {
	ae := newAttributeEncoder()
	ae.Uint64(nftaQuotaBytes, a.Bytes)
	if a.Flags != nil {
		ae.Uint32(nftaQuotaFlags, uint32(*a.Flags))
	}
	if a.Consumed != nil {
		ae.Uint64(nftaQuotaConsumed, *a.Consumed)
	}
	return ae.Encode()
}

func (a *ExprQuota) unmarshal(data []byte) error {
	ad, err := newAttributeDecoder(data)
	if err != nil {
		return err
	}
	for ad.Next() {
		switch ad.Type() {
		case nftaQuotaBytes:
			a.Bytes = ad.Uint64()
		case nftaQuotaFlags:
			v := QuotaFlags(ad.Uint32())
			a.Flags = &v
		case nftaQuotaConsumed:
			v := ad.Uint64()
			a.Consumed = &v
		}
	}
	return ad.Err()
}

// https://github.com/torvalds/linux/blob/v7.1/include/uapi/linux/netfilter/nf_tables.h#L703
type RangeOp uint32

const (
	RangeEq RangeOp = iota
	RangeNeq
)

// https://github.com/torvalds/linux/blob/v7.1/include/uapi/linux/netfilter/nf_tables.h#L714
const (
	nftaRangeSreg     = unix.NFTA_RANGE_SREG
	nftaRangeOp       = unix.NFTA_RANGE_OP
	nftaRangeFromData = unix.NFTA_RANGE_FROM_DATA
	nftaRangeToData   = unix.NFTA_RANGE_TO_DATA
)

// https://github.com/torvalds/linux/blob/v7.1/include/uapi/linux/netfilter/nf_tables.h#L714
type ExprRange struct {
	SReg     Reg
	Op       RangeOp
	FromData *ExprData
	ToData   *ExprData
}

func (ExprRange) exprName() exprName { return exprNameRange }

func (a *ExprRange) marshal() ([]byte, error) {
	ae := newAttributeEncoder()
	ae.Uint32(nftaRangeSreg, uint32(a.SReg))
	ae.Uint32(nftaRangeOp, uint32(a.Op))
	if a.FromData != nil {
		b, err := a.FromData.marshal()
		if err != nil {
			return nil, err
		}
		ae.Bytes(unix.NLA_F_NESTED|nftaRangeFromData, b)
	}
	if a.ToData != nil {
		b, err := a.ToData.marshal()
		if err != nil {
			return nil, err
		}
		ae.Bytes(unix.NLA_F_NESTED|nftaRangeToData, b)
	}
	return ae.Encode()
}

func (a *ExprRange) unmarshal(data []byte) error {
	ad, err := newAttributeDecoder(data)
	if err != nil {
		return err
	}
	for ad.Next() {
		switch ad.Type() {
		case nftaRangeSreg:
			a.SReg = Reg(ad.Uint32())
		case nftaRangeOp:
			a.Op = RangeOp(ad.Uint32())
		case nftaRangeFromData:
			a.FromData = &ExprData{}
			if err := a.FromData.unmarshal(ad.Bytes()); err != nil {
				return err
			}
		case nftaRangeToData:
			a.ToData = &ExprData{}
			if err := a.ToData.unmarshal(ad.Bytes()); err != nil {
				return err
			}
		}
	}
	return ad.Err()
}

// https://github.com/torvalds/linux/blob/v7.1/include/uapi/linux/netfilter/nf_tables.h#L1517
const (
	nftaRedirRegProtoMin = unix.NFTA_REDIR_REG_PROTO_MIN
	nftaRedirRegProtoMax = unix.NFTA_REDIR_REG_PROTO_MAX
	nftaRedirFlags       = unix.NFTA_REDIR_FLAGS
)

// https://github.com/torvalds/linux/blob/v7.1/include/uapi/linux/netfilter/nf_tables.h#L1517
type ExprRedir struct {
	RegProtoMin *uint32
	RegProtoMax *uint32
	Flags       *NatFlags
}

func (ExprRedir) exprName() exprName { return exprNameRedir }

func (a *ExprRedir) marshal() ([]byte, error) {
	ae := newAttributeEncoder()
	if a.RegProtoMin != nil {
		ae.Uint32(nftaRedirRegProtoMin, *a.RegProtoMin)
	}
	if a.RegProtoMax != nil {
		ae.Uint32(nftaRedirRegProtoMax, *a.RegProtoMax)
	}
	if a.Flags != nil {
		ae.Uint32(nftaRedirFlags, uint32(*a.Flags))
	}
	return ae.Encode()
}

func (a *ExprRedir) unmarshal(data []byte) error {
	ad, err := newAttributeDecoder(data)
	if err != nil {
		return err
	}
	for ad.Next() {
		switch ad.Type() {
		case nftaRedirRegProtoMin:
			v := ad.Uint32()
			a.RegProtoMin = &v
		case nftaRedirRegProtoMax:
			v := ad.Uint32()
			a.RegProtoMax = &v
		case nftaRedirFlags:
			v := NatFlags(ad.Uint32())
			a.Flags = &v
		}
	}
	return ad.Err()
}

// https://github.com/torvalds/linux/blob/v7.1/include/uapi/linux/netfilter/nf_tables.h#L1404
type RejectType uint32

const (
	RejectICMPUnreach RejectType = iota
	RejectTCPRST
	RejectICMPXUnreach
)

// https://github.com/torvalds/linux/blob/v7.1/include/uapi/linux/netfilter/nf_tables.h#L1417
type RejectInetCode uint8

const (
	RejectICMPXNoRoute RejectInetCode = iota
	RejectICMPXPortUnreach
	RejectICMPXHostUnreach
	RejectICMPXAdminProhibited
)

// https://github.com/torvalds/linux/blob/v7.1/include/uapi/linux/netfilter/nf_tables.h#L1436
const (
	nftaRejectType     = unix.NFTA_REJECT_TYPE
	nftaRejectIcmpCode = unix.NFTA_REJECT_ICMP_CODE
)

// https://github.com/torvalds/linux/blob/v7.1/include/uapi/linux/netfilter/nf_tables.h#L1436
type ExprReject struct {
	Type     *RejectType
	IcmpCode *RejectInetCode
}

func (ExprReject) exprName() exprName { return exprNameReject }

func (a *ExprReject) marshal() ([]byte, error) {
	ae := newAttributeEncoder()
	if a.Type != nil {
		ae.Uint32(nftaRejectType, uint32(*a.Type))
	}
	if a.IcmpCode != nil {
		ae.Uint8(nftaRejectIcmpCode, uint8(*a.IcmpCode))
	}
	return ae.Encode()
}

func (a *ExprReject) unmarshal(data []byte) error {
	ad, err := newAttributeDecoder(data)
	if err != nil {
		return err
	}
	for ad.Next() {
		switch ad.Type() {
		case nftaRejectType:
			v := RejectType(ad.Uint32())
			a.Type = &v
		case nftaRejectIcmpCode:
			v := RejectInetCode(ad.Uint8())
			a.IcmpCode = &v
		}
	}
	return ad.Err()
}

// https://github.com/torvalds/linux/blob/v7.1/include/uapi/linux/netfilter/nf_tables.h#L1011
type RtKey uint32

const (
	RtKeyClassID RtKey = iota
	RtKeyNextHop4
	RtKeyNextHop6
	RtKeyTCPMSS
	RtKeyXFRM
)

// https://github.com/torvalds/linux/blob/v7.1/include/uapi/linux/netfilter/nf_tables.h#L1085
const (
	nftaRtDreg = unix.NFTA_RT_DREG
	nftaRtKey  = unix.NFTA_RT_KEY
	nftaRtSreg = 0x03
)

// https://github.com/torvalds/linux/blob/v7.1/include/uapi/linux/netfilter/nf_tables.h#L1085
type ExprRt struct {
	Key  *RtKey
	DReg *Reg
	SReg *Reg
}

func (ExprRt) exprName() exprName { return exprNameRt }

func (a *ExprRt) marshal() ([]byte, error) {
	ae := newAttributeEncoder()
	if a.Key != nil {
		ae.Uint32(nftaRtKey, uint32(*a.Key))
	}
	if a.DReg != nil {
		ae.Uint32(nftaRtDreg, uint32(*a.DReg))
	}
	if a.SReg != nil {
		ae.Uint32(nftaRtSreg, uint32(*a.SReg))
	}
	return ae.Encode()
}

func (a *ExprRt) unmarshal(data []byte) error {
	ad, err := newAttributeDecoder(data)
	if err != nil {
		return err
	}
	for ad.Next() {
		switch ad.Type() {
		case nftaRtKey:
			v := RtKey(ad.Uint32())
			a.Key = &v
		case nftaRtDreg:
			v := Reg(ad.Uint32())
			a.DReg = &v
		case nftaRtSreg:
			v := Reg(ad.Uint32())
			a.SReg = &v
		}
	}
	return ad.Err()
}

// https://github.com/torvalds/linux/blob/v7.1/include/uapi/linux/netfilter/nf_tables.h#L1115
type SocketKey uint32

const (
	SocketKeyTransparent SocketKey = iota
	SocketKeyMark
	SocketKeyWildcard
	SocketKeyCGroupV2
)

// https://github.com/torvalds/linux/blob/v7.1/include/uapi/linux/netfilter/nf_tables.h#L1099
const (
	nftaSocketKey   = 0x01
	nftaSocketDreg  = 0x02
	nftaSocketLevel = 0x03
)

// https://github.com/torvalds/linux/blob/v7.1/include/uapi/linux/netfilter/nf_tables.h#L1099
type ExprSocket struct {
	Key   SocketKey
	DReg  Reg
	Level *uint32
}

func (ExprSocket) exprName() exprName { return exprNameSocket }

func (a *ExprSocket) marshal() ([]byte, error) {
	ae := newAttributeEncoder()
	ae.Uint32(nftaSocketKey, uint32(a.Key))
	ae.Uint32(nftaSocketDreg, uint32(a.DReg))
	if a.Level != nil {
		ae.Uint32(nftaSocketLevel, *a.Level)
	}
	return ae.Encode()
}

func (a *ExprSocket) unmarshal(data []byte) error {
	ad, err := newAttributeDecoder(data)
	if err != nil {
		return err
	}
	for ad.Next() {
		switch ad.Type() {
		case nftaSocketKey:
			a.Key = SocketKey(ad.Uint32())
		case nftaSocketDreg:
			a.DReg = Reg(ad.Uint32())
		case nftaSocketLevel:
			v := ad.Uint32()
			a.Level = &v
		}
	}
	return ad.Err()
}

// https://github.com/torvalds/linux/blob/v7.1/include/uapi/linux/netfilter/nf_synproxy.h
type SynproxyFlags uint32

const (
	SynproxyMSS       SynproxyFlags = 1 << 0
	SynproxyWScale    SynproxyFlags = 1 << 1
	SynproxySACKPerm  SynproxyFlags = 1 << 2
	SynproxyTimestamp SynproxyFlags = 1 << 3
	SynproxyECN       SynproxyFlags = 1 << 4
)

// http://github.com/torvalds/linux/blob/v7.1/include/uapi/linux/netfilter/nf_tables.h#L1774
const (
	nftaSynproxyMss    = 0x01
	nftaSynproxyWscale = 0x02
	nftaSynproxyFlags  = 0x03
)

// https://github.com/torvalds/linux/blob/v7.1/include/uapi/linux/netfilter/nf_tables.h#L1774
type ExprSynproxy struct {
	MSS    *uint16
	WScale *uint8
	Flags  *SynproxyFlags
}

func (ExprSynproxy) exprName() exprName { return exprNameSynproxy }

func (a *ExprSynproxy) marshal() ([]byte, error) {
	ae := newAttributeEncoder()
	if a.MSS != nil {
		ae.Uint16(nftaSynproxyMss, *a.MSS)
	}
	if a.WScale != nil {
		ae.Uint8(nftaSynproxyWscale, *a.WScale)
	}
	if a.Flags != nil {
		ae.Uint32(nftaSynproxyFlags, uint32(*a.Flags))
	}
	return ae.Encode()
}

func (a *ExprSynproxy) unmarshal(data []byte) error {
	ad, err := newAttributeDecoder(data)
	if err != nil {
		return err
	}
	for ad.Next() {
		switch ad.Type() {
		case nftaSynproxyMss:
			v := ad.Uint16()
			a.MSS = &v
		case nftaSynproxyWscale:
			v := ad.Uint8()
			a.WScale = &v
		case nftaSynproxyFlags:
			v := SynproxyFlags(ad.Uint32())
			a.Flags = &v
		}
	}
	return ad.Err()
}

// https://github.com/torvalds/linux/blob/v7.1/include/uapi/linux/netfilter/nf_tables.h#L1485
const (
	nftaTproxyFamily  = 0x01
	nftaTproxyRegAddr = 0x02
	nftaTproxyRegPort = 0x03
)

// https://github.com/torvalds/linux/blob/v7.1/include/uapi/linux/netfilter/nf_tables.h#L1485
type ExprTproxy struct {
	Family  *Family
	RegAddr *uint32
	RegPort *uint32
}

func (ExprTproxy) exprName() exprName { return exprNameTproxy }

func (a *ExprTproxy) marshal() ([]byte, error) {
	ae := newAttributeEncoder()
	if a.Family != nil {
		ae.Uint32(nftaTproxyFamily, uint32(*a.Family))
	}
	if a.RegAddr != nil {
		ae.Uint32(nftaTproxyRegAddr, *a.RegAddr)
	}
	if a.RegPort != nil {
		ae.Uint32(nftaTproxyRegPort, *a.RegPort)
	}
	return ae.Encode()
}

func (a *ExprTproxy) unmarshal(data []byte) error {
	ad, err := newAttributeDecoder(data)
	if err != nil {
		return err
	}
	for ad.Next() {
		switch ad.Type() {
		case nftaTproxyFamily:
			v := Family(ad.Uint32())
			a.Family = &v
		case nftaTproxyRegAddr:
			v := ad.Uint32()
			a.RegAddr = &v
		case nftaTproxyRegPort:
			v := ad.Uint32()
			a.RegPort = &v
		}
	}
	return ad.Err()
}

// https://github.com/torvalds/linux/blob/v7.1/include/uapi/linux/netfilter/nf_tables.h#L1998
type TunnelKey uint32

const (
	TunnelKeyPath TunnelKey = iota
	TunnelKeyID
)

// https://github.com/torvalds/linux/blob/v7.1/include/uapi/linux/netfilter/nf_tables.h#L2005
type TunnelMode uint32

const (
	TunnelModeNone TunnelMode = iota
	TunnelModeRx
	TunnelModeTx
)

// https://github.com/torvalds/linux/blob/v7.1/include/uapi/linux/netfilter/nf_tables.h#L2013
const (
	nftaTunnelKey  = 0x01
	nftaTunnelDreg = 0x02
	nftaTunnelMode = 0x03
)

// https://github.com/torvalds/linux/blob/v7.1/include/uapi/linux/netfilter/nf_tables.h#L2013
type ExprTunnel struct {
	Key  TunnelKey
	DReg Reg
	Mode *TunnelMode
}

func (ExprTunnel) exprName() exprName { return exprNameTunnel }

func (a *ExprTunnel) marshal() ([]byte, error) {
	ae := newAttributeEncoder()
	ae.Uint32(nftaTunnelKey, uint32(a.Key))
	ae.Uint32(nftaTunnelDreg, uint32(a.DReg))
	if a.Mode != nil {
		ae.Uint32(nftaTunnelMode, uint32(*a.Mode))
	}
	return ae.Encode()
}

func (a *ExprTunnel) unmarshal(data []byte) error {
	ad, err := newAttributeDecoder(data)
	if err != nil {
		return err
	}
	for ad.Next() {
		switch ad.Type() {
		case nftaTunnelKey:
			a.Key = TunnelKey(ad.Uint32())
		case nftaTunnelDreg:
			a.DReg = Reg(ad.Uint32())
		case nftaTunnelMode:
			v := TunnelMode(ad.Uint32())
			a.Mode = &v
		}
	}
	return ad.Err()
}

// https://github.com/torvalds/linux/blob/8b789f2b7602a818e7c7488c74414fae21392b63/include/uapi/linux/netfilter.h#L11
type Verdict int32

// Standard netfilter verdicts
// https://github.com/torvalds/linux/blob/8b789f2b7602a818e7c7488c74414fae21392b63/include/uapi/linux/netfilter.h#L11
const (
	VerdictDrop Verdict = iota
	VerdictAccept
	VerdictStolen
	VerdictQueue
	VerdictRepeat
)

// nftables-specific verdicts
// https://github.com/torvalds/linux/blob/f83a4f2a4d8c485922fba3018a64fc8f4cfd315f/include/uapi/linux/netfilter/nf_tables.h#L68
const (
	VerdictContinue Verdict = -1
	VerdictBreak    Verdict = -2
	VerdictJump     Verdict = -3
	VerdictGoto     Verdict = -4
	VerdictReturn   Verdict = -5
)

// https://github.com/torvalds/linux/blob/v7.1/include/uapi/linux/netfilter/nf_tables.h#L529
const (
	nftaVerdictCode    = unix.NFTA_VERDICT_CODE
	nftaVerdictChain   = unix.NFTA_VERDICT_CHAIN
	nftaVerdictChainID = 0x03
)

// https://github.com/torvalds/linux/blob/v7.1/include/uapi/linux/netfilter/nf_tables.h#L529
type ExprVerdict struct {
	Code    Verdict
	Chain   string
	ChainID *uint32
}

func (ExprVerdict) exprName() exprName { return exprNameVerdict }

func (a *ExprVerdict) marshal() ([]byte, error) {
	ae := newAttributeEncoder()
	ae.Uint32(nftaVerdictCode, uint32(int32(a.Code)))
	if a.Chain != "" {
		ae.String(nftaVerdictChain, a.Chain)
	}
	if a.ChainID != nil {
		ae.Uint32(nftaVerdictChainID, *a.ChainID)
	}
	return ae.Encode()
}

func (a *ExprVerdict) unmarshal(data []byte) error {
	ad, err := newAttributeDecoder(data)
	if err != nil {
		return err
	}
	for ad.Next() {
		switch ad.Type() {
		case nftaVerdictCode:
			a.Code = Verdict(int32(ad.Uint32()))
		case nftaVerdictChain:
			a.Chain = ad.String()
		case nftaVerdictChainID:
			v := ad.Uint32()
			a.ChainID = &v
		}
	}
	return ad.Err()
}

// https://github.com/torvalds/linux/blob/v7.1/include/uapi/linux/netfilter/nf_tables.h#L1821
type XfrmKey uint32

const (
	XfrmKeyDAddrIP4 XfrmKey = iota + 1
	XfrmKeyDAddrIP6
	XfrmKeySAddrIP4
	XfrmKeySAddrIP6
	XfrmKeyReqID
	XfrmKeySPI
)

// https://github.com/torvalds/linux/blob/v7.1/include/uapi/linux/netfilter/nf_tables.h#L1804
const (
	nftaXfrmDreg  = 0x01
	nftaXfrmKey   = 0x02
	nftaXfrmDir   = 0x03
	nftaXfrmSpnum = 0x04
)

// https://github.com/torvalds/linux/blob/v7.1/include/uapi/linux/netfilter/nf_tables.h#L1804
type ExprXfrm struct {
	DReg  *Reg
	Key   *XfrmKey
	Dir   *uint8
	Spnum *uint32
}

func (ExprXfrm) exprName() exprName { return exprNameXfrm }

func (a *ExprXfrm) marshal() ([]byte, error) {
	ae := newAttributeEncoder()
	if a.DReg != nil {
		ae.Uint32(nftaXfrmDreg, uint32(*a.DReg))
	}
	if a.Key != nil {
		ae.Uint32(nftaXfrmKey, uint32(*a.Key))
	}
	if a.Dir != nil {
		ae.Uint8(nftaXfrmDir, *a.Dir)
	}
	if a.Spnum != nil {
		ae.Uint32(nftaXfrmSpnum, *a.Spnum)
	}
	return ae.Encode()
}

func (a *ExprXfrm) unmarshal(data []byte) error {
	ad, err := newAttributeDecoder(data)
	if err != nil {
		return err
	}
	for ad.Next() {
		switch ad.Type() {
		case nftaXfrmDreg:
			v := Reg(ad.Uint32())
			a.DReg = &v
		case nftaXfrmKey:
			v := XfrmKey(ad.Uint32())
			a.Key = &v
		case nftaXfrmDir:
			v := ad.Uint8()
			a.Dir = &v
		case nftaXfrmSpnum:
			v := ad.Uint32()
			a.Spnum = &v
		}
	}
	return ad.Err()
}
