package nftnl

import (
	"encoding/binary"
	"fmt"

	"golang.org/x/sys/unix"
)

// https://github.com/torvalds/linux/blob/v7.1/include/uapi/linux/netfilter/nf_tables.h#L1663
type ObjType uint32

const (
	ObjTypeCounter   ObjType = 1
	ObjTypeQuota     ObjType = 2
	ObjTypeCtHelper  ObjType = 3
	ObjTypeLimit     ObjType = 4
	ObjTypeConnlimit ObjType = 5
	ObjTypeTunnel    ObjType = 6
	ObjTypeCtTimeout ObjType = 7
	ObjTypeSecmark   ObjType = 8
	ObjTypeCtExpect  ObjType = 9
	ObjTypeSynproxy  ObjType = 10
)

// ObjData is implemented by each stateful object type and carries the
// type-specific payload nested inside NFTA_OBJ_DATA.
type ObjData interface {
	ObjType() ObjType
	marshal() ([]byte, error)
	unmarshal(data []byte) error
}

// https://github.com/torvalds/linux/blob/v7.1/include/uapi/linux/netfilter/nf_tables.h#L1677
const (
	nftaObjTable    = unix.NFTA_OBJ_TABLE
	nftaObjName     = unix.NFTA_OBJ_NAME
	nftaObjType     = unix.NFTA_OBJ_TYPE
	nftaObjData     = unix.NFTA_OBJ_DATA
	nftaObjUse      = unix.NFTA_OBJ_USE
	nftaObjHandle   = 0x06
	nftaObjUserdata = 0x08 // 0x07 is NFTA_OBJ_PAD
)

// https://github.com/torvalds/linux/blob/v7.1/include/uapi/linux/netfilter/nf_tables.h#L1677
type Obj struct {
	Table    string
	Name     string
	Data     ObjData
	Use      uint32
	Handle   *uint64
	UserData UserData
}

func (a *Obj) marshal() ([]byte, error) {
	ae := newAttributeEncoder()
	ae.String(nftaObjTable, a.Table)
	ae.String(nftaObjName, a.Name)
	if a.Handle != nil {
		ae.Uint64(nftaObjHandle, *a.Handle)
	}
	if b := a.UserData.marshal(); b != nil {
		ae.Bytes(nftaObjUserdata, b)
	}
	if a.Data != nil {
		ae.Uint32(nftaObjType, uint32(a.Data.ObjType()))
		data, err := a.Data.marshal()
		if err != nil {
			return nil, err
		}
		ae.Bytes(unix.NLA_F_NESTED|nftaObjData, data)
	}
	return ae.Encode()
}

func (a *Obj) unmarshal(data []byte) error {
	ad, err := newAttributeDecoder(data)
	if err != nil {
		return err
	}

	var objType ObjType
	var rawData []byte

	for ad.Next() {
		switch ad.Type() {
		case nftaObjTable:
			a.Table = ad.String()
		case nftaObjName:
			a.Name = ad.String()
		case nftaObjType:
			objType = ObjType(ad.Uint32())
		case nftaObjData:
			rawData = ad.Bytes()
		case nftaObjUse:
			a.Use = ad.Uint32()
		case nftaObjHandle:
			v := ad.Uint64()
			a.Handle = &v
		case nftaObjUserdata:
			if err := a.UserData.unmarshal(ad.Bytes()); err != nil {
				return err
			}
		}
	}
	if err := ad.Err(); err != nil {
		return err
	}

	if rawData != nil {
		d, err := objDataFactory(objType)
		if err != nil {
			return err
		}
		if err := d.unmarshal(rawData); err != nil {
			return err
		}
		a.Data = d
	}

	return nil
}

// https://github.com/torvalds/linux/blob/v7.1/include/uapi/linux/netfilter/nf_tables.h#L1663
func objDataFactory(objType ObjType) (ObjData, error) {
	switch objType {
	case ObjTypeCounter:
		return &ObjCounter{}, nil
	case ObjTypeQuota:
		return &ObjQuota{}, nil
	case ObjTypeCtHelper:
		return &ObjCtHelper{}, nil
	case ObjTypeLimit:
		return &ObjLimit{}, nil
	case ObjTypeConnlimit:
		return &ObjConnlimit{}, nil
	case ObjTypeCtTimeout:
		return &ObjCtTimeout{}, nil
	case ObjTypeSecmark:
		return &ObjSecmark{}, nil
	case ObjTypeCtExpect:
		return &ObjCtExpect{}, nil
	case ObjTypeSynproxy:
		return &ObjSynproxy{}, nil
	case ObjTypeTunnel:
		return &ObjTunnel{}, nil
	default:
		return nil, fmt.Errorf("unknown object type %d", objType)
	}
}

// Shares nftaCounter* consts with ExprCounter in expr_attrs.go.
// https://github.com/torvalds/linux/blob/v7.1/include/uapi/linux/netfilter/nf_tables.h#L1266
type ObjCounter struct {
	Bytes   uint64
	Packets uint64
}

func (*ObjCounter) ObjType() ObjType { return ObjTypeCounter }

func (a *ObjCounter) marshal() ([]byte, error) {
	ae := newAttributeEncoder()
	ae.Uint64(nftaCounterBytes, a.Bytes)
	ae.Uint64(nftaCounterPackets, a.Packets)
	return ae.Encode()
}

func (a *ObjCounter) unmarshal(data []byte) error {
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

// Shares nftaQuota* consts with ExprQuota in expr_attrs.go.
// Bytes is always marshaled; Flags and Consumed are optional (presence-bit guarded in libnftnl).
// https://github.com/torvalds/linux/blob/f83a4f2a4d8c485922fba3018a64fc8f4cfd315f/include/uapi/linux/netfilter/nf_tables.h#L1366
type ObjQuota struct {
	Bytes    uint64
	Flags    *QuotaFlags
	Consumed *uint64
}

func (*ObjQuota) ObjType() ObjType { return ObjTypeQuota }

func (a *ObjQuota) marshal() ([]byte, error) {
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

func (a *ObjQuota) unmarshal(data []byte) error {
	ad, err := newAttributeDecoder(data)
	if err != nil {
		return err
	}
	for ad.Next() {
		switch ad.Type() {
		case nftaQuotaBytes:
			a.Bytes = ad.Uint64()
		case nftaQuotaFlags:
			v := ad.Uint32()
			a.Flags = new(QuotaFlags(v))
		case nftaQuotaConsumed:
			v := ad.Uint64()
			a.Consumed = &v
		}
	}
	return ad.Err()
}

// https://github.com/torvalds/linux/blob/v7.1/include/uapi/linux/netfilter/nf_tables.h#L1633
const (
	nftaCtHelperName    = unix.NFTA_CT_HELPER_NAME
	nftaCtHelperL3proto = unix.NFTA_CT_HELPER_L3PROTO
	nftaCtHelperL4proto = unix.NFTA_CT_HELPER_L4PROTO
)

// All fields are optional (presence-bit guarded in libnftnl).
// https://github.com/torvalds/linux/blob/v7.1/include/uapi/linux/netfilter/nf_tables.h#L1633
type ObjCtHelper struct {
	Name    string
	L3Proto *uint16
	L4Proto *uint8
}

func (*ObjCtHelper) ObjType() ObjType { return ObjTypeCtHelper }

func (a *ObjCtHelper) marshal() ([]byte, error) {
	ae := newAttributeEncoder()
	if a.Name != "" {
		ae.String(nftaCtHelperName, a.Name)
	}
	if a.L3Proto != nil {
		ae.Uint16(nftaCtHelperL3proto, *a.L3Proto)
	}
	if a.L4Proto != nil {
		ae.Uint8(nftaCtHelperL4proto, *a.L4Proto)
	}
	return ae.Encode()
}

func (a *ObjCtHelper) unmarshal(data []byte) error {
	ad, err := newAttributeDecoder(data)
	if err != nil {
		return err
	}
	for ad.Next() {
		switch ad.Type() {
		case nftaCtHelperName:
			a.Name = ad.String()
		case nftaCtHelperL3proto:
			v := ad.Uint16()
			a.L3Proto = &v
		case nftaCtHelperL4proto:
			v := ad.Uint8()
			a.L4Proto = &v
		}
	}
	return ad.Err()
}

// Shares nftaLimit* consts with ExprLimit in expr_attrs.go.
// https://github.com/torvalds/linux/blob/v7.1/include/uapi/linux/netfilter/nf_tables.h#L1227
type ObjLimit struct {
	Rate  uint64
	Unit  *uint64
	Burst *uint32
	Type  *LimitType
	Flags *LimitFlags
}

func (*ObjLimit) ObjType() ObjType { return ObjTypeLimit }

func (a *ObjLimit) marshal() ([]byte, error) {
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

func (a *ObjLimit) unmarshal(data []byte) error {
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
			v := ad.Uint32()
			a.Flags = new(LimitFlags(v))
		}
	}
	return ad.Err()
}

// https://github.com/torvalds/linux/blob/v7.1/include/uapi/linux/netfilter/nf_tables.h#L1227
type ObjConnlimit struct {
	Count *uint32
	Flags *ConnlimitFlags
}

func (*ObjConnlimit) ObjType() ObjType { return ObjTypeConnlimit }

func (a *ObjConnlimit) marshal() ([]byte, error) {
	ae := newAttributeEncoder()
	if a.Count != nil {
		ae.Uint32(nftaConnlimitCount, *a.Count)
	}
	if a.Flags != nil {
		ae.Uint32(nftaConnlimitFlags, uint32(*a.Flags))
	}
	return ae.Encode()
}

func (a *ObjConnlimit) unmarshal(data []byte) error {
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

// https://github.com/torvalds/linux/blob/v7.1/include/uapi/linux/netfilter/nf_tables.h#L1642
const (
	nftaCtTimeoutL3proto = 0x01
	nftaCtTimeoutL4proto = 0x02
	nftaCtTimeoutData    = 0x03
)

// https://github.com/torvalds/linux/blob/v7.1/include/uapi/linux/netfilter/nf_tables.h#L1642
type ObjCtTimeout struct {
	L3Proto  *uint16
	L4Proto  *uint8
	Timeouts []uint32
}

func (*ObjCtTimeout) ObjType() ObjType { return ObjTypeCtTimeout }

func (a *ObjCtTimeout) marshal() ([]byte, error) {
	ae := newAttributeEncoder()
	if a.L3Proto != nil {
		ae.Uint16(nftaCtTimeoutL3proto, *a.L3Proto)
	}
	if a.L4Proto != nil {
		ae.Uint8(nftaCtTimeoutL4proto, *a.L4Proto)
	}
	if len(a.Timeouts) > 0 {
		inner := newAttributeEncoder()
		for i, v := range a.Timeouts {
			// kernel uses 1-based attribute types for each state index
			inner.Uint32(uint16(i+1), v)
		}
		data, err := inner.Encode()
		if err != nil {
			return nil, err
		}
		ae.Bytes(unix.NLA_F_NESTED|nftaCtTimeoutData, data)
	}
	return ae.Encode()
}

func (a *ObjCtTimeout) unmarshal(data []byte) error {
	ad, err := newAttributeDecoder(data)
	if err != nil {
		return err
	}
	for ad.Next() {
		switch ad.Type() {
		case nftaCtTimeoutL3proto:
			v := ad.Uint16()
			a.L3Proto = &v
		case nftaCtTimeoutL4proto:
			v := ad.Uint8()
			a.L4Proto = &v
		case nftaCtTimeoutData:
			inner, err := newAttributeDecoder(ad.Bytes())
			if err != nil {
				return err
			}
			for inner.Next() {
				// attribute type is the 1-based state index
				idx := int(inner.Type()) - 1
				if idx < 0 {
					continue
				}
				if idx >= len(a.Timeouts) {
					grown := make([]uint32, idx+1)
					copy(grown, a.Timeouts)
					a.Timeouts = grown
				}
				a.Timeouts[idx] = inner.Uint32()
			}
			if err := inner.Err(); err != nil {
				return err
			}
		}
	}
	return ad.Err()
}

// https://github.com/torvalds/linux/blob/v7.1/include/uapi/linux/netfilter/nf_tables.h#L1389
const (
	nftaSecmarkCtx = 0x01
)

// https://github.com/torvalds/linux/blob/v7.1/include/uapi/linux/netfilter/nf_tables.h#L1389
type ObjSecmark struct {
	Ctx string
}

func (*ObjSecmark) ObjType() ObjType { return ObjTypeSecmark }

func (a *ObjSecmark) marshal() ([]byte, error) {
	ae := newAttributeEncoder()
	ae.String(nftaSecmarkCtx, a.Ctx)
	return ae.Encode()
}

func (a *ObjSecmark) unmarshal(data []byte) error {
	ad, err := newAttributeDecoder(data)
	if err != nil {
		return err
	}
	for ad.Next() {
		if ad.Type() == nftaSecmarkCtx {
			a.Ctx = ad.String()
		}
	}
	return ad.Err()
}

// https://github.com/torvalds/linux/blob/v7.1/include/uapi/linux/netfilter/nf_tables.h#L1651
const (
	nftaCtExpectL3proto = 0x01
	nftaCtExpectL4proto = 0x02
	nftaCtExpectDport   = 0x03
	nftaCtExpectTimeout = 0x04
	nftaCtExpectSize    = 0x05
)

// https://github.com/torvalds/linux/blob/v7.1/include/uapi/linux/netfilter/nf_tables.h#L1651
type ObjCtExpect struct {
	L3Proto *uint16
	L4Proto *uint8
	DPort   *uint16
	Timeout *uint32
	Size    *uint8
}

func (*ObjCtExpect) ObjType() ObjType { return ObjTypeCtExpect }

func (a *ObjCtExpect) marshal() ([]byte, error) {
	ae := newAttributeEncoder()
	if a.L3Proto != nil {
		ae.Uint16(nftaCtExpectL3proto, *a.L3Proto)
	}
	if a.L4Proto != nil {
		ae.Uint8(nftaCtExpectL4proto, *a.L4Proto)
	}
	if a.DPort != nil {
		ae.Uint16(nftaCtExpectDport, *a.DPort)
	}
	if a.Timeout != nil {
		// nft_ct.c uses nla_put_u32 (host byte order), not nla_put_be32
		var buf [4]byte
		binary.NativeEndian.PutUint32(buf[:], *a.Timeout)
		ae.Bytes(nftaCtExpectTimeout, buf[:])
	}
	if a.Size != nil {
		ae.Uint8(nftaCtExpectSize, *a.Size)
	}
	return ae.Encode()
}

func (a *ObjCtExpect) unmarshal(data []byte) error {
	ad, err := newAttributeDecoder(data)
	if err != nil {
		return err
	}
	for ad.Next() {
		switch ad.Type() {
		case nftaCtExpectL3proto:
			v := ad.Uint16()
			a.L3Proto = &v
		case nftaCtExpectL4proto:
			v := ad.Uint8()
			a.L4Proto = &v
		case nftaCtExpectDport:
			v := ad.Uint16()
			a.DPort = &v
		case nftaCtExpectTimeout:
			// nft_ct.c uses nla_get_u32 (host byte order), not nla_get_be32
			b := ad.Bytes()
			if len(b) == 4 {
				v := binary.NativeEndian.Uint32(b)
				a.Timeout = &v
			}
		case nftaCtExpectSize:
			v := ad.Uint8()
			a.Size = &v
		}
	}
	return ad.Err()
}

// Shares nftaSynproxy* consts with ExprSynproxy in expr_attrs.go.
// https://github.com/torvalds/linux/blob/v7.1/include/uapi/linux/netfilter/nf_tables.h#L1774
type ObjSynproxy struct {
	MSS    *uint16
	WScale *uint8
	Flags  *SynproxyFlags
}

func (*ObjSynproxy) ObjType() ObjType { return ObjTypeSynproxy }

func (a *ObjSynproxy) marshal() ([]byte, error) {
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

func (a *ObjSynproxy) unmarshal(data []byte) error {
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

// https://github.com/torvalds/linux/blob/v7.1/include/uapi/linux/netfilter/nf_tables.h#L1922
const (
	nftaTunnelKeyIPSrc = 0x01
	nftaTunnelKeyIPDst = 0x02
)

// https://github.com/torvalds/linux/blob/v7.1/include/uapi/linux/netfilter/nf_tables.h#L1922
type TunnelKeyIP struct {
	Src *uint32
	Dst *uint32
}

func (a *TunnelKeyIP) marshal() ([]byte, error) {
	ae := newAttributeEncoder()
	if a.Src != nil {
		ae.Uint32(nftaTunnelKeyIPSrc, *a.Src)
	}
	if a.Dst != nil {
		ae.Uint32(nftaTunnelKeyIPDst, *a.Dst)
	}
	return ae.Encode()
}

func (a *TunnelKeyIP) unmarshal(data []byte) error {
	ad, err := newAttributeDecoder(data)
	if err != nil {
		return err
	}
	for ad.Next() {
		switch ad.Type() {
		case nftaTunnelKeyIPSrc:
			v := ad.Uint32()
			a.Src = &v
		case nftaTunnelKeyIPDst:
			v := ad.Uint32()
			a.Dst = &v
		}
	}
	return ad.Err()
}

// https://github.com/torvalds/linux/blob/v7.1/include/uapi/linux/netfilter/nf_tables.h#L1930
const (
	nftaTunnelKeyIP6Src       = 0x01
	nftaTunnelKeyIP6Dst       = 0x02
	nftaTunnelKeyIP6Flowlabel = 0x03
)

// https://github.com/torvalds/linux/blob/v7.1/include/uapi/linux/netfilter/nf_tables.h#L1930
type TunnelKeyIP6 struct {
	Src       [16]byte
	Dst       [16]byte
	FlowLabel *uint32
}

func (a *TunnelKeyIP6) marshal() ([]byte, error) {
	ae := newAttributeEncoder()
	ae.Bytes(nftaTunnelKeyIP6Src, a.Src[:])
	ae.Bytes(nftaTunnelKeyIP6Dst, a.Dst[:])
	if a.FlowLabel != nil {
		ae.Uint32(nftaTunnelKeyIP6Flowlabel, *a.FlowLabel)
	}
	return ae.Encode()
}

func (a *TunnelKeyIP6) unmarshal(data []byte) error {
	ad, err := newAttributeDecoder(data)
	if err != nil {
		return err
	}
	for ad.Next() {
		switch ad.Type() {
		case nftaTunnelKeyIP6Src:
			copy(a.Src[:], ad.Bytes())
		case nftaTunnelKeyIP6Dst:
			copy(a.Dst[:], ad.Bytes())
		case nftaTunnelKeyIP6Flowlabel:
			v := ad.Uint32()
			a.FlowLabel = &v
		}
	}
	return ad.Err()
}

// https://github.com/torvalds/linux/blob/v7.1/include/uapi/linux/netfilter/nf_tables.h#L1948
const (
	nftaTunnelKeyVxlanGBP = 0x01
)

// https://github.com/torvalds/linux/blob/v7.1/include/uapi/linux/netfilter/nf_tables.h#L1948
type TunnelKeyVxlanOpts struct {
	GBP *uint32
}

func (a *TunnelKeyVxlanOpts) marshal() ([]byte, error) {
	ae := newAttributeEncoder()
	if a.GBP != nil {
		ae.Uint32(nftaTunnelKeyVxlanGBP, *a.GBP)
	}
	return ae.Encode()
}

func (a *TunnelKeyVxlanOpts) unmarshal(data []byte) error {
	ad, err := newAttributeDecoder(data)
	if err != nil {
		return err
	}
	for ad.Next() {
		if ad.Type() == nftaTunnelKeyVxlanGBP {
			v := ad.Uint32()
			a.GBP = &v
		}
	}
	return ad.Err()
}

// https://github.com/torvalds/linux/blob/v7.1/include/uapi/linux/netfilter/nf_tables.h#L1955
const (
	nftaTunnelKeyErspanVersion = 0x01
	nftaTunnelKeyErspanV1Index = 0x02
	nftaTunnelKeyErspanV2HWID  = 0x03
	nftaTunnelKeyErspanV2Dir   = 0x04
)

// https://github.com/torvalds/linux/blob/v7.1/include/uapi/linux/netfilter/nf_tables.h#L1955
type TunnelKeyErspanOpts struct {
	Version *uint32
	V1Index *uint32
	V2HWID  *uint8
	V2Dir   *uint8
}

func (a *TunnelKeyErspanOpts) marshal() ([]byte, error) {
	ae := newAttributeEncoder()
	if a.Version != nil {
		ae.Uint32(nftaTunnelKeyErspanVersion, *a.Version)
	}
	if a.V1Index != nil {
		ae.Uint32(nftaTunnelKeyErspanV1Index, *a.V1Index)
	}
	if a.V2HWID != nil {
		ae.Uint8(nftaTunnelKeyErspanV2HWID, *a.V2HWID)
	}
	if a.V2Dir != nil {
		ae.Uint8(nftaTunnelKeyErspanV2Dir, *a.V2Dir)
	}
	return ae.Encode()
}

func (a *TunnelKeyErspanOpts) unmarshal(data []byte) error {
	ad, err := newAttributeDecoder(data)
	if err != nil {
		return err
	}
	for ad.Next() {
		switch ad.Type() {
		case nftaTunnelKeyErspanVersion:
			v := ad.Uint32()
			a.Version = &v
		case nftaTunnelKeyErspanV1Index:
			v := ad.Uint32()
			a.V1Index = &v
		case nftaTunnelKeyErspanV2HWID:
			v := ad.Uint8()
			a.V2HWID = &v
		case nftaTunnelKeyErspanV2Dir:
			v := ad.Uint8()
			a.V2Dir = &v
		}
	}
	return ad.Err()
}

// https://github.com/torvalds/linux/blob/v7.1/include/uapi/linux/netfilter/nf_tables.h#L1965
const (
	nftaTunnelKeyGeneveClass = 0x01
	nftaTunnelKeyGeneveType  = 0x02
	nftaTunnelKeyGeneveData  = 0x03
)

// https://github.com/torvalds/linux/blob/v7.1/include/uapi/linux/netfilter/nf_tables.h#L1965
type TunnelKeyGeneveOpts struct {
	Class *uint16
	Type  *uint8
	Data  []byte
}

func (a *TunnelKeyGeneveOpts) marshal() ([]byte, error) {
	ae := newAttributeEncoder()
	if a.Class != nil {
		ae.Uint16(nftaTunnelKeyGeneveClass, *a.Class)
	}
	if a.Type != nil {
		ae.Uint8(nftaTunnelKeyGeneveType, *a.Type)
	}
	if len(a.Data) > 0 {
		ae.Bytes(nftaTunnelKeyGeneveData, a.Data)
	}
	return ae.Encode()
}

func (a *TunnelKeyGeneveOpts) unmarshal(data []byte) error {
	ad, err := newAttributeDecoder(data)
	if err != nil {
		return err
	}
	for ad.Next() {
		switch ad.Type() {
		case nftaTunnelKeyGeneveClass:
			v := ad.Uint16()
			a.Class = &v
		case nftaTunnelKeyGeneveType:
			v := ad.Uint8()
			a.Type = &v
		case nftaTunnelKeyGeneveData:
			a.Data = ad.Bytes()
		}
	}
	return ad.Err()
}

// https://github.com/torvalds/linux/blob/v7.1/include/uapi/linux/netfilter/nf_tables.h#L1939
const (
	nftaTunnelKeyOptsVxlan  = 0x01
	nftaTunnelKeyOptsErspan = 0x02
	nftaTunnelKeyOptsGeneve = 0x03
)

// TunnelKeyOpts holds tunnel option data. Only one of Vxlan/Erspan should be set;
// Geneve may have multiple entries (one per option TLV).
// https://github.com/torvalds/linux/blob/v7.1/include/uapi/linux/netfilter/nf_tables.h#L1939
type TunnelKeyOpts struct {
	Vxlan  *TunnelKeyVxlanOpts
	Erspan *TunnelKeyErspanOpts
	Geneve []TunnelKeyGeneveOpts
}

func (a *TunnelKeyOpts) marshal() ([]byte, error) {
	ae := newAttributeEncoder()
	if a.Vxlan != nil {
		b, err := a.Vxlan.marshal()
		if err != nil {
			return nil, err
		}
		ae.Bytes(unix.NLA_F_NESTED|nftaTunnelKeyOptsVxlan, b)
	}
	if a.Erspan != nil {
		b, err := a.Erspan.marshal()
		if err != nil {
			return nil, err
		}
		ae.Bytes(unix.NLA_F_NESTED|nftaTunnelKeyOptsErspan, b)
	}
	for _, g := range a.Geneve {
		b, err := g.marshal()
		if err != nil {
			return nil, err
		}
		ae.Bytes(unix.NLA_F_NESTED|nftaTunnelKeyOptsGeneve, b)
	}
	return ae.Encode()
}

func (a *TunnelKeyOpts) unmarshal(data []byte) error {
	ad, err := newAttributeDecoder(data)
	if err != nil {
		return err
	}
	for ad.Next() {
		switch ad.Type() {
		case nftaTunnelKeyOptsVxlan:
			a.Vxlan = &TunnelKeyVxlanOpts{}
			if err := a.Vxlan.unmarshal(ad.Bytes()); err != nil {
				return err
			}
		case nftaTunnelKeyOptsErspan:
			a.Erspan = &TunnelKeyErspanOpts{}
			if err := a.Erspan.unmarshal(ad.Bytes()); err != nil {
				return err
			}
		case nftaTunnelKeyOptsGeneve:
			var g TunnelKeyGeneveOpts
			if err := g.unmarshal(ad.Bytes()); err != nil {
				return err
			}
			a.Geneve = append(a.Geneve, g)
		}
	}
	return ad.Err()
}

// https://github.com/torvalds/linux/blob/v7.1/include/uapi/linux/netfilter/nf_tables.h#L1974
type TunnelFlags uint32

const (
	TunnelZeroCsumTX   TunnelFlags = 1 << 0
	TunnelDontFragment TunnelFlags = 1 << 1
	TunnelSeqNumber    TunnelFlags = 1 << 2
)

// https://github.com/torvalds/linux/blob/v7.1/include/uapi/linux/netfilter/nf_tables.h#L1983
const (
	nftaTunnelKeyID    = 0x01
	nftaTunnelKeyIP    = 0x02
	nftaTunnelKeyIP6   = 0x03
	nftaTunnelKeyFlags = 0x04
	nftaTunnelKeyTOS   = 0x05
	nftaTunnelKeyTTL   = 0x06
	nftaTunnelKeySport = 0x07
	nftaTunnelKeyDport = 0x08
	nftaTunnelKeyOpts  = 0x09
)

// https://github.com/torvalds/linux/blob/v7.1/include/uapi/linux/netfilter/nf_tables.h#L1983
type ObjTunnel struct {
	ID    *uint32
	IP    *TunnelKeyIP
	IP6   *TunnelKeyIP6
	Flags *TunnelFlags
	TOS   *uint8
	TTL   *uint8
	Sport *uint16
	Dport *uint16
	Opts  *TunnelKeyOpts
}

func (*ObjTunnel) ObjType() ObjType { return ObjTypeTunnel }

func (a *ObjTunnel) marshal() ([]byte, error) {
	ae := newAttributeEncoder()
	if a.ID != nil {
		ae.Uint32(nftaTunnelKeyID, *a.ID)
	}
	if a.IP != nil {
		b, err := a.IP.marshal()
		if err != nil {
			return nil, err
		}
		ae.Bytes(unix.NLA_F_NESTED|nftaTunnelKeyIP, b)
	}
	if a.IP6 != nil {
		b, err := a.IP6.marshal()
		if err != nil {
			return nil, err
		}
		ae.Bytes(unix.NLA_F_NESTED|nftaTunnelKeyIP6, b)
	}
	if a.Flags != nil {
		ae.Uint32(nftaTunnelKeyFlags, uint32(*a.Flags))
	}
	if a.TOS != nil {
		ae.Uint8(nftaTunnelKeyTOS, *a.TOS)
	}
	if a.TTL != nil {
		ae.Uint8(nftaTunnelKeyTTL, *a.TTL)
	}
	if a.Sport != nil {
		ae.Uint16(nftaTunnelKeySport, *a.Sport)
	}
	if a.Dport != nil {
		ae.Uint16(nftaTunnelKeyDport, *a.Dport)
	}
	if a.Opts != nil {
		b, err := a.Opts.marshal()
		if err != nil {
			return nil, err
		}
		ae.Bytes(unix.NLA_F_NESTED|nftaTunnelKeyOpts, b)
	}
	return ae.Encode()
}

func (a *ObjTunnel) unmarshal(data []byte) error {
	ad, err := newAttributeDecoder(data)
	if err != nil {
		return err
	}
	for ad.Next() {
		switch ad.Type() {
		case nftaTunnelKeyID:
			v := ad.Uint32()
			a.ID = &v
		case nftaTunnelKeyIP:
			a.IP = &TunnelKeyIP{}
			if err := a.IP.unmarshal(ad.Bytes()); err != nil {
				return err
			}
		case nftaTunnelKeyIP6:
			a.IP6 = &TunnelKeyIP6{}
			if err := a.IP6.unmarshal(ad.Bytes()); err != nil {
				return err
			}
		case nftaTunnelKeyFlags:
			v := TunnelFlags(ad.Uint32())
			a.Flags = &v
		case nftaTunnelKeyTOS:
			v := ad.Uint8()
			a.TOS = &v
		case nftaTunnelKeyTTL:
			v := ad.Uint8()
			a.TTL = &v
		case nftaTunnelKeySport:
			v := ad.Uint16()
			a.Sport = &v
		case nftaTunnelKeyDport:
			v := ad.Uint16()
			a.Dport = &v
		case nftaTunnelKeyOpts:
			a.Opts = &TunnelKeyOpts{}
			if err := a.Opts.unmarshal(ad.Bytes()); err != nil {
				return err
			}
		}
	}
	return ad.Err()
}
