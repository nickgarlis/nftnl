package nftnl

import (
	"encoding/binary"
	"fmt"
	"strings"
)

func udPut(buf []byte, typ uint8, val []byte) []byte {
	buf = append(buf, typ, uint8(len(val)))
	return append(buf, val...)
}

func udPutString(buf []byte, typ uint8, s *string) []byte {
	if s == nil {
		return buf
	}
	return udPut(buf, typ, append([]byte(*s), 0))
}

func udString(val []byte) *string {
	return new(strings.TrimRight(string(val), "\x00"))
}

func udPutUint64BE(buf []byte, typ uint8, v *uint64) []byte {
	if v == nil {
		return buf
	}
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], *v)
	return udPut(buf, typ, b[:])
}

func udUint64BE(val []byte) *uint64 {
	if len(val) != 8 {
		return nil
	}
	return new(binary.BigEndian.Uint64(val))
}

func udEach(data []byte, fn func(typ uint8, val []byte)) error {
	for len(data) >= 2 {
		typ := data[0]
		l := int(data[1])
		if len(data) < 2+l {
			return fmt.Errorf("nftnl: userdata TLV truncated at type %d", typ)
		}
		fn(typ, data[2:2+l])
		data = data[2+l:]
	}
	return nil
}

const (
	udTableComment uint8 = 0
	udTableNFTVer  uint8 = 1
	udTableNFTBld  uint8 = 2
)

// NFTVersion is the nft release that created the table.
type NFTVersion struct {
	Major uint8
	Minor uint8
	Patch uint8
}

func udPutNFTVersion(buf []byte, typ uint8, v *NFTVersion) []byte {
	if v == nil {
		return buf
	}
	return udPut(buf, typ, []byte{v.Major, v.Minor, v.Patch, 0})
}

func udNFTVersion(val []byte) *NFTVersion {
	if len(val) != 4 {
		return nil
	}
	return &NFTVersion{Major: val[0], Minor: val[1], Patch: val[2]}
}

// Table userdata
//
// https://git.netfilter.org/libnftnl/tree/include/libnftnl/udata.h?id=0f48d7638800bb48c863e6b7e5f2fe92972bb31c#n12
type TableUserData struct {
	// Table comment
	Comment *string
	// nft version that created the table
	NFTVer *NFTVersion
	// Timestamp in seconds of the nft build that created the table
	NFTBld *uint64
}

func (a *TableUserData) marshal() []byte {
	if a == nil {
		return nil
	}
	var buf []byte
	buf = udPutString(buf, udTableComment, a.Comment)
	buf = udPutNFTVersion(buf, udTableNFTVer, a.NFTVer)
	buf = udPutUint64BE(buf, udTableNFTBld, a.NFTBld)
	return buf
}

func (a *TableUserData) unmarshal(data []byte) error {
	return udEach(data, func(typ uint8, val []byte) {
		switch typ {
		case udTableComment:
			a.Comment = udString(val)
		case udTableNFTVer:
			a.NFTVer = udNFTVersion(val)
		case udTableNFTBld:
			a.NFTBld = udUint64BE(val)
		}
	})
}

const udChainComment uint8 = 0

// Chain userdata
//
// https://git.netfilter.org/libnftnl/tree/include/libnftnl/udata.h?id=0f48d7638800bb48c863e6b7e5f2fe92972bb31c#n20
type ChainUserData struct {
	// Chain comment
	Comment *string
}

func (a *ChainUserData) marshal() []byte {
	if a == nil {
		return nil
	}
	return udPutString(nil, udChainComment, a.Comment)
}

func (a *ChainUserData) unmarshal(data []byte) error {
	return udEach(data, func(typ uint8, val []byte) {
		if typ == udChainComment {
			a.Comment = udString(val)
		}
	})
}

const (
	udRuleComment uint8 = 0
)

// Rule userdata
//
// https://git.netfilter.org/libnftnl/tree/include/libnftnl/udata.h?id=0f48d7638800bb48c863e6b7e5f2fe92972bb31c#n26
type RuleUserData struct {
	// Rule comment
	Comment *string
	// TODO: investigate whether the rest of the fields are useful to expose.
}

func (a *RuleUserData) marshal() []byte {
	if a == nil {
		return nil
	}
	var buf []byte
	buf = udPutString(buf, udRuleComment, a.Comment)
	return buf
}

func (a *RuleUserData) unmarshal(data []byte) error {
	return udEach(data, func(typ uint8, val []byte) {
		if typ == udRuleComment {
			a.Comment = udString(val)
		}
	})
}

const udObjComment uint8 = 0

// Object userdata
//
// https://git.netfilter.org/libnftnl/tree/include/libnftnl/udata.h?id=0f48d7638800bb48c863e6b7e5f2fe92972bb31c#n33
type ObjUserData struct {
	// Object comment
	Comment *string
}

func (a *ObjUserData) marshal() []byte {
	if a == nil {
		return nil
	}
	return udPutString(nil, udObjComment, a.Comment)
}

func (a *ObjUserData) unmarshal(data []byte) error {
	return udEach(data, func(typ uint8, val []byte) {
		if typ == udObjComment {
			a.Comment = udString(val)
		}
	})
}

const udSetComment uint8 = 7

// Set userdata
//
// https://git.netfilter.org/libnftnl/tree/include/libnftnl/udata.h?id=0f48d7638800bb48c863e6b7e5f2fe92972bb31c#n41
type SetUserData struct {
	// Set comment
	Comment *string
	// TODO: investigate whether the rest of the fields are useful to expose.
}

func (a *SetUserData) marshal() []byte {
	if a == nil {
		return nil
	}
	return udPutString(nil, udSetComment, a.Comment)
}

func (a *SetUserData) unmarshal(data []byte) error {
	return udEach(data, func(typ uint8, val []byte) {
		if typ == udSetComment {
			a.Comment = udString(val)
		}
	})
}

const udSetElemComment uint8 = 0

// Set element userdata
//
// https://git.netfilter.org/libnftnl/tree/include/libnftnl/udata.h?id=0f48d7638800bb48c863e6b7e5f2fe92972bb31c#n61
type SetElemUserData struct {
	// Set element comment
	Comment *string
	// TODO: investigate whether the rest of the fields are useful to expose.
}

func (a *SetElemUserData) marshal() []byte {
	if a == nil {
		return nil
	}
	return udPutString(nil, udSetElemComment, a.Comment)
}

func (a *SetElemUserData) unmarshal(data []byte) error {
	return udEach(data, func(typ uint8, val []byte) {
		if typ == udSetElemComment {
			a.Comment = udString(val)
		}
	})
}
