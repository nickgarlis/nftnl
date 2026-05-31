package nftnl

import (
	"fmt"
	"strings"
)

// UserData is a dictionary over the nftables userdata TLV blob.
// Keys are uint8 type codes whose meaning depends on which object the userdata
// is attached to — use the UD* constants below.  The TLV wire encoding is
// handled transparently by marshal/unmarshal.
//
// The zero value (nil map) is an empty dictionary ready for use.
type UserData map[uint8][]byte

// Set stores raw bytes for the given type key.
func (u *UserData) Set(typ uint8, data []byte) {
	if *u == nil {
		*u = make(UserData)
	}
	(*u)[typ] = data
}

// Get returns the raw bytes for the given type key.
func (u UserData) Get(typ uint8) ([]byte, bool) {
	v, ok := u[typ]
	return v, ok
}

// SetString stores a null-terminated string for the given type key.
// The null terminator is required by libnftnl's TLV string convention.
func (u *UserData) SetString(typ uint8, s string) {
	u.Set(typ, append([]byte(s), 0))
}

// GetString returns the string for the given type key, stripping the null terminator.
func (u UserData) GetString(typ uint8) (string, bool) {
	b, ok := u[typ]
	if !ok {
		return "", false
	}
	return strings.TrimRight(string(b), "\x00"), true
}

// Del removes the entry for the given type key.
func (u UserData) Del(typ uint8) {
	delete(u, typ)
}

// Len returns the number of entries.
func (u UserData) Len() int {
	return len(u)
}

// marshal encodes to the libnftnl TLV wire format. Returns nil if empty.
func (u UserData) marshal() []byte {
	if len(u) == 0 {
		return nil
	}
	var buf []byte
	for k, v := range u {
		buf = append(buf, k, uint8(len(v)))
		buf = append(buf, v...)
	}
	return buf
}

// unmarshal decodes the libnftnl TLV wire format into the dictionary.
func (u *UserData) unmarshal(data []byte) error {
	for len(data) >= 2 {
		typ := data[0]
		l := int(data[1])
		if len(data) < 2+l {
			return fmt.Errorf("nftnl: userdata TLV truncated at type %d", typ)
		}
		val := make([]byte, l)
		copy(val, data[2:2+l])
		u.Set(typ, val)
		data = data[2+l:]
	}
	return nil
}

// https://git.netfilter.org/libnftnl/tree/include/libnftnl/udata.h
const (
	TableUDComment uint8 = 0
	TableUDNFTVer  uint8 = 1
	TableUDNFTBld  uint8 = 2
)

// https://git.netfilter.org/libnftnl/tree/include/libnftnl/udata.h
const (
	RuleUDComment        uint8 = 0
	RuleUDEbtablesPolicy uint8 = 1
)

// https://git.netfilter.org/libnftnl/tree/include/libnftnl/udata.h
const (
	SetUDKeyByteOrder  uint8 = 0
	SetUDDataByteOrder uint8 = 1
	SetUDMergeElements uint8 = 2
	SetUDKeyTypeof     uint8 = 3
	SetUDDataTypeof    uint8 = 4
	SetUDExpr          uint8 = 5
	SetUDDataInterval  uint8 = 6
	SetUDComment       uint8 = 7
)

// https://git.netfilter.org/libnftnl/tree/include/libnftnl/udata.h
const (
	SetElemUDComment uint8 = 0
	SetElemUDFlags   uint8 = 1
)
