package nftnl

import (
	"golang.org/x/sys/unix"
)

// https://github.com/torvalds/linux/blob/v7.1/include/uapi/linux/netfilter/nf_tables.h#L263
const (
	nftaRuleTable       = unix.NFTA_RULE_TABLE
	nftaRuleChain       = unix.NFTA_RULE_CHAIN
	nftaRuleHandle      = unix.NFTA_RULE_HANDLE
	nftaRuleExpressions = unix.NFTA_RULE_EXPRESSIONS
	nftaRuleCompat      = unix.NFTA_RULE_COMPAT
	nftaRulePosition    = unix.NFTA_RULE_POSITION
	nftaRuleUserdata    = unix.NFTA_RULE_USERDATA
	nftaRuleID          = unix.NFTA_RULE_ID
	nftaRulePositionID  = 0x0a
	nftaRuleChainID     = 0x0b
	nftaListElem        = unix.NFTA_LIST_ELEM
)

// https://github.com/torvalds/linux/blob/v7.1/include/uapi/linux/netfilter/nf_tables.h#L294
type RuleCompatFlags uint32

const (
	RuleCompatUnused RuleCompatFlags = 1 << 0
	// Invert the check result
	RuleCompatInv RuleCompatFlags = 1 << 1
)

// https://github.com/torvalds/linux/blob/v7.1/include/uapi/linux/netfilter/nf_tables.h#L306
const (
	nftaRuleCompatProto = unix.NFTA_RULE_COMPAT_PROTO
	nftaRuleCompatFlags = unix.NFTA_RULE_COMPAT_FLAGS
)

// Rule compatibility attributes
//
// https://github.com/torvalds/linux/blob/v7.1/include/uapi/linux/netfilter/nf_tables.h#L306
type RuleCompat struct {
	// Numeric value of handled protocol
	Proto *uint32
	// Bitmask of rule compatibility flags
	Flags *RuleCompatFlags
}

func (a *RuleCompat) marshal() ([]byte, error) {
	ae := newAttributeEncoder()
	if a.Proto != nil {
		ae.Uint32(nftaRuleCompatProto, *a.Proto)
	}
	if a.Flags != nil {
		ae.Uint32(nftaRuleCompatFlags, uint32(*a.Flags))
	}
	return ae.Encode()
}

func (a *RuleCompat) unmarshal(data []byte) error {
	ad, err := newAttributeDecoder(data)
	if err != nil {
		return err
	}
	for ad.Next() {
		switch ad.Type() {
		case nftaRuleCompatProto:
			v := ad.Uint32()
			a.Proto = &v
		case nftaRuleCompatFlags:
			v := ad.Uint32()
			a.Flags = new(RuleCompatFlags(v))
		}
	}
	return ad.Err()
}

// Rule attributes
//
// https://github.com/torvalds/linux/blob/v7.1/include/uapi/linux/netfilter/nf_tables.h#L263
type Rule struct {
	// Name of the table containing the rule
	Table string
	// Name of the chain containing the rule
	Chain *string
	// Numeric handle of the rule
	Handle *uint64
	// List of expressions
	Expressions []Expr
	// Compatibility specifications of the rule
	Compat *RuleCompat
	// Numeric handle of the previous rule
	Position *uint64
	// User data binary
	UserData UserData
	// Uniquely identifies a rule in a transaction
	ID *uint32
	// Transaction unique identifier of the previous rule
	PositionID *uint32
	// Add the rule to chain by ID, alternative to Rule.Chain
	ChainID *uint32
}

func (a *Rule) marshal() ([]byte, error) {
	ae := newAttributeEncoder()
	ae.String(nftaRuleTable, a.Table)
	if a.Chain != nil {
		ae.String(nftaRuleChain, *a.Chain)
	}
	if a.Handle != nil {
		ae.Uint64(nftaRuleHandle, *a.Handle)
	}
	if a.Compat != nil {
		b, err := a.Compat.marshal()
		if err != nil {
			return nil, err
		}
		ae.Bytes(unix.NLA_F_NESTED|nftaRuleCompat, b)
	}
	if a.Position != nil {
		ae.Uint64(nftaRulePosition, *a.Position)
	}
	if b := a.UserData.marshal(); b != nil {
		ae.Bytes(nftaRuleUserdata, b)
	}
	if a.ID != nil {
		ae.Uint32(nftaRuleID, *a.ID)
	}
	if a.PositionID != nil {
		ae.Uint32(nftaRulePositionID, *a.PositionID)
	}
	if a.ChainID != nil {
		ae.Uint32(nftaRuleChainID, *a.ChainID)
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
		ae.Bytes(unix.NLA_F_NESTED|nftaRuleExpressions, b)
	}
	return ae.Encode()
}

func (a *Rule) unmarshal(data []byte) error {
	ad, err := newAttributeDecoder(data)
	if err != nil {
		return err
	}
	for ad.Next() {
		switch ad.Type() {
		case nftaRuleTable:
			a.Table = ad.String()
		case nftaRuleChain:
			v := ad.String()
			a.Chain = &v
		case nftaRuleHandle:
			v := ad.Uint64()
			a.Handle = &v
		case nftaRuleCompat:
			a.Compat = &RuleCompat{}
			if err := a.Compat.unmarshal(ad.Bytes()); err != nil {
				return err
			}
		case nftaRulePosition:
			v := ad.Uint64()
			a.Position = &v
		case nftaRuleUserdata:
			if err := a.UserData.unmarshal(ad.Bytes()); err != nil {
				return err
			}
		case nftaRuleID:
			v := ad.Uint32()
			a.ID = &v
		case nftaRulePositionID:
			v := ad.Uint32()
			a.PositionID = &v
		case nftaRuleChainID:
			v := ad.Uint32()
			a.ChainID = &v
		case nftaRuleExpressions:
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
