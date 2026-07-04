package nftnl

import (
	"encoding/binary"
	"fmt"

	"github.com/mdlayher/netlink"
)

type Attrs interface {
	marshal() ([]byte, error)
	unmarshal(data []byte) error
}

func (msgType MsgType) newAttrs() (Attrs, error) {
	switch msgType {
	case MsgNewTable, MsgGetTable, MsgDelTable, MsgDestroyTable:
		return &Table{}, nil
	case MsgNewChain, MsgGetChain, MsgDelChain, MsgDestroyChain:
		return &Chain{}, nil
	case MsgNewRule, MsgGetRule, MsgDelRule, MsgGetRuleReset, MsgDestroyRule:
		return &Rule{}, nil
	case MsgNewSet, MsgGetSet, MsgDelSet, MsgDestroySet:
		return &Set{}, nil
	case MsgNewSetElem, MsgGetSetElem, MsgDelSetElem, MsgDestroySetElem, MsgGetSetElemReset:
		return &SetElemList{}, nil
	case MsgNewGen, MsgGetGen:
		return &Gen{}, nil
	case MsgTrace:
		return &Trace{}, nil
	case MsgNewObj, MsgGetObj, MsgDelObj, MsgGetObjReset, MsgDestroyObj:
		return &Obj{}, nil
	case MsgNewFlowtable, MsgGetFlowtable, MsgDelFlowtable, MsgDestroyFlowtable:
		return &Flowtable{}, nil
	default:
		return nil, fmt.Errorf("unknown message type %d", msgType)
	}
}

// As extracts the concrete attrs value from a Msg, returning false if the
// type does not match.
func As[T Attrs](a Attrs) (T, bool) {
	t, ok := a.(T)
	return t, ok
}

func newAttributeDecoder(b []byte) (*netlink.AttributeDecoder, error) {
	ad, err := netlink.NewAttributeDecoder(b)
	if err != nil {
		return nil, err
	}

	ad.ByteOrder = binary.BigEndian

	return ad, nil
}

func newAttributeEncoder() *netlink.AttributeEncoder {
	ae := netlink.NewAttributeEncoder()

	ae.ByteOrder = binary.BigEndian

	return ae
}
