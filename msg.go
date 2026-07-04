package nftnl

import (
	"fmt"

	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

// MsgType
// https://github.com/torvalds/linux/blob/v7.1/include/uapi/linux/netfilter/nf_tables.h#L77
type MsgType uint16

const (
	MsgNewTable         MsgType = iota // create a new table
	MsgGetTable                        // get a table
	MsgDelTable                        // delete a table
	MsgNewChain                        // create a new chain
	MsgGetChain                        // get a chain
	MsgDelChain                        // delete a chain
	MsgNewRule                         // create a new rule
	MsgGetRule                         // get a rule
	MsgDelRule                         // delete a rule
	MsgNewSet                          // create a new set
	MsgGetSet                          // get a set
	MsgDelSet                          // delete a set
	MsgNewSetElem                      // create a new set element
	MsgGetSetElem                      // get a set element
	MsgDelSetElem                      // delete a set element
	MsgNewGen                          // announce a new generation (event only)
	MsgGetGen                          // get the rule-set generation
	MsgTrace                           // trace event (event only)
	MsgNewObj                          // create a stateful object
	MsgGetObj                          // get a stateful object
	MsgDelObj                          // delete a stateful object
	MsgGetObjReset                     // get and reset a stateful object
	MsgNewFlowtable                    // create a new flow table
	MsgGetFlowtable                    // get a flow table
	MsgDelFlowtable                    // delete a flow table
	MsgGetRuleReset                    // get rules and reset stateful expressions
	MsgDestroyTable                    // destroy a table (idempotent)
	MsgDestroyChain                    // destroy a chain (idempotent)
	MsgDestroyRule                     // destroy a rule (idempotent)
	MsgDestroySet                      // destroy a set (idempotent)
	MsgDestroySetElem                  // destroy a set element (idempotent)
	MsgDestroyObj                      // destroy a stateful object (idempotent)
	MsgDestroyFlowtable                // destroy a flow table (idempotent)
	MsgGetSetElemReset                 // get set elements and reset stateful expressions
)

func (m MsgType) String() string {
	switch m {
	case MsgNewTable:
		return "MsgNewTable"
	case MsgGetTable:
		return "MsgGetTable"
	case MsgDelTable:
		return "MsgDelTable"
	case MsgNewChain:
		return "MsgNewChain"
	case MsgGetChain:
		return "MsgGetChain"
	case MsgDelChain:
		return "MsgDelChain"
	case MsgNewRule:
		return "MsgNewRule"
	case MsgGetRule:
		return "MsgGetRule"
	case MsgDelRule:
		return "MsgDelRule"
	case MsgNewSet:
		return "MsgNewSet"
	case MsgGetSet:
		return "MsgGetSet"
	case MsgDelSet:
		return "MsgDelSet"
	case MsgNewSetElem:
		return "MsgNewSetElem"
	case MsgGetSetElem:
		return "MsgGetSetElem"
	case MsgDelSetElem:
		return "MsgDelSetElem"
	case MsgNewGen:
		return "MsgNewGen"
	case MsgGetGen:
		return "MsgGetGen"
	case MsgTrace:
		return "MsgTrace"
	case MsgNewObj:
		return "MsgNewObj"
	case MsgGetObj:
		return "MsgGetObj"
	case MsgDelObj:
		return "MsgDelObj"
	case MsgGetObjReset:
		return "MsgGetObjReset"
	case MsgNewFlowtable:
		return "MsgNewFlowtable"
	case MsgGetFlowtable:
		return "MsgGetFlowtable"
	case MsgDelFlowtable:
		return "MsgDelFlowtable"
	case MsgGetRuleReset:
		return "MsgGetRuleReset"
	case MsgDestroyTable:
		return "MsgDestroyTable"
	case MsgDestroyChain:
		return "MsgDestroyChain"
	case MsgDestroyRule:
		return "MsgDestroyRule"
	case MsgDestroySet:
		return "MsgDestroySet"
	case MsgDestroySetElem:
		return "MsgDestroySetElem"
	case MsgDestroyObj:
		return "MsgDestroyObj"
	case MsgDestroyFlowtable:
		return "MsgDestroyFlowtable"
	case MsgGetSetElemReset:
		return "MsgGetSetElemReset"
	}
	return fmt.Sprintf("MsgType(%d)", uint16(m))
}

// https://github.com/torvalds/linux/blob/v7.1/include/uapi/linux/netfilter.h#L37
type Family = uint8

const (
	FamilyUnspec Family = unix.NFPROTO_UNSPEC
	FamilyInet   Family = unix.NFPROTO_INET
	FamilyIPv4   Family = unix.NFPROTO_IPV4
	FamilyIPv6   Family = unix.NFPROTO_IPV6
	FamilyARP    Family = unix.NFPROTO_ARP
	FamilyNetdev Family = unix.NFPROTO_NETDEV
	FamilyBridge Family = unix.NFPROTO_BRIDGE
)

type Msg struct {
	Type   MsgType
	Family Family
	Flags  netlink.HeaderFlags
	Attrs  Attrs
}

func (m *Msg) marshal() (netlink.Message, error) {
	h := header{
		SubsysID: unix.NFNL_SUBSYS_NFTABLES,
		MsgType:  uint16(m.Type),
		Flags:    m.Flags,
	}
	nfg := nfGenMsg{
		Family:  m.Family,
		Version: unix.NFNETLINK_V0,
	}

	nlMsg := netlink.Message{Header: h.marshal()}
	data := nfg.marshal()
	if m.Attrs != nil {
		attrs, err := m.Attrs.marshal()
		if err != nil {
			return netlink.Message{}, err
		}
		data = append(data, attrs...)
	}
	nlMsg.Data = data
	return nlMsg, nil
}

func (m *Msg) unmarshal(msg netlink.Message) error {
	var h header
	if err := h.unmarshal(msg.Header); err != nil {
		return err
	}
	m.Type = MsgType(h.MsgType)
	m.Flags = h.Flags

	if len(msg.Data) >= 4 {
		var nfg nfGenMsg
		if err := nfg.unmarshal(msg); err != nil {
			return err
		}
		m.Family = nfg.Family
	}

	if len(msg.Data) > 4 {
		attr, err := m.Type.newAttrs()
		if err != nil {
			return err
		}
		if attr != nil {
			m.Attrs = attr
			if err := m.Attrs.unmarshal(msg.Data[4:]); err != nil {
				return err
			}
		}
	}

	return nil
}
