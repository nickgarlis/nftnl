package nftnl

import (
	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

type header struct {
	SubsysID uint16
	MsgType  uint16
	Flags    netlink.HeaderFlags
}

func (h *header) marshal() netlink.Header {
	var t netlink.HeaderType
	if h.SubsysID == unix.NFNL_SUBSYS_NFTABLES {
		t = netlink.HeaderType((h.SubsysID << 8) | h.MsgType)
	} else {
		t = netlink.HeaderType(h.SubsysID)
	}
	return netlink.Header{Type: t, Flags: h.Flags}
}

func (h *header) unmarshal(nlh netlink.Header) error {
	h.SubsysID = uint16(nlh.Type >> 8)
	h.MsgType = uint16(nlh.Type & 0xff)
	h.Flags = nlh.Flags
	return nil
}
