package nftnl

import (
	"encoding/binary"
	"fmt"

	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

// https://github.com/torvalds/linux/blob/f83a4f2a4d8c485922fba3018a64fc8f4cfd315f/include/uapi/linux/netfilter/nfnetlink.h#L34C8-L34C16
type nfGenMsg struct {
	Family uint8
	// Default unix.NFNETLINK_V0
	Version uint8
	ResID   uint16
}

func (h *nfGenMsg) marshal() []byte {
	if h.Version == 0 {
		h.Version = unix.NFNETLINK_V0
	}

	resID := make([]byte, 2)
	binary.BigEndian.PutUint16(resID, h.ResID)

	return append(
		[]byte{h.Family, h.Version},
		resID...,
	)
}

func (h *nfGenMsg) unmarshal(msg netlink.Message) error {
	if len(msg.Data) < 4 {
		return fmt.Errorf("nfmsg: invalid length %d", len(msg.Data))
	}
	b := msg.Data[:4] // NFGenMsg is always 4 bytes

	h.Family = b[0]
	h.Version = b[1]
	h.ResID = binary.BigEndian.Uint16(b[2:4])

	return nil
}
