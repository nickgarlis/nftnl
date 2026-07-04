package nftnl

import (
	"sync"

	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

type Batch struct {
	mu       sync.Mutex
	messages []Msg
	genID    uint32
}

func NewBatch() *Batch {
	return &Batch{}
}

// NewBatchWithGenID creates a batch that will be rejected by the kernel with
// ERESTART if the ruleset generation ID has changed since id was fetched.
// Callers obtain the generation ID by sending NFT_MSG_GETGEN and reading
// Gen.ID from the response.
func NewBatchWithGenID(id uint32) *Batch {
	return &Batch{genID: id}
}

func (b *Batch) Add(msg Msg) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.messages = append(b.messages, msg)
}

func (b *Batch) marshal() ([]netlink.Message, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	result := make([]netlink.Message, 0, len(b.messages)+2)
	result = append(result, batchBegin(b.genID))

	for _, msg := range b.messages {
		nlMsg, err := msg.marshal()
		if err != nil {
			return nil, err
		}
		result = append(result, nlMsg)
	}

	result = append(result, batchCtrl(unix.NFNL_MSG_BATCH_END))
	return result, nil
}

// batchBegin builds the NFNL_MSG_BATCH_BEGIN control message.
// If genID is non-zero it is encoded as NFNL_BATCH_GENID so the kernel
// rejects the batch with ERESTART if the ruleset has changed.
func batchBegin(genID uint32) netlink.Message {
	nfg := nfGenMsg{
		Family:  unix.NFPROTO_UNSPEC,
		Version: unix.NFNETLINK_V0,
		ResID:   unix.NFNL_SUBSYS_NFTABLES,
	}
	data := nfg.marshal()
	if genID != 0 {
		ae := newAttributeEncoder()
		ae.Uint32(unix.NFNL_BATCH_GENID, genID)
		if b, err := ae.Encode(); err == nil {
			data = append(data, b...)
		}
	}
	return netlink.Message{
		Header: netlink.Header{
			Type:  netlink.HeaderType(unix.NFNL_MSG_BATCH_BEGIN),
			Flags: netlink.Request,
		},
		Data: data,
	}
}

func batchCtrl(msgType uint16) netlink.Message {
	nfg := nfGenMsg{
		Family:  unix.NFPROTO_UNSPEC,
		Version: unix.NFNETLINK_V0,
		ResID:   unix.NFNL_SUBSYS_NFTABLES,
	}
	return netlink.Message{
		Header: netlink.Header{
			Type:  netlink.HeaderType(msgType),
			Flags: netlink.Request,
		},
		Data: nfg.marshal(),
	}
}
