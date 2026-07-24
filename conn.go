package nftnl

import (
	"errors"
	"fmt"
	"math"
	"os"
	"sync"

	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

type Config struct {
	// NetNS is the network namespace to operate in. If 0, the current
	// network namespace is used.
	NetNS int
}

type Conn struct {
	// netlink socket using NETLINK_NETFILTER protocol.
	nlconn *netlink.Conn
	mu     sync.Mutex
}

// recvBufSize returns the userspace buffer size passed to recvmsg.
// Takes the larger of NFT_NLMSG_MAXSIZE and NFT_MNL_ACK_MAXSIZE from the nft
// CLI: NFT_NLMSG_MAXSIZE wins on large-page systems (PAGE_SIZE > 8192),
// NFT_MNL_ACK_MAXSIZE wins otherwise as it is sized to hold a NLMSG_ERROR
// that echoes back the largest possible request.
func recvBufSize() int {
	const nfgenmsgSize = 4 // sizeof(struct nfgenmsg)
	nftNlmsgMaxsize := math.MaxUint16 + os.Getpagesize()
	nftMnlAckMaxsize := unix.SizeofNlMsghdr + nfgenmsgSize + (1 << 16) + min(os.Getpagesize(), 8192)
	return max(nftNlmsgMaxsize, nftMnlAckMaxsize)
}

func Open(config *Config) (*Conn, error) {
	if config == nil {
		config = &Config{}
	}
	nlconn, err := netlink.Dial(unix.NETLINK_NETFILTER, &netlink.Config{
		NetNS:             config.NetNS,
		MessageBufferSize: recvBufSize(),
	})
	if err != nil {
		return nil, err
	}
	return &Conn{
		nlconn: nlconn,
	}, nil
}

func (c *Conn) receive() ([]Msg, error) {
	var msgs []Msg
	var firstErr error
	for {
		ready, err := isReadReady(c.nlconn)
		if err != nil {
			return nil, err
		}
		if !ready {
			break
		}
		for nlMsg, err := range c.nlconn.ReceiveIter() {
			if err != nil {
				if firstErr == nil {
					firstErr = err
				}
				continue
			}
			if nlMsg.Header.Type>>8 != unix.NFNL_SUBSYS_NFTABLES {
				continue
			}
			var m Msg
			if err := m.unmarshal(nlMsg); err != nil {
				if firstErr == nil {
					firstErr = err
				}
				continue
			}
			msgs = append(msgs, m)
		}
	}
	return msgs, firstErr
}

// enrichBatchErr annotates a *netlink.OpError with the MsgType of the command
// that caused it, using the sequence number to look it up in seqMap.
func enrichBatchErr(err error, seqMap map[uint32]MsgType) error {
	var opErr *netlink.OpError
	if !errors.As(err, &opErr) || opErr.Sequence == 0 {
		return err
	}
	msgType, ok := seqMap[opErr.Sequence]
	if !ok {
		return err
	}
	return fmt.Errorf("%s: %w", msgType, err)
}

func (c *Conn) Send(msg Msg) ([]Msg, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	nlMsg, err := msg.marshal()
	if err != nil {
		return nil, err
	}

	if _, err := c.nlconn.Send(nlMsg); err != nil {
		return nil, err
	}

	return c.receive()
}

func (c *Conn) SendBatch(batch *Batch) ([]Msg, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	nlMsgs, err := batch.marshal()
	if err != nil {
		return nil, err
	}

	// Validate inner messages (skip BEGIN at [0] and END at [len-1]).
	numCmds := len(nlMsgs) - 2
	var totalSize int
	for _, m := range nlMsgs[1 : len(nlMsgs)-1] {
		if m.Header.Flags&netlink.Dump == netlink.Dump {
			return nil, fmt.Errorf("SendBatch: batch cannot contain dump messages")
		}
		totalSize += len(m.Data) + 16 // 16 = nlmsghdr size
	}

	if err := ensureSendBuffer(c.nlconn, totalSize); err != nil {
		return nil, err
	}

	// Receive buffer: 1 KB per command, minimum MNL_SOCKET_BUFFER_SIZE (8192).
	// Mirrors mnl_set_rcvbuffer() in the nft CLI.
	rcvSize := max(numCmds*1024, 8192)
	if err := ensureRecvBuffer(c.nlconn, rcvSize); err != nil {
		return nil, err
	}

	sentMsgs, err := c.nlconn.SendMessages(nlMsgs)
	if err != nil {
		return nil, err
	}

	// Build seq → MsgType map so errors can be annotated with the failing command type.
	// sentMsgs[0] = BATCH_BEGIN, sentMsgs[len-1] = BATCH_END — skip both.
	seqMap := make(map[uint32]MsgType, len(batch.messages))
	for i, sent := range sentMsgs {
		if i == 0 || i == len(sentMsgs)-1 {
			continue
		}
		if i-1 < len(batch.messages) {
			seqMap[sent.Header.Sequence] = batch.messages[i-1].Type
		}
	}

	msgs, err := c.receive()
	return msgs, enrichBatchErr(err, seqMap)
}

func (c *Conn) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.nlconn.Close()
}
