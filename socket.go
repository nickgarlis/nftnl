package nftnl

import (
	"fmt"

	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

// ensureSendBuffer grows SO_SNDBUF to at least needed bytes.
// Mirrors mnl_set_sndbuffer() in the nft CLI.
func ensureSendBuffer(conn *netlink.Conn, needed int) error {
	cur, err := conn.WriteBuffer()
	if err != nil {
		return fmt.Errorf("get write buffer: %w", err)
	}
	if cur >= needed {
		return nil
	}
	return conn.SetWriteBuffer(needed)
}

// ensureRecvBuffer grows SO_RCVBUF to at least needed bytes.
// Mirrors mnl_set_rcvbuffer() in the nft CLI.
func ensureRecvBuffer(conn *netlink.Conn, needed int) error {
	cur, err := conn.ReadBuffer()
	if err != nil {
		return fmt.Errorf("get read buffer: %w", err)
	}
	if cur >= needed {
		return nil
	}
	return conn.SetReadBuffer(needed)
}

// isReadReady reports whether the netlink socket has data available to read.
// Uses poll(2) with a zero timeout so it returns immediately without blocking.
// poll(2) is used instead of pselect(2) because FdSet.Set panics for fd >= 1024.
// EINTR is retried in a loop since signals can interrupt poll spuriously.
func isReadReady(conn *netlink.Conn) (bool, error) {
	rawConn, err := conn.SyscallConn()
	if err != nil {
		return false, fmt.Errorf("get raw conn: %w", err)
	}

	var n int
	var opErr error
	err = rawConn.Control(func(fd uintptr) {
		fds := []unix.PollFd{{
			Fd:     int32(fd),
			Events: unix.POLLIN,
		}}
		for {
			n, opErr = unix.Poll(fds, 0) // 0: return immediately
			if opErr != unix.EINTR {
				break
			}
		}
	})
	if err != nil {
		return false, err
	}
	if opErr != nil {
		return false, fmt.Errorf("poll: %w", opErr)
	}
	return n > 0, nil
}
