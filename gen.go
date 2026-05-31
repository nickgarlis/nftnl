package nftnl

import "golang.org/x/sys/unix"

// https://github.com/torvalds/linux/blob/v7.1/include/uapi/linux/netfilter/nf_tables.h#L1583
const (
	nftaGenID       = unix.NFTA_GEN_ID
	nftaGenProcPID  = unix.NFTA_GEN_PROC_PID
	nftaGenProcName = unix.NFTA_GEN_PROC_NAME
)

// https://github.com/torvalds/linux/blob/v7.1/include/uapi/linux/netfilter/nf_tables.h#L1583
type Gen struct {
	ID       uint32
	ProcPID  *uint32
	ProcName string
}

func (g *Gen) marshal() ([]byte, error) {
	ae := newAttributeEncoder()
	ae.Uint32(nftaGenID, g.ID)
	if g.ProcPID != nil {
		ae.Uint32(nftaGenProcPID, *g.ProcPID)
	}
	if g.ProcName != "" {
		ae.String(nftaGenProcName, g.ProcName)
	}
	return ae.Encode()
}

func (g *Gen) unmarshal(b []byte) error {
	ad, err := newAttributeDecoder(b)
	if err != nil {
		return err
	}
	for ad.Next() {
		switch ad.Type() {
		case nftaGenID:
			g.ID = ad.Uint32()
		case nftaGenProcPID:
			v := ad.Uint32()
			g.ProcPID = &v
		case nftaGenProcName:
			g.ProcName = ad.String()
		}
	}
	return ad.Err()
}
