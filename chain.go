package nftnl

import (
	"math"

	"golang.org/x/sys/unix"
)

// Hook numbers for Hook.HookNum.
//
// https://github.com/torvalds/linux/blob/v7.1/include/uapi/linux/netfilter_ipv4.h#L15
type HookNum uint32

const (
	HookPreRouting HookNum = iota
	HookLocalIn
	HookForward
	HookLocalOut
	HookPostRouting
)

// Chain priorities for Hook.Priority.
//
// https://github.com/torvalds/linux/blob/v7.1/include/uapi/linux/netfilter_ipv4.h#L29
type Priority = int32

const (
	PriorityFirst           Priority = math.MinInt32
	PriorityRawBeforeDefrag          = -450
	PriorityConntrackDefrag          = -400
	PriorityRaw                      = -300
	PrioritySELinuxFirst             = -225
	PriorityConntrack                = -200
	PriorityMangle                   = -150
	PriorityNATDst                   = -100
	PriorityFilter                   = 0
	PrioritySecurity                 = 50
	PriorityNATSrc                   = 100
	PrioritySELinuxLast              = 225
	PriorityConntrackHelper          = 300
	PriorityLast                     = math.MaxInt32
)

// https://github.com/torvalds/linux/blob/v7.1/include/uapi/linux/netfilter/nf_tables.h#L165
const (
	nftaHookHooknum  = unix.NFTA_HOOK_HOOKNUM
	nftaHookPriority = unix.NFTA_HOOK_PRIORITY
	nftaHookDev      = unix.NFTA_HOOK_DEV
	nftaHookDevs     = 0x04
	nftaDeviceName   = 0x01
)

// Hook attributes.
//
// https://github.com/torvalds/linux/blob/v7.1/include/uapi/linux/netfilter/nf_tables.h#L165
type Hook struct {
	HookNum  HookNum
	Priority Priority
	Dev      *string
	Devs     []string
}

func (a *Hook) marshal() ([]byte, error) {
	ae := newAttributeEncoder()
	ae.Uint32(nftaHookHooknum, uint32(a.HookNum))
	ae.Uint32(nftaHookPriority, uint32(a.Priority))
	if len(a.Devs) > 0 {
		inner := newAttributeEncoder()
		for _, dev := range a.Devs {
			inner.String(nftaDeviceName, dev)
		}
		b, err := inner.Encode()
		if err != nil {
			return nil, err
		}
		ae.Bytes(unix.NLA_F_NESTED|nftaHookDevs, b)
	} else if a.Dev != nil {
		ae.String(nftaHookDev, *a.Dev)
	}
	return ae.Encode()
}

func (a *Hook) unmarshal(data []byte) error {
	ad, err := newAttributeDecoder(data)
	if err != nil {
		return err
	}
	for ad.Next() {
		switch ad.Type() {
		case nftaHookHooknum:
			a.HookNum = HookNum(ad.Uint32())
		case nftaHookPriority:
			a.Priority = int32(ad.Uint32())
		case nftaHookDev:
			v := ad.String()
			a.Dev = &v
		case nftaHookDevs:
			inner, err := newAttributeDecoder(ad.Bytes())
			if err != nil {
				return err
			}
			for inner.Next() {
				if inner.Type() == nftaDeviceName {
					a.Devs = append(a.Devs, inner.String())
				}
			}
			if err := inner.Err(); err != nil {
				return err
			}
		}
	}
	return ad.Err()
}

// https://github.com/torvalds/linux/blob/v7.1/include/uapi/linux/netfilter/nf_tables.h#L230
const (
	nftaChainTable    = unix.NFTA_CHAIN_TABLE
	nftaChainHandle   = unix.NFTA_CHAIN_HANDLE
	nftaChainName     = unix.NFTA_CHAIN_NAME
	nftaChainHook     = unix.NFTA_CHAIN_HOOK
	nftaChainPolicy   = unix.NFTA_CHAIN_POLICY
	nftaChainUse      = unix.NFTA_CHAIN_USE
	nftaChainType     = unix.NFTA_CHAIN_TYPE
	nftaChainCounters = unix.NFTA_CHAIN_COUNTERS
	nftaChainFlags    = 0x0a
	nftaChainID       = 0x0b
	nftaChainUserdata = 0x0c
)

// Chain flags
//
// https://github.com/torvalds/linux/blob/v7.1/include/uapi/linux/netfilter/nf_tables.h#L220
type ChainFlags uint32

const (
	ChainBase      ChainFlags = 1 << 0
	ChainHWOffload ChainFlags = 1 << 1
	ChainBinding   ChainFlags = 1 << 2
)

// https://github.com/torvalds/linux/blob/v7.1/include/uapi/linux/netfilter/nf_tables.h#L225
type ChainPolicy uint32

const (
	ChainPolicyDrop ChainPolicy = iota
	ChainPolicyAccept
)

// Chain attributes
//
// https://github.com/torvalds/linux/blob/v7.1/include/uapi/linux/netfilter/nf_tables.h#L230
type Chain struct {
	Table    string
	Name     string
	Handle   *uint64
	Hook     *Hook
	Policy   *ChainPolicy
	Use      *uint32
	Type     string
	Counters *ExprCounter
	Flags    *ChainFlags
	ID       *uint32
	UserData UserData
}

func (a *Chain) marshal() ([]byte, error) {
	ae := newAttributeEncoder()
	ae.String(nftaChainTable, a.Table)
	ae.String(nftaChainName, a.Name)
	if a.Handle != nil {
		ae.Uint64(nftaChainHandle, *a.Handle)
	}
	if a.Hook != nil {
		b, err := a.Hook.marshal()
		if err != nil {
			return nil, err
		}
		ae.Bytes(unix.NLA_F_NESTED|nftaChainHook, b)
	}
	if a.Policy != nil {
		ae.Uint32(nftaChainPolicy, uint32(*a.Policy))
	}
	if a.Type != "" {
		ae.String(nftaChainType, a.Type)
	}
	if a.Counters != nil {
		b, err := a.Counters.marshal()
		if err != nil {
			return nil, err
		}
		ae.Bytes(unix.NLA_F_NESTED|nftaChainCounters, b)
	}
	if a.Flags != nil {
		ae.Uint32(nftaChainFlags, uint32(*a.Flags))
	}
	if a.ID != nil {
		ae.Uint32(nftaChainID, *a.ID)
	}
	if b := a.UserData.marshal(); b != nil {
		ae.Bytes(nftaChainUserdata, b)
	}
	return ae.Encode()
}

func (a *Chain) unmarshal(data []byte) error {
	ad, err := newAttributeDecoder(data)
	if err != nil {
		return err
	}
	for ad.Next() {
		switch ad.Type() {
		case nftaChainTable:
			a.Table = ad.String()
		case nftaChainName:
			a.Name = ad.String()
		case nftaChainHandle:
			v := ad.Uint64()
			a.Handle = &v
		case nftaChainHook:
			a.Hook = &Hook{}
			if err := a.Hook.unmarshal(ad.Bytes()); err != nil {
				return err
			}
		case nftaChainPolicy:
			v := ChainPolicy(ad.Uint32())
			a.Policy = &v
		case nftaChainUse:
			v := ad.Uint32()
			a.Use = &v
		case nftaChainType:
			a.Type = ad.String()
		case nftaChainCounters:
			a.Counters = &ExprCounter{}
			if err := a.Counters.unmarshal(ad.Bytes()); err != nil {
				return err
			}
		case nftaChainFlags:
			v := ChainFlags(ad.Uint32())
			a.Flags = &v
		case nftaChainID:
			v := ad.Uint32()
			a.ID = &v
		case nftaChainUserdata:
			if err := a.UserData.unmarshal(ad.Bytes()); err != nil {
				return err
			}
		}
	}
	return ad.Err()
}
