package nftnl

import "golang.org/x/sys/unix"

// https://github.com/torvalds/linux/blob/v7.1/include/uapi/linux/netfilter/nf_tables.h#L1541
type TraceType uint32

const (
	TraceTypePolicy TraceType = iota + 1
	TraceTypeReturn
	TraceTypeRule
)

const (
	nftaTraceTable           = unix.NFTA_TRACE_TABLE
	nftaTraceChain           = unix.NFTA_TRACE_CHAIN
	nftaTraceRuleHandle      = unix.NFTA_TRACE_RULE_HANDLE
	nftaTraceType            = unix.NFTA_TRACE_TYPE
	nftaTraceVerdict         = unix.NFTA_TRACE_VERDICT
	nftaTraceID              = unix.NFTA_TRACE_ID
	nftaTraceLLHeader        = unix.NFTA_TRACE_LL_HEADER
	nftaTraceNetworkHeader   = unix.NFTA_TRACE_NETWORK_HEADER
	nftaTraceTransportHeader = unix.NFTA_TRACE_TRANSPORT_HEADER
	nftaTraceIIF             = unix.NFTA_TRACE_IIF
	nftaTraceIIFType         = unix.NFTA_TRACE_IIFTYPE
	nftaTraceOIF             = unix.NFTA_TRACE_OIF
	nftaTraceOIFType         = unix.NFTA_TRACE_OIFTYPE
	nftaTraceMark            = unix.NFTA_TRACE_MARK
	nftaTraceNFProto         = unix.NFTA_TRACE_NFPROTO
	nftaTracePolicy          = unix.NFTA_TRACE_POLICY
)

// https://github.com/torvalds/linux/blob/v7.1/include/uapi/linux/netfilter/nf_tables.h#L1549
type Trace struct {
	Table           string
	Chain           string
	ID              uint32
	Type            TraceType
	RuleHandle      *uint64
	Verdict         *ExprVerdict
	LLHeader        []byte
	NetworkHeader   []byte
	TransportHeader []byte
	IIF             *uint32
	IIFType         *uint16
	OIF             *uint32
	OIFType         *uint16
	Mark            *uint32
	NFProto         *Family
	Policy          *ChainPolicy
}

func (t *Trace) marshal() ([]byte, error) {
	ae := newAttributeEncoder()
	ae.String(nftaTraceTable, t.Table)
	ae.String(nftaTraceChain, t.Chain)
	ae.Uint32(nftaTraceID, t.ID)
	ae.Uint32(nftaTraceType, uint32(t.Type))
	if t.RuleHandle != nil {
		ae.Uint64(nftaTraceRuleHandle, *t.RuleHandle)
	}
	if t.Verdict != nil {
		b, err := t.Verdict.marshal()
		if err != nil {
			return nil, err
		}
		ae.Bytes(unix.NLA_F_NESTED|nftaTraceVerdict, b)
	}
	if t.LLHeader != nil {
		ae.Bytes(nftaTraceLLHeader, t.LLHeader)
	}
	if t.NetworkHeader != nil {
		ae.Bytes(nftaTraceNetworkHeader, t.NetworkHeader)
	}
	if t.TransportHeader != nil {
		ae.Bytes(nftaTraceTransportHeader, t.TransportHeader)
	}
	if t.IIF != nil {
		ae.Uint32(nftaTraceIIF, *t.IIF)
	}
	if t.IIFType != nil {
		ae.Uint16(nftaTraceIIFType, *t.IIFType)
	}
	if t.OIF != nil {
		ae.Uint32(nftaTraceOIF, *t.OIF)
	}
	if t.OIFType != nil {
		ae.Uint16(nftaTraceOIFType, *t.OIFType)
	}
	if t.Mark != nil {
		ae.Uint32(nftaTraceMark, *t.Mark)
	}
	if t.NFProto != nil {
		ae.Uint32(nftaTraceNFProto, uint32(*t.NFProto))
	}
	if t.Policy != nil {
		ae.Uint32(nftaTracePolicy, uint32(*t.Policy))
	}
	return ae.Encode()
}

func (t *Trace) unmarshal(data []byte) error {
	ad, err := newAttributeDecoder(data)
	if err != nil {
		return err
	}
	for ad.Next() {
		switch ad.Type() {
		case nftaTraceTable:
			t.Table = ad.String()
		case nftaTraceChain:
			t.Chain = ad.String()
		case nftaTraceID:
			t.ID = ad.Uint32()
		case nftaTraceType:
			t.Type = TraceType(ad.Uint32())
		case nftaTraceRuleHandle:
			v := ad.Uint64()
			t.RuleHandle = &v
		case nftaTraceVerdict:
			t.Verdict = &ExprVerdict{}
			if err := t.Verdict.unmarshal(ad.Bytes()); err != nil {
				return err
			}
		case nftaTraceLLHeader:
			t.LLHeader = ad.Bytes()
		case nftaTraceNetworkHeader:
			t.NetworkHeader = ad.Bytes()
		case nftaTraceTransportHeader:
			t.TransportHeader = ad.Bytes()
		case nftaTraceIIF:
			v := ad.Uint32()
			t.IIF = &v
		case nftaTraceIIFType:
			v := ad.Uint16()
			t.IIFType = &v
		case nftaTraceOIF:
			v := ad.Uint32()
			t.OIF = &v
		case nftaTraceOIFType:
			v := ad.Uint16()
			t.OIFType = &v
		case nftaTraceMark:
			v := ad.Uint32()
			t.Mark = &v
		case nftaTraceNFProto:
			v := Family(ad.Uint32())
			t.NFProto = &v
		case nftaTracePolicy:
			v := ChainPolicy(ad.Uint32())
			t.Policy = &v
		}
	}
	return ad.Err()
}
