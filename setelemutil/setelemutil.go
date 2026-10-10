// Package setelemutil provides shorthand for building nftnl.SetElem values.
// The range helpers are only for interval sets (nftnl.SetInterval).
package setelemutil

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net/netip"
	"slices"
	"time"

	"github.com/nickgarlis/nftnl"
)

// Attrs is optional metadata for an interval's start element.
type Attrs struct {
	Comment string
	// Timeout is rounded up to whole milliseconds, since the kernel reads 0
	// as no timeout. Requires nftnl.SetTimeout on the set.
	Timeout time.Duration
}

func (a *Attrs) apply(e *nftnl.SetElem) error {
	if a == nil {
		return nil
	}
	if a.Timeout < 0 {
		return fmt.Errorf("setelemutil: negative timeout %s", a.Timeout)
	}
	if a.Comment != "" {
		e.UserData = &nftnl.SetElemUserData{Comment: &a.Comment}
	}
	if a.Timeout > 0 {
		ms := uint64(a.Timeout / time.Millisecond)
		if a.Timeout%time.Millisecond != 0 {
			ms++
		}
		e.Timeout = &ms
	}
	return nil
}

// Interval returns the start and end elements for the inclusive range [first, last]
// of big-endian keys. Only for interval sets (nftnl.SetInterval).
func Interval(first, last []byte, attrs *Attrs) ([]nftnl.SetElem, error) {
	if len(first) != len(last) {
		return nil, fmt.Errorf("setelemutil: Interval: keys of different lengths (%d and %d)", len(first), len(last))
	}
	if bytes.Compare(first, last) > 0 {
		return nil, fmt.Errorf("setelemutil: Interval: first key is after last")
	}

	start := nftnl.SetElem{Key: &nftnl.ExprData{Value: slices.Clone(first)}}
	if err := attrs.apply(&start); err != nil {
		return nil, err
	}

	end := slices.Clone(last)
	// A range ending at the top of the key space has no end element; the kernel matches it to the end.
	if wrapped := incBytes(end); wrapped {
		return []nftnl.SetElem{start}, nil
	}
	ie := nftnl.SetElemIntervalEnd
	return []nftnl.SetElem{start, {Key: &nftnl.ExprData{Value: end}, Flags: &ie}}, nil
}

// IPPrefix returns the elements for the range p covers.
// Only for interval sets (nftnl.SetInterval).
func IPPrefix(p netip.Prefix, attrs *Attrs) ([]nftnl.SetElem, error) {
	p = p.Masked()
	first := p.Addr().Unmap().AsSlice()
	last := slices.Clone(first)
	for i := p.Bits(); i < len(last)*8; i++ {
		last[i/8] |= 1 << (7 - uint(i%8))
	}
	return Interval(first, last, attrs)
}

// IPRange returns the elements for the inclusive range [first, last].
// Only for interval sets (nftnl.SetInterval).
func IPRange(first, last netip.Addr, attrs *Attrs) ([]nftnl.SetElem, error) {
	first, last = first.Unmap(), last.Unmap()
	if first.Is4() != last.Is4() {
		return nil, fmt.Errorf("setelemutil: IPRange: address family mismatch")
	}
	return Interval(first.AsSlice(), last.AsSlice(), attrs)
}

// PortRange returns the elements for the inclusive port range [first, last].
// Only for interval sets (nftnl.SetInterval).
func PortRange(first, last uint16, attrs *Attrs) ([]nftnl.SetElem, error) {
	return Interval(
		binary.BigEndian.AppendUint16(nil, first),
		binary.BigEndian.AppendUint16(nil, last),
		attrs,
	)
}

// incBytes adds 1 to a big-endian value in place, reporting whether it wrapped.
func incBytes(b []byte) (wrapped bool) {
	for i := len(b) - 1; i >= 0; i-- {
		b[i]++
		if b[i] != 0 {
			return false
		}
	}
	return true
}
