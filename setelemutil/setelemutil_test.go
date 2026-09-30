package setelemutil

import (
	"math"
	"net/netip"
	"testing"
	"time"

	"github.com/nickgarlis/nftnl"
)

func TestInterval(t *testing.T) {
	for _, tt := range []struct {
		name      string
		elems     []nftnl.SetElem
		wantStart []byte
		wantEnd   []byte // nil: no end element
	}{
		{"prefix", must(IPPrefix(netip.MustParsePrefix("10.0.0.0/24"), nil)), []byte{10, 0, 0, 0}, []byte{10, 0, 1, 0}},
		{"prefix with host bits", must(IPPrefix(netip.MustParsePrefix("10.0.0.7/24"), nil)), []byte{10, 0, 0, 0}, []byte{10, 0, 1, 0}},
		{"single address", must(IPPrefix(netip.MustParsePrefix("192.0.2.1/32"), nil)), []byte{192, 0, 2, 1}, []byte{192, 0, 2, 2}},
		{"ipv4 to the top", must(IPPrefix(netip.MustParsePrefix("240.0.0.0/4"), nil)), []byte{240, 0, 0, 0}, nil},
		{"last ipv4 address", must(IPPrefix(netip.MustParsePrefix("255.255.255.255/32"), nil)), []byte{255, 255, 255, 255}, nil},
		{"all of ipv4", must(IPPrefix(netip.MustParsePrefix("0.0.0.0/0"), nil)), []byte{0, 0, 0, 0}, nil},
		{"ipv6 to the top", must(IPPrefix(netip.MustParsePrefix("ff00::/8"), nil)), netip.MustParseAddr("ff00::").AsSlice(), nil},
		{"ipv6 prefix", must(IPPrefix(netip.MustParsePrefix("2001:db8::/32"), nil)),
			netip.MustParseAddr("2001:db8::").AsSlice(), netip.MustParseAddr("2001:db9::").AsSlice()},
		{"ports", must(PortRange(80, 443, nil)), []byte{0, 80}, []byte{0x01, 0xbc}},
		{"ports to the top", must(PortRange(60000, 65535, nil)), []byte{0xea, 0x60}, nil},
		{"ip range", must(IPRange(netip.MustParseAddr("10.0.0.1"), netip.MustParseAddr("10.0.0.5"), nil)),
			[]byte{10, 0, 0, 1}, []byte{10, 0, 0, 6}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			want := 2
			if tt.wantEnd == nil {
				want = 1
			}
			if len(tt.elems) != want {
				t.Fatalf("got %d elements, want %d", len(tt.elems), want)
			}
			start := tt.elems[0]
			if string(start.Key.Value) != string(tt.wantStart) {
				t.Errorf("start: got %v, want %v", start.Key.Value, tt.wantStart)
			}
			if start.Flags != nil {
				t.Errorf("start: got flags %v, want none", *start.Flags)
			}
			if tt.wantEnd == nil {
				return
			}
			end := tt.elems[1]
			if string(end.Key.Value) != string(tt.wantEnd) {
				t.Errorf("end: got %v, want %v", end.Key.Value, tt.wantEnd)
			}
			if end.Flags == nil || *end.Flags != nftnl.SetElemIntervalEnd {
				t.Errorf("end: got flags %v, want nftnl.SetElemIntervalEnd", end.Flags)
			}
		})
	}
}

func TestAttrs(t *testing.T) {
	elems := must(IPPrefix(netip.MustParsePrefix("10.0.0.0/8"), &Attrs{Comment: "office", Timeout: time.Second}))
	if elems[0].Timeout == nil || *elems[0].Timeout != 1000 || elems[0].UserData == nil {
		t.Errorf("start: got timeout %v userdata %v", elems[0].Timeout, elems[0].UserData)
	}
	if elems[1].Timeout != nil || elems[1].UserData != nil {
		t.Errorf("end: got timeout %v userdata %v, want none", elems[1].Timeout, elems[1].UserData)
	}

	elems = must(IPPrefix(netip.MustParsePrefix("10.0.0.0/8"), &Attrs{}))
	if elems[0].Timeout != nil || elems[0].UserData != nil {
		t.Errorf("zero Attrs: got timeout %v userdata %v, want none", elems[0].Timeout, elems[0].UserData)
	}
}

func TestAttrsTimeoutRoundsUp(t *testing.T) {
	for timeout, want := range map[time.Duration]uint64{
		400 * time.Microsecond:             1,
		time.Millisecond:                   1,
		time.Millisecond + time.Nanosecond: 2,
		1500 * time.Millisecond:            1500,
		time.Hour:                          3_600_000,
		time.Duration(math.MaxInt64):       uint64(math.MaxInt64/int64(time.Millisecond)) + 1,
	} {
		elems := must(IPPrefix(netip.MustParsePrefix("10.0.0.0/8"), &Attrs{Timeout: timeout}))
		if elems[0].Timeout == nil || *elems[0].Timeout != want {
			t.Errorf("%s: got %v, want %d ms", timeout, elems[0].Timeout, want)
		}
	}
}

func TestErrors(t *testing.T) {
	if _, err := Interval([]byte{0, 1}, []byte{0, 0, 1}, nil); err == nil {
		t.Error("keys of different lengths: want an error")
	}
	if _, err := PortRange(443, 80, nil); err == nil {
		t.Error("first after last: want an error")
	}
	if _, err := IPRange(netip.MustParseAddr("10.0.0.1"), netip.MustParseAddr("::1"), nil); err == nil {
		t.Error("mixed families: want an error")
	}
	if _, err := IPPrefix(netip.MustParsePrefix("10.0.0.0/8"), &Attrs{Timeout: -time.Second}); err == nil {
		t.Error("negative timeout: want an error")
	}
}

func must(elems []nftnl.SetElem, err error) []nftnl.SetElem {
	if err != nil {
		panic(err)
	}
	return elems
}
