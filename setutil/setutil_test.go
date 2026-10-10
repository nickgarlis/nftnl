package setutil

import (
	"testing"

	"github.com/nickgarlis/nftnl"
)

func TestSets(t *testing.T) {
	anon := nftnl.SetAnonymous | nftnl.SetConstant
	for _, tt := range []struct {
		name      string
		set       nftnl.Set
		wantName  string
		wantFlags nftnl.SetFlags
		wantType  nftnl.DataType
		wantLen   uint32
	}{
		{"IPv4", IPv4("t", "s", 7), "s", 0, nftnl.DataTypeIPAddr, 4},
		{"IPv6", IPv6("t", "s", 7), "s", 0, nftnl.DataTypeIP6Addr, 16},
		{"Port", Port("t", "s", 7), "s", 0, nftnl.DataTypeInetService, 2},
		{"IPv4Interval", IPv4Interval("t", "s", 7), "s", nftnl.SetInterval, nftnl.DataTypeIPAddr, 4},
		{"IPv6Interval", IPv6Interval("t", "s", 7), "s", nftnl.SetInterval, nftnl.DataTypeIP6Addr, 16},
		{"PortInterval", PortInterval("t", "s", 7), "s", nftnl.SetInterval, nftnl.DataTypeInetService, 2},
		{"AnonIPv4", AnonIPv4("t", 7), nftnl.SetAnonTemplate, anon, nftnl.DataTypeIPAddr, 4},
		{"AnonIPv6", AnonIPv6("t", 7), nftnl.SetAnonTemplate, anon, nftnl.DataTypeIP6Addr, 16},
		{"AnonPort", AnonPort("t", 7), nftnl.SetAnonTemplate, anon, nftnl.DataTypeInetService, 2},
		{"AnonIPv4Interval", AnonIPv4Interval("t", 7), nftnl.SetAnonTemplate, anon | nftnl.SetInterval, nftnl.DataTypeIPAddr, 4},
		{"AnonIPv6Interval", AnonIPv6Interval("t", 7), nftnl.SetAnonTemplate, anon | nftnl.SetInterval, nftnl.DataTypeIP6Addr, 16},
		{"AnonPortInterval", AnonPortInterval("t", 7), nftnl.SetAnonTemplate, anon | nftnl.SetInterval, nftnl.DataTypeInetService, 2},
	} {
		t.Run(tt.name, func(t *testing.T) {
			s := tt.set
			if *s.Table != "t" || *s.Name != tt.wantName || *s.ID != 7 {
				t.Errorf("table/name/id = %q/%q/%d, want t/%q/7", *s.Table, *s.Name, *s.ID, tt.wantName)
			}
			if *s.Flags != tt.wantFlags {
				t.Errorf("flags = %#x, want %#x", *s.Flags, tt.wantFlags)
			}
			if *s.KeyType != tt.wantType || *s.KeyLen != tt.wantLen {
				t.Errorf("key = %d/%d, want %d/%d", *s.KeyType, *s.KeyLen, tt.wantType, tt.wantLen)
			}
		})
	}
}
