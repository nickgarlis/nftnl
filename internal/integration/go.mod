module github.com/nftnl/internal/integration

go 1.26.3

replace github.com/nickgarlis/nftnl => ../../

require (
	github.com/google/go-cmp v0.7.0
	github.com/mdlayher/netlink v1.11.2
	github.com/nickgarlis/nftnl v0.0.0-00010101000000-000000000000
	github.com/vishvananda/netns v0.0.5
	golang.org/x/sys v0.47.0
)

require (
	github.com/mdlayher/socket v0.6.0 // indirect
	golang.org/x/net v0.53.0 // indirect
	golang.org/x/sync v0.20.0 // indirect
)
