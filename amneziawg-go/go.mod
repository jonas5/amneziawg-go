module github.com/amnezia-vpn/amneziawg-go

go 1.24.4

require (
	github.com/amnezia-vpn/amnezia-xray-core v0.0.0-00010101000000-000000000000
	github.com/stretchr/testify v1.10.0
	github.com/tevino/abool v1.2.0
	go.uber.org/atomic v1.11.0
	golang.org/x/crypto v0.39.0
	golang.org/x/exp v0.0.0-20230725093048-515e97ebf090
	golang.org/x/net v0.41.0
	golang.org/x/sys v0.33.0
	golang.zx2c4.com/wintun v0.0.0-20230126152724-0fa3db229ce2
	gvisor.dev/gvisor v0.0.0-20250428193742-2d800c3129d5
)

replace github.com/amnezia-vpn/amnezia-xray-core => ../amnezia-xray-core

require (
	github.com/andybalholm/brotli v1.1.0 // indirect
	github.com/cloudflare/circl v1.6.1 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/google/btree v1.1.3 // indirect
	github.com/klauspost/compress v1.17.8 // indirect
	github.com/pires/go-proxyproto v0.8.1 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/quic-go/quic-go v0.52.0 // indirect
	github.com/refraction-networking/utls v1.7.3 // indirect
	github.com/sagernet/sing v0.5.1 // indirect
	github.com/xtls/reality v0.0.0-20250607105625-90e738a94c8c // indirect
	golang.org/x/text v0.26.0 // indirect
	golang.org/x/time v0.9.0 // indirect
	google.golang.org/grpc v1.73.0 // indirect
	google.golang.org/protobuf v1.36.6 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)
