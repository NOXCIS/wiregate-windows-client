module github.com/NOXCIS/wiregate-windows-client

go 1.24.4

require (
	github.com/NOXCIS/wiregate-windows v0.1.8
	github.com/amnezia-vpn/amneziawg-go v0.2.16
	github.com/lxn/walk v0.0.0-20210112085537-c389da54e794
	github.com/lxn/win v0.0.0-20210218163916-a377121e959e
	golang.org/x/crypto v0.39.0
	golang.org/x/sys v0.33.0
	golang.org/x/text v0.26.0
	golang.zx2c4.com/wintun v0.0.0-20230126152724-0fa3db229ce2
)

require (
	github.com/andybalholm/brotli v1.0.6 // indirect
	github.com/cloudflare/circl v1.3.7 // indirect
	github.com/gorilla/websocket v1.5.3 // indirect
	github.com/klauspost/compress v1.17.4 // indirect
	github.com/refraction-networking/utls v1.6.6 // indirect
	golang.org/x/mod v0.25.0 // indirect
	golang.org/x/net v0.41.0 // indirect
	golang.org/x/sync v0.15.0 // indirect
	golang.org/x/tools v0.33.0 // indirect
)

replace (
	// Use local modified wiregate-windows module with TLS and split tunneling support
	github.com/NOXCIS/wiregate-windows => ../wiregate-windows
	github.com/lxn/walk => golang.zx2c4.com/wireguard/windows v0.0.0-20210121140954-e7fc19d483bd
	github.com/lxn/win => golang.zx2c4.com/wireguard/windows v0.0.0-20210224134948-620c54ef6199
)
