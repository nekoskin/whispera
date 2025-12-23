module whispera

go 1.24.1

require (
	github.com/flynn/noise v1.1.0
	github.com/golang-jwt/jwt/v5 v5.3.0
	github.com/miekg/dns v1.1.68
	github.com/pion/dtls/v2 v2.2.7
	github.com/pion/stun v0.6.1
	github.com/prometheus/client_golang v1.23.2
	github.com/quic-go/quic-go v0.56.0
	github.com/songgao/water v0.0.0-20200317203138-2b4b6d7c09d8
	github.com/xtls/reality v0.0.0-20251116175510-cd53f7d50237
	golang.org/x/crypto v0.43.0
	golang.org/x/net v0.47.0
	golang.zx2c4.com/wintun v0.0.0-20230126152724-0fa3db229ce2
	google.golang.org/grpc v1.75.1
	gopkg.in/yaml.v3 v3.0.1
	gvisor.dev/gvisor v0.0.0-20251115042331-9fc4303aefe1
	nhooyr.io/websocket v1.8.10
)

replace (
	golang.org/x/crypto => golang.org/x/crypto v0.41.0
	golang.org/x/net => golang.org/x/net v0.43.0
	golang.org/x/sys => golang.org/x/sys v0.35.0
	golang.org/x/text => golang.org/x/text v0.28.0
	gvisor.dev/gvisor => ./internal/gvisor/gvisor@v0.0.0-20251115042331-9fc4303aefe1
)

require (
	github.com/andybalholm/brotli v1.0.6 // indirect
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/cloudflare/circl v1.6.1 // indirect
	github.com/google/btree v1.1.2 // indirect
	github.com/juju/ratelimit v1.0.2 // indirect
	github.com/klauspost/compress v1.18.0 // indirect
	github.com/munnerz/goautoneg v0.0.0-20191010083416-a7dc8b61c822 // indirect
	github.com/pion/logging v0.2.2 // indirect
	github.com/pion/transport/v2 v2.2.1 // indirect
	github.com/pires/go-proxyproto v0.8.1 // indirect
	github.com/prometheus/client_model v0.6.2 // indirect
	github.com/prometheus/common v0.66.1 // indirect
	github.com/prometheus/procfs v0.16.1 // indirect
	github.com/refraction-networking/utls v1.8.1 // indirect
	go.yaml.in/yaml/v2 v2.4.2 // indirect
	golang.org/x/mod v0.28.0 // indirect
	golang.org/x/sync v0.17.0 // indirect
	golang.org/x/sys v0.37.0 // indirect
	golang.org/x/text v0.31.0 // indirect
	golang.org/x/time v0.12.0 // indirect
	golang.org/x/tools v0.37.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20251111163417-95abcf5c77ba // indirect
	google.golang.org/protobuf v1.36.10 // indirect
)
