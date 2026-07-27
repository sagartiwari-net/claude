module claude-ai-go-proxy

go 1.22

toolchain go1.24.2

require (
	github.com/andybalholm/brotli v1.1.0
	github.com/go-sql-driver/mysql v1.8.1
	github.com/refraction-networking/utls v1.6.7
	golang.org/x/net v0.25.0
	toolsmandi.com/proxy-security v0.0.0
)

replace toolsmandi.com/proxy-security => ../proxy-security

require (
	filippo.io/edwards25519 v1.1.0 // indirect
	github.com/cloudflare/circl v1.3.7 // indirect
	github.com/klauspost/compress v1.17.4 // indirect
	github.com/oschwald/maxminddb-golang v1.13.1 // indirect
	golang.org/x/crypto v0.23.0 // indirect
	golang.org/x/sys v0.21.0 // indirect
	golang.org/x/text v0.15.0 // indirect
)
