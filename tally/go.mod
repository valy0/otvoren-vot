module github.com/valy0/otvoren-vot/tally

go 1.24.4

replace github.com/valy0/otvoren-vot/crypto => ../crypto

replace github.com/valy0/otvoren-vot/pkg/middleware => ../pkg/middleware

require (
	filippo.io/edwards25519 v1.2.0
	github.com/valy0/otvoren-vot/crypto v0.0.0-00010101000000-000000000000
	github.com/valy0/otvoren-vot/pkg/middleware v0.0.0
)
