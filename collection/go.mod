module github.com/valy0/otvoren-vot/collection

go 1.24.4

require (
	github.com/golang-jwt/jwt/v5 v5.3.1
	github.com/gowebpki/jcs v1.0.1
	github.com/jackc/pgx/v5 v5.8.0
	github.com/valy0/otvoren-vot/crypto v0.0.0-00010101000000-000000000000
	github.com/valy0/otvoren-vot/pkg/jwtauth v0.0.0
	github.com/valy0/otvoren-vot/pkg/middleware v0.0.0
)

require (
	github.com/jackc/pgpassfile v1.0.0 // indirect
	github.com/jackc/pgservicefile v0.0.0-20240606120523-5a60cdf6a761 // indirect
	github.com/jackc/puddle/v2 v2.2.2 // indirect
	golang.org/x/sync v0.17.0 // indirect
	golang.org/x/text v0.29.0 // indirect
)

replace github.com/valy0/otvoren-vot/crypto => ../crypto

replace github.com/valy0/otvoren-vot/pkg/jwtauth => ../pkg/jwtauth

replace github.com/valy0/otvoren-vot/pkg/middleware => ../pkg/middleware
