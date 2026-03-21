module github.com/valy0/otvoren-vot/collection

go 1.24.4

require (
	github.com/gowebpki/jcs v1.0.1
	github.com/jackc/pgx/v5 v5.8.0
	github.com/valy0/otvoren-vot/crypto v0.0.0-00010101000000-000000000000
)

require (
	github.com/jackc/pgpassfile v1.0.0 // indirect
	github.com/jackc/pgservicefile v0.0.0-20240606120523-5a60cdf6a761 // indirect
	github.com/jackc/puddle/v2 v2.2.2 // indirect
	golang.org/x/sync v0.17.0 // indirect
	golang.org/x/text v0.29.0 // indirect
)

replace github.com/valy0/otvoren-vot/crypto => ../crypto
