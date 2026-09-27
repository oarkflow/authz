module examples

go 1.26.5

replace github.com/oarkflow/authz => ../

replace github.com/oarkflow/authz/contrib => ../contrib

require (
	github.com/oarkflow/authz v0.0.0-00010101000000-000000000000
	github.com/oarkflow/authz/contrib v0.0.0-00010101000000-000000000000
	github.com/oarkflow/fh v0.0.26
	github.com/redis/go-redis/v9 v9.22.0
)

require (
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	go.uber.org/atomic v1.12.0 // indirect
	golang.org/x/crypto v0.57.0 // indirect
	golang.org/x/net v0.59.0 // indirect
	golang.org/x/sys v0.48.0 // indirect
	golang.org/x/text v0.42.0 // indirect
)
