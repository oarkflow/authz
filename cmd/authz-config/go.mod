module github.com/oarkflow/authz/cmd/authz-config

go 1.26.2

require (
	github.com/oarkflow/authz v0.0.0-00010101000000-000000000000
	github.com/oarkflow/authz/contrib v0.0.0-00010101000000-000000000000
	github.com/oarkflow/squealx v0.0.77
)

require (
	github.com/dustin/go-humanize v1.0.1 // indirect
	github.com/goccy/go-reflect v1.2.0 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/mattn/go-isatty v0.0.22 // indirect
	github.com/ncruces/go-strftime v1.0.0 // indirect
	github.com/oarkflow/date v0.0.4 // indirect
	github.com/oarkflow/expr v0.0.11 // indirect
	github.com/oarkflow/jet v0.0.4 // indirect
	github.com/oarkflow/json v0.0.28 // indirect
	github.com/remyoudompheng/bigfft v0.0.0-20230129092748-24d4a6f8daec // indirect
	golang.org/x/crypto v0.53.0 // indirect
	golang.org/x/sys v0.46.0 // indirect
	modernc.org/libc v1.73.4 // indirect
	modernc.org/mathutil v1.7.1 // indirect
	modernc.org/memory v1.11.0 // indirect
	modernc.org/sqlite v1.52.0 // indirect
)

replace (
	github.com/oarkflow/authz => ../../
	github.com/oarkflow/authz/contrib => ../../contrib
)
