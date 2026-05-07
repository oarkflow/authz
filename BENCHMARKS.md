# Configuration Format Benchmarks

These benchmarks compare `.authz` DSL parsing against JSON and YAML decoding for equivalent authorization configuration payloads.

## Latest Run

- CPU: Apple M2 Pro
- OS/Arch: darwin arm64
- Command:

```bash
GOCACHE=$PWD/.gocache go test -run '^$' -bench 'BenchmarkConfigFormatDecode|BenchmarkDSLParse|BenchmarkJSONDecode|BenchmarkYAMLDecode' -benchmem .
```

## Decode / Parse Results

### Focused Parser Benchmarks

| Benchmark | Time | Memory | Allocs |
|---|---:|---:|---:|
| `BenchmarkDSLParse` | **2,050 ns/op** | 2,544 B/op | 54 allocs/op |
| `BenchmarkJSONDecode` | 48,961 ns/op | 7,464 B/op | 221 allocs/op |
| `BenchmarkDSLParseLarge` | **3,736 ns/op** | 4,450 B/op | 113 allocs/op |

DSL is about **23.9x faster than JSON** in the focused small-config parser benchmark.

### Equivalent Wire-Format Benchmarks

These compare a generated `.authz` file against JSON/YAML payloads with the same tenants, policies, roles, ACLs, memberships, hierarchy, and engine settings. JSON/YAML decode into a simple wire DTO with string conditions, so the comparison does not penalize them with `Expr` interface reconstruction.

| Small Config | Time | Relative | Memory | Allocs |
|---|---:|---:|---:|---:|
| `.authz` DSL | **6,480 ns/op** | **1.0x** | **6,552 B/op** | **170 allocs/op** |
| JSON | 31,112 ns/op | 4.8x slower | 9,584 B/op | 193 allocs/op |
| YAML | 171,149 ns/op | 26.4x slower | 100,721 B/op | 2,035 allocs/op |

| Large Config | Time | Relative | Memory | Allocs |
|---|---:|---:|---:|---:|
| `.authz` DSL | **58,216 ns/op** | **1.0x** | **53,648 B/op** | **1,481 allocs/op** |
| JSON | 268,329 ns/op | 4.6x slower | 80,592 B/op | 1,639 allocs/op |
| YAML | 1,449,862 ns/op | 24.9x slower | 821,061 B/op | 17,566 allocs/op |

## Result

`.authz` is the fastest human-readable configuration format in the benchmark suite:

- Faster than JSON for small and large config decode.
- Lower allocation count than JSON for small and large config decode.
- Much faster than YAML for small and large config decode.
- Lower CPU cost while still parsing into production `authz.Config` objects with typed conditions.

## Optimization Applied

The DSL parser now captures `time.Now()` once per parse and reuses that timestamp for parsed policies, roles, and ACLs. It also reuses the tokenizer scratch slice, parses comma-separated string lists without `strings.Split`, lazily allocates optional config sections, and reuses adjacent repeated parsed condition trees.

## Reproducing

Run all tests:

```bash
GOCACHE=$PWD/.gocache go test ./...
```

Run just the format benchmarks:

```bash
GOCACHE=$PWD/.gocache go test -run '^$' -bench 'BenchmarkConfigFormatDecode|BenchmarkDSLParse|BenchmarkJSONDecode|BenchmarkYAMLDecode' -benchmem .
```
