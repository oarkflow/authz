# Configuration Format Benchmarks

These benchmarks compare `.authz` DSL parsing against JSON and YAML decoding for equivalent authorization configuration payloads.

## Latest Run

- CPU: Apple M2 Pro
- OS/Arch: darwin arm64
- Command:

```bash
GOCACHE=$PWD/.gocache go test -mod=mod -run '^$' -bench 'BenchmarkConfigFormatDecode|BenchmarkDSLParse|BenchmarkJSONDecode|BenchmarkYAMLDecode|BenchmarkConfigSignatureVerify|BenchmarkValidateConfigLarge' -benchmem .
```

## Decode / Parse Results

### Focused Parser Benchmarks

| Benchmark | Time | Memory | Allocs |
|---|---:|---:|---:|
| `BenchmarkDSLParse` | **1,860 ns/op** | 1,456 B/op | 16 allocs/op |
| `BenchmarkJSONDecode` | 48,248 ns/op | 7,464 B/op | 221 allocs/op |
| `BenchmarkDSLParseLarge` | **21,911 ns/op** | 33,988 B/op | 14 allocs/op |

DSL is about **25.9x faster than JSON** in the focused small-config parser benchmark.

### Equivalent Wire-Format Benchmarks

These compare a generated `.authz` file against JSON/YAML payloads with the same tenants, policies, roles, ACLs, memberships, hierarchy, and engine settings. JSON/YAML decode into a simple wire DTO with string conditions, so the comparison does not penalize them with `Expr` interface reconstruction.

| Small Config | Time | Relative | Memory | Allocs |
|---|---:|---:|---:|---:|
| `.authz` DSL | **7,321 ns/op** | **1.0x** | **4,632 B/op** | **14 allocs/op** |
| JSON | 30,471 ns/op | 4.2x slower | 9,584 B/op | 193 allocs/op |
| YAML | 167,187 ns/op | 22.8x slower | 100,722 B/op | 2,035 allocs/op |

| Large Config | Time | Relative | Memory | Allocs |
|---|---:|---:|---:|---:|
| `.authz` DSL | **64,338 ns/op** | **1.0x** | **39,000 B/op** | **14 allocs/op** |
| JSON | 255,276 ns/op | 4.0x slower | 80,592 B/op | 1,639 allocs/op |
| YAML | 1,431,942 ns/op | 22.3x slower | 821,067 B/op | 17,566 allocs/op |

## Verification Benchmarks

| Benchmark | Time | Memory | Allocs |
|---|---:|---:|---:|
| `BenchmarkConfigSignatureVerify` | 60,175 ns/op | 49 B/op | 1 alloc/op |
| `BenchmarkConfigSignatureVerifyWithKey` | 59,546 ns/op | 1 B/op | 0 allocs/op |
| `BenchmarkValidateConfigLarge` | 8,955 ns/op | 11,736 B/op | 19 allocs/op |

## Result

`.authz` is the fastest human-readable configuration format in the benchmark suite:

- Faster than JSON for small and large config decode.
- Lower allocation count than JSON for small and large config decode.
- Much faster than YAML for small and large config decode.
- Lower CPU cost while still parsing into production `authz.Config` objects with typed conditions.

## Optimization Applied

The DSL parser now captures `time.Now()` once per parse and reuses that timestamp for parsed policies, roles, and ACLs. It also reuses tokenizer scratch space, uses zero-copy token strings, pre-counts directive/list sizes, allocates policies/roles/ACLs in contiguous blocks, parses comma-separated lists into per-parse contiguous backing arrays, lazily allocates optional config sections, and reuses adjacent repeated parsed condition trees.

The zero-copy token path means parsed config strings reference the immutable input buffer supplied to `Parse`; callers should not mutate that byte slice after parsing.

Config signature verification now scans bytes directly instead of converting the whole config to strings and splitting/joining lines. Hot paths can use `VerifyConfigSignatureWithKey` with a decoded Ed25519 public key to avoid per-call key decoding and run signature verification with zero allocations.

## Reproducing

Run all tests:

```bash
GOCACHE=$PWD/.gocache go test -mod=mod ./...
```

Run just the format benchmarks:

```bash
GOCACHE=$PWD/.gocache go test -mod=mod -run '^$' -bench 'BenchmarkConfigFormatDecode|BenchmarkDSLParse|BenchmarkJSONDecode|BenchmarkYAMLDecode|BenchmarkConfigSignatureVerify|BenchmarkValidateConfigLarge' -benchmem .
```
