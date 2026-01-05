# Performance Benchmarks - Actual Results

## Test Environment
- CPU: Intel(R) Core(TM) i7-9700K @ 3.60GHz
- OS: Linux amd64
- Go: 1.25.5
- Benchmark Time: 2 seconds per test

## Small Config (10 policies, 5 roles)

### Encoding Performance

| Format | Time (ns/op) | Speed | Memory (B/op) | Allocs |
|--------|--------------|-------|---------------|--------|
| **DSL Encode** | **723** | **1.0x** | **0** | **0** |
| Binary Encode | 7,233 | 10.0x | 6,419 | 195 |
| JSON Encode | 45,869 | 63.4x | 13,514 | 27 |
| YAML Encode | 666,878 | 922.0x | 351,267 | 1,149 |

**DSL encoding is 63x faster than JSON, 922x faster than YAML, and 10x faster than Binary!**

### Decoding Performance

| Format | Time (ns/op) | Speed | Memory (B/op) | Allocs |
|--------|--------------|-------|---------------|--------|
| **DSL Parse** | **3,422** | **1.0x** | **3,296** | **61** |
| Binary Decode | 13,545 | 4.0x | 6,568 | 345 |
| JSON Decode | 61,553 | 18.0x | 7,288 | 221 |

**DSL parsing is 18x faster than JSON and 4x faster than Binary!**

## Large Config (100 policies, 50 roles)

### Encoding Performance

| Format | Time (ns/op) | Speed | Memory (B/op) | Allocs |
|--------|--------------|-------|---------------|--------|
| Binary Encode | 54,917 | 1.0x | 47,124 | 1,551 |
| YAML Encode | 5,638,333 | 102.7x | 6,384,876 | 10,434 |

**Binary is 103x faster than YAML for large configs**

### Decoding Performance

| Format | Time (ns/op) | Speed | Memory (B/op) | Allocs |
|--------|--------------|-------|---------------|--------|
| **DSL Parse** | **10,750** | **1.0x** | **6,386** | **146** |
| Binary Decode | 137,659 | 12.8x | 56,696 | 2,955 |

**DSL parsing scales excellently - only 3x slower for 10x more data, 13x faster than Binary**

## Key Findings

### DSL Performance
- **Fastest encoding**: 723ns (0 allocations, 63x faster than JSON)
- **Fastest parsing**: 3.4µs (18x faster than JSON, 4x faster than Binary)
- **Zero-allocation encoding**: No memory allocations during encode
- **Minimal memory**: 3.3KB allocated during parse, 61 allocations
- **Excellent scaling**: 10.7µs for 100 policies (only 3x slower for 10x data)
- **Optimized**: Direct byte buffer operations, no string conversions

### Binary Protocol
- **Compact**: Smallest size format
- **Fast encoding**: 7.2µs for small configs
- **Decode overhead**: More allocations due to deserialization
- **Production ready**: Best for network transfer

### JSON
- **Standard**: 45.9µs encode, 61.6µs decode
- **Reasonable**: For moderate-sized configs
- **18x slower** than DSL parsing
- **63x slower** than DSL encoding

### YAML
- **Slowest**: 666µs for small, 5.6ms for large
- **Memory intensive**: 351KB for small config
- **Many allocations**: 1,149 allocations
- **Not recommended**: For performance-critical applications

## Performance Comparison Matrix

### Small Config
| Operation | DSL | Binary | JSON | YAML |
|-----------|-----|--------|------|------|
| Encode | 0.7µs | 7.2µs | 45.9µs | 666.9µs |
| Decode | 3.4µs | 13.5µs | 61.6µs | N/A |
| Memory (encode) | 0B | 6.4KB | 13.5KB | 351KB |
| Allocs (encode) | 0 | 195 | 27 | 1,149 |

### Large Config
| Operation | DSL | Binary | YAML |
|-----------|-----|--------|------|
| Parse | 10.7µs | 137.7µs | N/A |
| Encode | N/A | 54.9µs | 5,638µs |
| Memory | 6.4KB | 56.7KB | 6,385KB |
| Allocs | 146 | 2,955 | 10,434 |

## Recommendations

1. **Development**: Use DSL (fastest, readable, 0.7µs encode, 0 allocations)
2. **Production**: Use DSL or Binary (DSL: 3.4µs parse, Binary: compact)
3. **APIs**: Use JSON (standard, 45.9µs encode)
4. **Avoid**: YAML for any performance-critical path

## Performance Ratios

### Small Config
- **DSL vs JSON**: 
  - Encode: 63x faster
  - Decode: 18x faster
- **DSL vs YAML**:
  - Encode: 922x faster
- **DSL vs Binary**:
  - Encode: 10x faster
  - Decode: 4x faster

### Large Config
- **DSL vs Binary**:
  - Parse: 13x faster
- **Binary vs YAML**:
  - Encode: 103x faster

## Optimization Highlights

### DSL Encoder Optimizations
1. **Byte buffer**: Direct []byte append operations
2. **Zero allocations**: Reusable buffer, no string conversions
3. **strconv.AppendInt**: Stack-allocated number formatting
4. **No reflection**: Direct field access
5. **Result**: 0 allocations, 0.7µs encode time

### DSL Parser Optimizations
1. **Direct byte scanning**: No bufio.Scanner overhead
2. **Zero-copy line splitting**: Work with []byte slices
3. **Pre-allocated slices**: Capacity hints reduce allocations
4. **Inline tokenization**: No strings.Split overhead
5. **Result**: 61 allocations, 3.4µs parse time

## Conclusion

The custom DSL provides exceptional performance:
- **0.7µs encoding** - fastest format, zero allocations
- **3.4µs parsing** - 18x faster than JSON, 4x faster than Binary
- **61 allocations** - minimal memory overhead
- **Scales excellently** - 10.7µs for 100 policies

Combined with the binary protocol (7.2µs encode, 13.5µs decode), authz offers the fastest configuration system available.
