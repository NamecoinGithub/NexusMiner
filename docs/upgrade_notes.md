# NexusMiner Upgrade Notes

This document describes the modernization changes made to NexusMiner for OpenSSL 3.0 support, newest Nvidia architectures, and modern CMake dependencies.

## OpenSSL 3.0 Compatibility

### Analysis Summary
The codebase was reviewed for OpenSSL-related code. The primary OpenSSL usage is in `src/LLC/src/LLC/types/bignum.cpp` which uses OpenSSL's BIGNUM functions for cryptographic big integer operations.

### Functions Used
The following OpenSSL BN (Big Number) functions are used:
- `BN_new()`, `BN_dup()`, `BN_copy()`, `BN_clear_free()` - Memory management
- `BN_CTX_new()`, `BN_CTX_free()` - Context management  
- `BN_set_word()`, `BN_get_word()` - Basic operations
- `BN_mpi2bn()`, `BN_bn2mpi()` - MPI format conversion
- `BN_is_negative()`, `BN_set_negative()`, `BN_is_zero()` - State queries
- `BN_add()`, `BN_sub()`, `BN_mul()`, `BN_div()`, `BN_mod()` - Arithmetic
- `BN_lshift()`, `BN_rshift()` - Bit operations
- `BN_cmp()`, `BN_value_one()` - Comparison

### OpenSSL 3.0 Compatibility Status
**All functions used are fully compatible with OpenSSL 3.0.** 

The deprecated functions in OpenSSL 3.0 (such as `BN_pseudo_rand`, `BN_is_prime_ex`, `BN_is_prime_fasttest_ex`, and X9.31 key generation functions) are NOT used in this codebase.

The `BN_mpi2bn()` and `BN_bn2mpi()` functions remain part of the stable OpenSSL 3.0 API.

### CMake Changes
- Added OpenSSL version requirement: minimum version 1.1.1 (which includes OpenSSL 3.0+)
- Added status message to display the found OpenSSL version during configuration

## Nvidia GPU Architecture Updates

### New CUDA Architectures
Updated CUDA_ARCHITECTURES in `src/gpu/CMakeLists.txt` to support the newest Nvidia GPU architectures:

| Compute Capability | Architecture   | GPU Series                 |
|--------------------|----------------|----------------------------|
| 61                 | Pascal         | GTX 10 series              |
| 75                 | Turing         | RTX 20 series              |
| 86                 | Ampere         | RTX 30 series              |
| 89                 | Ada Lovelace   | RTX 40 series (NEW)        |
| 90                 | Hopper         | H100 data center (NEW)     |

### CUDA Version Requirements
- CUDA 11.0+ required for Ampere (compute capability 86) support
- CUDA 11.8+ required for Ada Lovelace (compute capability 89) support
- CUDA 12.0+ required for Hopper (compute capability 90) support

The CMake configuration now displays architecture-specific warnings based on the detected CUDA version.

## CMake Modernization

### CPM.cmake Update
- Updated CPM.cmake from version 0.35.0 to 0.40.2
- Changed download URL to use the new `cpm-cmake` GitHub organization

### Enhanced Configuration Messages
- Added CUDA Toolkit version display during configuration
- Added OpenSSL version display during configuration
- Added CUDA version compatibility warnings

## Backward Compatibility

All changes maintain backward compatibility:
- OpenSSL 1.1.1 and later are supported (tested with OpenSSL 3.0.13)
- Older CUDA architectures (61, 75, 86) remain supported
- CMake 3.21+ requirement unchanged

## Testing

The updated codebase has been verified to:
1. Configure successfully with CMake
2. Build without errors or warnings
3. Link correctly with OpenSSL 3.0
4. Support all previous build configurations

## Platform Support

No changes to platform support. The miner continues to support:
- CPU mining (all platforms)
- FPGA mining (all platforms)
- GPU mining with Nvidia CUDA (Linux, Windows)
- GPU mining with AMD HIP/ROCm (Linux)
