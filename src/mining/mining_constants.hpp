#ifndef NEXUSMINER_MINING_CONSTANTS_HPP
#define NEXUSMINER_MINING_CONSTANTS_HPP

/// @file mining_constants.hpp
/// @brief Named constants for mining parameters, replacing magic numbers.
///
/// These constants are referenced by CPU, GPU, and protocol modules.
/// Centralizing them here makes tuning visible and grep-friendly.

#include <cstdint>

namespace nexusminer {
namespace mining {

// ============================================================================
//  Prime sieve constants
// ============================================================================

/// Maximum sieve length in integers (CPU).
/// Controls the size of the boolean sieve array; larger values trade
/// memory for better chain coverage.
static constexpr int CPU_SIEVE_LENGTH_MAX = 30'000'000;

/// Primorial end-prime limit for the CPU sieve.
/// Primes up to this value are included in the primorial calculation.
static constexpr int CPU_PRIMORIAL_END_PRIME = 3'000'000;

/// Minimum acceptable prime-chain length for both CPU and GPU.
/// Chains shorter than this are discarded before Fermat testing.
static constexpr int MIN_CHAIN_LENGTH = 8;

/// Maximum allowable prime gap (half-value, since sieve excludes evens).
/// Gaps larger than 2 × this value terminate chain search.
static constexpr int MAX_PRIME_GAP_HALF = 6;

/// Upper bound for sieving primes (CPU segmented sieve).
/// Primes beyond this are not sieved; chain_sieve.hpp uses 3 × 10^8.
static constexpr uint32_t CPU_SIEVING_PRIME_LIMIT = 300'000'000;

/// L1 cache size assumption for segmented sieve (bytes).
static constexpr int L1_CACHE_BYTES = 32'768;

/// L2 cache size assumption for segmented sieve (bytes).
static constexpr int L2_CACHE_BYTES = 262'144;

/// First prime at which sieving begins (after primorial {2,3,5}).
static constexpr int SIEVING_START_PRIME = 7;

// ============================================================================
//  GPU-specific prime sieve constants
// ============================================================================

/// Default Fermat-test batch size for GPU prime sieve.
static constexpr int GPU_FERMAT_BATCH_SIZE_DEFAULT = 200'000;

/// Maximum Fermat-test batch size for GPU prime sieve.
static constexpr int GPU_FERMAT_BATCH_SIZE_MAX = 1'000'000;

// ============================================================================
//  Hash mining constants
// ============================================================================

/// How often the hash worker logs performance (number of hashes).
static constexpr uint64_t HASH_LOG_INTERVAL = 1'000'000;

// ============================================================================
//  Difficulty encoding
// ============================================================================

/// Fractional difficulty base used in nBits encoding / decoding.
/// GetFractionalDifficulty multiplies the fraction remainder by this value.
static constexpr uint64_t DIFFICULTY_FRACTION_BASE = 10'000'000;

// ============================================================================
//  Block / network sanity limits
// ============================================================================

/// Minimum unified height for mainnet blocks (genesis guard).
static constexpr uint32_t MAINNET_MIN_HEIGHT = 1'000'000;

} // namespace mining
} // namespace nexusminer

#endif // NEXUSMINER_MINING_CONSTANTS_HPP
