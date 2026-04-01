#ifndef NEXUSMINER_MINING_MINING_CONSTANTS_HPP
#define NEXUSMINER_MINING_MINING_CONSTANTS_HPP

#include <cstdint>

namespace nexusminer {
namespace mining {

/**
 * @brief Mining-specific constants for CPU and GPU worker parameters.
 *
 * Protocol-level constants live in protocol/protocol_constants.hpp.
 * Cryptographic sizing lives in protocol/falcon_constants.hpp.
 * This file covers sieve, hashing, and prime-chain tuning parameters.
 */

// =========================================================================
// CPU Prime Sieve Parameters
// =========================================================================

/// Maximum number of elements in the CPU prime sieve.
/// Limited by available memory; sieve range is 2× this value.
constexpr int CPU_SIEVE_LENGTH_MAX = 30'000'000;

/// Upper bound for the primorial computation (Sieve of Eratosthenes limit).
constexpr int CPU_PRIMORIAL_END_PRIME = 3'000'000;

/// Minimum chain length required for a valid prime chain.
constexpr int CPU_MIN_CHAIN_LENGTH = 8;

/// Largest allowable prime gap, divided by 2 (sieve excludes even numbers).
constexpr int CPU_MAX_PRIME_GAP = 12 / 2;

// =========================================================================
// GPU Prime Sieve Parameters
// =========================================================================

/// Default GPU Fermat-test batch size (normal load).
constexpr int GPU_FERMAT_BATCH_SIZE = 200'000;

/// Maximum GPU Fermat-test batch size (high-throughput mode).
constexpr int GPU_FERMAT_BATCH_SIZE_MAX = 1'000'000;

// =========================================================================
// Hash Worker Parameters
// =========================================================================

/// Number of hashes between progress-log updates.
constexpr uint64_t HASH_LOG_INTERVAL = 1'000'000;

} // namespace mining
} // namespace nexusminer

#endif // NEXUSMINER_MINING_MINING_CONSTANTS_HPP
