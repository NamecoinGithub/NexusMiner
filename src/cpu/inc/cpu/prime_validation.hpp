#ifndef NEXUSMINER_PRIME_VALIDATION_HPP
#define NEXUSMINER_PRIME_VALIDATION_HPP

#include <vector>
#include <cstdint>
#include <cstddef>
#include "LLC/types/uint1024.h"
#include "mining/mining_constants.hpp"

namespace nexusminer {
namespace prime {

//==============================================================================
// Serialized vOffsets layout (single source of truth for miner + tests)
//==============================================================================
//
// `GetOffsetsImpl` emits, for a Cunningham chain of length N (N >= 2):
//
//   (N - 1) gap bytes, each in {2, 4, 6, 8, 10, 12}
//   followed by 4 bytes of fractional difficulty (uint32_t, little-endian)
//
// Therefore a well-formed serialized offsets vector has size:
//
//   size == (N - 1) + kPrimeOffsetFractionBytes
//
// Historical bug: the miner used to hard-code `size == 10` (chain length 7),
// silently dropping every length-8+ find as "malformed".  The check is now
// a range gate driven by these constants.
//
// Bounds rationale:
//   * kMinSerializedPrimeOffsets = 5  -> chain length 2 (smallest meaningful
//     Cunningham cluster) + 4 fraction bytes.
//   * kMaxSerializedPrimeOffsets = 22 -> chain length 19 + 4 fraction bytes.
//     Cunningham chain world record is currently 17 primes; 19 gives
//     headroom for future records without ever dropping a real find.

/** Fractional-difficulty tail size appended by GetOffsetsImpl (uint32_t LE). */
inline constexpr std::size_t kPrimeOffsetFractionBytes = 4;

/** Minimum well-formed serialized vOffsets size (chain length 2). */
inline constexpr std::size_t kMinSerializedPrimeOffsets =
    /*chain length 2 -> 1 gap*/ 1 + kPrimeOffsetFractionBytes;  // 5

/** Maximum supported chain length recognised by the miner.
 *  Set generously above the Cunningham world record (17) so a record-breaking
 *  find is never silently dropped by the miner-side sanity gate. */
inline constexpr std::size_t kMaxRecognisedChainLength = 19;

/** Maximum well-formed serialized vOffsets size (chain length kMax... above). */
inline constexpr std::size_t kMaxSerializedPrimeOffsets =
    (kMaxRecognisedChainLength - 1) + kPrimeOffsetFractionBytes;  // 22

/** Returns true if `offsets` could plausibly have been produced by
 *  GetOffsetsImpl for some valid chain length in [2, kMaxRecognisedChainLength].
 *  Used as a defense-in-depth gate after ValidatePrimeCandidate succeeds.
 *  This replaces the previous (buggy) `size() == 10` equality check that
 *  silently rejected every chain of length >= 8. */
inline bool is_well_formed_prime_offsets(const std::vector<uint8_t>& offsets)
{
    return offsets.size() >= kMinSerializedPrimeOffsets &&
           offsets.size() <= kMaxSerializedPrimeOffsets;
}

// Compile-time guarantee: any chain at the configured minimum target length
// must serialize to a size the sanity gate accepts.  This catches any future
// drift where mining::MIN_CHAIN_LENGTH is bumped past kMaxRecognisedChainLength
// without also bumping the protocol-side max constants.
static_assert(
    static_cast<std::size_t>(mining::MIN_CHAIN_LENGTH) <= kMaxRecognisedChainLength,
    "mining::MIN_CHAIN_LENGTH exceeds kMaxRecognisedChainLength — bump "
    "kMaxRecognisedChainLength (and PRIME_VOFFSETS_MAX_SIZE in falcon_constants.hpp)");
static_assert(
    static_cast<std::size_t>(mining::MIN_CHAIN_LENGTH) >= 2,
    "mining::MIN_CHAIN_LENGTH must be >= 2 (single-prime chains are meaningless)");

/** Miller_Rabin
 *
 *  OpenSSL probabilistic primality test wrapper.
 *  Matches LLL-TAO implementation (1 round).
 *
 *  @param[in] hashTest The 1024-bit number to test
 *  @return True if passes Miller-Rabin, false otherwise
 *
 **/
bool Miller_Rabin(const uint1024_t& hashTest);

/** PrimeCheck
 *
 *  Determines if given number is Prime using three sequential tests
 *  that short-circuit on failure (each must pass before the next runs):
 *  1. SmallDivisors  — fast rejection by small primes
 *  2. Miller_Rabin   — probabilistic OpenSSL test
 *  3. FermatTest     — final Fermat primality test
 *  Matches the LLL-TAO implementation exactly.
 *
 *  @param[in] hashTest The 1024-bit number to test for primality
 *
 *  @return True if number passes all three primality tests, false otherwise
 *
 **/
bool PrimeCheck(const uint1024_t& hashTest);

/** GetOffsets
 *
 *  Find Cunningham chain offsets for prime cluster.
 *  Returns list of offsets forming a dense prime cluster.
 *  Matches LLL-TAO GetOffsets() implementation.
 *
 *  @param[in] hashPrime The prime base number
 *  @param[out] vOffsets Vector to store offsets
 *
 *  @return True if valid cluster found, false otherwise
 *
 **/
bool GetOffsets(const uint1024_t& hashPrime, std::vector<uint8_t>& vOffsets);

/** GetPrimeDifficulty
 *
 *  Calculate prime cluster difficulty from offsets.
 *  Difficulty = cluster_size + fractional_remainder.
 *  Matches LLL-TAO GetPrimeDifficulty() implementation.
 *
 *  @param[in] hashPrime The prime base number
 *  @param[in] vOffsets The offsets from GetOffsets()
 *
 *  @return Prime difficulty value (e.g., 6.523871)
 *
 **/
double GetPrimeDifficulty(const uint1024_t& hashPrime, const std::vector<uint8_t>& vOffsets);

/** ValidatePrimeCandidate
 *
 *  Complete validation of a prime mining candidate.
 *  Checks:
 *  1. Base is prime
 *  2. Forms valid Cunningham chain
 *  3. Difficulty meets requirement
 *
 *  @param[in] hashPrime The prime base (ProofHash + nonce)
 *  @param[in] nRequiredDifficulty Minimum difficulty from nBits
 *  @param[out] vOffsets Offsets found (if valid)
 *  @param[out] nDifficulty Actual difficulty (if valid)
 *
 *  @return True if valid prime solution, false otherwise
 *
 **/
bool ValidatePrimeCandidate(
    const uint1024_t& hashPrime,
    double nRequiredDifficulty,
    std::vector<uint8_t>& vOffsets,
    double& nDifficulty
);

} // namespace prime
} // namespace nexusminer

#endif // NEXUSMINER_PRIME_VALIDATION_HPP
