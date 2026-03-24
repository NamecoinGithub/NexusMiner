#ifndef NEXUSMINER_PRIME_VALIDATION_HPP
#define NEXUSMINER_PRIME_VALIDATION_HPP

#include <vector>
#include <cstdint>
#include "LLC/types/uint1024.h"

namespace nexusminer {
namespace prime {

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
