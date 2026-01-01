#include "cpu/prime_validation.hpp"
#include <boost/multiprecision/cpp_int.hpp>
#include <spdlog/spdlog.h>

namespace nexusminer {
namespace prime {

namespace {
    // Small primes for divisibility check
    const unsigned int SMALL_PRIMES[] = {
        2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47
    };
    const size_t NUM_SMALL_PRIMES = sizeof(SMALL_PRIMES) / sizeof(SMALL_PRIMES[0]);
    
    // Fractional remainder constant for perfect primes
    constexpr double PRIME_FRACTIONAL_REMAINDER = 0.999;
}

/** SmallDivisors
 *
 *  Quick primality filter using small prime divisibility.
 *  Tests if the number is divisible by small primes.
 *
 *  @param[in] n The number to test
 *
 *  @return True if NOT divisible by small primes (passes filter), false otherwise
 **/
bool SmallDivisors(const uint1024_t& n)
{
    // Convert to boost::multiprecision for modulo operations
    boost::multiprecision::uint1024_t bn;
    
    // Convert uint1024_t to boost uint1024_t
    std::string hexStr = n.GetHex();
    if (hexStr.empty()) {
        return false;
    }
    
    try {
        bn = boost::multiprecision::uint1024_t("0x" + hexStr);
    } catch (...) {
        return false;
    }
    
    // Check divisibility by small primes
    for (size_t i = 0; i < NUM_SMALL_PRIMES; i++)
    {
        // Check if n % prime == 0 (i.e., n is divisible by prime)
        if (bn % SMALL_PRIMES[i] == 0)
        {
            // Special case: if n equals the prime itself, it's prime
            if (bn == SMALL_PRIMES[i])
                return true;
            
            // Otherwise, it's composite (divisible by a small prime)
            return false;
        }
    }
    
    return true;
}

/** FermatTest
 *
 *  Performs Fermat primality test: checks if 2^(n-1) mod n == 1.
 *  This is a probabilistic primality test.
 *
 *  @param[in] n The number to test for primality
 *
 *  @return True if n passes Fermat test (likely prime), false otherwise
 **/
bool FermatTest(const uint1024_t& n)
{
    // Convert to boost::multiprecision for modular exponentiation
    std::string hexStr = n.GetHex();
    if (hexStr.empty()) {
        return false;
    }
    
    boost::multiprecision::uint1024_t bn;
    try {
        bn = boost::multiprecision::uint1024_t("0x" + hexStr);
    } catch (...) {
        return false;
    }
    
    // Base case: numbers less than 2 are not prime
    if (bn < 2)
        return false;
    
    // Fermat test: compute 2^(n-1) mod n
    // If result is 1, n is probably prime
    boost::multiprecision::uint1024_t base = 2;
    boost::multiprecision::uint1024_t exponent = bn - 1;
    boost::multiprecision::uint1024_t result;
    
    try {
        result = boost::multiprecision::powm(base, exponent, bn);
    } catch (...) {
        return false;
    }
    
    return (result == 1);
}

bool PrimeCheck(const uint1024_t& hashTest)
{
    // Quick filter: check divisibility by small primes
    if (!SmallDivisors(hashTest))
        return false;
    
    // Fermat primality test
    return FermatTest(hashTest);
}

/** GetFractionalDifficulty
 *
 *  Calculate fractional difficulty from Fermat test remainder.
 *  Matches LLL-TAO implementation exactly.
 *
 *  @param[in] hashComposite The composite number to test
 *
 *  @return Fractional difficulty as uint32_t
 **/
static uint32_t GetFractionalDifficulty(const uint1024_t& hashComposite)
{
    // Convert to boost::multiprecision for calculation
    std::string hexStr = hashComposite.GetHex();
    if (hexStr.empty()) {
        return 0;
    }
    
    boost::multiprecision::uint1024_t composite;
    try {
        composite = boost::multiprecision::uint1024_t("0x" + hexStr);
    } catch (...) {
        return 0;
    }
    
    // Fermat test: compute 2^(composite-1) mod composite
    boost::multiprecision::uint1024_t base = 2;
    boost::multiprecision::uint1024_t exponent = composite - 1;
    boost::multiprecision::uint1024_t remainder;
    
    try {
        remainder = boost::multiprecision::powm(base, exponent, composite);
    } catch (...) {
        return 0;
    }
    
    // Formula from LLL-TAO: ((composite - remainder) << 24) / composite
    boost::multiprecision::uint1024_t numerator = (composite - remainder) << 24;
    boost::multiprecision::uint1024_t result = numerator / composite;
    
    // Convert to uint32_t
    // If result is too large, return max uint32_t
    if (result > 0xFFFFFFFF) {
        return 0xFFFFFFFF;
    }
    
    return static_cast<uint32_t>(result & 0xFFFFFFFF);
}

/** GetOffsets - with pre-validation flag to avoid duplicate PrimeCheck
 *
 *  Find Cunningham chain offsets for prime cluster.
 *  Matches LLL-TAO implementation exactly.
 *
 *  @param[in] hashPrime The prime base number
 *  @param[out] vOffsets Vector to store offsets
 *  @param[in] alreadyValidated If true, skip initial PrimeCheck (caller already validated)
 *
 *  @return True if valid cluster found, false otherwise
 **/
static bool GetOffsetsImpl(const uint1024_t& hashPrime, std::vector<uint8_t>& vOffsets, bool alreadyValidated = false)
{
    // Clear output vector
    vOffsets.clear();
    
    // Check if base is prime (skip if already validated)
    if (!alreadyValidated && !PrimeCheck(hashPrime))
        return false;
    
    // Start building Cunningham chain - matching LLL-TAO exactly
    // Don't push initial 0 - start with nOffset = 2
    uint1024_t lastPrime = hashPrime;
    uint1024_t next = hashPrime + 2;
    uint8_t nOffset = 2;  // Start at 2, not 0
    
    // Test consecutive odd numbers
    // Maximum gap in cluster is 12 (as per Nexus protocol)
    // Use nOffset <= 12 as loop condition per LLL-TAO
    while (nOffset <= 12)
    {
        if (PrimeCheck(next))
        {
            // Found a prime in the chain - extend search range
            lastPrime = next;
            vOffsets.push_back(nOffset);
            nOffset = 2;  // Reset to 2 after finding a prime (will test next+2)
            next = lastPrime + 2;  // Start from last prime + 2
        }
        else
        {
            nOffset += 2;  // Increment offset
            next += 2;     // Move to next odd number
        }
    }
    
    // Append fractional difficulty as 4-byte value at the end
    if (!vOffsets.empty())
    {
        // Calculate fractional difficulty for the next candidate after the chain
        uint32_t fractional = GetFractionalDifficulty(next);
        
        // Append as 4 bytes (big-endian)
        vOffsets.push_back((fractional >> 24) & 0xFF);
        vOffsets.push_back((fractional >> 16) & 0xFF);
        vOffsets.push_back((fractional >> 8) & 0xFF);
        vOffsets.push_back(fractional & 0xFF);
    }
    
    return !vOffsets.empty();
}

bool GetOffsets(const uint1024_t& hashPrime, std::vector<uint8_t>& vOffsets)
{
    return GetOffsetsImpl(hashPrime, vOffsets, false);
}

double GetPrimeDifficulty(const uint1024_t& hashPrime, const std::vector<uint8_t>& vOffsets)
{
    if (vOffsets.empty())
        return 0.0;
    
    // Cluster size is the number of primes found
    // Note: last 4 bytes are fractional difficulty, not offsets
    size_t clusterSize = (vOffsets.size() >= 4) ? (vOffsets.size() - 4) : vOffsets.size();
    
    // Extract fractional difficulty from last 4 bytes if present
    double fractionalRemainder = 0.0;
    
    if (vOffsets.size() >= 4)
    {
        // Extract 4-byte fractional difficulty (big-endian)
        uint32_t fractional = 
            (static_cast<uint32_t>(vOffsets[vOffsets.size() - 4]) << 24) |
            (static_cast<uint32_t>(vOffsets[vOffsets.size() - 3]) << 16) |
            (static_cast<uint32_t>(vOffsets[vOffsets.size() - 2]) << 8) |
            static_cast<uint32_t>(vOffsets[vOffsets.size() - 1]);
        
        // Calculate fractional remainder using LLL-TAO formula: 1000000.0 / fractional
        if (fractional != 0)
        {
            fractionalRemainder = 1000000.0 / static_cast<double>(fractional);
            
            // Keep fractional in bounds [0, 1]
            if (fractionalRemainder > 1.0 || fractionalRemainder < 0.0)
                fractionalRemainder = 0.0;
        }
    }
    
    return static_cast<double>(clusterSize) + fractionalRemainder;
}

bool ValidatePrimeCandidate(
    const uint1024_t& hashPrime,
    double nRequiredDifficulty,
    std::vector<uint8_t>& vOffsets,
    double& nDifficulty)
{
    // Step 1: Check if base is prime
    if (!PrimeCheck(hashPrime))
    {
        nDifficulty = 0.0;
        vOffsets.clear();
        return false;
    }
    
    // Step 2: Find Cunningham chain offsets (skip redundant PrimeCheck)
    if (!GetOffsetsImpl(hashPrime, vOffsets, true))
    {
        nDifficulty = 0.0;
        return false;
    }
    
    // Step 3: Calculate difficulty
    nDifficulty = GetPrimeDifficulty(hashPrime, vOffsets);
    
    // Step 4: Check if difficulty meets requirement
    if (nDifficulty < nRequiredDifficulty)
    {
        return false;
    }
    
    // All checks passed
    return true;
}

} // namespace prime
} // namespace nexusminer
