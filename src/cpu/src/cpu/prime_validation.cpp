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

/** GetOffsets - with pre-validation flag to avoid duplicate PrimeCheck
 *
 *  Find Cunningham chain offsets for prime cluster.
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
    
    // Start building Cunningham chain
    // Offsets represent gaps from previous prime in chain
    // First offset is always 0 (base prime)
    vOffsets.push_back(0);
    
    uint1024_t lastPrime = hashPrime;
    uint1024_t next = hashPrime + 2;
    uint8_t nOffset = 0;
    
    // Test consecutive odd numbers up to lastPrime + 12
    // Maximum gap in cluster is 12 (as per Nexus protocol)
    // Note: lastPrime is updated in the loop, so the search extends with each prime found
    while (next <= lastPrime + 12)
    {
        nOffset += 2;
        
        if (PrimeCheck(next))
        {
            // Found a prime in the chain - extend search range
            lastPrime = next;
            vOffsets.push_back(nOffset);
            nOffset = 0; // Reset offset counter after finding a prime
        }
        
        next += 2; // Move to next odd number
    }
    
    // A valid cluster needs at least the base prime
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
    size_t clusterSize = vOffsets.size();
    
    // Calculate the position of the last prime in the chain
    // by summing all offsets
    uint1024_t lastPrime = hashPrime;
    uint32_t totalOffset = 0;
    for (uint8_t offset : vOffsets)
    {
        totalOffset += offset;
    }
    lastPrime = hashPrime + totalOffset;
    
    // Test next candidate (lastPrime + 2) for fractional difficulty
    uint1024_t nextCandidate = lastPrime + 2;
    
    // Perform partial Fermat test to get fractional difficulty
    // This measures "how close" the next number is to being prime
    std::string hexStr = nextCandidate.GetHex();
    if (hexStr.empty())
        return static_cast<double>(clusterSize);
    
    boost::multiprecision::uint1024_t bn;
    try {
        bn = boost::multiprecision::uint1024_t("0x" + hexStr);
    } catch (...) {
        return static_cast<double>(clusterSize);
    }
    
    // Compute Fermat test remainder: 2^(n-1) mod n
    boost::multiprecision::uint1024_t base = 2;
    boost::multiprecision::uint1024_t exponent = bn - 1;
    boost::multiprecision::uint1024_t remainder;
    
    try {
        remainder = boost::multiprecision::powm(base, exponent, bn);
    } catch (...) {
        return static_cast<double>(clusterSize);
    }
    
    // Calculate fractional component similar to Prime::GetFractionalDifficulty
    // Formula from reference: 1000000.0 / ((composite - fermatRemainder) << 24 / composite)
    // Simplified: measure how close remainder is to 1 (which indicates primality)
    double fractionalRemainder = 0.0;
    
    if (remainder != 0)
    {
        // Use simplified calculation: 1000000 / fractional_difficulty_bits
        // This gives a value in [0, 1] range
        
        // Count bits in remainder to estimate fractional difficulty
        int remainderBits = 0;
        boost::multiprecision::uint1024_t temp = remainder;
        while (temp > 0)
        {
            temp >>= 1;
            remainderBits++;
        }
        
        // If remainder is 1, next candidate is prime (fractional = ~1.0)
        // If remainder is large, next candidate is far from prime (fractional = ~0.0)
        if (remainder == 1)
        {
            fractionalRemainder = PRIME_FRACTIONAL_REMAINDER; // Almost exactly prime
        }
        else
        {
            // Compute fractional based on bit position
            // Higher bit count = larger remainder = lower fractional difficulty
            fractionalRemainder = 1.0 / (static_cast<double>(remainderBits) + 1.0);
        }
        
        // Keep fractional in bounds [0, 1]
        if (fractionalRemainder > 1.0)
            fractionalRemainder = 1.0;
        if (fractionalRemainder < 0.0)
            fractionalRemainder = 0.0;
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
