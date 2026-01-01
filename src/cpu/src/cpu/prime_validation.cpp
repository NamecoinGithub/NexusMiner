#include "cpu/prime_validation.hpp"
#include <boost/multiprecision/cpp_int.hpp>
#include <spdlog/spdlog.h>

namespace nexusminer {
namespace prime {

namespace {
    // Match LLL-TAO exactly: 11 small primes
    const uint16_t SMALL_PRIMES[11] = { 2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31 };
}

/** SmallDivisors
 *  Match LLL-TAO implementation exactly.
 *  Returns false if divisible by any small prime (composite).
 *  Returns true if passes all small prime tests (might be prime).
 **/
bool SmallDivisors(const uint1024_t& hashTest)
{
    // Convert to boost for modulo operations
    std::string hexStr = hashTest.GetHex();
    if (hexStr.empty())
        return false;
    
    boost::multiprecision::uint1024_t bn;
    try {
        bn = boost::multiprecision::uint1024_t("0x" + hexStr);
    } catch (...) {
        return false;
    }
    
    // Match LLL-TAO: check all 11 primes, return false if divisible
    // NO special case for small primes - they would never appear in mining anyway
    for (int i = 0; i < 11; ++i)
    {
        if (bn % SMALL_PRIMES[i] == 0)
            return false;
    }
    
    return true;
}

/** FermatTestResult
 *  Performs Fermat primality test: 2^(n-1) mod n
 *  Returns the RESULT (not bool) to match LLL-TAO.
 *  If result == 1, the number is probably prime.
 **/
boost::multiprecision::uint1024_t FermatTestResult(const uint1024_t& hashTest)
{
    std::string hexStr = hashTest.GetHex();
    if (hexStr.empty())
        return boost::multiprecision::uint1024_t(0);
    
    boost::multiprecision::uint1024_t bn;
    try {
        bn = boost::multiprecision::uint1024_t("0x" + hexStr);
    } catch (...) {
        return boost::multiprecision::uint1024_t(0);
    }
    
    if (bn < 2)
        return boost::multiprecision::uint1024_t(0);
    
    // Fermat test: 2^(n-1) mod n
    boost::multiprecision::uint1024_t base = 2;
    boost::multiprecision::uint1024_t exponent = bn - 1;
    
    try {
        return boost::multiprecision::powm(base, exponent, bn);
    } catch (...) {
        return boost::multiprecision::uint1024_t(0);
    }
}

bool PrimeCheck(const uint1024_t& hashTest)
{
    // Step 1: Small divisor tests (fast rejection)
    if (!SmallDivisors(hashTest))
        return false;
    
    // Step 2: Fermat test - check if result equals 1
    boost::multiprecision::uint1024_t result = FermatTestResult(hashTest);
    if (result != 1)
        return false;
    
    return true;
}

/** GetFractionalDifficulty
 *  Match LLL-TAO formula: ((composite - fermatResult) << 24) / composite
 **/
static uint32_t GetFractionalDifficulty(const uint1024_t& hashComposite)
{
    std::string hexStr = hashComposite.GetHex();
    if (hexStr.empty())
        return 0;
    
    boost::multiprecision::uint1024_t composite;
    try {
        composite = boost::multiprecision::uint1024_t("0x" + hexStr);
    } catch (...) {
        return 0;
    }
    
    // Get Fermat test result
    boost::multiprecision::uint1024_t fermatResult = FermatTestResult(hashComposite);
    
    // LLL-TAO formula: ((a - b) << 24) / a
    // Use larger type to prevent overflow during shift
    boost::multiprecision::uint1056_t a(composite);
    boost::multiprecision::uint1056_t b(fermatResult);
    
    boost::multiprecision::uint1056_t numerator = (a - b) << 24;
    boost::multiprecision::uint1056_t result = numerator / a;
    
    // Convert to uint32_t
    return static_cast<uint32_t>(result & 0xFFFFFFFF);
}

/** GetOffsets - Match LLL-TAO exactly
 **/
static bool GetOffsetsImpl(const uint1024_t& hashPrime, std::vector<uint8_t>& vOffsets, bool alreadyValidated = false)
{
    vOffsets.clear();
    
    // Check if base is prime
    if (!alreadyValidated && !PrimeCheck(hashPrime))
        return false;
    
    // Match LLL-TAO loop structure exactly
    uint8_t nOffset = 2;
    uint1024_t hashLast = hashPrime;
    
    for (uint1024_t hashNext = hashPrime + 2; nOffset <= 12; hashNext += 2, nOffset += 2)
    {
        if (PrimeCheck(hashNext))
        {
            hashLast = hashNext;
            vOffsets.push_back(nOffset);
            nOffset = 0;  // Reset after finding prime
        }
    }
    
    // Append fractional difficulty as 4 bytes (LITTLE-ENDIAN to match LLL-TAO)
    uint32_t nFraction = GetFractionalDifficulty(hashLast + nOffset);
    
    // LLL-TAO uses raw memory insert which is little-endian on x86/x64
    vOffsets.push_back(nFraction & 0xFF);
    vOffsets.push_back((nFraction >> 8) & 0xFF);
    vOffsets.push_back((nFraction >> 16) & 0xFF);
    vOffsets.push_back((nFraction >> 24) & 0xFF);
    
    return true;  // Always return true if base was prime (offsets may be empty but fractional is appended)
}

bool GetOffsets(const uint1024_t& hashPrime, std::vector<uint8_t>& vOffsets)
{
    return GetOffsetsImpl(hashPrime, vOffsets, false);
}

double GetPrimeDifficulty(const uint1024_t& hashPrime, const std::vector<uint8_t>& vOffsets)
{
    if (vOffsets.size() < 4)
        return 0.0;
    
    // Cluster size = 1 (base prime) + number of offsets found
    // Last 4 bytes are fractional, so offset count = size - 4
    size_t nOffsetCount = vOffsets.size() - 4;
    uint32_t nClusterSize = 1 + static_cast<uint32_t>(nOffsetCount);
    
    // Extract fractional difficulty from last 4 bytes (LITTLE-ENDIAN)
    uint32_t nFraction = 
        static_cast<uint32_t>(vOffsets[vOffsets.size() - 4]) |
        (static_cast<uint32_t>(vOffsets[vOffsets.size() - 3]) << 8) |
        (static_cast<uint32_t>(vOffsets[vOffsets.size() - 2]) << 16) |
        (static_cast<uint32_t>(vOffsets[vOffsets.size() - 1]) << 24);
    
    // Calculate fractional remainder: 1000000.0 / nFraction
    double nRemainder = 0.0;
    if (nFraction != 0)
    {
        nRemainder = 1000000.0 / static_cast<double>(nFraction);
        
        // Keep in bounds [0, 1] per LLL-TAO
        if (nRemainder > 1.0 || nRemainder < 0.0)
            nRemainder = 0.0;
    }
    
    return static_cast<double>(nClusterSize) + nRemainder;
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
