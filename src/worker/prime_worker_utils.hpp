#ifndef NEXUSMINER_PRIME_WORKER_UTILS_HPP
#define NEXUSMINER_PRIME_WORKER_UTILS_HPP

#include <boost/multiprecision/cpp_int.hpp>
#include <sstream>
#include "LLC/types/bignum.h"
#include "hash/nexus_skein.hpp"
#include "hash/nexus_keccak.hpp"
#include "worker.hpp"

namespace nexusminer {
namespace prime_worker_utils {

using uint1k = boost::multiprecision::uint1024_t;

/**
 * @brief Convert boost uint1024_t to LLC::CBigNum
 * 
 * This is a common utility function used by both CPU and GPU prime workers
 * to convert boost multiprecision integers to CBigNum for difficulty calculations.
 * 
 * @param p The boost uint1024_t value to convert
 * @return LLC::CBigNum The converted big number
 */
inline LLC::CBigNum boost_uint1024_t_to_CBignum(uint1k p)
{
    std::stringstream ss;
    ss << std::hex << p;
    std::string p_hex_str = ss.str();
    LLC::CBigNum p_CBignum;
    p_CBignum.SetHex(p_hex_str);
    return p_CBignum;
}

/**
 * @brief Calculate the base hash for prime mining from block header
 * 
 * This function computes the base hash used by prime workers by calculating
 * Skein-1024 followed by Keccak-1024 on the block header (excluding nonce).
 * This is identical code shared between CPU and GPU prime workers.
 * 
 * @param block_data The block data containing the header information
 * @return uint1k The computed base hash as a 1024-bit unsigned integer
 */
inline uint1k calculate_prime_base_hash(const Block_data& block_data)
{
    bool excludeNonce = true;  // prime block hash excludes the nonce
    std::vector<unsigned char> headerB = block_data.GetHeaderBytes(excludeNonce);
    
    // Calculate the block hash using Skein-1024
    NexusSkein skein;
    skein.setMessage(headerB);
    skein.calculateHash();
    NexusSkein::stateType hash = skein.getHash();
    
    // Apply Keccak-1024
    NexusKeccak keccak(hash);
    keccak.calculateHash();
    NexusKeccak::k_1024 keccakFullHash_i = keccak.getHashResult();
    keccakFullHash_i.isBigInt = true;
    uint1k keccakFullHash("0x" + keccakFullHash_i.toHexString(true));
    
    return keccakFullHash;
}

} // namespace prime_worker_utils
} // namespace nexusminer

#endif // NEXUSMINER_PRIME_WORKER_UTILS_HPP
