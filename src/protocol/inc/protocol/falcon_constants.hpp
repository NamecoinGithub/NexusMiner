#ifndef NEXUSMINER_PROTOCOL_FALCON_CONSTANTS_HPP
#define NEXUSMINER_PROTOCOL_FALCON_CONSTANTS_HPP

#include <cstddef>

namespace nexusminer {
namespace protocol {

/**
 * @brief Falcon-512 signature constants for validation
 * 
 * These constants define the expected size ranges for Falcon-512 signatures
 * as used in the NexusMiner authentication protocol.
 * 
 * Falcon-512 signatures are variable length due to the compression algorithm.
 * The typical range is 600-700 bytes, with most signatures falling within
 * 617-690 bytes.
 */
namespace FalconConstants {

    /**
     * Falcon-512 public key size (fixed)
     */
    constexpr size_t FALCON512_PUBKEY_SIZE = 897;
    
    /**
     * Falcon-512 private key size (fixed)
     */
    constexpr size_t FALCON512_PRIVKEY_SIZE = 1281;
    
    /**
     * Minimum expected Falcon-512 signature size
     * Using a conservative lower bound to account for natural variation
     */
    constexpr size_t FALCON512_SIG_MIN = 600;
    
    /**
     * Maximum expected Falcon-512 signature size
     * Using a conservative upper bound to account for natural variation
     */
    constexpr size_t FALCON512_SIG_MAX = 700;

} // namespace FalconConstants

} // namespace protocol
} // namespace nexusminer

#endif // NEXUSMINER_PROTOCOL_FALCON_CONSTANTS_HPP
