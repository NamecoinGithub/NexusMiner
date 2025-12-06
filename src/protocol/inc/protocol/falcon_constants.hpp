#ifndef NEXUSMINER_PROTOCOL_FALCON_CONSTANTS_HPP
#define NEXUSMINER_PROTOCOL_FALCON_CONSTANTS_HPP

#include <cstddef>
#include <cstdint>

namespace nexusminer {
namespace protocol {

/**
 * @brief Falcon-512 and Protocol Constants for Stateless Mining
 * 
 * These constants define size limits for the Falcon signature protocol
 * used in NexusMiner ↔ LLL-TAO Node communication.
 * 
 * IMPORTANT: All multi-byte integer fields use LITTLE-ENDIAN byte order
 * for consistency with the rest of the protocol (nonce, timestamp, etc.)
 * 
 * DUAL SIGNATURE ARCHITECTURE:
 * 1. Disposable Falcon Wrapper - Signs fixed 80-byte message (merkle + nonce + timestamp)
 *    for session authentication. NOT stored on blockchain. Always enabled.
 * 2. Physical Block Signature - Signs full block data + nonce for permanent proof
 *    of authorship. STORED on blockchain. Enabled via "enable_block_signing": true.
 *    This is the emergency backup system.
 * 
 * References:
 * - LLL-TAO: src/LLC/falcon/falcon.h (FALCON_SIG_VARTIME_MAXSIZE)
 * - LLL-TAO: src/TAO/Ledger/include/constants.h (MAX_BLOCK_SIZE)
 * - LLL-TAO: src/LLP/disposable_falcon.cpp (SignedWorkSubmission format)
 */
namespace FalconConstants {

    //==========================================================================
    // Falcon-512 Key Sizes (Fixed per Falcon Specification)
    //==========================================================================
    
    /** Falcon-512 public key size (fixed) */
    constexpr size_t FALCON512_PUBKEY_SIZE = 897;
    
    /** Falcon-512 private key size (fixed) */
    constexpr size_t FALCON512_PRIVKEY_SIZE = 1281;

    //==========================================================================
    // Falcon-512 Signature Sizes (Variable due to compression algorithm)
    //==========================================================================
    
    /** Minimum Falcon-512 signature size (typical lower bound) */
    constexpr size_t FALCON512_SIG_MIN = 600;
    
    /** Typical maximum for authentication signatures (address + timestamp)
     *  Most authentication signatures fall within 617-690 bytes.
     *  This constant represents a conservative upper bound for auth use cases. */
    constexpr size_t FALCON512_SIG_AUTH_MAX = 700;
    
    /** Absolute maximum Falcon-512 signature size
     *  Per Falcon spec: FALCON_SIG_VARTIME_MAXSIZE(logn=9) = 752 bytes
     *  This covers ALL possible Falcon-512 signatures regardless of message */
    constexpr size_t FALCON512_SIG_ABSOLUTE_MAX = 752;
    
    /** Legacy alias for backward compatibility */
    constexpr size_t FALCON512_SIG_MAX = FALCON512_SIG_ABSOLUTE_MAX;

    //==========================================================================
    // ChaCha20-Poly1305 AEAD Encryption Constants
    //==========================================================================
    
    /** ChaCha20-Poly1305 nonce size (prepended to ciphertext) */
    constexpr size_t CHACHA20_NONCE_SIZE = 12;
    
    /** ChaCha20-Poly1305 authentication tag size (appended to ciphertext) */
    constexpr size_t CHACHA20_AUTH_TAG_SIZE = 16;
    
    /** Total ChaCha20-Poly1305 overhead (nonce + auth tag) */
    constexpr size_t CHACHA20_OVERHEAD = CHACHA20_NONCE_SIZE + CHACHA20_AUTH_TAG_SIZE;  // 28 bytes

    //==========================================================================
    // Protocol Field Sizes
    //==========================================================================
    
    /** Merkle root size (uint512_t) */
    constexpr size_t MERKLE_ROOT_SIZE = 64;
    
    /** Nonce size (uint64_t, little-endian) */
    constexpr size_t NONCE_SIZE = 8;
    
    /** Timestamp size (uint64_t, little-endian) */
    constexpr size_t TIMESTAMP_SIZE = 8;
    
    /** Length field size for variable-length fields (2 bytes, little-endian) */
    constexpr size_t LENGTH_FIELD_SIZE = 2;
    
    /** Tritium GenesisHash size (uint256_t) */
    constexpr size_t GENESIS_HASH_SIZE = 32;

    //==========================================================================
    // Submit Block Message (What Gets Signed - Fixed Size)
    //==========================================================================
    
    /** Size of the message signed in Submit Block wrapper
     *  merkle_root(64) + nonce(8) + timestamp(8) = 80 bytes
     *  NOTE: This is FIXED regardless of actual block size */
    constexpr size_t SUBMIT_BLOCK_MESSAGE_SIZE = 
        MERKLE_ROOT_SIZE + NONCE_SIZE + TIMESTAMP_SIZE;  // 80 bytes

    //==========================================================================
    // Submit Block Wrapper Sizes (Serialized Transmission)
    //==========================================================================
    
    /** Submit Block wrapper - LOCALHOST (no encryption)
     *  merkle(64) + nonce(8) + timestamp(8) + sig_len(2) + sig(752) = 834 bytes */
    constexpr size_t SUBMIT_BLOCK_WRAPPER_MAX = 
        MERKLE_ROOT_SIZE + NONCE_SIZE + TIMESTAMP_SIZE + 
        LENGTH_FIELD_SIZE + FALCON512_SIG_ABSOLUTE_MAX;  // 834 bytes
    static_assert(SUBMIT_BLOCK_WRAPPER_MAX == 834, "SUBMIT_BLOCK_WRAPPER_MAX size calculation mismatch");
    
    /** Submit Block wrapper - PUBLIC MINER (with ChaCha20 encryption)
     *  nonce(12) + encrypted_payload(834) + auth_tag(16) = 862 bytes */
    constexpr size_t SUBMIT_BLOCK_WRAPPER_ENCRYPTED_MAX = 
        SUBMIT_BLOCK_WRAPPER_MAX + CHACHA20_OVERHEAD;  // 862 bytes
    static_assert(SUBMIT_BLOCK_WRAPPER_ENCRYPTED_MAX == 862, "SUBMIT_BLOCK_WRAPPER_ENCRYPTED_MAX size calculation mismatch");

    //==========================================================================
    // Authentication Response Sizes
    //==========================================================================
    
    /** Auth response - LOCALHOST (no encryption on pubkey)
     *  pubkey_len(2) + pubkey(897) + timestamp(8) + sig_len(2) + sig(752) = 1661 bytes */
    constexpr size_t AUTH_RESPONSE_MAX = 
        LENGTH_FIELD_SIZE + FALCON512_PUBKEY_SIZE + TIMESTAMP_SIZE + 
        LENGTH_FIELD_SIZE + FALCON512_SIG_ABSOLUTE_MAX;  // 1661 bytes
    static_assert(AUTH_RESPONSE_MAX == 1661, "AUTH_RESPONSE_MAX size calculation mismatch");
    
    /** Auth response - PUBLIC MINER (ChaCha20 wrapped pubkey)
     *  pubkey_len(2) + wrapped_pubkey(897+28) + timestamp(8) + sig_len(2) + sig(752) = 1689 bytes */
    constexpr size_t AUTH_RESPONSE_ENCRYPTED_MAX = 
        LENGTH_FIELD_SIZE + FALCON512_PUBKEY_SIZE + CHACHA20_OVERHEAD + 
        TIMESTAMP_SIZE + LENGTH_FIELD_SIZE + FALCON512_SIG_ABSOLUTE_MAX;  // 1689 bytes
    static_assert(AUTH_RESPONSE_ENCRYPTED_MAX == 1689, "AUTH_RESPONSE_ENCRYPTED_MAX size calculation mismatch");
    
    /** Auth response with optional GenesisHash binding
     *  Add 32 bytes for Tritium genesis hash */
    constexpr size_t AUTH_RESPONSE_WITH_GENESIS_MAX = 
        AUTH_RESPONSE_ENCRYPTED_MAX + GENESIS_HASH_SIZE;  // 1721 bytes
    static_assert(AUTH_RESPONSE_WITH_GENESIS_MAX == 1721, "AUTH_RESPONSE_WITH_GENESIS_MAX size calculation mismatch");

    //==========================================================================
    // Block Size Limits (Mirrored from LLL-TAO TAO::Ledger::constants.h)
    //==========================================================================
    
    /** Maximum block size in transit (2 MB) */
    constexpr uint32_t MAX_BLOCK_SIZE = 1024 * 1024 * 2;  // 2,097,152 bytes
    
    /** Maximum block size for generation (~1 MB) */
    constexpr uint32_t MAX_BLOCK_SIZE_GEN = 1000000;  // 1,000,000 bytes
    
    /** Maximum contracts per transaction */
    constexpr uint32_t MAX_TRANSACTION_CONTRACTS = 100;

    //==========================================================================
    // Physical Block Signature (Stored on Blockchain - Emergency Backup System)
    //==========================================================================
    
    /** Physical block signature - signs full block data + nonce
     *  This signature IS stored on the blockchain for permanent proof of authorship.
     *  Enabled via config: "enable_block_signing": true
     *  
     *  Unlike the Disposable Falcon wrapper (which signs a fixed 80-byte message),
     *  the Physical Block Signature signs the FULL block data which can be up to
     *  MAX_BLOCK_SIZE (2MB).
     *  
     *  Message format: [block_data (variable, up to MAX_BLOCK_SIZE)] + [nonce (8 bytes LE)]
     *  Signature: Falcon-512 (~600-752 bytes)
     *  
     *  This is the emergency backup system for proving block authorship when
     *  the Disposable Falcon session authentication is insufficient.
     */
    
    /** Minimum physical block signature size */
    constexpr size_t PHYSICAL_BLOCK_SIG_MIN = FALCON512_SIG_MIN;  // 600 bytes
    
    /** Maximum physical block signature size */
    constexpr size_t PHYSICAL_BLOCK_SIG_MAX = FALCON512_SIG_ABSOLUTE_MAX;  // 752 bytes
    
    /** Maximum message size for physical block signature
     *  block_data (up to 2,097,152 bytes) + nonce (8 bytes) = 2,097,160 bytes total */
    constexpr size_t PHYSICAL_BLOCK_SIG_MESSAGE_MAX = MAX_BLOCK_SIZE + NONCE_SIZE;
    
    /** Physical block signature overhead added to block transmission
     *  sig_len(2) + signature(752) = 754 bytes max */
    constexpr size_t PHYSICAL_BLOCK_SIG_OVERHEAD = LENGTH_FIELD_SIZE + FALCON512_SIG_ABSOLUTE_MAX;  // 754 bytes
    
    /** Minimum block submission size with physical signature
     *  Smallest valid block header + sig overhead */
    constexpr size_t BLOCK_WITH_PHYSICAL_SIG_MIN_OVERHEAD = PHYSICAL_BLOCK_SIG_OVERHEAD;  // 754 bytes
    
    /** Check if physical block signature size is valid */
    constexpr bool is_valid_physical_block_sig_size(size_t size) {
        return size >= PHYSICAL_BLOCK_SIG_MIN && size <= PHYSICAL_BLOCK_SIG_MAX;
    }

    //==========================================================================
    // Dual-Signature Submit Block (Disposable + Physical Combined)
    //==========================================================================
    
    /** Submit Block with BOTH signatures - LOCALHOST (no encryption)
     *  Combines disposable wrapper (834) + physical signature overhead (754)
     *  Used when both session authentication AND permanent proof are required.
     *  wrapper(834) + physical_sig_overhead(754) = 1,588 bytes */
    constexpr size_t SUBMIT_BLOCK_DUAL_SIG_MAX = 
        SUBMIT_BLOCK_WRAPPER_MAX + PHYSICAL_BLOCK_SIG_OVERHEAD;  // 1,588 bytes
    static_assert(SUBMIT_BLOCK_DUAL_SIG_MAX == 1588, "SUBMIT_BLOCK_DUAL_SIG_MAX size calculation mismatch");
    
    /** Submit Block with BOTH signatures - PUBLIC MINER (with ChaCha20 encryption)
     *  Dual-signature submission with encryption overhead
     *  dual_sig(1588) + chacha20_overhead(28) = 1,616 bytes */
    constexpr size_t SUBMIT_BLOCK_DUAL_SIG_ENCRYPTED_MAX = 
        SUBMIT_BLOCK_DUAL_SIG_MAX + CHACHA20_OVERHEAD;  // 1,616 bytes
    static_assert(SUBMIT_BLOCK_DUAL_SIG_ENCRYPTED_MAX == 1616, "SUBMIT_BLOCK_DUAL_SIG_ENCRYPTED_MAX size calculation mismatch");

    //==========================================================================
    // Validation Helpers
    //==========================================================================
    
    /** Check if signature size is within valid Falcon-512 range */
    constexpr bool is_valid_signature_size(size_t size) {
        return size >= FALCON512_SIG_MIN && size <= FALCON512_SIG_ABSOLUTE_MAX;
    }
    
    /** Check if public key size matches Falcon-512 */
    constexpr bool is_valid_pubkey_size(size_t size) {
        return size == FALCON512_PUBKEY_SIZE;
    }
    
    /** Check if private key size matches Falcon-512 */
    constexpr bool is_valid_privkey_size(size_t size) {
        return size == FALCON512_PRIVKEY_SIZE;
    }

} // namespace FalconConstants

} // namespace protocol
} // namespace nexusminer

#endif // NEXUSMINER_PROTOCOL_FALCON_CONSTANTS_HPP
