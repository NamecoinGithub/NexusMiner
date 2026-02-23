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
 * SIGNATURE ARCHITECTURE:
 * The miner uses a SINGLE Falcon key pair (the auth key) for ALL operations:
 * 1. Authentication - Signs challenge with auth private key during handshake
 * 2. Block Submission - Signs block data with SAME auth private key
 * 3. Node Verification - Node uses auth public key (from mapSessionKeys) to verify ALL signatures
 * 
 * This ensures signature verification succeeds because signing and verifying keys match.
 * The auth key is session-specific (generated fresh for each mining session) but is 
 * used consistently throughout that session for both authentication and block signatures.
 * 
 * Optional Physical Block Signature:
 * - Signs full block data + nonce for permanent proof of authorship
 * - REMOVED: Physical Falcon has been permanently removed (overly complex, not workable)
 * - Note: Disposable Falcon signatures (for session auth) are ALWAYS ON and NOT stored on blockchain
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
    // Falcon-1024 Key Sizes (Fixed per Falcon Specification)
    //==========================================================================
    
    /** Falcon-1024 public key size (fixed) */
    constexpr size_t FALCON1024_PUBKEY_SIZE = 1793;
    
    /** Falcon-1024 private key size (fixed) */
    constexpr size_t FALCON1024_PRIVKEY_SIZE = 2305;

    //==========================================================================
    // Falcon-512 Signature Sizes (Variable due to compression algorithm)
    //==========================================================================
    
    /** Minimum Falcon-512 signature size (typical lower bound) */
    constexpr size_t FALCON512_SIG_MIN = 600;
    
    /** Typical maximum for VARIABLE-TIME signatures (reference only)
     *  Per Falcon spec: FALCON_SIG_VARTIME_MAXSIZE(logn=9) = 752 bytes
     *  This is the maximum for variable-time signatures, but LLL-TAO uses constant-time mode. */
    constexpr size_t FALCON512_SIG_VARTIME_MAX = 752;
    
    /** Constant-Time Falcon-512 signature size (exact)
     *  Per Falcon spec: FALCON_SIG_CT_SIZE(logn=9) = 809 bytes
     *  LLL-TAO's FLKey::Sign() uses ct=1, producing exactly 809 bytes */
    constexpr size_t FALCON512_SIG_CT_SIZE = 809;
    
    /** Absolute maximum Falcon-512 signature size
     *  This is the CT size since LLL-TAO uses constant-time signing */
    constexpr size_t FALCON512_SIG_ABSOLUTE_MAX = 809;
    
    /** Legacy alias for backward compatibility */
    constexpr size_t FALCON512_SIG_MAX = FALCON512_SIG_ABSOLUTE_MAX;

    //==========================================================================
    // Falcon-1024 Signature Sizes (Variable due to compression algorithm)
    //==========================================================================
    
    /** Minimum Falcon-1024 signature size (typical lower bound) */
    constexpr size_t FALCON1024_SIG_MIN = 1100;
    
    /** Typical maximum for VARIABLE-TIME signatures (reference only)
     *  Per Falcon spec: FALCON_SIG_VARTIME_MAXSIZE(logn=10) = 1462 bytes
     *  This is the maximum for variable-time signatures, but LLL-TAO uses constant-time mode. */
    constexpr size_t FALCON1024_SIG_VARTIME_MAX = 1462;
    
    /** Constant-Time Falcon-1024 signature size (exact)
     *  Per Falcon spec: FALCON_SIG_CT_SIZE(logn=10) = 1577 bytes
     *  LLL-TAO's FLKey::Sign() uses ct=1, producing exactly 1577 bytes */
    constexpr size_t FALCON1024_SIG_CT_SIZE = 1577;
    
    /** Absolute maximum Falcon-1024 signature size
     *  This is the CT size since LLL-TAO uses constant-time signing */
    constexpr size_t FALCON1024_SIG_ABSOLUTE_MAX = 1577;
    
    /** Alias for consistency */
    constexpr size_t FALCON1024_SIG_MAX = FALCON1024_SIG_ABSOLUTE_MAX;

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
    // Full Block Size Constants (PR #65: Full Block Serialization)
    //==========================================================================
    
    /** Full Tritium block size
     *  UPDATED: Now supports blocks with transactions (up to 2MB)
     *  Previous: 216 bytes (empty Tritium block with coinbase only)
     *  Current: 2MB (maximum network block size with transactions)
     *  
     *  NOTE: Block size varies:
     *  - Empty block (coinbase only): 216 bytes
     *  - Block with transactions: up to 2MB (2,097,152 bytes)
     *  
     *  This constant defines the maximum buffer size needed for block handling.
     *  Matches LLL-TAO MAX_BLOCK_SIZE from TAO/Ledger/include/constants.h
     */
    constexpr size_t FULL_BLOCK_TRITIUM_SIZE = 2 * 1024 * 1024;  // 2,097,152 bytes (was: 216)
    
    /** Full Legacy block size
     *  UPDATED: Now supports blocks with transactions (up to 2MB)
     *  Previous: 220 bytes (empty Legacy block with coinbase only)
     *  Current: 2MB (maximum network block size with transactions)
     *  
     *  NOTE: Block size varies:
     *  - Empty block (coinbase only): 220 bytes
     *  - Block with transactions: up to 2MB (2,097,152 bytes)
     */
    constexpr size_t FULL_BLOCK_LEGACY_SIZE = 2 * 1024 * 1024;  // 2,097,152 bytes (was: 220)
    
    /** Compact block header size (Phase-2 stateless mining protocol, legacy pool format) */
    constexpr size_t COMPACT_BLOCK_HEADER_SIZE = 92;

    //==========================================================================
    // Submit Block Message (What Gets Signed)
    //==========================================================================
    
    /** OLD compact format size (merkle_root + nonce + timestamp)
     *  merkle_root(64) + nonce(8) + timestamp(8) = 80 bytes
     *  NOTE: Kept for reference, no longer used in SOLO mining after PR #65 */
    constexpr size_t SUBMIT_BLOCK_MESSAGE_COMPACT_SIZE = 
        MERKLE_ROOT_SIZE + NONCE_SIZE + TIMESTAMP_SIZE;  // 80 bytes
    
    /** NEW Tritium full block format (full_block + timestamp)
     *  UPDATED: Now uses 2MB max block size constant
     *  full_block(2MB max) + timestamp(8) = 2,097,160 bytes max
     *  Used for SOLO mining after PR #65 */
    constexpr size_t SUBMIT_BLOCK_MESSAGE_TRITIUM_SIZE = 
        FULL_BLOCK_TRITIUM_SIZE + TIMESTAMP_SIZE;  // 2,097,160 bytes max (was: 224)
    
    /** NEW Legacy full block format (full_block + timestamp)
     *  UPDATED: Now uses 2MB max block size constant
     *  full_block(2MB max) + timestamp(8) = 2,097,160 bytes max
     *  Used for SOLO mining after PR #65 */
    constexpr size_t SUBMIT_BLOCK_MESSAGE_LEGACY_SIZE = 
        FULL_BLOCK_LEGACY_SIZE + TIMESTAMP_SIZE;  // 2,097,160 bytes max (was: 228)
    
    /** Legacy alias for backward compatibility (deprecated, use SUBMIT_BLOCK_MESSAGE_TRITIUM_SIZE) */
    constexpr size_t SUBMIT_BLOCK_MESSAGE_SIZE = SUBMIT_BLOCK_MESSAGE_COMPACT_SIZE;  // 80 bytes (old)

    //==========================================================================
    // Submit Block Wrapper Sizes (Serialized Transmission)
    //==========================================================================
    
    /** Submit Block wrapper - Tritium LOCALHOST (no encryption)
     *  UPDATED: Now supports 2MB blocks with transactions
     *  Format: [block(2MB max)][timestamp(8)][sig_len(2)][signature(809 max)]
     *  Calculation: 2,097,152 + 8 + 2 + 809 = 2,097,971 bytes
     *  Previous: 1,035 bytes (216-byte empty block)
     */
    constexpr size_t SUBMIT_BLOCK_WRAPPER_TRITIUM_MAX = 
        FULL_BLOCK_TRITIUM_SIZE + TIMESTAMP_SIZE + 
        LENGTH_FIELD_SIZE + FALCON512_SIG_ABSOLUTE_MAX;  // 2,097,971 bytes (was: 1,035)
    static_assert(SUBMIT_BLOCK_WRAPPER_TRITIUM_MAX == 2097971, "SUBMIT_BLOCK_WRAPPER_TRITIUM_MAX size calculation mismatch");
    
    /** Submit Block wrapper - Tritium PUBLIC MINER (with ChaCha20 encryption)
     *  UPDATED: Now supports 2MB blocks with transactions
     *  ChaCha20-Poly1305 overhead: nonce(12) + auth_tag(16) = 28 bytes
     *  Calculation: 2,097,971 + 28 = 2,097,999 bytes
     *  Previous: 1,063 bytes
     */
    constexpr size_t SUBMIT_BLOCK_WRAPPER_TRITIUM_ENCRYPTED_MAX = 
        SUBMIT_BLOCK_WRAPPER_TRITIUM_MAX + CHACHA20_OVERHEAD;  // 2,097,999 bytes (was: 1,063)
    static_assert(SUBMIT_BLOCK_WRAPPER_TRITIUM_ENCRYPTED_MAX == 2097999, "SUBMIT_BLOCK_WRAPPER_TRITIUM_ENCRYPTED_MAX size calculation mismatch");
    
    /** Submit Block wrapper - Legacy LOCALHOST (no encryption)
     *  UPDATED: Now supports 2MB blocks with transactions
     *  Calculation: 2,097,152 + 8 + 2 + 809 = 2,097,971 bytes
     *  Previous: 1,039 bytes (220-byte empty block)
     */
    constexpr size_t SUBMIT_BLOCK_WRAPPER_LEGACY_MAX = 
        FULL_BLOCK_LEGACY_SIZE + TIMESTAMP_SIZE + 
        LENGTH_FIELD_SIZE + FALCON512_SIG_ABSOLUTE_MAX;  // 2,097,971 bytes (was: 1,039)
    static_assert(SUBMIT_BLOCK_WRAPPER_LEGACY_MAX == 2097971, "SUBMIT_BLOCK_WRAPPER_LEGACY_MAX size calculation mismatch");
    
    /** Submit Block wrapper - Legacy PUBLIC MINER (with ChaCha20 encryption)
     *  UPDATED: Now supports 2MB blocks with transactions
     *  Calculation: 2,097,971 + 28 = 2,097,999 bytes
     *  Previous: 1,067 bytes
     */
    constexpr size_t SUBMIT_BLOCK_WRAPPER_LEGACY_ENCRYPTED_MAX = 
        SUBMIT_BLOCK_WRAPPER_LEGACY_MAX + CHACHA20_OVERHEAD;  // 2,097,999 bytes (was: 1,067)
    static_assert(SUBMIT_BLOCK_WRAPPER_LEGACY_ENCRYPTED_MAX == 2097999, "SUBMIT_BLOCK_WRAPPER_LEGACY_ENCRYPTED_MAX size calculation mismatch");
    
    /** Legacy aliases for backward compatibility (point to Tritium values) */
    constexpr size_t SUBMIT_BLOCK_WRAPPER_MAX = SUBMIT_BLOCK_WRAPPER_TRITIUM_MAX;
    constexpr size_t SUBMIT_BLOCK_WRAPPER_ENCRYPTED_MAX = SUBMIT_BLOCK_WRAPPER_TRITIUM_ENCRYPTED_MAX;

    //==========================================================================
    // Authentication Response Sizes
    //==========================================================================
    
    /** Auth response - LOCALHOST (no encryption on pubkey)
     *  pubkey_len(2) + pubkey(897) + timestamp(8) + sig_len(2) + sig(809) = 1718 bytes */
    constexpr size_t AUTH_RESPONSE_MAX = 
        LENGTH_FIELD_SIZE + FALCON512_PUBKEY_SIZE + TIMESTAMP_SIZE + 
        LENGTH_FIELD_SIZE + FALCON512_SIG_ABSOLUTE_MAX;  // 1718 bytes
    static_assert(AUTH_RESPONSE_MAX == 1718, "AUTH_RESPONSE_MAX size calculation mismatch");
    
    /** Auth response - PUBLIC MINER (ChaCha20 wrapped pubkey)
     *  pubkey_len(2) + wrapped_pubkey(897+28) + timestamp(8) + sig_len(2) + sig(809) = 1746 bytes */
    constexpr size_t AUTH_RESPONSE_ENCRYPTED_MAX = 
        LENGTH_FIELD_SIZE + FALCON512_PUBKEY_SIZE + CHACHA20_OVERHEAD + 
        TIMESTAMP_SIZE + LENGTH_FIELD_SIZE + FALCON512_SIG_ABSOLUTE_MAX;  // 1746 bytes
    static_assert(AUTH_RESPONSE_ENCRYPTED_MAX == 1746, "AUTH_RESPONSE_ENCRYPTED_MAX size calculation mismatch");
    
    /** Auth response with optional GenesisHash binding
     *  Add 32 bytes for Tritium genesis hash */
    constexpr size_t AUTH_RESPONSE_WITH_GENESIS_MAX = 
        AUTH_RESPONSE_ENCRYPTED_MAX + GENESIS_HASH_SIZE;  // 1778 bytes
    static_assert(AUTH_RESPONSE_WITH_GENESIS_MAX == 1778, "AUTH_RESPONSE_WITH_GENESIS_MAX size calculation mismatch");

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
    // Physical Block Signature (Stored on Blockchain - Optional Enhanced Validation)
    //==========================================================================
    
    /** Physical block signature - signs full block data + nonce
     *  NOTE: Physical Falcon has been permanently removed (overly complex, not workable).
     *  These constants are retained for reference only.
     *  
     *  NOTE: This is different from Disposable Falcon signatures which are ALWAYS ON
     *  for session authentication but NOT stored on blockchain (0 bytes overhead).
     *  
     *  Uses the SAME auth key as block submission signatures (not a separate key).
     *  The Physical Block Signature signs the FULL block data which can be up to
     *  MAX_BLOCK_SIZE (2MB), whereas the block submission signature signs a fixed
     *  80-byte message (merkle + nonce + timestamp).
     *  
     *  Message format: [block_data (variable, up to MAX_BLOCK_SIZE)] + [nonce (8 bytes LE)]
     *  Signature: Falcon-512 (~600-809 bytes)
     *  
     *  This provides enhanced validation for proving block authorship with the same
     *  auth key used throughout the mining session.
     */
    
    /** Minimum physical block signature size */
    constexpr size_t PHYSICAL_BLOCK_SIG_MIN = FALCON512_SIG_MIN;  // 600 bytes
    
    /** Maximum physical block signature size */
    constexpr size_t PHYSICAL_BLOCK_SIG_MAX = FALCON512_SIG_ABSOLUTE_MAX;  // 809 bytes
    
    /** Maximum message size for physical block signature
     *  block_data (up to 2,097,152 bytes) + nonce (8 bytes) = 2,097,160 bytes total */
    constexpr size_t PHYSICAL_BLOCK_SIG_MESSAGE_MAX = MAX_BLOCK_SIZE + NONCE_SIZE;
    
    /** Physical block signature overhead added to block transmission
     *  sig_len(2) + signature(809) = 811 bytes max */
    constexpr size_t PHYSICAL_BLOCK_SIG_OVERHEAD = LENGTH_FIELD_SIZE + FALCON512_SIG_ABSOLUTE_MAX;  // 811 bytes
    
    /** Minimum block submission size with physical signature
     *  Smallest valid block header + sig overhead */
    constexpr size_t BLOCK_WITH_PHYSICAL_SIG_MIN_OVERHEAD = PHYSICAL_BLOCK_SIG_OVERHEAD;  // 811 bytes
    
    /** Check if physical block signature size is valid */
    constexpr bool is_valid_physical_block_sig_size(size_t size) {
        return size >= PHYSICAL_BLOCK_SIG_MIN && size <= PHYSICAL_BLOCK_SIG_MAX;
    }

    //==========================================================================
    // Dual-Signature Submit Block (Block Submission + Physical Combined)
    //==========================================================================
    
    /** Submit Block with BOTH signatures - Tritium LOCALHOST (no encryption)
     *  UPDATED: Now supports 2MB blocks with transactions
     *  Combines block submission signature + physical signature overhead
     *  Used when both session authentication AND permanent proof are required.
     *  Both signatures use the SAME auth key (not separate keys).
     *  Calculation: wrapper(2,097,971) + physical_sig_overhead(811) = 2,098,782 bytes
     *  Previous: 1,846 bytes (216-byte empty block)
     */
    constexpr size_t SUBMIT_BLOCK_DUAL_SIG_TRITIUM_MAX = 
        SUBMIT_BLOCK_WRAPPER_TRITIUM_MAX + PHYSICAL_BLOCK_SIG_OVERHEAD;  // 2,098,782 bytes (was: 1,846)
    static_assert(SUBMIT_BLOCK_DUAL_SIG_TRITIUM_MAX == 2098782, "SUBMIT_BLOCK_DUAL_SIG_TRITIUM_MAX size calculation mismatch");
    
    /** Submit Block with BOTH signatures - Tritium PUBLIC MINER (with ChaCha20 encryption)
     *  UPDATED: Now supports 2MB blocks with transactions
     *  Dual-signature submission with encryption overhead
     *  Calculation: dual_sig(2,098,782) + chacha20_overhead(28) = 2,098,810 bytes
     *  Previous: 1,874 bytes
     */
    constexpr size_t SUBMIT_BLOCK_DUAL_SIG_TRITIUM_ENCRYPTED_MAX = 
        SUBMIT_BLOCK_DUAL_SIG_TRITIUM_MAX + CHACHA20_OVERHEAD;  // 2,098,810 bytes (was: 1,874)
    static_assert(SUBMIT_BLOCK_DUAL_SIG_TRITIUM_ENCRYPTED_MAX == 2098810, "SUBMIT_BLOCK_DUAL_SIG_TRITIUM_ENCRYPTED_MAX size calculation mismatch");
    
    /** Submit Block with BOTH signatures - Legacy LOCALHOST (no encryption)
     *  UPDATED: Now supports 2MB blocks with transactions
     *  Calculation: wrapper(2,097,971) + physical_sig_overhead(811) = 2,098,782 bytes
     *  Previous: 1,850 bytes (220-byte empty block)
     */
    constexpr size_t SUBMIT_BLOCK_DUAL_SIG_LEGACY_MAX = 
        SUBMIT_BLOCK_WRAPPER_LEGACY_MAX + PHYSICAL_BLOCK_SIG_OVERHEAD;  // 2,098,782 bytes (was: 1,850)
    static_assert(SUBMIT_BLOCK_DUAL_SIG_LEGACY_MAX == 2098782, "SUBMIT_BLOCK_DUAL_SIG_LEGACY_MAX size calculation mismatch");
    
    /** Submit Block with BOTH signatures - Legacy PUBLIC MINER (with ChaCha20 encryption)
     *  UPDATED: Now supports 2MB blocks with transactions
     *  Calculation: dual_sig(2,098,782) + chacha20_overhead(28) = 2,098,810 bytes
     *  Previous: 1,878 bytes
     */
    constexpr size_t SUBMIT_BLOCK_DUAL_SIG_LEGACY_ENCRYPTED_MAX = 
        SUBMIT_BLOCK_DUAL_SIG_LEGACY_MAX + CHACHA20_OVERHEAD;  // 2,098,810 bytes (was: 1,878)
    static_assert(SUBMIT_BLOCK_DUAL_SIG_LEGACY_ENCRYPTED_MAX == 2098810, "SUBMIT_BLOCK_DUAL_SIG_LEGACY_ENCRYPTED_MAX size calculation mismatch");
    
    /** Legacy aliases for backward compatibility (point to Tritium values) */
    constexpr size_t SUBMIT_BLOCK_DUAL_SIG_MAX = SUBMIT_BLOCK_DUAL_SIG_TRITIUM_MAX;
    constexpr size_t SUBMIT_BLOCK_DUAL_SIG_ENCRYPTED_MAX = SUBMIT_BLOCK_DUAL_SIG_TRITIUM_ENCRYPTED_MAX;

    //==========================================================================
    // Validation Helpers
    //==========================================================================
    
    /** Check if signature size is within valid Falcon-512 or Falcon-1024 range */
    constexpr bool is_valid_signature_size(size_t size) {
        return (size >= FALCON512_SIG_MIN && size <= FALCON512_SIG_ABSOLUTE_MAX) ||
               (size >= FALCON1024_SIG_MIN && size <= FALCON1024_SIG_ABSOLUTE_MAX);
    }
    
    /** Check if public key size matches Falcon-512 or Falcon-1024 */
    constexpr bool is_valid_pubkey_size(size_t size) {
        return size == FALCON512_PUBKEY_SIZE || size == FALCON1024_PUBKEY_SIZE;
    }
    
    /** Check if private key size matches Falcon-512 or Falcon-1024 */
    constexpr bool is_valid_privkey_size(size_t size) {
        return size == FALCON512_PRIVKEY_SIZE || size == FALCON1024_PRIVKEY_SIZE;
    }

} // namespace FalconConstants

} // namespace protocol
} // namespace nexusminer

#endif // NEXUSMINER_PROTOCOL_FALCON_CONSTANTS_HPP
