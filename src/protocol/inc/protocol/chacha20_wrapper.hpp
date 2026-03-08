#ifndef NEXUSMINER_PROTOCOL_CHACHA20_WRAPPER_HPP
#define NEXUSMINER_PROTOCOL_CHACHA20_WRAPPER_HPP

#include <vector>
#include <cstdint>
#include <string>
#include <memory>
#include "spdlog/spdlog.h"

namespace nexusminer {
namespace protocol {

/**
 * @brief ChaCha20 Encryption Wrapper for Falcon Public Key Protection
 * 
 * This class provides ChaCha20 encryption for protecting Falcon Public Keys
 * during the handshake process with the LLL-TAO Node. ChaCha20 encryption is:
 * - OPTIONAL for localhost mining (direct IPC communication)
 * - MANDATORY for public/remote mining (HTTPS/TLS communication)
 * 
 * The wrapper uses OpenSSL's EVP interface for ChaCha20-Poly1305 AEAD encryption.
 *
 * Canonical SUBMIT_BLOCK wire format (Tritium Falcon-1024):
 *   Hash / Prime-with-empty-offsets plaintext :
 *     [block(216)][timestamp(8 LE)][sig_len(2 LE)][Falcon-1024 sig(1577)]
 *     = 1803 bytes
 *   Prime plaintext with vOffsets :
 *     [block(216)][vOffsets(N)][timestamp(8 LE)][sig_len(2 LE)][Falcon-1024 sig(1577)]
 *     = 1803 + N bytes
 *   Encrypted :
 *     [nonce(12)][ciphertext(plaintext_size)][Poly1305 tag(16)]
 *     = plaintext_size + 28 bytes
 *
 * Use encrypt_submit_block_payload() to enforce this layout in one place.
 */
class ChaCha20Wrapper {
public:

    // =========================================================================
    // Tritium Falcon-1024 SUBMIT_BLOCK canonical wire-format constants
    // (matches LLL-TAO src/LLP/include/falcon_constants.h)
    // =========================================================================

    /** 216-byte serialised Tritium block header */
    static constexpr size_t TRITIUM_BLOCK_SIZE             = 216;
    /** Tritium Prime mining channel */
    static constexpr uint32_t CHANNEL_PRIME                = 1;
    /** Tritium Hash mining channel */
    static constexpr uint32_t CHANNEL_HASH                 = 2;
    /** Submission timestamp field (8 bytes, little-endian) */
    static constexpr size_t SUBMIT_TIMESTAMP_SIZE          = 8;
    /** Signature length field (2 bytes, little-endian) */
    static constexpr size_t SUBMIT_SIGLEN_FIELD_SIZE       = 2;
    /** Falcon-1024 constant-time signature size */
    static constexpr size_t FALCON1024_CT_SIG_SIZE         = 1577;
    /** Expected plaintext for a Falcon-1024 Tritium Hash (or Prime empty-offset) submission */
    static constexpr size_t TRITIUM_F1024_PLAINTEXT_EXPECTED =
        TRITIUM_BLOCK_SIZE + SUBMIT_TIMESTAMP_SIZE +
        SUBMIT_SIGLEN_FIELD_SIZE + FALCON1024_CT_SIG_SIZE; // 1803

    /** ChaCha20-Poly1305 nonce size (prepended to encrypted output) */
    static constexpr size_t CHACHA20_NONCE_SIZE            = 12;
    /** Poly1305 authentication tag size (appended to encrypted output) */
    static constexpr size_t CHACHA20_TAG_SIZE              = 16;
    /** Total overhead added by encrypt_submit_block_payload() */
    static constexpr size_t CHACHA20_OVERHEAD              =
        CHACHA20_NONCE_SIZE + CHACHA20_TAG_SIZE; // 28
    /** Expected encrypted output for a Falcon-1024 Tritium Hash (or Prime empty-offset) submission */
    static constexpr size_t TRITIUM_F1024_ENCRYPTED_EXPECTED =
        TRITIUM_F1024_PLAINTEXT_EXPECTED + CHACHA20_OVERHEAD; // 1831

    struct SubmitBlockPayloadInfo {
        uint32_t channel = CHANNEL_HASH;
        size_t base_block_size = TRITIUM_BLOCK_SIZE;
        size_t offset_bytes_count = 0;
        size_t timestamp_size = SUBMIT_TIMESTAMP_SIZE;
        size_t sig_len_field_size = SUBMIT_SIGLEN_FIELD_SIZE;

        constexpr size_t minimum_plaintext_size() const
        {
            return base_block_size + offset_bytes_count +
                   timestamp_size + sig_len_field_size;
        }

        constexpr bool is_prime_channel() const { return channel == CHANNEL_PRIME; }
        constexpr bool is_hash_channel() const { return channel == CHANNEL_HASH; }
    };

    static constexpr size_t compute_submit_plaintext_size(
        size_t base_block_size,
        size_t offset_bytes_count,
        size_t signature_size)
    {
        return base_block_size + offset_bytes_count +
               SUBMIT_TIMESTAMP_SIZE + SUBMIT_SIGLEN_FIELD_SIZE + signature_size;
    }

    static constexpr size_t compute_submit_encrypted_size(size_t plaintext_size)
    {
        return plaintext_size + CHACHA20_OVERHEAD;
    }

    /**
     * @brief Encryption/Decryption result structure
     */
    struct CryptoResult {
        bool success;
        std::vector<uint8_t> data;
        std::string error_message;
    };
    
    /**
     * @brief Constructor
     */
    ChaCha20Wrapper();
    
    /**
     * @brief Destructor
     */
    ~ChaCha20Wrapper();
    
    /**
     * @brief Encrypt data using ChaCha20-Poly1305
     * 
     * @param plaintext Data to encrypt
     * @param key 256-bit (32-byte) encryption key
     * @param nonce 96-bit (12-byte) nonce/IV
     * @param aad Additional authenticated data (optional)
     * @return CryptoResult containing ciphertext + tag or error
     */
    CryptoResult encrypt(const std::vector<uint8_t>& plaintext,
                        const std::vector<uint8_t>& key,
                        const std::vector<uint8_t>& nonce,
                        const std::vector<uint8_t>& aad = {});
    
    /**
     * @brief Decrypt data using ChaCha20-Poly1305
     * 
     * @param ciphertext Data to decrypt (includes 16-byte auth tag at end)
     * @param key 256-bit (32-byte) encryption key
     * @param nonce 96-bit (12-byte) nonce/IV
     * @param aad Additional authenticated data (must match encryption)
     * @return CryptoResult containing plaintext or error
     */
    CryptoResult decrypt(const std::vector<uint8_t>& ciphertext,
                        const std::vector<uint8_t>& key,
                        const std::vector<uint8_t>& nonce,
                        const std::vector<uint8_t>& aad = {});
    
    /**
     * @brief Wrap Falcon Public Key for handshake transmission
     * 
     * This is the primary use case: encrypt Falcon Public Key before sending
     * to LLL-TAO Node during initial handshake.
     * 
     * @param falcon_pubkey Falcon-512 public key (897 bytes)
     * @param session_key Derived session key for encryption
     * @param nonce Random nonce for this encryption
     * @return CryptoResult containing wrapped key or error
     */
    CryptoResult wrap_falcon_pubkey(const std::vector<uint8_t>& falcon_pubkey,
                                    const std::vector<uint8_t>& session_key,
                                    const std::vector<uint8_t>& nonce);
    
    /**
     * @brief Unwrap received Falcon Public Key (for testing/validation)
     * 
     * @param wrapped_pubkey Encrypted public key data
     * @param session_key Decryption key
     * @param nonce Nonce used during encryption
     * @return CryptoResult containing unwrapped key or error
     */
    CryptoResult unwrap_falcon_pubkey(const std::vector<uint8_t>& wrapped_pubkey,
                                      const std::vector<uint8_t>& session_key,
                                      const std::vector<uint8_t>& nonce);
    
    /**
     * @brief Build and encrypt a canonical Tritium full-block SUBMIT_BLOCK payload.
     *
     * This is the SINGLE authoritative place where the Tritium Falcon-1024
     * submit-block wire format is assembled and encrypted.  Callers supply the
     * pre-built plaintext (already containing the serialised block, timestamp,
     * sig_len field, and Falcon signature) and the session key; this method
     * validates the sizes, generates a fresh nonce, and returns:
     *
     *   [nonce(12)][ciphertext(plaintext_size)][Poly1305 tag(16)]
     *
     * Size invariants (enforced with log warnings/errors):
     *   - Hash / Prime-empty-offsets expected plaintext : 1803 bytes
     *   - Prime expected plaintext                      : 1803 + vOffsets.size()
     *   - Expected ciphertext                          : plaintext + 28
     *
     * The canonical plaintext layout (built by the caller) must be:
     *   Hash :  [block(216)][timestamp(8 LE)][sig_len(2 LE)][Falcon-1024 sig(1577)]
     *   Prime: [block(216)][vOffsets(N)][timestamp(8 LE)][sig_len(2 LE)][Falcon-1024 sig(1577)]
     *
     * AAD for SUBMIT_BLOCK is always empty ({}) — matching the node-side
     * LLC::DecryptPayloadChaCha20() call which passes no AAD.
     *
     * @param plaintext     Pre-assembled SUBMIT_BLOCK plaintext payload.
     * @param session_key   32-byte ChaCha20 session key derived at login.
     * @param payload_info  Channel-aware sizing metadata for Prime vs Hash.
     * @return CryptoResult with data=[nonce][ciphertext][tag] on success.
     */
    CryptoResult encrypt_submit_block_payload(
        const std::vector<uint8_t>& plaintext,
        const std::vector<uint8_t>& session_key,
        const SubmitBlockPayloadInfo& payload_info);

    /**
     * @brief Generate random nonce for ChaCha20
     * 
     * @return 12-byte random nonce
     */
    static std::vector<uint8_t> generate_nonce();
    
    /**
     * @brief Generate random encryption key
     * 
     * @return 32-byte random key
     */
    static std::vector<uint8_t> generate_key();
    
    /**
     * @brief Check if ChaCha20 is available in OpenSSL
     * 
     * @return true if ChaCha20-Poly1305 is supported
     */
    static bool is_available();

private:
    
    // Logger
    std::shared_ptr<spdlog::logger> m_logger;
};

} // namespace protocol
} // namespace nexusminer

#endif // NEXUSMINER_PROTOCOL_CHACHA20_WRAPPER_HPP
