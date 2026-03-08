#ifndef NEXUSMINER_PROTOCOL_SUBMIT_BLOCK_PAYLOAD_INFO_HPP
#define NEXUSMINER_PROTOCOL_SUBMIT_BLOCK_PAYLOAD_INFO_HPP

/**
 * @file submit_block_payload_info.hpp
 * @brief Canonical SubmitBlockPayloadInfo struct for channel-aware SUBMIT_BLOCK sizing.
 *
 * This lightweight header is the single canonical definition of
 * SubmitBlockPayloadInfo.  Both stateless_block_utility.hpp and
 * chacha20_wrapper.hpp include it so they share the same type without a
 * circular dependency.
 */

#include <cstdint>
#include <cstddef>

namespace nexusminer {
namespace protocol {

/**
 * @brief Channel-aware payload metadata for SUBMIT_BLOCK sizing.
 *
 * Computes expected plaintext and encrypted sizes from real inputs rather
 * than assuming a universal fixed Tritium payload size.
 *
 * For **signed** submissions (Falcon wrapper active):
 *   Hash:   plaintext = base_block_size + timestamp_size + sig_len_field_size + signature_size
 *   Prime:  plaintext = base_block_size + offset_bytes_count + timestamp_size + sig_len_field_size + signature_size
 *   encrypted = plaintext + CHACHA20_OVERHEAD (nonce 12 + tag 16 = 28)
 *
 * For unsigned submissions (falcon == nullptr), the actual plaintext is just
 * base_block_size (Hash) or base_block_size + offset_bytes_count (Prime),
 * without timestamp/sig fields.  In that case set signature_size = 0 and note
 * that expected_plaintext_size() will include the timestamp + sig_len overhead
 * of 10 bytes even though they are absent; callers should check the actual
 * plaintext size directly for unsigned payloads.
 */
struct SubmitBlockPayloadInfo
{
    uint32_t channel{0};              ///< 1 = Prime, 2 = Hash
    size_t   base_block_size{0};      ///< 216 for Tritium (empty block body)
    size_t   offset_bytes_count{0};   ///< 0 for Hash, variable for Prime (vOffsets.size())
    size_t   timestamp_size{8};       ///< always 8 (uint64_t LE)
    size_t   sig_len_field_size{2};   ///< always 2 (uint16_t LE)
    size_t   signature_size{0};       ///< parsed/actual Falcon signature length

    /// ChaCha20-Poly1305 overhead: nonce(12) + auth_tag(16)
    static constexpr size_t CHACHA20_OVERHEAD = 28;

    /// Expected plaintext size: block + offsets + timestamp + sig_len + sig
    size_t expected_plaintext_size() const {
        return base_block_size + offset_bytes_count
             + timestamp_size + sig_len_field_size + signature_size;
    }

    /// Expected encrypted size: plaintext + ChaCha20 overhead
    size_t expected_encrypted_size() const {
        return expected_plaintext_size() + CHACHA20_OVERHEAD;
    }
};

} // namespace protocol
} // namespace nexusminer

#endif // NEXUSMINER_PROTOCOL_SUBMIT_BLOCK_PAYLOAD_INFO_HPP
