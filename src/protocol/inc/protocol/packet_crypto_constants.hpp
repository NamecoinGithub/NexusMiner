#ifndef NEXUSMINER_PROTOCOL_PACKET_CRYPTO_CONSTANTS_HPP
#define NEXUSMINER_PROTOCOL_PACKET_CRYPTO_CONSTANTS_HPP

#include <cstddef>
#include <cstdint>

namespace nexusminer {
namespace protocol {
namespace packet_crypto_constants {

constexpr const char* PROTOCOL_VERSION_TAG = "nexusminer-transport-crypto-v1";
constexpr std::size_t CHACHA20_KEY_LENGTH = 32;
constexpr std::size_t CHACHA20_NONCE_LENGTH = 12;
constexpr std::size_t CHACHA20_AUTH_TAG_LENGTH = 16;
constexpr std::size_t CHACHA20_AEAD_OVERHEAD =
    CHACHA20_NONCE_LENGTH + CHACHA20_AUTH_TAG_LENGTH;

constexpr std::size_t LEGACY_FRAME_NONCE_BYTES = CHACHA20_NONCE_LENGTH;
constexpr std::size_t LEGACY_FRAME_TAG_BYTES = CHACHA20_AUTH_TAG_LENGTH;
constexpr std::size_t LEGACY_FRAME_FIXED_OVERHEAD =
    LEGACY_FRAME_NONCE_BYTES + LEGACY_FRAME_TAG_BYTES;

constexpr std::uint8_t EVP_FRAME_VERSION = 1;
constexpr std::uint8_t EVP_FLAG_SESSION_BOUND = 0x01;
constexpr std::size_t EVP_FRAME_VERSION_BYTES = 1;
constexpr std::size_t EVP_FRAME_FLAGS_BYTES = 1;
// SessionID wire width is fixed to uint32 little-endian.
constexpr std::size_t EVP_FRAME_SESSION_ID_BYTES = 4;
// Session epoch and generation IDs are fixed to uint64 little-endian.
constexpr std::size_t EVP_FRAME_SESSION_EPOCH_BYTES = 8;
constexpr std::size_t EVP_FRAME_GENERATION_BYTES = 8;
constexpr std::size_t EVP_FRAME_HEADER_BYTES =
    EVP_FRAME_VERSION_BYTES + EVP_FRAME_FLAGS_BYTES +
    EVP_FRAME_SESSION_ID_BYTES + EVP_FRAME_SESSION_EPOCH_BYTES +
    EVP_FRAME_GENERATION_BYTES;
constexpr std::size_t EVP_FRAME_SESSION_ID_OFFSET = 2;
constexpr std::size_t EVP_FRAME_SESSION_EPOCH_OFFSET =
    EVP_FRAME_SESSION_ID_OFFSET + EVP_FRAME_SESSION_ID_BYTES;
constexpr std::size_t EVP_FRAME_GENERATION_OFFSET =
    EVP_FRAME_SESSION_EPOCH_OFFSET + EVP_FRAME_SESSION_EPOCH_BYTES;
constexpr std::size_t EVP_FRAME_NONCE_OFFSET = EVP_FRAME_HEADER_BYTES;
constexpr std::size_t EVP_FRAME_FIXED_OVERHEAD =
    EVP_FRAME_HEADER_BYTES + CHACHA20_NONCE_LENGTH + CHACHA20_AUTH_TAG_LENGTH;

} // namespace packet_crypto_constants
} // namespace protocol
} // namespace nexusminer

#endif // NEXUSMINER_PROTOCOL_PACKET_CRYPTO_CONSTANTS_HPP
