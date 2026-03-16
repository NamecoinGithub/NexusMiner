#ifndef NEXUSMINER_PROTOCOL_PACKET_CRYPTO_CONSTANTS_HPP
#define NEXUSMINER_PROTOCOL_PACKET_CRYPTO_CONSTANTS_HPP

#include <cstddef>

namespace nexusminer {
namespace protocol {
namespace packet_crypto_constants {

constexpr const char* PROTOCOL_VERSION_TAG = "nexusminer-transport-crypto-v1";
constexpr std::size_t CHACHA20_KEY_LENGTH = 32;
constexpr std::size_t CHACHA20_NONCE_LENGTH = 12;
constexpr std::size_t CHACHA20_AUTH_TAG_LENGTH = 16;
constexpr std::size_t CHACHA20_AEAD_OVERHEAD =
    CHACHA20_NONCE_LENGTH + CHACHA20_AUTH_TAG_LENGTH;

} // namespace packet_crypto_constants
} // namespace protocol
} // namespace nexusminer

#endif // NEXUSMINER_PROTOCOL_PACKET_CRYPTO_CONSTANTS_HPP
