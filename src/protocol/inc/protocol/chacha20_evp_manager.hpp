#ifndef NEXUSMINER_PROTOCOL_CHACHA20_EVP_MANAGER_HPP
#define NEXUSMINER_PROTOCOL_CHACHA20_EVP_MANAGER_HPP

#include "protocol/chacha20_wrapper.hpp"
#include "protocol/packet_crypto_constants.hpp"
#include "spdlog/spdlog.h"
#include <memory>

namespace nexusminer {
namespace protocol {

class ChaCha20EvpManager {
public:
    using CryptoResult = ChaCha20Wrapper::CryptoResult;

    explicit ChaCha20EvpManager(std::shared_ptr<spdlog::logger> logger = nullptr);

    bool is_available() const;

    CryptoResult encrypt(const std::vector<uint8_t>& plaintext,
                         const std::vector<uint8_t>& key,
                         const std::vector<uint8_t>& nonce,
                         const std::vector<uint8_t>& aad = {}) const;

    CryptoResult decrypt(const std::vector<uint8_t>& ciphertext_with_tag,
                         const std::vector<uint8_t>& key,
                         const std::vector<uint8_t>& nonce,
                         const std::vector<uint8_t>& aad = {}) const;

private:
    std::shared_ptr<spdlog::logger> m_logger;
};

} // namespace protocol
} // namespace nexusminer

#endif // NEXUSMINER_PROTOCOL_CHACHA20_EVP_MANAGER_HPP
