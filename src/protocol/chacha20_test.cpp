/**
 * @file chacha20_test.cpp
 * @brief Unit tests for ChaCha20-Poly1305 AEAD wrapper and AAD domain separation
 *
 * Validates the implementation of:
 *   - Basic encrypt/decrypt round-trip
 *   - AAD (Additional Authenticated Data) domain separation
 *   - AAD mismatch detection (Poly1305 tag failure)
 *   - Empty vs non-empty AAD behavior
 *   - Input validation (key size, nonce size, empty plaintext)
 *   - Falcon public key wrap/unwrap
 *   - Nonce uniqueness
 *   - SUBMIT_BLOCK AAD is empty {} (no domain separation, matches node behavior)
 *   - KDF domain separator consistency
 */

#include "protocol/chacha20_wrapper.hpp"
#include "protocol/falcon_constants.hpp"
#include <iostream>
#include <cstdint>
#include <vector>
#include <string>
#include <cstring>
#include <openssl/sha.h>

// Mock logger for testing
#include "spdlog/spdlog.h"
#include "spdlog/sinks/null_sink.h"
#include <gtest/gtest.h>

using namespace nexusminer::protocol;

// ═══════════════════════════════════════════════════════════════════════════
// Helper: generate deterministic test key (32 bytes)
// ═══════════════════════════════════════════════════════════════════════════
static std::vector<uint8_t> make_test_key() {
    std::vector<uint8_t> key(32, 0);
    for (size_t i = 0; i < 32; ++i)
        key[i] = static_cast<uint8_t>(i + 1);
    return key;
}

// ═══════════════════════════════════════════════════════════════════════════
// Helper: generate deterministic test nonce (12 bytes)
// ═══════════════════════════════════════════════════════════════════════════
static std::vector<uint8_t> make_test_nonce() {
    std::vector<uint8_t> nonce(12, 0);
    for (size_t i = 0; i < 12; ++i)
        nonce[i] = static_cast<uint8_t>(0xA0 + i);
    return nonce;
}

// ═══════════════════════════════════════════════════════════════════════════
// Helper: generate test plaintext of given size
// ═══════════════════════════════════════════════════════════════════════════
static std::vector<uint8_t> make_test_plaintext(size_t size) {
    std::vector<uint8_t> pt(size);
    for (size_t i = 0; i < size; ++i)
        pt[i] = static_cast<uint8_t>(i & 0xFF);
    return pt;
}

// AAD constants matching solo.cpp (these MUST stay in sync)
static const std::vector<uint8_t> AAD_FALCON_PUBKEY{
    'F','A','L','C','O','N','_','P','U','B','K','E','Y'
};

static const std::vector<uint8_t> AAD_REWARD_ADDRESS{
    'R','E','W','A','R','D','_',
    'A','D','D','R','E','S','S'
};

static const std::vector<uint8_t> AAD_REWARD_RESULT{
    'R','E','W','A','R','D','_',
    'R','E','S','U','L','T'
};

// AAD_BLOCK_SUBMISSION is intentionally empty: the node decrypts SUBMIT_BLOCK
// with no AAD (default empty vector), so the miner must also encrypt with {}.
// See: LLL-TAO stateless_miner_connection.cpp ~L1186 (no AAD argument).
static const std::vector<uint8_t> AAD_BLOCK_SUBMISSION{};

static const std::string KDF_DOMAIN = "nexus-mining-chacha20-v1";

static std::vector<uint8_t> derive_session_key_for_test(const std::vector<uint8_t>& genesis) {
    std::vector<uint8_t> preimage;
    preimage.insert(preimage.end(), KDF_DOMAIN.begin(), KDF_DOMAIN.end());
    preimage.insert(preimage.end(), genesis.begin(), genesis.end());

    std::vector<uint8_t> derived_key(SHA256_DIGEST_LENGTH);
    SHA256(preimage.data(), preimage.size(), derived_key.data());
    return derived_key;
}

static std::string format_hex_prefix(const std::vector<uint8_t>& bytes, size_t prefix_bytes) {
    static const char* const HEX = "0123456789abcdef";
    const size_t prefix_size = std::min(bytes.size(), prefix_bytes);
    std::string out;
    out.reserve(prefix_size * 2);

    for (size_t i = 0; i < prefix_size; ++i) {
        uint8_t byte = bytes[i];
        out.push_back(HEX[(byte >> 4) & 0x0F]);
        out.push_back(HEX[byte & 0x0F]);
    }

    return out;
}
