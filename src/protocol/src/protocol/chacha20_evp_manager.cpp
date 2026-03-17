/*__________________________________________________________________________________________

    Hash(BEGIN(Satoshi[2010]), END(Sunny[2012])) == Videlicet[2014]++

    (c) Copyright The Nexus Developers 2014 - 2025

    Distributed under the MIT software license, see the accompanying
    file COPYING or http://www.opensource.org/licenses/mit-license.php.

    "ad vocem populi" - To the Voice of the People

____________________________________________________________________________________________*/

#include "protocol/chacha20_evp_manager.hpp"
#include "protocol/chacha20_wrapper.hpp"

#include <spdlog/spdlog.h>
#include <algorithm>
#include <stdexcept>

namespace nexusminer {
namespace protocol {

/* ──────────────────────────────────────────────────────────────────────────────
 * ChaCha20 wire-format constants (must match node-side expectations)
 * ────────────────────────────────────────────────────────────────────────────*/
static constexpr size_t CHACHA20_NONCE_WIRE_SIZE = 12u;   // 96-bit nonce
static constexpr size_t CHACHA20_TAG_SIZE         = 16u;   // 128-bit Poly1305 tag


/* ──────────────────────────────────────────────────────────────────────────────
 * Singleton
 * ────────────────────────────────────────────────────────────────────────────*/

ChaCha20EVPManager& ChaCha20EVPManager::Get()
{
    static ChaCha20EVPManager instance;
    return instance;
}

ChaCha20EVPManager::ChaCha20EVPManager()
    : m_mode(EncryptionMode::EVP)
    , m_mode_locked(false)
    , m_wrapper(std::make_unique<ChaCha20Wrapper>())
{
    auto logger = spdlog::get("logger");
    if (logger)
        logger->info("[EVPManager] Initialized — default mode: EVP (ChaCha20-Poly1305)");
}


/* ──────────────────────────────────────────────────────────────────────────────
 * Startup configuration
 * ────────────────────────────────────────────────────────────────────────────*/

bool ChaCha20EVPManager::configure(EncryptionMode mode)
{
    auto logger = spdlog::get("logger");

    std::lock_guard<std::mutex> lock(m_mutex);

    if (m_mode_locked)
    {
        if (logger)
            logger->error("[EVPManager] configure() called after lock_mode() — ignoring "
                          "(current mode: {})", mode_name(m_mode));
        return false;
    }

    /* Prevent EVP+TLS co-active: mode is a global Either/Or */
    if (mode == EncryptionMode::TLS && m_mode == EncryptionMode::EVP)
    {
        if (logger)
            logger->warn("[EVPManager] Switching EVP → TLS: ChaCha20 application-layer "
                         "encryption will be DISABLED for BOTH lanes.");
    }
    else if (mode == EncryptionMode::EVP && m_mode == EncryptionMode::TLS)
    {
        if (logger)
            logger->warn("[EVPManager] Switching TLS → EVP: TLS was configured but EVP "
                         "(ChaCha20) will now handle both lanes.");
    }

    m_mode = mode;

    if (logger)
        logger->info("[EVPManager] Encryption mode set to: {}", mode_name(m_mode));

    return true;
}

void ChaCha20EVPManager::lock_mode()
{
    std::lock_guard<std::mutex> lock(m_mutex);
    m_mode_locked = true;

    auto logger = spdlog::get("logger");
    if (logger)
        logger->info("[EVPManager] Mode locked to: {} — no further configure() calls accepted.",
                     mode_name(m_mode));
}

EncryptionMode ChaCha20EVPManager::get_mode() const
{
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_mode;
}

bool ChaCha20EVPManager::is_evp_active() const
{
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_mode == EncryptionMode::EVP;
}

bool ChaCha20EVPManager::is_tls_active() const
{
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_mode == EncryptionMode::TLS;
}


/* ──────────────────────────────────────────────────────────────────────────────
 * Session key registry
 * ────────────────────────────────────────────────────────────────────────────*/

void ChaCha20EVPManager::register_session(uint32_t nSessionId,
                                           const std::vector<uint8_t>& session_key,
                                           const std::string& fingerprint)
{
    auto logger = spdlog::get("logger");

    if (session_key.size() != 32u)
    {
        if (logger)
            logger->error("[EVPManager] register_session: invalid key size {} for session={}",
                          session_key.size(), nSessionId);
        return;
    }

    std::lock_guard<std::mutex> lock(m_mutex);

    SessionKeyEntry entry;
    entry.session_key = session_key;
    entry.fingerprint = fingerprint;
    entry.ready       = true;

    bool is_refresh = (m_session_keys.count(nSessionId) > 0);
    m_session_keys[nSessionId] = std::move(entry);

    if (logger)
    {
        if (is_refresh)
            logger->info("[EVPManager] Session key refreshed for session={} fp={}", nSessionId, fingerprint);
        else
            logger->info("[EVPManager] Session key registered for session={} fp={}", nSessionId, fingerprint);
    }
}

void ChaCha20EVPManager::remove_session(uint32_t nSessionId)
{
    std::lock_guard<std::mutex> lock(m_mutex);

    auto it = m_session_keys.find(nSessionId);
    if (it != m_session_keys.end())
    {
        /* Zero the key material before erase */
        std::fill(it->second.session_key.begin(), it->second.session_key.end(), 0u);
        m_session_keys.erase(it);

        auto logger = spdlog::get("logger");
        if (logger)
            logger->debug("[EVPManager] Session key removed for session={}", nSessionId);
    }
}

uint32_t ChaCha20EVPManager::prune_expired_sessions(const std::vector<uint32_t>& live_sessions)
{
    std::lock_guard<std::mutex> lock(m_mutex);

    uint32_t nRemoved = 0;

    for (auto it = m_session_keys.begin(); it != m_session_keys.end(); )
    {
        bool is_live = std::find(live_sessions.begin(), live_sessions.end(), it->first)
                       != live_sessions.end();
        if (!is_live)
        {
            /* Zero key material */
            std::fill(it->second.session_key.begin(), it->second.session_key.end(), 0u);
            it = m_session_keys.erase(it);
            ++nRemoved;
        }
        else
        {
            ++it;
        }
    }

    if (nRemoved > 0)
    {
        auto logger = spdlog::get("logger");
        if (logger)
            logger->debug("[EVPManager] Pruned {} expired session key(s)", nRemoved);
    }

    return nRemoved;
}

bool ChaCha20EVPManager::has_session_key(uint32_t nSessionId) const
{
    std::lock_guard<std::mutex> lock(m_mutex);

    auto it = m_session_keys.find(nSessionId);
    return it != m_session_keys.end() && it->second.ready;
}


/* ──────────────────────────────────────────────────────────────────────────────
 * Packet-level encrypt / decrypt (hot path)
 * ────────────────────────────────────────────────────────────────────────────*/

EVPPacketResult ChaCha20EVPManager::encrypt_packet(uint32_t nSessionId,
                                                     const std::vector<uint8_t>& plaintext,
                                                     const std::vector<uint8_t>& aad)
{
    EVPPacketResult result;

    /* ── Mode gate ── */
    EncryptionMode current_mode;
    std::vector<uint8_t> session_key;
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        current_mode = m_mode;

        if (current_mode == EncryptionMode::EVP)
        {
            auto it = m_session_keys.find(nSessionId);
            if (it == m_session_keys.end() || !it->second.ready)
            {
                result.success = false;
                result.error_message = "No registered session key for session=" +
                                       std::to_string(nSessionId);
                return result;
            }
            session_key = it->second.session_key;
        }
    }

    /* ── Pass-through for NONE / TLS ── */
    if (current_mode != EncryptionMode::EVP)
    {
        result.success = true;
        result.data    = plaintext;
        return result;
    }

    /* ── EVP encrypt via ChaCha20Wrapper ── */
    auto nonce     = ChaCha20Wrapper::generate_nonce();           // 12 random bytes
    auto enc       = m_wrapper->encrypt(plaintext, session_key, nonce, aad);

    /* Zero the local session_key copy immediately after use */
    std::fill(session_key.begin(), session_key.end(), 0u);

    if (!enc.success)
    {
        result.success       = false;
        result.error_message = enc.error_message;
        return result;
    }

    /* Wire format: [nonce(12)][ciphertext+tag] */
    result.data.reserve(CHACHA20_NONCE_WIRE_SIZE + enc.data.size());
    result.data.insert(result.data.end(), nonce.begin(),    nonce.end());
    result.data.insert(result.data.end(), enc.data.begin(), enc.data.end());
    result.success = true;
    return result;
}

EVPPacketResult ChaCha20EVPManager::decrypt_packet(uint32_t nSessionId,
                                                     const std::vector<uint8_t>& ciphertext_wire,
                                                     const std::vector<uint8_t>& aad)
{
    EVPPacketResult result;

    /* ── Mode gate ── */
    EncryptionMode current_mode;
    std::vector<uint8_t> session_key;
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        current_mode = m_mode;

        if (current_mode == EncryptionMode::EVP)
        {
            auto it = m_session_keys.find(nSessionId);
            if (it == m_session_keys.end() || !it->second.ready)
            {
                result.success       = false;
                result.error_message = "No registered session key for session=" +
                                       std::to_string(nSessionId);
                return result;
            }
            session_key = it->second.session_key;
        }
    }

    /* ── Pass-through for NONE / TLS ── */
    if (current_mode != EncryptionMode::EVP)
    {
        result.success = true;
        result.data    = ciphertext_wire;
        return result;
    }

    /* ── Validate minimum size: nonce(12) + tag(16) = 28 bytes minimum ── */
    if (ciphertext_wire.size() < CHACHA20_NONCE_WIRE_SIZE + CHACHA20_TAG_SIZE)
    {
        result.success       = false;
        result.error_message = "EVP decrypt: wire payload too short (" +
                               std::to_string(ciphertext_wire.size()) + " bytes)";
        return result;
    }

    /* ── Unpack wire format: [nonce(12)][ciphertext+tag] ── */
    std::vector<uint8_t> nonce(ciphertext_wire.begin(),
                               ciphertext_wire.begin() + CHACHA20_NONCE_WIRE_SIZE);
    std::vector<uint8_t> ciphertext_and_tag(ciphertext_wire.begin() + CHACHA20_NONCE_WIRE_SIZE,
                                            ciphertext_wire.end());

    /* ── EVP decrypt via ChaCha20Wrapper ── */
    auto dec = m_wrapper->decrypt(ciphertext_and_tag, session_key, nonce, aad);

    /* Zero the local session_key copy immediately after use */
    std::fill(session_key.begin(), session_key.end(), 0u);

    if (!dec.success)
    {
        result.success       = false;
        result.error_message = dec.error_message;
        return result;
    }

    result.success = true;
    result.data    = std::move(dec.data);
    return result;
}


/* ──────────────────────────────────────────────────────────────────────────────
 * Diagnostics
 * ────────────────────────────────────────────────────────────────────────────*/

const char* ChaCha20EVPManager::mode_name(EncryptionMode mode)
{
    switch (mode)
    {
        case EncryptionMode::NONE:  return "NONE";
        case EncryptionMode::EVP:   return "EVP (ChaCha20-Poly1305)";
        case EncryptionMode::TLS:   return "TLS";
        default:                    return "UNKNOWN";
    }
}

size_t ChaCha20EVPManager::session_count() const
{
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_session_keys.size();
}

} // namespace protocol
} // namespace nexusminer
