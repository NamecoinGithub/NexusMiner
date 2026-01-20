#include "protocol/solo.hpp"
#include "protocol/protocol.hpp"
#include "protocol/falcon_constants.hpp"
#include "packet.hpp"
#include "network/connection.hpp"
#include "stats/stats_collector.hpp"
#include "LLP/block_utils.hpp"
#include "LLP/llp_logging.hpp"
#include "LLP/utils.hpp"
#include "../miner_keys.hpp"
#include "hex_utils.h"
#include <openssl/sha.h>
#include <chrono>
#include <sstream>
#include <iomanip>
#include <stdexcept>
#include <cstring>

namespace nexusminer
{
namespace protocol
{

// Protocol constants
constexpr size_t GENESIS_HASH_SIZE = 32;  // Tritium genesis hash size
constexpr size_t ADDRESS_DISPLAY_TRUNCATE = 40;  // Max characters to display for addresses in logs
constexpr size_t MIN_GENESIS_LOG_SIZE = 8;  // Minimum genesis bytes to log (for sanity check)
constexpr size_t MAX_GENESIS_LOG_BYTES = 32;  // Maximum genesis bytes to log (avoid excessive output)

// Push notification payload offsets (12-byte format, big-endian)
constexpr size_t PUSH_NOTIFICATION_UNIFIED_HEIGHT_OFFSET = 0;   // Unified blockchain height (4 bytes)
constexpr size_t PUSH_NOTIFICATION_CHANNEL_HEIGHT_OFFSET = 4;   // Channel-specific height (4 bytes)
constexpr size_t PUSH_NOTIFICATION_DIFFICULTY_OFFSET = 8;       // Mining difficulty (4 bytes)
constexpr size_t PUSH_NOTIFICATION_PAYLOAD_SIZE = 12;           // Total payload size

// ChaCha20 key derivation domain separator
static const std::string KDF_DOMAIN = "nexus-mining-chacha20-v1";

// ChaCha20 AAD for Falcon public key encryption (as vector for efficiency)
static const std::vector<uint8_t> AAD_DOMAIN_VEC{'F','A','L','C','O','N','_','P','U','B','K','E','Y'};

/* AAD (Additional Authenticated Data) constants for ChaCha20-Poly1305 AEAD
 * These MUST match the node's expectations for domain separation.
 * See: LLL-TAO/src/LLP/stateless_miner.cpp line 48-50 */

/** AAD for encrypting MINER_SET_REWARD payload (reward address)
 *  Node expects: "REWARD_ADDRESS" (14 bytes) */
static const std::vector<uint8_t> AAD_REWARD_ADDRESS{
    'R','E','W','A','R','D','_',
    'A','D','D','R','E','S','S'
};

/** AAD for decrypting MINER_REWARD_RESULT response
 *  Node uses: "REWARD_RESULT" (13 bytes) */
static const std::vector<uint8_t> AAD_REWARD_RESULT{
    'R','E','W','A','R','D','_',
    'R','E','S','U','L','T'
};

/** AAD for encrypting SUBMIT_BLOCK payload
 *  Node expects: empty AAD (no domain separation for block submissions) */
static const std::vector<uint8_t> AAD_BLOCK_SUBMISSION{};

// Helper function to serialize uint64 to little-endian bytes
static void append_uint64_le(std::vector<uint8_t>& dest, uint64_t value) {
    for (int i = 0; i < 8; ++i) {
        dest.push_back((value >> (i * 8)) & 0xFF);
    }
}

// Helper function to serialize uint32 to little-endian bytes
static void append_uint32_le(std::vector<uint8_t>& dest, uint32_t value) {
    for (int i = 0; i < 4; ++i) {
        dest.push_back((value >> (i * 8)) & 0xFF);
    }
}

// Helper function to serialize uint16 to little-endian bytes  
static void append_uint16_le(std::vector<uint8_t>& dest, uint16_t value) {
    dest.push_back(value & 0xFF);
    dest.push_back((value >> 8) & 0xFF);
}

// Helper function to get channel name string for logging
static std::string get_channel_name(uint32_t channel) {
    switch(channel) {
        case mining::CHANNEL_PRIME: return "Prime";
        case mining::CHANNEL_HASH:  return "Hash";
        default:                     return "Unknown";
    }
}

Solo::Solo(std::uint8_t channel, std::shared_ptr<stats::Collector> stats_collector)
: m_channel{channel}
, m_logger{spdlog::get("logger")}
, m_current_height{0}
, m_current_difficulty{0}
, m_current_reward{0}
, m_set_block_handler{}
, m_stats_collector{std::move(stats_collector)}
, m_authenticated{false}
, m_session_id{0}
, m_address{"127.0.0.1"}  // Default address, can be overridden
, m_auth_timestamp{0}
, m_auth_state{AuthState::NOT_AUTHENTICATED}
, m_miner_id{"NexusMiner"}  // Default miner ID
, m_falcon_wrapper{nullptr}
, m_disposable_falcon_enabled{true}  // ALWAYS ON - Disposable Falcon (core protocol, accepts both F-512/F-1024)
, m_physical_falcon_enabled{false}  // CONFIGURABLE - Physical Falcon OFF by default (lazy miner economics, 61% blockchain savings)
, m_chacha20_wrapper{nullptr}  // Lazy initialization when needed
, m_enable_chacha20{true}  // ALWAYS ON - Core implementation (localhost miners, SessionID protection, etc.)
, m_session_manager{nullptr}
, m_template_interface{nullptr}
, m_connection{nullptr}
, m_reward_address{""}  // Empty until configured
, m_reward_bound{false}  // Not bound until successful MINER_REWARD_RESULT
, m_last_round_status{false, 0, 0, 0, 0, 0, false}  // Initialize GET_ROUND status (with difficulty and channel heights)
, m_last_get_round_time{std::chrono::steady_clock::now()}  // Initialize to now
, m_current_poll_interval_ms{POLL_INTERVAL_MIN_MS}  // Start at minimum interval (5s)
, m_needs_initial_round_check{false}  // No template yet
, m_template_unified_height{0}  // No template yet
, m_stateless_protocol_active{false}  // Start with stateless protocol inactive
, m_waiting_for_stateless_response{false}  // Not waiting initially
, m_miner_ready_sent_time_ns{0}  // Will be set when MINER_READY is sent (nanoseconds since epoch)
{
   // Log constructor call with requested channel value
    m_logger->info("Solo::Solo: ctor called, channel={}", static_cast<int>(m_channel));
    
    // Clamp channel to valid LLL-TAO channels: 1 = prime, 2 = hash
    if (m_channel != 1 && m_channel != 2) {
        m_logger->warn("Invalid channel {} specified. Valid channels: 1 (prime), 2 (hash). Defaulting to 2 (hash).", 
            static_cast<int>(m_channel));
        m_channel = 2;
    }
    
    // Note: ChaCha20 wrapper is lazily initialized when enable_chacha20_wrapping() is called
    // This avoids unnecessary resource allocation when ChaCha20 is not needed
    
    // Initialize session manager with default keepalive interval (24 hours)
    m_session_manager = std::make_unique<SessionManager>(24);
    m_logger->info("[Solo] Session manager initialized for adaptive cache management");
    
    // Initialize client-side channel managers (mirrors NODE's PR #136)
    m_prime_manager = std::make_unique<mining::PrimeClientManager>();
    m_hash_manager = std::make_unique<mining::HashClientManager>();
    m_logger->info("[Solo] Client channel managers initialized (Prime + Hash)");
    
    // Initialize the Mining Template Interface for unified READ/FEED operations
    // Session ID starts at 0 (unauthenticated) and will be updated after MINER_AUTH_RESULT
    // The session ID binds the template interface to the FALCON authenticated tunnel
    m_template_interface = std::make_unique<MiningTemplateInterface>(m_channel, 0);
    m_logger->info("[Solo] Mining Template Interface initialized for unified READ/FEED system");
    
    // Setup template feed handler - called automatically when templates are validated
    m_template_interface->set_template_feed_handler(
        [this](const MiningTemplateInterface::MiningTemplate& tmpl, uint32_t nBits) {
            // Log new template (infrequent: once per block, typically every few minutes)
            std::string channel_name = (tmpl.block.nChannel == 1) ? "Prime" : "Hash";
            m_logger->info("[Solo] ═══════════════════════════════════════");
            m_logger->info("[Solo] 🆕 NEW MINING TEMPLATE RECEIVED");
            m_logger->info("[Solo]   Channel:         {} ({})", tmpl.block.nChannel, channel_name);
            m_logger->info("[Solo]   Unified height:  {} (reference only)", tmpl.block.nHeight);
            if (tmpl.nChannelHeight > 0) {
                m_logger->info("[Solo]   Channel height:  {} (mining for next block)", tmpl.nChannelHeight);
            } else {
                m_logger->info("[Solo]   Channel height:  (pending finalization via GET_ROUND)");
            }
            m_logger->info("[Solo]   Difficulty:      0x{:08x}", nBits);
            m_logger->info("[Solo] ═══════════════════════════════════════");
            
            // Feed to worker threads via set_block_handler
            if (m_set_block_handler) {
                m_logger->info("[Solo] Distributing template to worker threads...");
                m_set_block_handler(tmpl.block, nBits);
                m_logger->info("[Solo] ✓ Template distributed - workers should start mining");
            } else {
                m_logger->error("[Solo] CRITICAL: No block handler registered!");
            }
        }
    );
    m_logger->info("[Solo] Template feed handler registered - ready to distribute work to workers");
}

std::vector<uint8_t> Solo::derive_chacha20_session_key(const std::vector<uint8_t>& genesis)
{
    std::vector<uint8_t> preimage;
    preimage.insert(preimage.end(), KDF_DOMAIN.begin(), KDF_DOMAIN.end());
    preimage.insert(preimage.end(), genesis.begin(), genesis.end());
    
    // Use OpenSSL SHA256 - output is always SHA256_DIGEST_LENGTH (32) bytes
    std::vector<uint8_t> key(SHA256_DIGEST_LENGTH);
    unsigned char* result = SHA256(preimage.data(), preimage.size(), key.data());
    if (!result) {
        // This should never happen - SHA256 only fails on internal OpenSSL errors
        m_logger->error("[Solo] CRITICAL: OpenSSL SHA256 internal error during key derivation");
        throw std::runtime_error("OpenSSL SHA256 internal error");
    }
    
    // DIAGNOSTIC: Log key derivation details for comparison with node logs
    m_logger->info("╔═══════════════════════════════════════════════════════════╗");
    m_logger->info("║  ChaCha20 KEY DERIVATION DIAGNOSTIC (Miner Side)          ║");
    m_logger->info("╠═══════════════════════════════════════════════════════════╣");
    m_logger->info("║ Domain: {}", KDF_DOMAIN);
    m_logger->info("║ Genesis size: {} bytes", genesis.size());
    
    // Log genesis bytes for comparison (sanity check: only if we have a reasonable amount)
    if (genesis.size() >= MIN_GENESIS_LOG_SIZE) {
        // Use existing keys::to_hex with truncated vector to limit log output
        size_t log_length = std::min(genesis.size(), MAX_GENESIS_LOG_BYTES);
        std::vector<uint8_t> genesis_truncated(genesis.begin(), genesis.begin() + log_length);
        m_logger->info("║ Genesis (hex): {}", nexusminer::keys::to_hex(genesis_truncated));
    }
    
    // Log derived key for comparison with node's "Derived Key (32 bytes):" log
    m_logger->info("║ Derived Key (hex): {}", nexusminer::keys::to_hex(key));
    m_logger->info("╚═══════════════════════════════════════════════════════════╝");
    
    return key;
}

std::vector<uint8_t> Solo::load_tritium_genesis()
{
    // Try to get genesis from session manager first
    if (m_session_manager && !m_session_manager->get_tritium_genesis().empty()) 
    {
        m_logger->info("[Solo Auth] Using genesis from session manager");
        return m_session_manager->get_tritium_genesis();
    }
    
    // If session manager doesn't have it, reload from persistent storage (handles reconnection)
    if (!m_persistent_tritium_genesis.empty())
    {
        auto genesis = m_persistent_tritium_genesis;
        
        // Restore to session manager for future use
        if (m_session_manager)
        {
            m_session_manager->set_tritium_genesis(genesis);
        }
        
        m_logger->info("[Solo Auth] Reloaded tritium_genesis from persistent storage ({} bytes)", genesis.size());
        return genesis;
    }
    
    // No genesis configured
    m_logger->warn("[Solo Auth] No tritium_genesis configured - using zero genesis");
    m_logger->warn("[Solo Auth] ChaCha20 encryption unavailable without valid genesis");
    return std::vector<uint8_t>(GENESIS_HASH_SIZE, 0);  // 32 zero bytes
}

// Helper function to check if genesis hash is valid (non-zero)
// Optimized to return early on first non-zero byte
static bool is_valid_genesis(const std::vector<uint8_t>& genesis) {
    if (genesis.empty()) {
        return false;
    }
    // Early return optimization - stop at first non-zero byte
    for (uint8_t byte : genesis) {
        if (byte != 0) {
            return true;
        }
    }
    return false;
}

void Solo::reset()
{
    m_current_height = 0;
    m_current_difficulty = 0;
    m_current_reward = 0;
    m_authenticated = false;
    m_session_id = 0;
    m_auth_timestamp = 0;
    m_auth_state = AuthState::NOT_AUTHENTICATED;
    m_reward_bound = false;  // Reset reward binding for new session
    
    // Reset stateless protocol state
    m_stateless_protocol_active = false;
    m_waiting_for_stateless_response = false;
    
    // Reset session manager
    if (m_session_manager) {
        m_session_manager->end_session();
    }
    
    // Reset template interface for new session
    if (m_template_interface) {
        m_template_interface->set_session_id(0);
        m_template_interface->reset_stats();
    }
}

network::Shared_payload Solo::login(Login_handler handler)
{
    // Clamp channel to valid values as safety net
    if (m_channel != 1 && m_channel != 2) {
        m_logger->warn("Solo::login: Invalid channel {}, clamping to 2 (hash)", static_cast<int>(m_channel));
        m_channel = 2;
    }
    
    // Falcon authentication is mandatory - no legacy fallback
    if (m_miner_pubkey.empty() || m_miner_privkey.empty()) {
        m_logger->error("[Solo Auth] CRITICAL: Falcon miner keys are required for authentication");
        m_logger->error("[Solo Auth] Legacy authentication mode has been removed");
        m_logger->error("[Solo Auth] Please configure Falcon keys in miner.conf:");
        m_logger->error("[Solo Auth]   1. Generate keys: ./NexusMiner --create-keys");
        m_logger->error("[Solo Auth]   2. Add falcon_miner_pubkey and falcon_miner_privkey to miner.conf");
        m_logger->error("[Solo Auth]   3. Whitelist your public key on the node:");
        m_logger->error("[Solo Auth]      - Config file: Add 'minerallowkey=<pubkey>' to nexus.conf");
        m_logger->error("[Solo Auth]      - Command line: Start nexus with -minerallowkey=<pubkey>");
        handler(false);
        return network::Shared_payload{};
    }
    
    if (!m_falcon_wrapper || !m_falcon_wrapper->is_valid()) {
        m_logger->error("[Solo Phase 2] Cannot authenticate - Falcon keys not loaded");
        handler(false);
        return network::Shared_payload{};
    }
    
    m_logger->info("[Solo Phase 2] Starting Falcon authentication (challenge-response)");
    m_logger->info("[Solo Auth] Using public key ({} bytes)", m_miner_pubkey.size());
    
    // Initialize authentication timestamp for this login attempt
    auto current_time = std::chrono::system_clock::now();
    m_auth_timestamp = static_cast<uint64_t>(
        std::chrono::system_clock::to_time_t(current_time));
    m_logger->info("[Solo Auth] Authentication timestamp set: {} (0x{:016x})", 
                   m_auth_timestamp, m_auth_timestamp);
    
    Packet packet(static_cast<uint8_t>(Packet::MINER_AUTH_INIT));  // 207 - m_is_valid = true automatically
    packet.m_data = std::make_shared<network::Payload>();
    
    // ═══════════════════════════════════════════════════════════
    // STEP 1: hashGenesis FIRST (32 bytes) - enables key derivation
    // ═══════════════════════════════════════════════════════════
    std::vector<uint8_t> tritium_genesis = load_tritium_genesis();
    
    // Genesis goes FIRST in the packet
    packet.m_data->insert(packet.m_data->end(), tritium_genesis.begin(), tritium_genesis.end());
    
    // ═══════════════════════════════════════════════════════════
    // STEP 2: Prepare pubkey (optionally ChaCha20 wrapped)
    // ═══════════════════════════════════════════════════════════
    std::vector<uint8_t> pubkey_to_send = m_miner_pubkey;
    bool wrapped = false;
    
    // Only wrap if we have a valid genesis (non-zero)
    bool has_valid_genesis = is_valid_genesis(tritium_genesis);
    
    if (m_enable_chacha20 && has_valid_genesis)
    {
        m_logger->info("[Solo Auth] ChaCha20 wrapping ENABLED (genesis-derived key)");
        
        try {
            // Derive session key from genesis
            auto session_key = derive_chacha20_session_key(tritium_genesis);
            auto nonce = ChaCha20Wrapper::generate_nonce();  // Random 12 bytes
            
            // Log the nonce being used for encryption
            m_logger->info("[Solo Auth] ChaCha20 nonce (12 bytes): {}", nexusminer::keys::to_hex(nonce));
            
            if (!m_chacha20_wrapper)
                m_chacha20_wrapper = std::make_unique<ChaCha20Wrapper>();
            
            // Use AAD for domain separation
            auto wrap_result = m_chacha20_wrapper->encrypt(m_miner_pubkey, session_key, nonce, AAD_DOMAIN_VEC);
            
            if (wrap_result.success)
            {
                // Build wrapped format: nonce(12) + ciphertext+tag(897+16)
                pubkey_to_send.clear();
                pubkey_to_send.insert(pubkey_to_send.end(), nonce.begin(), nonce.end());
                pubkey_to_send.insert(pubkey_to_send.end(), wrap_result.data.begin(), wrap_result.data.end());
                
                wrapped = true;
                m_logger->info("[Solo Auth] ✓ Pubkey wrapped: {} → {} bytes (genesis-derived key)",
                               m_miner_pubkey.size(), pubkey_to_send.size());
            }
            else
            {
                m_logger->warn("[Solo Auth] ChaCha20 wrap failed: {}", wrap_result.error_message);
                m_logger->warn("[Solo Auth] Falling back to unwrapped pubkey");
            }
        }
        catch (const std::exception& e) {
            m_logger->error("[Solo Auth] Key derivation failed: {}", e.what());
            m_logger->warn("[Solo Auth] Falling back to unwrapped pubkey");
        }
    }
    else if (m_enable_chacha20 && !has_valid_genesis)
    {
        m_logger->warn("[Solo Auth] ChaCha20 requested but no genesis for key derivation");
        m_logger->warn("[Solo Auth] Sending unwrapped pubkey");
    }
    
    // ═══════════════════════════════════════════════════════════
    // STEP 3: pubkey_len + pubkey
    // ═══════════════════════════════════════════════════════════
    uint16_t pubkey_len = static_cast<uint16_t>(pubkey_to_send.size());
    packet.m_data->push_back(static_cast<uint8_t>((pubkey_len >> 8) & 0xFF));
    packet.m_data->push_back(static_cast<uint8_t>(pubkey_len & 0xFF));
    packet.m_data->insert(packet.m_data->end(), pubkey_to_send.begin(), pubkey_to_send.end());
    
    // ═══════════════════════════════════════════════════════════
    // STEP 4: miner_id_len + miner_id
    // ═══════════════════════════════════════════════════════════
    std::string miner_id = m_miner_id.empty() ? "NexusMiner" : m_miner_id;
    uint16_t miner_id_len = static_cast<uint16_t>(miner_id.size());
    packet.m_data->push_back(static_cast<uint8_t>((miner_id_len >> 8) & 0xFF));
    packet.m_data->push_back(static_cast<uint8_t>(miner_id_len & 0xFF));
    packet.m_data->insert(packet.m_data->end(), miner_id.begin(), miner_id.end());
    
    packet.m_length = static_cast<uint32_t>(packet.m_data->size());
    
    // ═══════════════════════════════════════════════════════════
    // Debug: Verify packet is valid before transmission
    // ═══════════════════════════════════════════════════════════
    m_logger->debug("[Solo Auth] Packet built: header={}, length={}, data_size={}", 
                    packet.m_header, packet.m_length, 
                    packet.m_data ? packet.m_data->size() : 0);
    
    if (!packet.is_valid())
    {
        m_logger->error("[Solo Auth] CRITICAL: Packet is_valid() returned false!");
        m_logger->error("[Solo Auth]   header={}, m_length={}, is_auth_packet={}", 
                        packet.m_header, packet.m_length, packet.is_auth_packet());
        m_logger->error("[Solo Auth]   Validation state: {}", packet.get_validation_state());
    }
    
    auto bytes = packet.get_bytes();
    if (!bytes || bytes->empty())
    {
        m_logger->error("[Solo Auth] CRITICAL: get_bytes() returned null/empty!");
        m_logger->error("[Solo Auth] Cannot transmit - payload is null or empty");
        return network::Shared_payload{};
    }
    
    m_logger->debug("[Solo Auth] Packet validation: SUCCESS - encoded {} bytes", bytes->size());
    
    // TRAINING WHEELS: Show hex dump of MINER_AUTH_INIT packet
    m_logger->info("[Solo Auth] MINER_AUTH_INIT packet hex dump (wire format):");
    m_logger->info("\n{}", format_llp_payload_hexdump(bytes, 128));
    
    // ═══════════════════════════════════════════════════════════
    // Log summary
    // ═══════════════════════════════════════════════════════════
    m_logger->info("");
    m_logger->info("═══════════════════════════════════════════════════════════");
    m_logger->info("    MINER_AUTH_INIT (Genesis-First Protocol)");
    m_logger->info("═══════════════════════════════════════════════════════════");
    m_logger->info("  Genesis:     {} bytes ({})", tritium_genesis.size(),
                   has_valid_genesis ? "VALID - key derivation enabled" : "ZERO");
    m_logger->info("  Public Key:  {} bytes {}", pubkey_len,
                   wrapped ? "(ChaCha20 wrapped)" : "(unwrapped)");
    m_logger->info("  Miner ID:    '{}'", miner_id);
    m_logger->info("  Total Size:  {} bytes", packet.m_length);
    m_logger->info("═══════════════════════════════════════════════════════════");
    m_logger->info("");
    
    // Set state to waiting for challenge
    m_auth_state = AuthState::WAITING_FOR_CHALLENGE;
    
    // Login handler will be called after successful authentication in MINER_AUTH_RESULT
    // For now, mark as "in progress"
    handler(true);
    
    return bytes;
}

network::Shared_payload Solo::get_work()
{
    /* Validate prerequisites */
    if (!m_authenticated) {
        m_logger->error("[Solo] Cannot request work - not authenticated");
        m_logger->error("[Solo]   Current auth state: {}", 
            m_auth_state == AuthState::NOT_AUTHENTICATED ? "NOT_AUTHENTICATED" :
            m_auth_state == AuthState::WAITING_FOR_CHALLENGE ? "WAITING_FOR_CHALLENGE" :
            m_auth_state == AuthState::WAITING_FOR_RESULT ? "WAITING_FOR_RESULT" :
            "AUTHENTICATED");
        m_logger->error("[Solo]   Waiting for Falcon authentication to complete");
        return nullptr;
    }
    
    // Only validate reward binding if a reward address was configured
    // (Reward binding is optional for localhost/testing, but required for production)
    if (!m_reward_address.empty() && !m_reward_bound) {
        m_logger->error("[Solo] Cannot request work - reward address not bound");
        return nullptr;
    }
    
    m_logger->info("[Solo] Requesting mining template via GET_BLOCK");
    m_logger->info("[Solo]   Session ID: 0x{:08x}", m_session_id);
    m_logger->info("[Solo]   Authenticated: {}", m_authenticated ? "YES" : "NO");
    m_logger->info("[Solo]   Reward bound: {}", m_reward_bound ? "YES" : "NO");

    /* Build GET_BLOCK packet (header-only, no payload) */
    Packet packet{ static_cast<uint8_t>(Packet::GET_BLOCK) };  // Header = 129 (0x81)
    packet.m_length = 0;  // No payload for GET_BLOCK
    
    // Debug logging to diagnose packet encoding
    m_logger->debug("[Solo] GET_BLOCK packet: header=0x{:02x} length={} is_valid={}", 
                   static_cast<int>(packet.m_header),
                   packet.m_length, 
                   packet.is_valid());
    
    auto payload = packet.get_bytes();
    if (payload && !payload->empty()) {
        m_logger->debug("[Solo] GET_BLOCK encoded payload size: {} bytes", payload->size());
        // TRAINING WHEELS: Show GET_BLOCK packet (should be just header byte)
        m_logger->info("[Solo] GET_BLOCK packet hex dump:");
        m_logger->info("\n{}", format_llp_payload_hexdump(payload, 16));
    } else {
        m_logger->error("[Solo] GET_BLOCK get_bytes() returned null or empty payload!");
    }
    
    return payload;     
}

network::Shared_payload Solo::get_height()
{
    m_logger->info("[Solo] Requesting blockchain height via GET_HEIGHT");
    
    // GET_HEIGHT is a header-only request packet (opcode 130, >= 128)
    Packet packet{ static_cast<uint8_t>(Packet::GET_HEIGHT) };
    
    // Debug logging to verify packet encoding
    m_logger->debug("[Solo] GET_HEIGHT packet: header=0x{:02x} length={} is_valid={}", 
                   static_cast<int>(packet.m_header),
                   packet.m_length, 
                   packet.is_valid());
    
    auto payload = packet.get_bytes();
    if (payload && !payload->empty()) {
        m_logger->debug("[Solo] GET_HEIGHT encoded payload size: {} bytes (header-only)", payload->size());
    } else {
        m_logger->error("[Solo] GET_HEIGHT get_bytes() returned null or empty payload!");
    }
    
    return payload;
}

network::Shared_payload Solo::send_get_round()
{
    // CRITICAL: Validate authentication before sending GET_ROUND
    // Node will reject unauthenticated GET_ROUND requests
    if (!m_authenticated) {
        m_logger->warn("[Solo GET_ROUND] Cannot send GET_ROUND - not authenticated yet");
        m_logger->debug("[Solo GET_ROUND]   Current auth state: {}", 
            m_auth_state == AuthState::NOT_AUTHENTICATED ? "NOT_AUTHENTICATED" :
            m_auth_state == AuthState::WAITING_FOR_CHALLENGE ? "WAITING_FOR_CHALLENGE" :
            m_auth_state == AuthState::WAITING_FOR_RESULT ? "WAITING_FOR_RESULT" :
            "AUTHENTICATED");
        return nullptr;
    }
    
    m_logger->debug("[Solo GET_ROUND] Requesting round status via GET_ROUND");
    
    // GET_ROUND is a header-only request packet (opcode 133, >= 128)
    Packet packet{ static_cast<uint8_t>(Packet::GET_ROUND) };
    
    // Debug logging to verify packet encoding
    m_logger->debug("[Solo GET_ROUND] Packet: header=0x{:02x} length={} is_valid={}", 
                   static_cast<int>(packet.m_header),
                   packet.m_length, 
                   packet.is_valid());
    
    auto payload = packet.get_bytes();
    if (payload && !payload->empty()) {
        m_logger->debug("[Solo GET_ROUND] Encoded payload size: {} bytes (header-only)", payload->size());
    } else {
        m_logger->error("[Solo GET_ROUND] get_bytes() returned null or empty payload!");
    }
    
    return payload;
}

network::Shared_payload Solo::submit_block(std::vector<std::uint8_t> const& block_data, std::uint64_t nonce)
{
    // Enhanced diagnostics: Validate block_data before submission
    if (block_data.empty()) {
        m_logger->error("[Solo Submit] CRITICAL: block_data is empty! Cannot submit block.");
        return network::Shared_payload{};
    }
    
    // Verify Falcon wrapper is available (required for stateless sessions)
    if (!m_falcon_wrapper || !m_falcon_wrapper->is_valid()) {
        m_logger->error("[Solo Submit] CRITICAL: Falcon wrapper not available for block signing");
        m_logger->error("[Solo Submit] Stateless sessions REQUIRE signed block submissions per LLL-TAO protocol");
        return network::Shared_payload{};
    }
    
    // ════════════════════════════════════════════════════════════════════════════════
    // TRAINING WHEELS MODE: Comprehensive SUBMIT_BLOCK logging
    // ════════════════════════════════════════════════════════════════════════════════
    m_logger->info("════════════════════════════════════════════════════════");
    m_logger->info("📤 SUBMIT_BLOCK PREPARATION (Training Wheels Mode)");
    m_logger->info("════════════════════════════════════════════════════════");
    
    // Get current timestamp for block submission (8 bytes, little-endian)
    uint64_t submission_timestamp = static_cast<uint64_t>(
        std::chrono::system_clock::to_time_t(std::chrono::system_clock::now()));
    
    /* Block details */
    m_logger->info("📦 BLOCK DATA:");
    m_logger->info("   Serialized size: {} bytes (expected: 216)", block_data.size());
    m_logger->info("   Nonce: 0x{:016x}", nonce);
    
    // Build the complete submission payload: full_block + timestamp
    std::vector<uint8_t> message_to_sign;
    message_to_sign.reserve(block_data.size() + 8);  // full_block + timestamp(8)
    message_to_sign.insert(message_to_sign.end(), block_data.begin(), block_data.end());
    append_uint64_le(message_to_sign, submission_timestamp);
    
    // Generate Falcon signature for block submission
    auto sig_result = m_falcon_wrapper->sign_payload(message_to_sign, 
        FalconSignatureWrapper::SignatureType::BLOCK);
    
    if (!sig_result.success) {
        m_logger->error("❌ Falcon signature generation FAILED: {}", sig_result.error_message);
        m_logger->error("════════════════════════════════════════════════════════");
        return network::Shared_payload{};
    }
    
    /* Falcon signature details and validation */
    size_t expected_sig_size = m_falcon_wrapper->get_signature_size();
    std::string falcon_version = m_falcon_wrapper->is_falcon1024() ? "Falcon-1024" : "Falcon-512";
    
    m_logger->info("🔐 FALCON SIGNATURE ({}):", falcon_version);
    m_logger->info("   Signature size: {} bytes (expected: {})", 
                   sig_result.signature.size(), expected_sig_size);
    
    // Validate signature size matches the Falcon version
    if (sig_result.signature.size() != expected_sig_size) {
        m_logger->error("❌ SIGNATURE SIZE MISMATCH!");
        m_logger->error("   Expected: {} bytes ({})", expected_sig_size, falcon_version);
        m_logger->error("   Got: {} bytes", sig_result.signature.size());
        m_logger->error("   This indicates a key version mismatch or signing error");
        m_logger->error("════════════════════════════════════════════════════════");
        return network::Shared_payload{};
    }
    
    m_logger->info("   Timestamp: {} (0x{:016x})", submission_timestamp, submission_timestamp);
    m_logger->info("   Signed data format: [block({})][ timestamp(8)]", block_data.size());
    
    /* Build plaintext payload BEFORE encryption */
    std::vector<uint8_t> plaintextPayload;
    
    // Calculate total size: block + timestamp + siglen + sig + physiglen + (optional)physical_sig
    size_t payload_size = block_data.size() + 8 + 2 + sig_result.signature.size() + 2;
    if (m_physical_falcon_enabled) {
        payload_size += sig_result.signature.size();  // Physical signature same size as Disposable
    }
    plaintextPayload.reserve(payload_size);
    
    // Append full block (216 or 220 bytes)
    plaintextPayload.insert(plaintextPayload.end(), block_data.begin(), block_data.end());
    
    // Append timestamp (8 bytes LE)
    append_uint64_le(plaintextPayload, submission_timestamp);
    
    // Append Disposable signature length (2 bytes LE)
    uint16_t sig_len = static_cast<uint16_t>(sig_result.signature.size());
    append_uint16_le(plaintextPayload, sig_len);
    
    // Append Disposable signature bytes
    plaintextPayload.insert(plaintextPayload.end(), 
                           sig_result.signature.begin(), 
                           sig_result.signature.end());
    
    // Physical Falcon signature (optional, based on configuration)
    std::vector<uint8_t> physical_signature;
    uint16_t physical_sig_len = 0;
    
    if (m_physical_falcon_enabled) {
        m_logger->info("🔐 PHYSICAL FALCON SIGNATURE:");
        m_logger->info("   Generating Physical signature (permanent blockchain proof)...");
        
        // Sign the same message again for Physical signature (key bonding)
        auto physical_sig_result = m_falcon_wrapper->sign_payload(message_to_sign, 
            FalconSignatureWrapper::SignatureType::BLOCK);
        
        if (!physical_sig_result.success) {
            m_logger->error("❌ Physical Falcon signature generation FAILED: {}", physical_sig_result.error_message);
            m_logger->error("   Continuing without Physical signature");
            // Set physiglen to 0 and continue
        } else {
            // Validate Physical signature size matches Disposable (key bonding requirement)
            if (physical_sig_result.signature.size() != sig_result.signature.size()) {
                m_logger->error("❌ KEY BONDING VIOLATION!");
                m_logger->error("   Disposable sig: {} bytes", sig_result.signature.size());
                m_logger->error("   Physical sig:   {} bytes", physical_sig_result.signature.size());
                m_logger->error("   Both signatures MUST be same size (same key)");
                m_logger->error("════════════════════════════════════════════════════════");
                return network::Shared_payload{};
            }
            
            physical_signature = physical_sig_result.signature;
            physical_sig_len = static_cast<uint16_t>(physical_signature.size());
            
            m_logger->info("   Physical signature: {} bytes (matches Disposable)", physical_sig_len);
            m_logger->info("   Key bonding verified: Both signatures same size ✓");
            m_logger->info("   Blockchain overhead: {} bytes/block", physical_sig_len);
        }
    } else {
        m_logger->info("🔐 PHYSICAL FALCON: DISABLED (lazy miner economics)");
        m_logger->info("   Blockchain overhead: 0 bytes/block ✓");
    }
    
    // Append Physical signature length (2 bytes LE) - always present, even if 0
    append_uint16_le(plaintextPayload, physical_sig_len);
    
    // Append Physical signature bytes (only if present)
    if (physical_sig_len > 0) {
        plaintextPayload.insert(plaintextPayload.end(), 
                               physical_signature.begin(), 
                               physical_signature.end());
    }
    
    m_logger->info("📄 PLAINTEXT PAYLOAD (BEFORE ENCRYPTION):");
    m_logger->info("   Total size: {} bytes", plaintextPayload.size());
    if (m_physical_falcon_enabled && physical_sig_len > 0) {
        m_logger->info("   Format: [block({})][timestamp(8)][siglen(2)][disposable_sig({})][physiglen(2)][physical_sig({})]",
                       block_data.size(), sig_result.signature.size(), physical_sig_len);
    } else {
        m_logger->info("   Format: [block({})][timestamp(8)][siglen(2)][disposable_sig({})][physiglen(2=0)]",
                       block_data.size(), sig_result.signature.size());
    }
    m_logger->info("   First 64 bytes (hex - this is PLAINTEXT):");
    
    std::string hexDump = HexUtils::FormatHexDump(plaintextPayload, 64);
    std::vector<std::string> lines = HexUtils::SplitHexDump(hexDump, 32);
    for(const auto& line : lines)
        m_logger->info("      {}", line);
    
    m_logger->info("");
    
    /* Check encryption readiness */
    m_logger->info("🔒 CHACHA20-POLY1305 ENCRYPTION:");
    m_logger->info("   Checking encryption context...");
    m_logger->info("   ChaCha20 enabled: {}", m_enable_chacha20 ? "YES" : "NO");
    
    // Load genesis for key derivation
    std::vector<uint8_t> tritium_genesis = load_tritium_genesis();
    bool has_valid_genesis = is_valid_genesis(tritium_genesis);
    
    m_logger->info("   Genesis available: {}", has_valid_genesis ? "YES" : "NO");
    m_logger->info("   Session ID: 0x{:08x}", m_session_id);
    
    if(!m_enable_chacha20 || !has_valid_genesis)
    {
        m_logger->error("❌ ENCRYPTION NOT READY - CANNOT SUBMIT!");
        m_logger->error("   Modern nodes require ChaCha20 encryption");
        m_logger->error("   ChaCha20 enabled: {}", m_enable_chacha20 ? "YES" : "NO");
        m_logger->error("   Genesis available: {}", has_valid_genesis ? "YES" : "NO");
        m_logger->error("   Session may not be authenticated");
        m_logger->error("   Check that MINER_AUTH was successful");
        m_logger->error("════════════════════════════════════════════════════════");
        return network::Shared_payload{};
    }
    
    m_logger->info("   Status: Encrypting payload...");
    
    /* Encrypt the payload */
    try {
        // Initialize ChaCha20 wrapper if not already done
        if (!m_chacha20_wrapper)
            m_chacha20_wrapper = std::make_unique<ChaCha20Wrapper>();
        
        // Derive session key from genesis
        auto session_key = derive_chacha20_session_key(tritium_genesis);
        
        // Generate random nonce for this encryption
        auto nonce = ChaCha20Wrapper::generate_nonce();
        
        // Encrypt the payload with AAD for domain separation
        auto encrypt_result = m_chacha20_wrapper->encrypt(plaintextPayload, session_key, nonce, AAD_BLOCK_SUBMISSION);
        
        if(!encrypt_result.success || encrypt_result.data.empty())
        {
            m_logger->error("❌ ChaCha20 encryption FAILED!");
            m_logger->error("   Error: {}", encrypt_result.error_message);
            m_logger->error("   Encryption function returned false or empty result");
            m_logger->error("   Cannot submit without encryption");
            m_logger->error("════════════════════════════════════════════════════════");
            return network::Shared_payload{};
        }
        
        // Build encrypted payload: nonce(12) + ciphertext+tag
        std::vector<uint8_t> encryptedPayload;
        encryptedPayload.reserve(12 + encrypt_result.data.size());
        encryptedPayload.insert(encryptedPayload.end(), nonce.begin(), nonce.end());
        encryptedPayload.insert(encryptedPayload.end(), encrypt_result.data.begin(), encrypt_result.data.end());
        
        m_logger->info("   Status: ✅ ENCRYPTION SUCCESS");
        m_logger->info("   Encrypted size: {} bytes (includes 12-byte nonce + 16-byte auth tag)", encryptedPayload.size());
        m_logger->info("   First 64 bytes (hex - this should look RANDOM):");
        
        hexDump = HexUtils::FormatHexDump(encryptedPayload, 64);
        lines = HexUtils::SplitHexDump(hexDump, 32);
        for(const auto& line : lines)
            m_logger->info("      {}", line);
        
        /* CRITICAL: Validate encryption actually occurred */
        m_logger->info("");
        m_logger->info("🔍 ENCRYPTION VALIDATION:");
        
        // Check 1: Data should be different (compare first bytes of actual ciphertext, skip nonce)
        // NOTE: This is validation code, not secret comparison. We're checking if encryption
        // worked by comparing ciphertext vs plaintext. The result is immediately logged,
        // so timing information is not sensitive. Actual crypto auth tag verification is
        // done by OpenSSL's EVP interface using constant-time comparison internally.
        bool dataMatches = false;
        size_t checkSize = std::min(size_t(64), std::min(encrypt_result.data.size(), plaintextPayload.size()));
        
        if(checkSize > 0)
        {
            // Compare ciphertext (skip 12-byte nonce) with plaintext
            dataMatches = (memcmp(encrypt_result.data.data(), plaintextPayload.data(), checkSize) == 0);
        }
        
        if(dataMatches)
        {
            m_logger->error("❌ VALIDATION FAILED: Encrypted data MATCHES plaintext!");
            m_logger->error("   This means encryption DID NOT WORK!");
            m_logger->error("   Refusing to send - node will reject anyway");
            m_logger->error("════════════════════════════════════════════════════════");
            return network::Shared_payload{};
        }
        
        // Check 2: Count matching bytes (should be very few in encrypted data)
        size_t matchingBytes = 0;
        for(size_t i = 0; i < checkSize; ++i)
        {
            if(encrypt_result.data[i] == plaintextPayload[i])
                matchingBytes++;
        }
        
        double matchPercent = (double)matchingBytes * 100.0 / checkSize;
        
        m_logger->info("   Matching bytes: {}/{} ({}%)",
                       matchingBytes, checkSize, (int)matchPercent);
        
        if(matchPercent > 30.0)
        {
            m_logger->error("❌ VALIDATION FAILED: Too many matching bytes ({}%)", (int)matchPercent);
            m_logger->error("   Encrypted data doesn't look encrypted!");
            m_logger->error("   Expected < 30% match, encryption may have failed silently");
            m_logger->error("════════════════════════════════════════════════════════");
            return network::Shared_payload{};
        }
        
        // Check 3: Heuristic check for plaintext patterns (on ciphertext, not full payload with nonce)
        if(HexUtils::LooksLikePlaintext(encrypt_result.data, 64))
        {
            m_logger->warn("⚠️  WARNING: Encrypted data has plaintext-like patterns");
            m_logger->warn("   This is suspicious - encryption may not be working");
        }
        
        m_logger->info("   ✅ VALIDATION PASSED: Data is properly encrypted");
        m_logger->info("   Encrypted data is different from plaintext");
        m_logger->info("   Safe to send to node");
        
        m_logger->info("════════════════════════════════════════════════════════");
        
        // ═══════════════════════════════════════════════════════════════════
        // CONDITIONAL OPCODE SELECTION: Use correct opcode based on protocol mode
        // ═══════════════════════════════════════════════════════════════════
        const char* protocol_name = m_stateless_protocol_active ? "STATELESS" : "LEGACY";
        const char* packet_name = m_stateless_protocol_active ? "STATELESS_SUBMIT_BLOCK" : "SUBMIT_BLOCK";
        uint16_t opcode = m_stateless_protocol_active ? 0xD00A : static_cast<uint8_t>(Packet::SUBMIT_BLOCK);
        
        // Create packet with appropriate opcode (consistent constructor usage)
        Packet packet = m_stateless_protocol_active 
            ? Packet{ static_cast<uint16_t>(Packet::STATELESS_SUBMIT_BLOCK) }  // 0xD00A for stateless protocol
            : Packet{ static_cast<uint8_t>(Packet::SUBMIT_BLOCK) };  // legacy opcode
        
        packet.m_data = std::make_shared<network::Payload>(encryptedPayload);
        packet.m_length = static_cast<uint32_t>(encryptedPayload.size());
        
        m_logger->info("📤 Submitting block via {} protocol", protocol_name);
        m_logger->info("📤 Sending encrypted {} packet (opcode: 0x{:04x}) to node...", packet_name, opcode);
        
        auto result = packet.get_bytes();
        
        if (!result || result->empty()) {
            m_logger->error("❌ {} packet encoding failed!", packet_name);
            return network::Shared_payload{};
        }
        
        // Show final wire format hex dump
        m_logger->info("[Solo Submit] {} wire format (first 128 bytes):", packet_name);
        m_logger->info("\n{}", format_llp_payload_hexdump(result, 128));
        
        return result;
    }
    catch (const std::exception& e) {
        m_logger->error("❌ Exception during encryption: {}", e.what());
        m_logger->error("════════════════════════════════════════════════════════");
        return network::Shared_payload{};
    }
}

void Solo::process_messages(Packet packet, std::shared_ptr<network::Connection> connection)  
{
    // Store connection for multi-packet authentication flow
    if (connection) {
        m_connection = connection;
    }
    
    // Check for stateless protocol timeout (protocol negotiation)
    check_stateless_protocol_timeout(connection);
    
    // Reject invalid packets at the start
    if (!packet.m_is_valid) {
        m_logger->warn("Solo::process_messages: Received invalid packet - header={}, length={}", 
            static_cast<int>(packet.m_header), packet.m_length);
        return;
    }
    
    // Log received packet for diagnostics with port information
    if (connection) {
        auto const& remote_ep = connection->remote_endpoint();
        auto const& local_ep = connection->local_endpoint();
        m_logger->info("[Solo] ══════════════════════════════════════════════");
        // Use appropriate format based on opcode type
        if (packet.m_is_uint16_opcode) {
            m_logger->info("[Solo] RECEIVED PACKET: {} (0x{:04x})", 
                get_llp_header_name(packet.m_header), packet.m_header);
        } else {
            m_logger->info("[Solo] RECEIVED PACKET: {} (0x{:02x})", 
                get_llp_header_name(static_cast<uint8_t>(packet.m_header)), 
                static_cast<uint8_t>(packet.m_header));
        }
        m_logger->info("[Solo]   Length: {} bytes", packet.m_length);
        m_logger->info("[Solo]   Remote: {} | Local: {}", 
            remote_ep.to_string(), local_ep.to_string());
        
        // TRAINING WHEELS: Show hex dump of received packet payload (first 128 bytes)
        if (packet.m_data && !packet.m_data->empty()) {
            m_logger->info("[Solo] Payload hex dump:");
            m_logger->info("\n{}", format_llp_payload_hexdump(packet.m_data, 128));
        }
        m_logger->info("[Solo] ══════════════════════════════════════════════");
    } else {
        m_logger->info("[Solo] ══════════════════════════════════════════════");
        if (packet.m_is_uint16_opcode) {
            m_logger->info("[Solo] RECEIVED PACKET: {} (0x{:04x}), length={}", 
                get_llp_header_name(packet.m_header), packet.m_header,
                packet.m_length);
        } else {
            m_logger->info("[Solo] RECEIVED PACKET: {} (0x{:02x}), length={}", 
                get_llp_header_name(static_cast<uint8_t>(packet.m_header)), 
                static_cast<uint8_t>(packet.m_header), packet.m_length);
        }
        
        // TRAINING WHEELS: Show hex dump even without connection
        if (packet.m_data && !packet.m_data->empty()) {
            m_logger->info("[Solo] Payload hex dump:");
            m_logger->info("\n{}", format_llp_payload_hexdump(packet.m_data, 128));
        }
        m_logger->info("[Solo] ══════════════════════════════════════════════");
    }
    
    if (packet.m_header == Packet::BLOCK_HEIGHT)
    {
        // Validate packet data before processing
        if (!packet.m_data || packet.m_length < 4) {
            m_logger->warn("Solo::process_messages: BLOCK_HEIGHT packet has invalid data or length < 4");
            return;
        }
        
        auto const height = bytes2uint(*packet.m_data);
        
        // Log the received height information
        m_logger->info("[Solo] Received BLOCK_HEIGHT: height={}", height);
        
        if (height > m_current_height)
        {
            m_logger->info("Nexus Network: New height {} (old height: {})", height, m_current_height);
            m_current_height = height;
            
            // After receiving height, request actual work via GET_BLOCK
            m_logger->info("[Solo] Height updated, requesting work via GET_BLOCK");
            connection->transmit(get_work());          
        }
        else
        {
            // Height is unchanged or older than current
            if (height == m_current_height) {
                m_logger->debug("[Solo] Height unchanged ({}), no action needed", height);
            } else {
                m_logger->warn("[Solo] Received older height {} (current: {})", height, m_current_height);
            }
        }
    }
    // Handle BLOCK_REWARD response
    else if (packet.m_header == Packet::BLOCK_REWARD)
    {
        // Validate packet data before processing
        if (!packet.m_data || packet.m_length < 8) {
            m_logger->warn("Solo::process_messages: BLOCK_REWARD packet has invalid data or length < 8");
            return;
        }
        
        // Parse reward using bytes2uint64 (consistent with bytes2uint - big-endian byte order)
        m_current_reward = bytes2uint64(*packet.m_data);
        
        m_logger->info("[Solo] Received BLOCK_REWARD: reward={}", m_current_reward);
    }
    // Block from wallet received
    else if(packet.m_header == Packet::BLOCK_DATA)
    {
        // Enhanced diagnostics: Check payload is non-null
        if (!packet.m_data) {
            m_logger->error("[Solo] CRITICAL: BLOCK_DATA received with null payload");
            m_logger->error("[Solo] Recovery: Requesting new work to recover from empty payload scenario");
            if (connection) {
                auto work_payload = get_work();
                if (work_payload && !work_payload->empty()) {
                    connection->transmit(work_payload);
                } else {
                    m_logger->error("[Solo] CRITICAL: Recovery failed - GET_BLOCK also returned empty payload");
                }
            }
            return;
        }
        
        // ═══════════════════════════════════════════════════════════════════
        // CRITICAL FIX: Accept BLOCK_DATA as initial template after MINER_READY
        // ═══════════════════════════════════════════════════════════════════
        // Node sends BLOCK_DATA (opcode 0) instead of STATELESS_GET_BLOCK (0xD008)
        // This fixes the 5-second timeout that causes 0.00 GIPS (no mining work)
        handle_initial_template_response("BLOCK_DATA (0x00)");
        
        // ═══════════════════════════════════════════════════════════════════
        // ENHANCED DIAGNOSTICS: Template delivery tracking
        // ═══════════════════════════════════════════════════════════════════
        m_logger->info("[Solo Template Delivery] ═══════════════════════════════════");
        m_logger->info("[Solo Template Delivery] 📥 TEMPLATE RECEIVED VIA: BLOCK_DATA (0x00)");
        m_logger->info("[Solo Template Delivery]   Delivery Method: Legacy 8-bit opcode");
        m_logger->info("[Solo Template Delivery]   Payload Size: {} bytes", packet.m_data->size());
        m_logger->info("[Solo Template Delivery]   Packet Length: {} bytes", packet.m_length);
        m_logger->info("[Solo Template Delivery]   Protocol Mode: {}", 
            m_stateless_protocol_active.load() ? "Stateless (after initial)" : "Legacy Polling");
        m_logger->info("[Solo Template Delivery] ═══════════════════════════════════");
        
        // TRAINING WHEELS: Full hex dump of BLOCK_DATA payload for debugging
        m_logger->info("[Solo] BLOCK_DATA hex dump:");
        m_logger->info("\n{}", format_llp_payload_hexdump(packet.m_data, 256));
        
        // Validate packet has minimum required data
        if (packet.m_length < MIN_BLOCK_HEADER_SIZE) {
            m_logger->error("[Solo] CRITICAL: BLOCK_DATA packet has invalid length {} < minimum {}", 
                packet.m_length, MIN_BLOCK_HEADER_SIZE);
            m_logger->error("[Solo]   - This indicates corrupted or incomplete block data");
            m_logger->error("[Solo] Recovery: Requesting new work to recover from invalid payload");
            if (connection) {
                auto work_payload = get_work();
                if (work_payload && !work_payload->empty()) {
                    connection->transmit(work_payload);
                } else {
                    m_logger->error("[Solo] CRITICAL: Recovery failed - GET_BLOCK also returned empty payload");
                }
            }
            return;
        }
        
        // Use the Mining Template Interface for unified READ/FEED operations
        // This provides reliable template verification as part of the FALCON tunnel
        std::string source_endpoint;
        if (connection) {
            source_endpoint = connection->remote_endpoint().to_string();
        }
        
        if (m_template_interface) {
            m_logger->info("[Solo READ/FEED] Processing template via Mining Template Interface");
            
            auto validation_result = m_template_interface->read_template(packet.m_data, source_endpoint);
            
            if (!validation_result.is_valid) {
                m_logger->error("[Solo READ] Template validation failed: {}", validation_result.error_message);
                
                if (validation_result.is_stale) {
                    m_logger->warn("[Solo READ] Template is stale - requesting fresh work");
                }
                
                if (connection) {
                    auto work_payload = get_work();
                    if (work_payload && !work_payload->empty()) {
                        connection->transmit(work_payload);
                    }
                }
                return;
            }
            
            m_logger->info("[Solo READ] Template validated successfully in {} μs", 
                validation_result.validation_time.count());
            
            // Get the validated template
            auto const* tmpl = m_template_interface->get_current_template();
            if (!tmpl) {
                m_logger->error("[Solo FEED] No valid template available after validation");
                return;
            }
            
            // Update height tracking
            m_current_height = tmpl->block.nHeight;
            
            // Trigger intelligent polling: template received, will poll once after 100ms
            on_template_received(tmpl->block.nHeight);
            
            // Multi-channel height tracking: Request GET_ROUND immediately to finalize template
            // Template needs channel height before it can be used for mining
            if (m_template_interface->needs_channel_height_finalization()) {
                m_logger->info("[Solo] Template pending channel height finalization - requesting GET_ROUND");
                auto round_payload = send_get_round();
                if (round_payload && !round_payload->empty() && connection) {
                    connection->transmit(round_payload);
                    m_logger->debug("[Solo] GET_ROUND request sent for channel height finalization");
                }
                // Note: Template will be finalized when OLD_ROUND/NEW_ROUND response arrives
                // Workers will receive template after finalization
            }
            
            // FEED: Dispatch to block handler
            if (!m_set_block_handler) {
                m_logger->error("[Solo FEED] CRITICAL: No block handler set - cannot process BLOCK_DATA");
                m_logger->error("[Solo FEED]   - This indicates an initialization failure");
                m_logger->error("[Solo FEED] Recovery: Block will be discarded, requesting new work");
                if (connection) {
                    auto work_payload = get_work();
                    if (work_payload && !work_payload->empty()) {
                        connection->transmit(work_payload);
                    }
                }
                return;
            }
            
            m_logger->info("[Solo FEED] Dispatching validated template to workers (height: {}, nBits: 0x{:08x})", 
                tmpl->block.nHeight, tmpl->nBits);
            m_set_block_handler(tmpl->block, tmpl->nBits);
            
            // Log template interface statistics periodically
            auto stats = m_template_interface->get_stats();
            if (stats.templates_received % 10 == 0) {
                m_logger->debug("[Solo Template Stats] Received: {}, Validated: {}, Rejected: {}, Fed: {}",
                    stats.templates_received, stats.templates_validated, 
                    stats.templates_rejected, stats.templates_fed);
            }
        }
        else {
            // Fallback: Use legacy processing if template interface not available
            m_logger->warn("[Solo] Template interface not available, using legacy processing");
            
            try {
                // Use centralized deserializer
                auto block = nexusminer::llp_utils::deserialize_block_header(*packet.m_data);
                
                // Enhanced diagnostics: Log parsed header fields
                m_logger->info("[Solo] Received block header:");
                m_logger->info("[Solo]   - nVersion: {}", block.nVersion);
                m_logger->info("[Solo]   - nChannel: {}", block.nChannel);
                m_logger->info("[Solo]   - nHeight: {}", block.nHeight);
                m_logger->info("[Solo]   - nBits: 0x{:08x}", block.nBits);
                m_logger->info("[Solo]   - nNonce: {}", block.nNonce);
                
                // Phase 2: In stateless mining, we always accept the block from GET_BLOCK response
                // Update our height tracking to match
                if (block.nHeight > m_current_height || m_authenticated)
                {
                    if (m_authenticated && block.nHeight != m_current_height) {
                        m_logger->debug("[Solo Phase 2] Stateless mining - accepting block at height {}", block.nHeight);
                    }
                    m_current_height = block.nHeight;
                    
                    // Verify block handler is set
                    if (!m_set_block_handler)
                    {
                        m_logger->error("[Solo] CRITICAL: No block handler set - cannot process BLOCK_DATA");
                        m_logger->error("[Solo]   - This indicates an initialization failure");
                        m_logger->error("[Solo] Recovery: Block will be discarded, requesting new work");
                        if (connection) {
                            auto work_payload = get_work();
                            if (work_payload && !work_payload->empty()) {
                                connection->transmit(work_payload);
                            }
                        }
                        return;
                    }
                    
                    // Invoke block handler with nBits from the block
                    m_logger->debug("[Solo] Dispatching block to handler (height: {}, nBits: 0x{:08x})", 
                        block.nHeight, block.nBits);
                    m_set_block_handler(block, block.nBits);
                }
                else
                {
                    m_logger->warn("[Solo] Block height mismatch detected:");
                    m_logger->warn("[Solo]   - Received height: {}", block.nHeight);
                    m_logger->warn("[Solo]   - Current height: {}", m_current_height);
                    m_logger->info("[Solo] Recovery: Requesting new work at current height");
                    if (connection) {
                        auto work_payload = get_work();
                        if (work_payload && !work_payload->empty()) {
                            connection->transmit(work_payload);
                        } else {
                            m_logger->error("[Solo] CRITICAL: Recovery failed - GET_BLOCK returned empty payload");
                        }
                    }
                }
            }
            catch (const std::exception& e) {
                m_logger->error("[Solo] CRITICAL: Failed to deserialize BLOCK_DATA: {}", e.what());
                m_logger->error("[Solo]   - Payload size: {} bytes", packet.m_data->size());
                m_logger->error("[Solo]   - This may indicate protocol mismatch or data corruption");
                m_logger->error("[Solo] Recovery: Requesting new work to recover from deserialization failure");
                if (connection) {
                    auto work_payload = get_work();
                    if (work_payload && !work_payload->empty()) {
                        connection->transmit(work_payload);
                    } else {
                        m_logger->error("[Solo] CRITICAL: Recovery failed - GET_BLOCK also returned empty payload");
                    }
                }
                return;
            }
        }
    }
    else if(packet.m_header == Packet::ACCEPT)
    {
        stats::Global global_stats{};
        global_stats.m_accepted_blocks = 1;
        m_stats_collector->update_global_stats(global_stats);
        m_logger->info("Block Accepted By Nexus Network.");
        
        // Enhanced diagnostics: Log connection info for accepted block
        if (connection) {
            auto const& remote_ep = connection->remote_endpoint();
            std::string remote_addr;
            remote_ep.address(remote_addr);
            uint16_t actual_port = remote_ep.port();
            m_logger->info("[Solo] Block accepted on connection {}:{}", remote_addr, actual_port);
        }
        
        // Request new work with recovery logic
        auto work_payload = get_work();
        if (!work_payload || work_payload->empty()) {
            m_logger->error("[Solo] CRITICAL: GET_BLOCK request after ACCEPT returned empty payload!");
            m_logger->error("[Solo] Recovery: Retrying work request");
            // Retry once
            work_payload = get_work();
            if (!work_payload || work_payload->empty()) {
                m_logger->error("[Solo] CRITICAL: GET_BLOCK retry also failed - mining may stall");
            } else {
                connection->transmit(work_payload);
            }
        } else {
            connection->transmit(work_payload);
        }
    }
    else if(packet.m_header == Packet::REJECT)
    {
        stats::Global global_stats{};
        global_stats.m_rejected_blocks = 1;
        m_stats_collector->update_global_stats(global_stats);
        m_logger->warn("Block Rejected by Nexus Network.");
        
        // Enhanced diagnostics: Log connection info and possible reasons
        if (connection) {
            auto const& remote_ep = connection->remote_endpoint();
            std::string remote_addr;
            remote_ep.address(remote_addr);
            uint16_t actual_port = remote_ep.port();
            m_logger->warn("[Solo] Block rejected on connection {}:{}", remote_addr, actual_port);
        }
        
        m_logger->info("[Solo] Possible rejection reasons:");
        m_logger->info("[Solo]   - Block already found by another miner (stale)");
        m_logger->info("[Solo]   - Invalid proof-of-work (nonce doesn't meet difficulty)");
        m_logger->info("[Solo]   - Blockchain reorganization occurred");
        
        // Request new work with recovery logic
        auto work_payload = get_work();
        if (!work_payload || work_payload->empty()) {
            m_logger->error("[Solo] CRITICAL: GET_BLOCK request after REJECT returned empty payload!");
            m_logger->error("[Solo] Recovery: Retrying work request");
            // Retry once
            work_payload = get_work();
            if (!work_payload || work_payload->empty()) {
                m_logger->error("[Solo] CRITICAL: GET_BLOCK retry also failed - mining may stall");
            } else {
                connection->transmit(work_payload);
            }
        } else {
            connection->transmit(work_payload);
        }
    }
    // Handle NEW_ROUND response (LLL-TAO PR #151 - 12-byte format ONLY)
    else if (packet.m_header == Packet::NEW_ROUND)
    {
        m_logger->info("[Solo GET_ROUND] NEW_ROUND response received");
        
        // ✅ STRICT VALIDATION: ONLY 12 bytes accepted
        if (!packet.m_data || packet.m_length != 12) {
            m_logger->error("[Solo GET_ROUND] ❌ PROTOCOL ERROR: Invalid packet length");
            m_logger->error("[Solo GET_ROUND]   Expected:  12 bytes (unified + channel + difficulty)");
            m_logger->error("[Solo GET_ROUND]   Received:  {} bytes", packet.m_length);
            m_logger->error("[Solo GET_ROUND]   Node may be running incompatible version");
            m_logger->error("[Solo GET_ROUND]   Required:  LLL-TAO PR #151 or later");
            return;
        }
        
        // Parse 12-byte response (all big-endian)
        uint32_t unified_height = bytes2uint(*packet.m_data, 0);
        uint32_t channel_height = bytes2uint(*packet.m_data, 4);
        uint32_t difficulty = bytes2uint(*packet.m_data, 8);
        
        // Determine channel name for logging
        std::string channel_name = get_channel_name(m_channel);
        
        // Log response details
        m_logger->info("[Solo GET_ROUND] 🔔 NEW_ROUND:");
        m_logger->info("[Solo GET_ROUND]   Unified height:  {} (reference)", unified_height);
        m_logger->info("[Solo GET_ROUND]   {} height:      {}", channel_name, channel_height);
        m_logger->info("[Solo GET_ROUND]   Difficulty:      0x{:08x}", difficulty);
        
        // Update RoundStatus
        m_last_round_status.is_new_round = true;
        m_last_round_status.height = unified_height;
        m_last_round_status.difficulty = difficulty;
        m_last_round_status.has_channel_heights = true;
        
        // Set channel-specific height based on miner's channel
        // Reset all channels first, then set only the active channel
        m_last_round_status.prime_height = 0;
        m_last_round_status.hash_height = 0;
        m_last_round_status.stake_height = 0;
        
        if (m_channel == mining::CHANNEL_PRIME) {
            m_last_round_status.prime_height = channel_height;
        } else if (m_channel == mining::CHANNEL_HASH) {
            m_last_round_status.hash_height = channel_height;
        } else {
            m_logger->error("[Solo GET_ROUND] Invalid channel: {}", m_channel);
            m_logger->error("[Solo GET_ROUND] Expected 1 (Prime) or 2 (Hash), got {}", m_channel);
            return;
        }
        
        // Use sync_template_state to handle: channel manager updates, fork detection, 
        // template finalization, and template validation
        bool template_valid = sync_template_state(unified_height, channel_height);
        
        // CRITICAL FIX: After NEW_ROUND, check if we have a valid template
        // If not, request one via GET_BLOCK (legacy fallback behavior)
        bool needs_template = !template_valid || 
                             (m_template_interface && !m_template_interface->has_valid_template());
        
        if (needs_template) {
            if (!template_valid && m_template_interface) {
                m_logger->info("[Solo GET_ROUND] ✗ Template stale, requesting fresh work");
            } else {
                m_logger->info("[Solo GET_ROUND] ℹ️  NEW_ROUND received but no template - requesting work");
                m_logger->info("[Solo GET_ROUND]   This handles legacy nodes that send NEW_ROUND without BLOCK_DATA");
            }
            
            // Request template via legacy GET_BLOCK
            if (connection) {
                auto work_payload = get_work();
                if (work_payload && !work_payload->empty()) {
                    connection->transmit(work_payload);
                    m_logger->info("[Solo GET_ROUND] ✓ GET_BLOCK request sent after NEW_ROUND");
                } else {
                    m_logger->error("[Solo GET_ROUND] Failed to generate GET_BLOCK request");
                }
            }
        } else {
            m_logger->info("[Solo GET_ROUND] ✓ Template valid, continuing to mine");
        }
        
        // Update intelligent polling state
        on_new_round_received(unified_height);
    }
    // Handle OLD_ROUND response (LLL-TAO PR #151 - 12-byte format ONLY)
    else if (packet.m_header == Packet::OLD_ROUND)
    {
        m_logger->info("[Solo GET_ROUND] OLD_ROUND response received");
        
        // ✅ STRICT VALIDATION: ONLY 12 bytes accepted
        if (!packet.m_data || packet.m_length != 12) {
            m_logger->error("[Solo GET_ROUND] ❌ PROTOCOL ERROR: Invalid packet length");
            m_logger->error("[Solo GET_ROUND]   Expected:  12 bytes");
            m_logger->error("[Solo GET_ROUND]   Received:  {} bytes", packet.m_length);
            return;
        }
        
        // Parse 12-byte response (all big-endian)
        uint32_t unified_height = bytes2uint(*packet.m_data, 0);
        uint32_t channel_height = bytes2uint(*packet.m_data, 4);
        uint32_t difficulty = bytes2uint(*packet.m_data, 8);
        
        std::string channel_name = get_channel_name(m_channel);
        
        m_logger->info("[Solo GET_ROUND] ✓ OLD_ROUND (template still valid):");
        m_logger->info("[Solo GET_ROUND]   Unified:  {}", unified_height);
        m_logger->info("[Solo GET_ROUND]   {} height: {} (unchanged)", channel_name, channel_height);
        m_logger->info("[Solo GET_ROUND]   Difficulty: 0x{:08x}", difficulty);
        
        // Update RoundStatus
        m_last_round_status.is_new_round = false;
        m_last_round_status.height = unified_height;
        m_last_round_status.difficulty = difficulty;
        m_last_round_status.has_channel_heights = true;
        
        // Set channel-specific height based on miner's channel
        // Reset all channels first, then set only the active channel
        m_last_round_status.prime_height = 0;
        m_last_round_status.hash_height = 0;
        m_last_round_status.stake_height = 0;
        
        if (m_channel == mining::CHANNEL_PRIME) {
            m_last_round_status.prime_height = channel_height;
        } else if (m_channel == mining::CHANNEL_HASH) {
            m_last_round_status.hash_height = channel_height;
        } else {
            m_logger->error("[Solo GET_ROUND] Invalid channel: {}", m_channel);
            m_logger->error("[Solo GET_ROUND] Expected 1 (Prime) or 2 (Hash), got {}", m_channel);
            return;
        }
        
        // Use sync_template_state to handle: channel manager updates, fork detection,
        // template finalization, and template validation
        bool template_valid = sync_template_state(unified_height, channel_height);
        
        if (!template_valid && m_template_interface) {
            m_logger->warn("[Solo GET_ROUND] Unexpected: Template invalidated on OLD_ROUND");
            
            // Request fresh template
            if (connection) {
                auto work_payload = get_work();
                if (work_payload && !work_payload->empty()) {
                    connection->transmit(work_payload);
                }
            }
        }
        
        // Update intelligent polling state
        on_old_round_received();
    }
    else if (packet.m_header == Packet::MINER_AUTH_CHALLENGE)
    {
        // Phase 2 Challenge-Response Protocol:
        // Handle MINER_AUTH_CHALLENGE from node and respond with signed nonce
        m_logger->info("[Solo Auth] Received MINER_AUTH_CHALLENGE from node");
        handle_miner_auth_challenge(packet);
    }
    else if (packet.m_header == Packet::MINER_AUTH_RESULT)
    {
        // Phase 2: Handle MINER_AUTH_RESULT (auth result from node)
        // The node sends: [status(1)][session_id(4, optional, LE)]
        m_logger->info("[Solo Phase 2] Received MINER_AUTH_RESULT from node");
        
        // Enhanced diagnostics: Validate packet
        if (!packet.m_data || packet.m_length < 1) {
            m_logger->error("[Solo Auth] CRITICAL: MINER_AUTH_RESULT packet has invalid data");
            m_logger->error("[Solo Auth]   - Packet data null: {}", packet.m_data == nullptr);
            m_logger->error("[Solo Auth]   - Packet length: {}", packet.m_length);
            m_logger->error("[Solo Auth] Cannot proceed - authentication protocol error");
            return;
        }
        
        bool auth_success = (*packet.m_data)[0] != 0;
        
        m_logger->info("[Solo Auth] Authentication result:");
        m_logger->info("[Solo Auth]   - Status byte: 0x{:02x} ({})", 
            (*packet.m_data)[0], auth_success ? "SUCCESS" : "FAILURE");
        m_logger->info("[Solo Auth]   - Packet length: {} bytes", packet.m_length);
        
        if (auth_success) {
            m_authenticated = true;
            
            // Extract session ID if present (4 bytes, little-endian)
            if (packet.m_length >= 5) {
                // Read little-endian uint32
                m_session_id = static_cast<uint32_t>((*packet.m_data)[1]) | 
                               (static_cast<uint32_t>((*packet.m_data)[2]) << 8) | 
                               (static_cast<uint32_t>((*packet.m_data)[3]) << 16) | 
                               (static_cast<uint32_t>((*packet.m_data)[4]) << 24);
                
                // Visual box logging for success
                std::string genesis_status = (m_session_manager && !m_session_manager->get_tritium_genesis().empty()) 
                                             ? "CONFIGURED" : "NOT CONFIGURED";
                std::string chacha20_status = m_enable_chacha20 ? "ENABLED" : "DISABLED";
                
                // Prepare formatted strings with safe alignment
                std::stringstream pubkey_line, genesis_line, chacha20_line, session_line;
                pubkey_line << "║ Public Key:  " << m_miner_pubkey.size() << " bytes";
                genesis_line << "║ Genesis:     " << genesis_status;
                chacha20_line << "║ ChaCha20:    " << chacha20_status;
                session_line << "║ Session ID:  0x" << std::hex << std::setw(8) << std::setfill('0') << m_session_id;
                
                // Calculate padding (box width = 59 chars, '║' takes 1 char at end)
                auto pad_line = [](std::stringstream& ss) -> std::string {
                    std::string line = ss.str();
                    int padding = 58 - static_cast<int>(line.length());
                    if (padding < 0) padding = 0;  // Safety: never negative
                    return line + std::string(padding, ' ') + "║";
                };
                
                m_logger->info("╔═════════════════════════════════════════════════════════╗");
                m_logger->info("║       FALCON AUTHENTICATION SUCCESSFUL                  ║");
                m_logger->info("╠═════════════════════════════════════════════════════════╣");
                m_logger->info(pad_line(pubkey_line));
                m_logger->info(pad_line(genesis_line));
                m_logger->info(pad_line(chacha20_line));
                m_logger->info(pad_line(session_line));
                m_logger->info("╚═════════════════════════════════════════════════════════╝");
                
                m_logger->debug("[Solo Auth]   - Session ID bytes (LE): {:02x} {:02x} {:02x} {:02x}",
                    (*packet.m_data)[1], (*packet.m_data)[2], (*packet.m_data)[3], (*packet.m_data)[4]);
                
                // Start session in session manager
                if (m_session_manager) {
                    m_session_manager->set_state(SessionManager::SessionState::AUTHENTICATED);
                    m_session_manager->start_session(m_session_id);
                    m_logger->info("[Solo Session] Session started in session manager");
                }
                
                // Update template interface with authenticated session ID (FALCON tunnel established)
                if (m_template_interface) {
                    m_template_interface->set_session_id(m_session_id);
                    m_logger->info("[Solo Phase 2] FALCON tunnel established - Template interface bound to session");
                }
            } else {
                m_logger->info("[Solo Phase 2] ✓ Authentication SUCCEEDED");
                m_logger->warn("[Solo Auth]   - WARNING: No session ID provided by node (expected 5 bytes, got {})", 
                    packet.m_length);
            }
            
            // Log port information for authenticated session
            if (connection) {
                auto const& remote_ep = connection->remote_endpoint();
                std::string remote_addr;
                remote_ep.address(remote_addr);
                uint16_t actual_port = remote_ep.port();
                
                m_logger->info("[Solo Phase 2] Authenticated session established on {}:{}", 
                    remote_addr, actual_port);
                m_logger->debug("[Solo] Port Validation: Authenticated mining session using LLP port {}", 
                    actual_port);
                    
                // Enhanced connection trace
                auto const& local_ep = connection->local_endpoint();
                std::string local_addr;
                local_ep.address(local_addr);
                uint16_t local_port = local_ep.port();
                m_logger->info("[Solo Connection] Session details:");
                m_logger->info("[Solo Connection]   - Local endpoint: {}:{}", local_addr, local_port);
                m_logger->info("[Solo Connection]   - Remote endpoint: {}:{}", remote_addr, actual_port);
                m_logger->info("[Solo Connection]   - Session ID: 0x{:08x}", m_session_id);
            }
            
            // Check if we have a reward address to bind
            if (!m_reward_address.empty())
            {
                m_logger->info("[Solo Phase 2] Authentication successful - binding reward address");
                m_logger->info("[Solo Phase 2] Sending MINER_SET_REWARD (required before GET_BLOCK)");
                auto reward_payload = send_set_reward();
                if (reward_payload && !reward_payload->empty() && connection)
                {
                    connection->transmit(reward_payload);
                    // Note: SET_CHANNEL and GET_BLOCK will be sent after receiving MINER_REWARD_RESULT
                    // This is handled in handle_reward_result()
                    return;
                }
                else
                {
                    // CRITICAL: Failed to send reward address - cannot proceed with mining
                    m_logger->error("[Solo Reward] CRITICAL: Failed to send reward address");
                    m_logger->error("[Solo Reward] Mining cannot proceed without reward address binding");
                    m_logger->error("[Solo Reward] This typically indicates:");
                    m_logger->error("[Solo Reward]   - Invalid reward address format");
                    m_logger->error("[Solo Reward]   - ChaCha20 encryption failure");
                    m_logger->error("[Solo Reward]   - Missing tritium genesis for encryption");
                    
                    // Close connection to prevent invalid mining state
                    if (connection) {
                        connection->close();
                    }
                    return;
                }
            }
            
            // Now send SET_CHANNEL since we're authenticated (no reward binding)
            m_logger->info("[Solo Phase 2] No reward address configured - proceeding to SET_CHANNEL");
            send_set_channel(connection);
        }
        else {
            m_authenticated = false;
            
            // Visual box logging for failure
            uint8_t error_code = (packet.m_length >= 2) ? (*packet.m_data)[1] : 0x00;
            std::string error_message;
            std::string troubleshooting;
            
            // Interpret error codes based on LLL-TAO implementation
            switch (error_code) {
                case 0x01:
                    error_message = "Public key not whitelisted";
                    troubleshooting = "Add to nexus.conf minerallowkey";
                    break;
                case 0x02:
                    error_message = "Signature verification failed";
                    troubleshooting = "Check key pair in miner.conf";
                    break;
                case 0x03:
                    error_message = "Invalid message format";
                    troubleshooting = "Check protocol version";
                    break;
                case 0x04:
                    error_message = "Timestamp out of range";
                    troubleshooting = "Synchronize system clocks";
                    break;
                default: {
                    std::stringstream ss;
                    ss << "Unknown error 0x" << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(error_code);
                    error_message = ss.str();
                    troubleshooting = "Check node logs";
                    break;
                }
            }
            
            // Prepare formatted strings with safe alignment
            std::stringstream status_line, error_line, action_line;
            status_line << "║ Status:  0x" << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>((*packet.m_data)[0]);
            error_line << "║ Error:   " << error_message;
            action_line << "║ Action:  " << troubleshooting;
            
            // Calculate padding (box width = 59 chars)
            auto pad_line = [](std::stringstream& ss) -> std::string {
                std::string line = ss.str();
                int padding = 58 - static_cast<int>(line.length());
                if (padding < 0) padding = 0;  // Safety: never negative
                return line + std::string(padding, ' ') + "║";
            };
            
            m_logger->error("╔═════════════════════════════════════════════════════════╗");
            m_logger->error("║       FALCON AUTHENTICATION FAILED                      ║");
            m_logger->error("╠═════════════════════════════════════════════════════════╣");
            m_logger->error(pad_line(status_line));
            m_logger->error(pad_line(error_line));
            m_logger->error(pad_line(action_line));
            m_logger->error("╚═════════════════════════════════════════════════════════╝");
            
            // Log authentication attempt details for debugging
            m_logger->error("[Solo Auth] Authentication attempt details:");
            m_logger->error("[Solo Auth]   - Address used: '{}'", m_address);
            m_logger->error("[Solo Auth]   - Timestamp used: {} (0x{:016x})", m_auth_timestamp, m_auth_timestamp);
            m_logger->error("[Solo Auth]   - Public key size: {} bytes", m_miner_pubkey.size());
            
            // Enhanced diagnostics: Log timestamp synchronization info
            uint64_t current_time = static_cast<uint64_t>(std::chrono::system_clock::to_time_t(std::chrono::system_clock::now()));
            int64_t time_delta = static_cast<int64_t>(current_time) - static_cast<int64_t>(m_auth_timestamp);
            m_logger->error("[Solo Auth] Timestamp synchronization check:");
            m_logger->error("[Solo Auth]   - Current time: {} (0x{:016x})", current_time, current_time);
            m_logger->error("[Solo Auth]   - Auth timestamp: {} (0x{:016x})", m_auth_timestamp, m_auth_timestamp);
            m_logger->error("[Solo Auth]   - Time delta: {} seconds", time_delta);
            if (std::abs(time_delta) > 60) {
                m_logger->error("[Solo Auth] WARNING: Large time delta detected! This may indicate clock drift or replay attack protection.");
            }
            
            // Enhanced diagnostics: Log public key fingerprint for troubleshooting
            if (m_miner_pubkey.size() >= 16) {
                m_logger->error("[Solo Auth] Public key fingerprint (first 16 bytes):");
                m_logger->error("[Solo Auth]   {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x}",
                    m_miner_pubkey[0], m_miner_pubkey[1], m_miner_pubkey[2], m_miner_pubkey[3],
                    m_miner_pubkey[4], m_miner_pubkey[5], m_miner_pubkey[6], m_miner_pubkey[7],
                    m_miner_pubkey[8], m_miner_pubkey[9], m_miner_pubkey[10], m_miner_pubkey[11],
                    m_miner_pubkey[12], m_miner_pubkey[13], m_miner_pubkey[14], m_miner_pubkey[15]);
            }
            
            m_logger->error("[Solo Auth] Possible causes:");
            m_logger->error("[Solo Auth]   - Public key not whitelisted on node (check nexus.conf -minerallowkey)");
            m_logger->error("[Solo Auth]   - Invalid key format in miner.conf (must be valid hex strings)");
            m_logger->error("[Solo Auth]   - Falcon signature verification failed (key mismatch or corruption)");
            m_logger->error("[Solo Auth]   - Node missing Phase 2 stateless miner support");
            m_logger->error("[Solo Auth]   - Timestamp drift between miner and node (check system clocks)");
            m_logger->error("[Solo Auth] Mining cannot proceed without valid authentication");
            m_logger->error("[Solo Auth] Please verify:");
            m_logger->error("[Solo Auth]   1. Your public key is whitelisted: nexus.conf -minerallowkey=<pubkey>");
            m_logger->error("[Solo Auth]   2. Keys in miner.conf match the whitelisted key");
            m_logger->error("[Solo Auth]   3. Node is running LLL-TAO with Phase 2 miner support");
            m_logger->error("[Solo Auth]   4. System clocks are synchronized between miner and node");
            
            // Connection will fail - no fallback available
        }
    }
    else if (packet.m_header == Packet::CHANNEL_ACK)
    {
        // Phase 2: Handle CHANNEL_ACK response with dynamic port detection
        m_logger->info("[Solo Phase 2] Received CHANNEL_ACK from node");
        
        // Enhanced connection trace: Log actual connected port information
        if (connection) {
            auto const& remote_ep = connection->remote_endpoint();
            auto const& local_ep = connection->local_endpoint();
            std::string remote_addr;
            std::string local_addr;
            remote_ep.address(remote_addr);
            local_ep.address(local_addr);
            uint16_t actual_port = remote_ep.port();
            uint16_t local_port = local_ep.port();
            
            m_logger->info("[Solo Connection] CHANNEL_ACK connection details:");
            m_logger->info("[Solo Connection]   - Local: {}:{}", local_addr, local_port);
            m_logger->info("[Solo Connection]   - Remote: {}:{}", remote_addr, actual_port);
            m_logger->info("[Solo] Dynamic Port Detection: Successfully connected to {}:{}", 
                remote_addr, actual_port);
            m_logger->debug("[Solo] Port Validation: Using dynamically detected LLP port {}", actual_port);
        } else {
            m_logger->warn("[Solo Connection] WARNING: Connection object is null during CHANNEL_ACK");
        }
        
        // Parse channel acknowledgment with enhanced diagnostics
        if (packet.m_data && packet.m_length >= 1) {
            uint8_t acked_channel = (*packet.m_data)[0];
            m_logger->info("[Solo] Channel acknowledged: {} ({})", 
                static_cast<int>(acked_channel), 
                (acked_channel == 1) ? "prime" : "hash");
            
            // Validate acknowledged channel matches requested channel
            if (acked_channel != m_channel) {
                m_logger->warn("[Solo] WARNING: Channel mismatch detected!");
                m_logger->warn("[Solo]   - Requested channel: {} ({})", 
                    static_cast<int>(m_channel), (m_channel == 1) ? "prime" : "hash");
                m_logger->warn("[Solo]   - Acknowledged channel: {} ({})", 
                    static_cast<int>(acked_channel), (acked_channel == 1) ? "prime" : "hash");
            }
            
            // Update template interface with confirmed channel
            if (m_template_interface) {
                m_template_interface->set_channel(acked_channel);
                m_logger->info("[Solo] Template interface updated with confirmed channel");
            }
            
            // Extended CHANNEL_ACK: Check for optional port information (future protocol enhancement)
            // Format (if extended): [channel(1)][port(2, big-endian, optional)]
            if (packet.m_length >= 3) {
                // Node is sending back port information (future enhancement)
                uint16_t node_port = (static_cast<uint16_t>((*packet.m_data)[1]) << 8) | 
                                     static_cast<uint16_t>((*packet.m_data)[2]);
                
                m_logger->info("[Solo] Extended CHANNEL_ACK: Node communicated LLP port: {}", node_port);
                
                // Validate against actual connected port
                if (connection) {
                    uint16_t actual_port = connection->remote_endpoint().port();
                    if (node_port != actual_port) {
                        m_logger->warn("[Solo] Port mismatch detected:");
                        m_logger->warn("[Solo]   - Node advertised port: {}", node_port);
                        m_logger->warn("[Solo]   - Actually connected to port: {}", actual_port);
                        m_logger->info("[Solo] Recovery: Continuing with actual connection (port {})", actual_port);
                    } else {
                        m_logger->info("[Solo] Port validation successful: Both using port {}", actual_port);
                    }
                }
            }
        } else {
            m_logger->warn("[Solo] WARNING: CHANNEL_ACK packet has no data or insufficient length");
            m_logger->warn("[Solo]   - Packet data null: {}", packet.m_data == nullptr);
            m_logger->warn("[Solo]   - Packet length: {}", packet.m_length);
        }
        
        // Verify reward address is bound before requesting work (if configured)
        if (!m_reward_address.empty() && !m_reward_bound)
        {
            m_logger->error("[Solo] Cannot GET_BLOCK - reward address not bound yet");
            m_logger->error("[Solo] This indicates a protocol flow error:");
            m_logger->error("[Solo]   - MINER_REWARD_RESULT may have been lost or not received");
            m_logger->error("[Solo]   - SET_CHANNEL sent before reward binding completed");
            m_logger->error("[Solo]   - Network issue during reward binding handshake");
            m_logger->error("[Solo] Expected flow: Auth → MINER_SET_REWARD → MINER_REWARD_RESULT → SET_CHANNEL → CHANNEL_ACK → GET_BLOCK");
            m_logger->error("[Solo] Recovery: Disconnect and reconnect to retry authentication");
            
            // Close connection to force re-authentication
            if (connection) {
                connection->close();
            }
            return;
        }
        
        // Push notifications: Subscribe to block notifications (LLL-TAO PR #156)
        // Attempt stateless protocol (0xD007 MINER_READY)
        m_logger->info("[Solo Protocol] Attempting stateless protocol negotiation");
        m_logger->info("[Solo Protocol] Sending MINER_READY (0xD007) to subscribe to push notifications");
        
        auto miner_ready_payload = send_miner_ready();
        if (!miner_ready_payload || miner_ready_payload->empty()) {
            m_logger->error("[Solo Protocol] Failed to encode MINER_READY - falling back to polling");
        } else if (connection) {
            connection->transmit(miner_ready_payload);
            
            // Set waiting flags for protocol negotiation
            m_waiting_for_stateless_response = true;
            m_miner_ready_sent_time_ns = std::chrono::steady_clock::now().time_since_epoch().count();
            
            m_logger->info("[Solo Protocol] ✓ MINER_READY transmitted");
            m_logger->info("[Solo Protocol] Waiting for STATELESS_GET_BLOCK (0xD008) response...");
            m_logger->info("[Solo Protocol] Timeout: {} seconds", STATELESS_PROTOCOL_TIMEOUT_SECONDS);
            m_logger->info("[Solo Protocol] If timeout: Fall back to legacy GET_ROUND polling");
            
            // Return here - we'll wait for either:
            // 1. STATELESS_GET_BLOCK (0xD008) - stateless protocol success
            // 2. Timeout - fall back to legacy polling (handled in process_messages)
            return;
        } else {
            m_logger->error("[Solo Protocol] No connection available - cannot send MINER_READY");
        }
        
        // Fallback: Request work directly if MINER_READY failed
        m_logger->warn("[Solo Protocol] MINER_READY transmission failed - using legacy GET_BLOCK");
        m_logger->debug("[Solo Phase 2] Pre-GET_BLOCK state:");
        m_logger->debug("[Solo Phase 2]   - Connection valid: {}", connection ? "YES" : "NO");
        m_logger->debug("[Solo Phase 2]   - Session ID: 0x{:08x}", m_session_id);
        m_logger->debug("[Solo Phase 2]   - Authenticated: {}", m_authenticated ? "YES" : "NO");
        auto work_payload = get_work();
        if (!work_payload || work_payload->empty()) {
            m_logger->error("[Solo] CRITICAL: GET_BLOCK request returned empty payload!");
            m_logger->error("[Solo] This may indicate a packet encoding issue");
        } else if (connection) {
            connection->transmit(work_payload);
            m_logger->info("[Solo] GET_BLOCK transmitted successfully");
        } else {
            m_logger->error("[Solo] No connection available - cannot request work");
        }
    }
    else if (packet.m_header == Packet::SESSION_START)
    {
        // LLL-TAO PR #22: Handle SESSION_START for session management
        m_logger->info("[Solo Session] Received SESSION_START from node");
        
        if (packet.m_data && packet.m_length >= 4) {
            // Parse session timeout (4 bytes, little-endian)
            uint32_t session_timeout = (*packet.m_data)[0] |
                                       ((*packet.m_data)[1] << 8) |
                                       ((*packet.m_data)[2] << 16) |
                                       ((*packet.m_data)[3] << 24);
            
            m_logger->info("[Solo Session] Session parameters:");
            m_logger->info("[Solo Session]   - Timeout: {} seconds", session_timeout);
            m_logger->info("[Solo Session]   - Session ID: 0x{:08x}", m_session_id);
            
            // Parse optional genesis hash if present (32 bytes)
            if (packet.m_length >= 36) {
                m_logger->info("[Solo Session] GenesisHash reward mapping received");
            }
        }
    }
    else if (packet.m_header == Packet::SESSION_START)
    {
        // LLL-TAO PR #22: Handle SESSION_START (session parameters from node)
        // Format: [timeout(4, LE)][optional: session_key][optional: genesis_hash(32)]
        m_logger->info("[Solo Session] Received SESSION_START from node");
        
        if (packet.m_data && packet.m_length >= 4) {
            // Parse session timeout (4 bytes, little-endian)
            uint32_t session_timeout = (*packet.m_data)[0] |
                                      ((*packet.m_data)[1] << 8) |
                                      ((*packet.m_data)[2] << 16) |
                                      ((*packet.m_data)[3] << 24);
            
            m_logger->info("[Solo Session] Session parameters:");
            m_logger->info("[Solo Session]   - Timeout: {} seconds ({} hours)", 
                          session_timeout, session_timeout / 3600);
            
            // Extract optional session key (if present)
            std::vector<uint8_t> session_key;
            if (packet.m_length > 36) {  // timeout(4) + key(32) + genesis(32) minimum
                // Session key is 32 bytes after timeout
                session_key.assign(packet.m_data->begin() + 4, 
                                 packet.m_data->begin() + 36);
                m_logger->info("[Solo Session]   - Falcon Session Key received: {} bytes", 
                              session_key.size());
                
                // Extract optional genesis hash
                if (packet.m_length >= 68) {  // timeout(4) + key(32) + genesis(32)
                    std::vector<uint8_t> node_genesis(packet.m_data->begin() + 36,
                                                      packet.m_data->begin() + 68);
                    m_logger->info("[Solo Session]   - Tritium Genesis from node: {} bytes",
                                  node_genesis.size());
                }
            }
            
            // Update session manager with session key
            if (m_session_manager && !session_key.empty()) {
                m_session_manager->start_session(m_session_id, session_key, 
                                               m_session_manager->get_tritium_genesis());
                m_logger->info("[Solo Session] Session updated with Falcon Session Key");
            }
            
            // Adjust keepalive interval based on timeout (conservative: ping at 1/3 of timeout)
            if (session_timeout > 0 && m_session_manager) {
                uint16_t keepalive_hours = std::max(1u, session_timeout / (3 * 3600));
                m_session_manager->set_keepalive_interval(keepalive_hours);
                m_logger->info("[Solo Session] Keepalive interval adjusted to {} hours based on timeout",
                              keepalive_hours);
            }
        } else {
            m_logger->warn("[Solo Session] SESSION_START packet has invalid or insufficient data");
        }
    }
    else if (packet.m_header == Packet::SESSION_KEEPALIVE)
    {
        // LLL-TAO PR #22: Handle SESSION_KEEPALIVE response
        m_logger->debug("[Solo Session] Received SESSION_KEEPALIVE response");
        
        if (packet.m_data && packet.m_length >= 4) {
            // Parse remaining timeout (4 bytes, little-endian)
            uint32_t remaining_timeout = (*packet.m_data)[0] |
                                         ((*packet.m_data)[1] << 8) |
                                         ((*packet.m_data)[2] << 16) |
                                         ((*packet.m_data)[3] << 24);
            
            m_logger->debug("[Solo Session] Session keepalive acknowledged - {} seconds remaining", remaining_timeout);
            
            // Record keepalive in session manager
            if (m_session_manager) {
                m_session_manager->record_keepalive();
            }
        }
    }
    else if (packet.m_header == Packet::MINER_REWARD_RESULT)
    {
        // Phase 2: Handle MINER_REWARD_RESULT (reward binding result from node)
        handle_reward_result(packet);
    }
    else if (packet.m_header == Packet::PRIME_BLOCK_AVAILABLE)
    {
        m_logger->info("[Solo Push] ✉️  PRIME_BLOCK_AVAILABLE received");
        
        /* Validate channel (should only receive if mining Prime) */
        if (m_channel != mining::CHANNEL_PRIME)
        {
            m_logger->error("[Solo Push] ❌ Received PRIME_BLOCK_AVAILABLE but mining {} channel!",
                          m_channel == mining::CHANNEL_HASH ? "Hash" : "Unknown");
            m_logger->error("[Solo Push]    This should never happen (node filters by channel)");
            return;  // Protocol error
        }
        
        /* Validate packet length */
        if (!packet.m_data || packet.m_length != PUSH_NOTIFICATION_PAYLOAD_SIZE)
        {
            m_logger->error("[Solo Push] Invalid packet length: {} (expected {})", 
                          packet.m_length, PUSH_NOTIFICATION_PAYLOAD_SIZE);
            return;
        }
        
        /* Parse notification (big-endian) */
        uint32_t unified_height = bytes2uint(*packet.m_data, PUSH_NOTIFICATION_UNIFIED_HEIGHT_OFFSET);
        uint32_t prime_height = bytes2uint(*packet.m_data, PUSH_NOTIFICATION_CHANNEL_HEIGHT_OFFSET);
        uint32_t difficulty = bytes2uint(*packet.m_data, PUSH_NOTIFICATION_DIFFICULTY_OFFSET);
        
        m_logger->info("[Solo Push]   Unified height: {}", unified_height);
        m_logger->info("[Solo Push]   Prime height:   {}", prime_height);
        m_logger->info("[Solo Push]   Difficulty:     0x{:08x}", difficulty);
        
        /* Check if current template is stale */
        if (m_template_interface && m_template_interface->has_valid_template())
        {
            auto const* tmpl = m_template_interface->get_current_template();
            if (tmpl)
            {
                uint32_t current_prime_height = tmpl->nChannelHeight;
                uint32_t current_unified_height = tmpl->block.nHeight;
                
                m_logger->debug("[Solo Push] Current template: unified={}, prime={}", 
                              current_unified_height, current_prime_height);
                
                if (prime_height > current_prime_height)
                {
                    m_logger->info("[Solo Push] ✗ Template stale (was mining {}, new block {})", 
                                 current_prime_height, prime_height);
                    m_logger->info("[Solo Push] Requesting fresh Prime template...");
                    
                    if (connection) {
                        connection->transmit(get_work());
                    }
                }
                else if (prime_height == current_prime_height && unified_height > current_unified_height)
                {
                    m_logger->info("[Solo Push] ✓ Prime unchanged, unified advanced ({} → {})", 
                                 current_unified_height, unified_height);
                    // Continue mining current template
                }
                else
                {
                    m_logger->debug("[Solo Push] ✓ Template still valid");
                }
            }
        }
        else
        {
            /* No template yet - request one */
            m_logger->info("[Solo Push] No template - requesting initial Prime template");
            if (connection) {
                connection->transmit(get_work());
            }
        }
    }
    else if (packet.m_header == Packet::HASH_BLOCK_AVAILABLE)
    {
        m_logger->info("[Solo Push] ✉️  HASH_BLOCK_AVAILABLE received");
        
        /* Validate channel */
        if (m_channel != mining::CHANNEL_HASH)
        {
            m_logger->error("[Solo Push] ❌ Received HASH_BLOCK_AVAILABLE but mining {} channel!",
                          m_channel == mining::CHANNEL_PRIME ? "Prime" : "Unknown");
            return;
        }
        
        /* Validate packet */
        if (!packet.m_data || packet.m_length != PUSH_NOTIFICATION_PAYLOAD_SIZE)
        {
            m_logger->error("[Solo Push] Invalid packet length: {} (expected {})", 
                          packet.m_length, PUSH_NOTIFICATION_PAYLOAD_SIZE);
            return;
        }
        
        /* Parse notification (big-endian) */
        uint32_t unified_height = bytes2uint(*packet.m_data, PUSH_NOTIFICATION_UNIFIED_HEIGHT_OFFSET);
        uint32_t hash_height = bytes2uint(*packet.m_data, PUSH_NOTIFICATION_CHANNEL_HEIGHT_OFFSET);
        uint32_t difficulty = bytes2uint(*packet.m_data, PUSH_NOTIFICATION_DIFFICULTY_OFFSET);
        
        m_logger->info("[Solo Push]   Unified height: {}", unified_height);
        m_logger->info("[Solo Push]   Hash height:    {}", hash_height);
        m_logger->info("[Solo Push]   Difficulty:     0x{:08x}", difficulty);
        
        /* Check template staleness */
        if (m_template_interface && m_template_interface->has_valid_template())
        {
            auto const* tmpl = m_template_interface->get_current_template();
            if (tmpl)
            {
                uint32_t current_hash_height = tmpl->nChannelHeight;
                uint32_t current_unified_height = tmpl->block.nHeight;
                
                m_logger->debug("[Solo Push] Current template: unified={}, hash={}", 
                              current_unified_height, current_hash_height);
                
                if (hash_height > current_hash_height)
                {
                    m_logger->info("[Solo Push] ✗ Template stale - requesting fresh Hash template");
                    if (connection) {
                        connection->transmit(get_work());
                    }
                }
                else if (hash_height == current_hash_height && unified_height > current_unified_height)
                {
                    m_logger->info("[Solo Push] ✓ Hash unchanged, unified advanced ({} → {})", 
                                 current_unified_height, unified_height);
                    // Continue mining current template
                }
                else
                {
                    m_logger->debug("[Solo Push] ✓ Template still valid");
                }
            }
        }
        else
        {
            m_logger->info("[Solo Push] Requesting initial Hash template");
            if (connection) {
                connection->transmit(get_work());
            }
        }
    }
    // ═══════════════════════════════════════════════════════════════════════
    // NEW STATELESS MINING PROTOCOL HANDLERS (uint16_t opcodes, 0xD000+)
    // ═══════════════════════════════════════════════════════════════════════
    else if (packet.m_header == Packet::STATELESS_GET_BLOCK)
    {
        // ═══════════════════════════════════════════════════════════════════
        // STATELESS PROTOCOL AUTO-NEGOTIATION: Success!
        // ═══════════════════════════════════════════════════════════════════
        
        // Unified handler for initial template response
        handle_initial_template_response("STATELESS_GET_BLOCK (0xD008)");
        
        // ═══════════════════════════════════════════════════════════════════
        // ENHANCED DIAGNOSTICS: Template delivery tracking
        // ═══════════════════════════════════════════════════════════════════
        m_logger->info("[Solo Template Delivery] ═══════════════════════════════════");
        m_logger->info("[Solo Template Delivery] 📥 TEMPLATE RECEIVED VIA: STATELESS_GET_BLOCK (0xD008)");
        m_logger->info("[Solo Template Delivery]   Delivery Method: Stateless 16-bit opcode");
        m_logger->info("[Solo Template Delivery]   Payload Size: {} bytes", packet.m_length);
        m_logger->info("[Solo Template Delivery]   Expected Format: 12 metadata + 216 block");
        m_logger->info("[Solo Template Delivery]   Protocol Mode: Stateless Push");
        m_logger->info("[Solo Template Delivery] ═══════════════════════════════════");
        
        m_logger->info("[Solo Stateless] ✨ STATELESS_GET_BLOCK (0xD008) received!");
        m_logger->info("[Solo Stateless] This is the NEW push notification protocol");
        m_logger->info("[Solo Stateless] Template size: {} bytes (expected: 228)", packet.m_length);
        
        // Validate 228-byte template format (12 metadata + 216 block)
        constexpr size_t TEMPLATE_SIZE = 228;
        constexpr size_t METADATA_SIZE = 12;
        constexpr size_t BLOCK_SIZE = 216;
        
        if (!packet.m_data || packet.m_length != TEMPLATE_SIZE) {
            m_logger->error("[Solo Stateless] Invalid template size: {} (expected {})", 
                           packet.m_length, TEMPLATE_SIZE);
            return;
        }
        
        // ═══════════════════════════════════════════════════════════════════
        // CRITICAL VERIFICATION: Is metadata HOT (inserted on wire) or part of block?
        // ═══════════════════════════════════════════════════════════════════
        m_logger->info("[Solo Stateless] ═══════════════════════════════════════");
        m_logger->info("[Solo Stateless] ⚠️  CRITICAL ASSUMPTION VERIFICATION");
        m_logger->info("[Solo Stateless] Template format: 228 bytes = 12 metadata + 216 block");
        m_logger->info("[Solo Stateless] Assumption: Node sends HOT metadata (prepended on wire)");
        m_logger->info("[Solo Stateless]   - Bytes 0-11:   Metadata (unified_height, channel_height, difficulty)");
        m_logger->info("[Solo Stateless]   - Bytes 12-227: Block template (216-byte Tritium format)");
        m_logger->info("[Solo Stateless] Alternative: Metadata extracted from block fields (nHeight, nBits)");
        m_logger->info("[Solo Stateless] ═══════════════════════════════════════");
        
        // ═══════════════════════════════════════════════════════════════════
        // VALIDATION: Dump raw metadata bytes for format verification
        // ═══════════════════════════════════════════════════════════════════
        m_logger->info("[Solo Stateless] 📦 RAW METADATA (First 12 bytes of 228-byte payload)");
        m_logger->info("[Solo Stateless] Hex dump of metadata:");
        std::string metadata_hex;
        for (size_t i = 0; i < METADATA_SIZE && i < packet.m_data->size(); ++i) {
            char buf[4];
            snprintf(buf, sizeof(buf), "%02x ", (*packet.m_data)[i]);
            metadata_hex += buf;
            if ((i + 1) % 4 == 0) metadata_hex += " | ";  // Group by uint32
        }
        m_logger->info("[Solo Stateless]   {}", metadata_hex);
        
        // Also show first 32 bytes of block template for comparison
        m_logger->info("[Solo Stateless] 📦 RAW BLOCK START (Bytes 12-43 of 228-byte payload)");
        std::string block_hex;
        for (size_t i = METADATA_SIZE; i < METADATA_SIZE + 32 && i < packet.m_data->size(); ++i) {
            char buf[4];
            snprintf(buf, sizeof(buf), "%02x ", (*packet.m_data)[i]);
            block_hex += buf;
            if ((i - METADATA_SIZE + 1) % 8 == 0) block_hex += " | ";
        }
        m_logger->info("[Solo Stateless]   {}", block_hex);
        m_logger->info("[Solo Stateless] Expected block start: nVersion (4 bytes) = first uint32 shown above");
        m_logger->info("[Solo Stateless] ═══════════════════════════════════════");
        
        // Parse 12-byte metadata (big-endian per LLL-TAO PR #170)
        uint32_t unified_height = bytes2uint(*packet.m_data, 0);
        uint32_t channel_height = bytes2uint(*packet.m_data, 4);
        uint32_t difficulty = bytes2uint(*packet.m_data, 8);
        
        m_logger->info("[Solo Stateless] ═══════════════════════════════════════");
        m_logger->info("[Solo Stateless] 📦 PARSED TEMPLATE METADATA");
        m_logger->info("[Solo Stateless]   Unified height: {} (0x{:08x})", unified_height, unified_height);
        m_logger->info("[Solo Stateless]   Channel height: {} (0x{:08x})", channel_height, channel_height);
        m_logger->info("[Solo Stateless]   Difficulty:     0x{:08x} ({})", difficulty, difficulty);
        m_logger->info("[Solo Stateless]   Block size:     {} bytes", BLOCK_SIZE);
        
        // ═══════════════════════════════════════════════════════════════════
        // SANITY CHECKS: Validate parsed values are reasonable
        // ═══════════════════════════════════════════════════════════════════
        bool validation_warnings = false;
        
        if (unified_height == 0) {
            m_logger->warn("[Solo Stateless] ⚠️  Unified height is 0 - unusual but possible for genesis");
            validation_warnings = true;
        }
        if (unified_height > 100000000) {
            m_logger->error("[Solo Stateless] ❌ Unified height {} exceeds reasonable limit - possible byte order issue!", 
                           unified_height);
            validation_warnings = true;
        }
        
        if (channel_height == 0) {
            m_logger->warn("[Solo Stateless] ⚠️  Channel height is 0 - unusual but possible for genesis");
            validation_warnings = true;
        }
        if (channel_height > unified_height) {
            m_logger->error("[Solo Stateless] ❌ Channel height {} > unified height {} - invalid!", 
                           channel_height, unified_height);
            validation_warnings = true;
        }
        if (channel_height > 100000000) {
            m_logger->error("[Solo Stateless] ❌ Channel height {} exceeds reasonable limit - possible byte order issue!", 
                           channel_height);
            validation_warnings = true;
        }
        
        if (difficulty == 0) {
            m_logger->error("[Solo Stateless] ❌ Difficulty is 0 - invalid!");
            validation_warnings = true;
        }
        
        if (validation_warnings) {
            m_logger->warn("[Solo Stateless] ⚠️  VALIDATION WARNINGS DETECTED - verify metadata format with LLL-TAO PR #170");
            m_logger->warn("[Solo Stateless] ⚠️  Current parsing assumes: [unified_height(4)][channel_height(4)][difficulty(4)] in BIG-ENDIAN");
        } else {
            m_logger->info("[Solo Stateless] ✅ Metadata validation passed - values appear reasonable");
        }
        m_logger->info("[Solo Stateless] ═══════════════════════════════════════");
        
        // Extract 216-byte block template
        std::vector<uint8_t> block_template(packet.m_data->begin() + METADATA_SIZE,
                                             packet.m_data->end());
        
        if (block_template.size() != BLOCK_SIZE) {
            m_logger->error("[Solo Stateless] Block size mismatch: {} (expected {})",
                           block_template.size(), BLOCK_SIZE);
            return;
        }
        
        // Process the block template using existing infrastructure
        // The block_template contains the serialized block data
        m_logger->info("[Solo Stateless] Processing 216-byte block template...");
        
        // ═══════════════════════════════════════════════════════════════════
        // VERIFICATION: Confirm read_template can parse 216-byte Tritium blocks
        // ═══════════════════════════════════════════════════════════════════
        m_logger->info("[Solo Stateless] Verifying 216-byte Tritium block format:");
        m_logger->info("[Solo Stateless]   - Block size: {} bytes (Tritium format)", block_template.size());
        m_logger->info("[Solo Stateless]   - read_template supports: 92 (Compact), 216 (Tritium), 220+ (Legacy)");
        m_logger->info("[Solo Stateless]   - Expected: parse_block_header will deserialize as Tritium");
        
        // Feed to the template interface (same as BLOCK_DATA handling)
        if (m_template_interface) {
            auto block_payload = std::make_shared<network::Payload>(block_template);
            auto validation_result = m_template_interface->read_template(block_payload, 
                connection ? connection->remote_endpoint().to_string() : "unknown");
            
            if (!validation_result.is_valid) {
                m_logger->error("[Solo Stateless] Template validation failed: {}", 
                               validation_result.error_message);
                m_logger->error("[Solo Stateless] This may indicate block format mismatch or parsing issue");
                return;
            }
            
            m_logger->info("[Solo Stateless] ✅ Template validated in {} μs", 
                          validation_result.validation_time.count());
            m_logger->info("[Solo Stateless] ✅ read_template successfully parsed 216-byte Tritium block");
            
            // Update height tracking
            m_current_height = unified_height;
            
            // Set channel height on the template
            m_template_interface->set_channel_height(channel_height);
            
            // Template is now ready for mining!
            m_logger->info("[Solo Stateless] 🎯 Template ready for mining!");
            m_logger->info("[Solo Stateless] Mining for block height: {} (channel: {})",
                          unified_height, channel_height);
        }
        else {
            m_logger->error("[Solo Stateless] No template interface available!");
        }
    }
    else if (packet.m_header == Packet::STATELESS_NEW_BLOCK)
    {
        // Confirm stateless protocol is active (should already be, but safety check)
        m_stateless_protocol_active = true;
        
        // ═══════════════════════════════════════════════════════════════════
        // ENHANCED DIAGNOSTICS: Template delivery tracking
        // ═══════════════════════════════════════════════════════════════════
        m_logger->info("[Solo Template Delivery] ═══════════════════════════════════");
        m_logger->info("[Solo Template Delivery] 📥 TEMPLATE RECEIVED VIA: STATELESS_NEW_BLOCK (0xD009)");
        m_logger->info("[Solo Template Delivery]   Delivery Method: Stateless 16-bit opcode (push notification)");
        m_logger->info("[Solo Template Delivery]   Payload Size: {} bytes", packet.m_length);
        m_logger->info("[Solo Template Delivery]   Expected Format: 12 metadata + 216 block");
        m_logger->info("[Solo Template Delivery]   Protocol Mode: Stateless Push (network advanced)");
        m_logger->info("[Solo Template Delivery] ═══════════════════════════════════");
        
        m_logger->info("[Solo Stateless] 🔔 STATELESS_NEW_BLOCK (0xD009) received!");
        m_logger->info("[Solo Stateless] Network has advanced - NEW template pushed!");
        
        // Validate 228-byte template format (12 metadata + 216 block)
        constexpr size_t TEMPLATE_SIZE = 228;
        constexpr size_t METADATA_SIZE = 12;
        constexpr size_t BLOCK_SIZE = 216;
        
        if (!packet.m_data || packet.m_length != TEMPLATE_SIZE) {
            m_logger->error("[Solo Stateless] Invalid template size: {} (expected {})",
                           packet.m_length, TEMPLATE_SIZE);
            return;
        }
        
        // ═══════════════════════════════════════════════════════════════════
        // CRITICAL VERIFICATION: Is metadata HOT (inserted on wire) or part of block?
        // ═══════════════════════════════════════════════════════════════════
        m_logger->info("[Solo Stateless] ═══════════════════════════════════════");
        m_logger->info("[Solo Stateless] ⚠️  CRITICAL ASSUMPTION VERIFICATION (NEW_BLOCK)");
        m_logger->info("[Solo Stateless] Template format: 228 bytes = 12 metadata + 216 block");
        m_logger->info("[Solo Stateless] Assumption: Node sends HOT metadata (prepended on wire)");
        m_logger->info("[Solo Stateless]   - Bytes 0-11:   Metadata (unified_height, channel_height, difficulty)");
        m_logger->info("[Solo Stateless]   - Bytes 12-227: Block template (216-byte Tritium format)");
        m_logger->info("[Solo Stateless] ═══════════════════════════════════════");
        
        // ═══════════════════════════════════════════════════════════════════
        // VALIDATION: Dump raw metadata bytes for format verification
        // ═══════════════════════════════════════════════════════════════════
        m_logger->info("[Solo Stateless] 📦 RAW METADATA (First 12 bytes of 228-byte payload)");
        m_logger->info("[Solo Stateless] Hex dump of metadata:");
        std::string metadata_hex;
        for (size_t i = 0; i < METADATA_SIZE && i < packet.m_data->size(); ++i) {
            char buf[4];
            snprintf(buf, sizeof(buf), "%02x ", (*packet.m_data)[i]);
            metadata_hex += buf;
            if ((i + 1) % 4 == 0) metadata_hex += " | ";  // Group by uint32
        }
        m_logger->info("[Solo Stateless]   {}", metadata_hex);
        
        // Also show first 32 bytes of block template for comparison
        m_logger->info("[Solo Stateless] 📦 RAW BLOCK START (Bytes 12-43 of 228-byte payload)");
        std::string block_hex;
        for (size_t i = METADATA_SIZE; i < METADATA_SIZE + 32 && i < packet.m_data->size(); ++i) {
            char buf[4];
            snprintf(buf, sizeof(buf), "%02x ", (*packet.m_data)[i]);
            block_hex += buf;
            if ((i - METADATA_SIZE + 1) % 8 == 0) block_hex += " | ";
        }
        m_logger->info("[Solo Stateless]   {}", block_hex);
        m_logger->info("[Solo Stateless] Expected block start: nVersion (4 bytes) = first uint32 shown above");
        m_logger->info("[Solo Stateless] ═══════════════════════════════════════");
        
        // Parse 12-byte metadata (big-endian per LLL-TAO PR #170)
        uint32_t unified_height = bytes2uint(*packet.m_data, 0);
        uint32_t channel_height = bytes2uint(*packet.m_data, 4);
        uint32_t difficulty = bytes2uint(*packet.m_data, 8);
        
        m_logger->info("[Solo Stateless] ═══════════════════════════════════════");
        m_logger->info("[Solo Stateless] 🆕 NETWORK UPDATE (Push Notification)");
        m_logger->info("[Solo Stateless]   New unified height: {} (0x{:08x})", unified_height, unified_height);
        m_logger->info("[Solo Stateless]   New channel height: {} (0x{:08x})", channel_height, channel_height);
        m_logger->info("[Solo Stateless]   New difficulty:     0x{:08x} ({})", difficulty, difficulty);
        
        // ═══════════════════════════════════════════════════════════════════
        // SANITY CHECKS: Validate parsed values are reasonable
        // ═══════════════════════════════════════════════════════════════════
        bool validation_warnings = false;
        
        if (unified_height == 0) {
            m_logger->warn("[Solo Stateless] ⚠️  Unified height is 0 - unusual for NEW_BLOCK");
            validation_warnings = true;
        }
        if (unified_height > 100000000) {
            m_logger->error("[Solo Stateless] ❌ Unified height {} exceeds reasonable limit - possible byte order issue!", 
                           unified_height);
            validation_warnings = true;
        }
        
        if (channel_height > unified_height) {
            m_logger->error("[Solo Stateless] ❌ Channel height {} > unified height {} - invalid!", 
                           channel_height, unified_height);
            validation_warnings = true;
        }
        if (channel_height > 100000000) {
            m_logger->error("[Solo Stateless] ❌ Channel height {} exceeds reasonable limit - possible byte order issue!", 
                           channel_height);
            validation_warnings = true;
        }
        
        if (difficulty == 0) {
            m_logger->error("[Solo Stateless] ❌ Difficulty is 0 - invalid!");
            validation_warnings = true;
        }
        
        // ═══════════════════════════════════════════════════════════════════
        // EDGE CASE HANDLING: Reject stale or duplicate NEW_BLOCK pushes
        // ═══════════════════════════════════════════════════════════════════
        
        // Check if heights advanced (they should for NEW_BLOCK)
        if (m_current_height > 0 && unified_height <= m_current_height) {
            m_logger->warn("[Solo Stateless] ⚠️  NEW_BLOCK unified height {} not greater than current {} - possible stale/duplicate push",
                          unified_height, m_current_height);
            
            // Reject stale templates to avoid wasted mining effort
            if (unified_height < m_current_height) {
                m_logger->error("[Solo Stateless] ❌ REJECTING stale NEW_BLOCK (height {} < current {})",
                               unified_height, m_current_height);
                m_logger->error("[Solo Stateless] This may indicate network glitch or node issue");
                return;
            }
            
            // Equal height = duplicate push, warn but continue (might be valid reorg)
            if (unified_height == m_current_height) {
                m_logger->warn("[Solo Stateless] ⚠️  Duplicate NEW_BLOCK at same height {} - continuing (possible reorg)",
                              unified_height);
                m_logger->warn("[Solo Stateless] Consider tracking template hash to detect true duplicates");
            }
        }
        
        if (validation_warnings) {
            m_logger->warn("[Solo Stateless] ⚠️  VALIDATION WARNINGS DETECTED - verify metadata format with LLL-TAO PR #170");
            m_logger->warn("[Solo Stateless] ⚠️  Current parsing assumes: [unified_height(4)][channel_height(4)][difficulty(4)] in BIG-ENDIAN");
        } else {
            m_logger->info("[Solo Stateless] ✅ Metadata validation passed - values appear reasonable");
        }
        m_logger->info("[Solo Stateless] ═══════════════════════════════════════");
        
        // CRITICAL: Abandon current work and switch to new template!
        m_logger->warn("[Solo Stateless] ⚠️  Abandoning current work (network advanced)");
        
        // Extract 216-byte block template
        std::vector<uint8_t> block_template(packet.m_data->begin() + METADATA_SIZE,
                                             packet.m_data->end());
        
        if (block_template.size() != BLOCK_SIZE) {
            m_logger->error("[Solo Stateless] Block size mismatch: {} (expected {})",
                           block_template.size(), BLOCK_SIZE);
            return;
        }
        
        // Discard old template and process new one
        m_logger->info("[Solo Stateless] Processing NEW 216-byte block template...");
        m_logger->info("[Solo Stateless]   - Block size: {} bytes (Tritium format)", block_template.size());
        
        if (m_template_interface) {
            m_template_interface->discard_template("Network advanced (NEW_BLOCK push)");
            
            auto block_payload = std::make_shared<network::Payload>(block_template);
            auto validation_result = m_template_interface->read_template(block_payload,
                connection ? connection->remote_endpoint().to_string() : "unknown");
            
            if (!validation_result.is_valid) {
                m_logger->error("[Solo Stateless] New template validation failed: {}",
                               validation_result.error_message);
                m_logger->error("[Solo Stateless] This may indicate block format mismatch or parsing issue");
                return;
            }
            
            m_logger->info("[Solo Stateless] ✅ New template validated in {} μs",
                          validation_result.validation_time.count());
            m_logger->info("[Solo Stateless] ✅ read_template successfully parsed 216-byte Tritium block");
            
            // Update height tracking
            m_current_height = unified_height;
            
            // Set channel height on the template
            m_template_interface->set_channel_height(channel_height);
            
            m_logger->info("[Solo Stateless] ✅ Switched to new template - resumed mining!");
        }
        else {
            m_logger->error("[Solo Stateless] No template interface available!");
        }
    }
    else
    {
        m_logger->debug("Invalid header received: 0x{:04x}", packet.m_header);
    } 
}

void Solo::set_miner_keys(std::vector<uint8_t> const& pubkey, std::vector<uint8_t> const& privkey)
{
    m_miner_pubkey = pubkey;
    m_miner_privkey = privkey;
    
    // Detect Falcon version from key size
    bool is_falcon1024 = (pubkey.size() == FalconConstants::FALCON1024_PUBKEY_SIZE);
    std::string version = is_falcon1024 ? "Falcon-1024" : "Falcon-512";
    size_t expected_sig_size = is_falcon1024 ? 
        FalconConstants::FALCON1024_SIG_CT_SIZE : FalconConstants::FALCON512_SIG_CT_SIZE;
    
    m_logger->info("[Solo] Miner {} keys configured", version);
    m_logger->info("[Solo]   Public key:  {} bytes", pubkey.size());
    m_logger->info("[Solo]   Private key: {} bytes", privkey.size());
    m_logger->info("[Solo]   Signature:   {} bytes (CT)", expected_sig_size);
    
    // Initialize the Unified Falcon Signature Wrapper
    try {
        m_falcon_wrapper = std::make_unique<FalconSignatureWrapper>(pubkey, privkey);
        if (m_falcon_wrapper->is_valid()) {
            m_logger->info("[Solo] Falcon Signature Wrapper initialized successfully");
        } else {
            m_logger->error("[Solo] Falcon Signature Wrapper initialization failed - invalid keys");
            m_falcon_wrapper.reset();
        }
    } catch (const std::exception& e) {
        m_logger->error("[Solo] Failed to initialize Falcon Signature Wrapper: {}", e.what());
        m_falcon_wrapper.reset();
    }
}

network::Shared_payload Solo::send_session_keepalive()
{
    // LLL-TAO PR #22: Send SESSION_KEEPALIVE to maintain session
    m_logger->debug("[Solo Session] Sending SESSION_KEEPALIVE for session 0x{:08x}", m_session_id);
    
    // Build keepalive packet with session ID (4 bytes, little-endian)
    std::vector<uint8_t> keepalive_data;
    append_uint32_le(keepalive_data, m_session_id);
    
    Packet packet{ static_cast<uint8_t>(Packet::SESSION_KEEPALIVE), std::make_shared<network::Payload>(keepalive_data) };
    return packet.get_bytes();
}

void Solo::send_set_channel(std::shared_ptr<network::Connection> connection)
{
    std::string channel_name = (m_channel == 1) ? "prime" : "hash";
    m_logger->info("[Solo] Sending SET_CHANNEL channel={} ({})", static_cast<int>(m_channel), channel_name);
    
    std::vector<uint8_t> channel_data(1, m_channel);
    Packet set_channel_packet{ static_cast<uint8_t>(Packet::SET_CHANNEL), std::make_shared<network::Payload>(channel_data) };
    connection->transmit(set_channel_packet.get_bytes());
}

void Solo::set_tritium_genesis(std::vector<uint8_t> const& genesis)
{
    if (genesis.size() != 32) {
        m_logger->warn("[Solo] Invalid Tritium genesis size: {} (expected 32 bytes)", genesis.size());
        return;
    }
    
    // Store persistently to survive reconnections
    m_persistent_tritium_genesis = genesis;
    
    if (m_session_manager) {
        m_session_manager->set_tritium_genesis(genesis);
        m_logger->info("[Solo] Tritium genesis hash configured for reward binding");
    }
}

bool Solo::has_tritium_genesis() const
{
    // Check persistent storage first
    if (!m_persistent_tritium_genesis.empty()) {
        return true;
    }
    
    if (m_session_manager) {
        return !m_session_manager->get_tritium_genesis().empty();
    }
    return false;
}

void Solo::set_keepalive_interval(std::uint16_t hours)
{
    if (m_session_manager) {
        m_session_manager->set_keepalive_interval(hours);
        m_logger->info("[Solo] Keepalive interval set to {} hours", hours);
    }
}

std::uint32_t Solo::get_session_id() const
{
    if (m_session_manager) {
        return m_session_manager->get_session_id();
    }
    return m_session_id;  // Fallback to legacy session ID
}

bool Solo::is_session_active() const
{
    if (m_session_manager) {
        return m_session_manager->is_active();
    }
    return m_authenticated;  // Fallback to legacy auth status
}

bool Solo::is_keepalive_due() const
{
    if (m_session_manager) {
        return m_session_manager->is_keepalive_due();
    }
    return false;
}

void Solo::reset_auth_state()
{
    m_auth_state = AuthState::NOT_AUTHENTICATED;
    m_connection = nullptr;
    m_logger->debug("[Solo Auth] Authentication state reset");
}

void Solo::handle_miner_auth_challenge(const Packet& packet)
{
    m_logger->info("[Solo Phase 2] Received MINER_AUTH_CHALLENGE");
    
    // TRAINING WHEELS: Show hex dump of MINER_AUTH_CHALLENGE
    if (packet.m_data) {
        m_logger->info("[Solo Auth] MINER_AUTH_CHALLENGE hex dump:");
        m_logger->info("\n{}", format_llp_payload_hexdump(packet.m_data, 128));
    }
    
    // Defensive bounds check
    if (!packet.m_data || packet.m_data->size() < 2) {
        m_logger->error("[Solo Phase 2] MINER_AUTH_CHALLENGE too small: {} bytes", 
                       packet.m_data ? packet.m_data->size() : 0);
        reset_auth_state();
        return;
    }
    
    // Parse nonce_len (2 bytes, big-endian)
    uint16_t nonce_len = (static_cast<uint16_t>((*packet.m_data)[0]) << 8) |
                          static_cast<uint16_t>((*packet.m_data)[1]);
    
    m_logger->info("[Solo Auth] Challenge nonce length: {} bytes (big-endian encoding)", nonce_len);
    m_logger->info("[Solo Auth]   Bytes 0-1: {:02x} {:02x}", (*packet.m_data)[0], (*packet.m_data)[1]);
    
    if (packet.m_data->size() < static_cast<size_t>(2 + nonce_len)) {
        m_logger->error("[Solo Phase 2] MINER_AUTH_CHALLENGE: incomplete nonce (expected {} bytes, got {})", 
                       2 + nonce_len, packet.m_data->size());
        reset_auth_state();
        return;
    }
    
    // Extract nonce
    std::vector<uint8_t> nonce(packet.m_data->begin() + 2, packet.m_data->begin() + 2 + nonce_len);
    
    m_logger->info("[Solo Phase 2] Extracted nonce: {} bytes", nonce.size());
    
    // Show first 16 bytes of nonce for verification
    if (nonce.size() > 0) {
        std::ostringstream nonce_hex;
        nonce_hex << std::hex << std::setfill('0');
        size_t preview_len = std::min(nonce.size(), static_cast<size_t>(16));
        for (size_t i = 0; i < preview_len; ++i) {
            nonce_hex << std::setw(2) << static_cast<unsigned int>(nonce[i]) << " ";
        }
        m_logger->info("[Solo Auth] Nonce (first {} bytes): {}", preview_len, nonce_hex.str());
    }
    
    // Sign the NONCE (not address+timestamp!)
    if (!m_falcon_wrapper || !m_falcon_wrapper->is_valid()) {
        m_logger->error("[Solo Phase 2] Falcon wrapper not initialized");
        reset_auth_state();
        return;
    }
    
    auto sign_result = m_falcon_wrapper->sign_payload(nonce, FalconSignatureWrapper::SignatureType::AUTHENTICATION);
    if (!sign_result.success) {
        m_logger->error("[Solo Phase 2] Failed to sign nonce: {}", sign_result.error_message);
        reset_auth_state();
        return;
    }
    
    // Validate signature size
    size_t expected_sig_size = m_falcon_wrapper->get_signature_size();
    std::string falcon_version = m_falcon_wrapper->is_falcon1024() ? "Falcon-1024" : "Falcon-512";
    
    m_logger->info("[Solo Phase 2] Signed nonce with {}", falcon_version);
    m_logger->info("[Solo Phase 2]   Signature: {} bytes (expected: {})", 
                   sign_result.signature.size(), expected_sig_size);
    
    if (sign_result.signature.size() != expected_sig_size) {
        m_logger->error("[Solo Phase 2] SIGNATURE SIZE MISMATCH!");
        m_logger->error("[Solo Phase 2]   Expected: {} bytes ({})", expected_sig_size, falcon_version);
        m_logger->error("[Solo Phase 2]   Got: {} bytes", sign_result.signature.size());
        m_logger->error("[Solo Phase 2]   This indicates a key version mismatch");
        reset_auth_state();
        return;
    }
    
    // Build MINER_AUTH_RESPONSE packet
    Packet response_packet(static_cast<uint8_t>(Packet::MINER_AUTH_RESPONSE));  // 209 - m_is_valid = true automatically
    response_packet.m_data = std::make_shared<network::Payload>();
    
    // NOTE: MINER_AUTH_RESPONSE uses little-endian encoding per protocol specification
    // sig_len (2 bytes, little-endian)
    uint16_t sig_len = static_cast<uint16_t>(sign_result.signature.size());
    response_packet.m_data->push_back(static_cast<uint8_t>(sig_len & 0xFF));
    response_packet.m_data->push_back(static_cast<uint8_t>((sig_len >> 8) & 0xFF));
    
    // signature
    response_packet.m_data->insert(response_packet.m_data->end(), 
                                   sign_result.signature.begin(), 
                                   sign_result.signature.end());
    
    response_packet.m_length = static_cast<uint32_t>(response_packet.m_data->size());
    
    // Debug: Verify packet is valid before transmission
    m_logger->debug("[Solo Auth] MINER_AUTH_RESPONSE packet built: header={}, length={}, data_size={}", 
                    response_packet.m_header, response_packet.m_length, 
                    response_packet.m_data ? response_packet.m_data->size() : 0);
    
    if (!response_packet.is_valid())
    {
        m_logger->error("[Solo Auth] CRITICAL: MINER_AUTH_RESPONSE is_valid() returned false!");
        m_logger->error("[Solo Auth]   header={}, m_length={}, is_auth_packet={}", 
                        response_packet.m_header, response_packet.m_length, 
                        response_packet.is_auth_packet());
        m_logger->error("[Solo Auth]   Validation state: {}", response_packet.get_validation_state());
        reset_auth_state();
        return;
    }
    
    m_logger->info("[Solo Phase 2] Sending MINER_AUTH_RESPONSE: sig_len={}, total_size={}", 
                   sig_len, response_packet.m_length);
    
    // Validate packet serialization
    auto bytes = response_packet.get_bytes();
    if (!bytes || bytes->empty()) {
        m_logger->error("[Solo Auth] CRITICAL: MINER_AUTH_RESPONSE get_bytes() returned null/empty!");
        m_logger->error("[Solo Phase 2] Failed to serialize MINER_AUTH_RESPONSE packet");
        reset_auth_state();
        return;
    }
    
    m_logger->debug("[Solo Auth] MINER_AUTH_RESPONSE validation: SUCCESS - encoded {} bytes", bytes->size());
    
    // TRAINING WHEELS: Show hex dump of MINER_AUTH_RESPONSE packet
    m_logger->info("[Solo Auth] MINER_AUTH_RESPONSE packet hex dump (wire format):");
    m_logger->info("\n{}", format_llp_payload_hexdump(bytes, 128));
    
    // Set state to waiting for result
    m_auth_state = AuthState::WAITING_FOR_RESULT;
    
    // Transmit the response using stored connection
    if (m_connection) {
        m_connection->transmit(bytes);
    } else {
        m_logger->error("[Solo Phase 2] Cannot send MINER_AUTH_RESPONSE - no connection stored");
        reset_auth_state();
    }
}

network::Shared_payload Solo::send_set_reward()
{
    // Verify we have a reward address configured
    if (m_reward_address.empty()) {
        m_logger->warn("[Solo Reward] No reward address configured - skipping MINER_SET_REWARD");
        return nullptr;
    }
    
    // Verify we are authenticated (ChaCha20 encryption requires established session)
    if (!m_authenticated) {
        m_logger->error("[Solo Reward] Cannot send reward address - not authenticated");
        return nullptr;
    }
    
    m_logger->info("[Solo Reward] Sending MINER_SET_REWARD (encrypted)");
    m_logger->info("[Solo Reward]   Address: {}", m_reward_address);
    
    // Decode the base58 address to bytes
    std::vector<uint8_t> vAddress = decode_base58(m_reward_address);
    
    if (vAddress.empty()) {
        m_logger->error("[Solo Reward] Invalid reward address - base58 decode failed");
        return nullptr;
    }
    
    m_logger->info("[Solo Reward] Original address (Base58): {}", m_reward_address);
    m_logger->info("[Solo Reward] Decoded total bytes: {}", vAddress.size());
    
    // Build the payload - the address bytes (will be encrypted by ChaCha20)
    std::vector<uint8_t> payload_data;
    
    // Extract ONLY the 32-byte hash (skip version and checksum)
    if (vAddress.size() < 37) {
        m_logger->error("[Solo Reward] Decoded address too short: {} bytes (expected 37)", vAddress.size());
        return nullptr;
    }
    
    // Extract bytes 1-32 (skip version byte at index 0, skip checksum at end)
    std::vector<uint8_t> vHash(vAddress.begin() + 1, vAddress.begin() + 33);
    
    // Log the extracted hash for debugging
    std::string hex_hash;
    hex_hash.reserve(64);  // 32 bytes * 2 hex chars per byte
    for(const auto& byte : vHash) {
        char buf[3];
        snprintf(buf, sizeof(buf), "%02x", byte);
        hex_hash += buf;
    }
    m_logger->info("[Solo Reward] Extracted 32-byte hash (hex): {}", hex_hash);
    m_logger->info("[Solo Reward] Hash size: {} bytes", vHash.size());
    
    // If ChaCha20 encryption is enabled, encrypt the address
    if (m_enable_chacha20 && m_chacha20_wrapper)
    {
        // Load tritium genesis for key derivation
        std::vector<uint8_t> tritium_genesis = load_tritium_genesis();
        bool has_valid_genesis = is_valid_genesis(tritium_genesis);
        
        if (has_valid_genesis)
        {
            try {
                auto session_key = derive_chacha20_session_key(tritium_genesis);
                auto nonce = ChaCha20Wrapper::generate_nonce();
                
                // Encrypt the 32-byte hash (NOT the 37-byte address!)
                auto encrypt_result = m_chacha20_wrapper->encrypt(vHash, session_key, nonce, AAD_REWARD_ADDRESS);
                
                if (encrypt_result.success)
                {
                    // Build encrypted format: nonce(12) + ciphertext+tag
                    payload_data.insert(payload_data.end(), nonce.begin(), nonce.end());
                    payload_data.insert(payload_data.end(), encrypt_result.data.begin(), encrypt_result.data.end());
                    
                    m_logger->info("[Solo Reward] Address encrypted: {} → {} bytes",
                                   vHash.size(), payload_data.size());
                    m_logger->debug("[Solo Reward] Encrypted with AAD: REWARD_ADDRESS ({} bytes)", AAD_REWARD_ADDRESS.size());
                }
                else
                {
                    m_logger->error("[Solo Reward] ChaCha20 encryption failed: {}", encrypt_result.error_message);
                    return nullptr;
                }
            }
            catch (const std::exception& e) {
                m_logger->error("[Solo Reward] Encryption failed: {}", e.what());
                return nullptr;
            }
        }
        else
        {
            m_logger->error("[Solo Reward] ChaCha20 enabled but no valid genesis for key derivation");
            return nullptr;
        }
    }
    else
    {
        // Send unencrypted (only valid for localhost connections)
        m_logger->warn("[Solo Reward] ChaCha20 not enabled - sending reward address unencrypted");
        payload_data = vHash;
    }
    
    // Build the MINER_SET_REWARD packet
    Packet packet(static_cast<uint8_t>(Packet::MINER_SET_REWARD));
    packet.m_data = std::make_shared<network::Payload>(payload_data);
    packet.m_length = static_cast<uint32_t>(payload_data.size());
    
    m_logger->info("[Solo Reward] MINER_SET_REWARD packet built: {} bytes", packet.m_length);
    
    return packet.get_bytes();
}

network::Shared_payload Solo::send_miner_ready()
{
    m_logger->info("[Solo Push] Sending MINER_READY (subscribe to push notifications)");
    m_logger->info("[Solo Push]   Channel: {} ({})", 
                   m_channel, 
                   m_channel == mining::CHANNEL_PRIME ? "Prime" : "Hash");
    
    // MINER_READY is a header-only packet (no payload)
    Packet packet{ static_cast<uint8_t>(Packet::MINER_READY) };
    
    m_logger->debug("[Solo Push] MINER_READY packet: header=0x{:02x} length={} is_valid={}", 
                   static_cast<int>(packet.m_header),
                   packet.m_length, 
                   packet.is_valid());
    
    auto payload = packet.get_bytes();
    if (payload && !payload->empty()) {
        m_logger->info("[Solo Push] ✓ Subscribed to push notifications");
        m_logger->info("[Solo Push]   Node will send immediate {} notification",
                      m_channel == mining::CHANNEL_PRIME ? "PRIME_BLOCK_AVAILABLE" : "HASH_BLOCK_AVAILABLE");
        m_logger->info("[Solo Push]   Then push on every block validation");
        
        // TRAINING WHEELS: Show MINER_READY packet (should be just header byte)
        m_logger->info("[Solo Push] MINER_READY packet hex dump:");
        m_logger->info("\n{}", format_llp_payload_hexdump(payload, 16));
    } else {
        m_logger->error("[Solo Push] Failed to encode MINER_READY packet");
    }
    
    return payload;
}

bool Solo::finalize_template_with_channel_height(uint32_t node_channel_height, const std::string& context)
{
    if (!m_template_interface || node_channel_height == 0) {
        return false;
    }
    
    // Check if template needs finalization
    if (m_template_interface->needs_channel_height_finalization()) {
        // Template builds NEXT block, so channel height = node height + 1
        uint32_t template_channel_height = node_channel_height + 1;
        m_template_interface->set_channel_height(template_channel_height);
        m_logger->info("[Solo GET_ROUND] ✓ Template finalized with channel height {} ({})", 
            template_channel_height, context);
        return true;
    }
    
    return false;
}

mining::ClientChannelManager* Solo::get_channel_manager() const
{
    return get_channel_manager(m_channel);
}

mining::ClientChannelManager* Solo::get_channel_manager(uint32_t channel) const
{
    switch (channel) {
        case mining::CHANNEL_PRIME:
            return m_prime_manager.get();
        case mining::CHANNEL_HASH:
            return m_hash_manager.get();
        default:
            return nullptr;
    }
}

bool Solo::sync_template_state(uint32_t unified_height, uint32_t channel_height)
{
    // Get the appropriate channel manager for this miner's channel
    auto* pManager = get_channel_manager();
    if (!pManager) {
        m_logger->error("[Solo Sync] No channel manager for channel {}", m_channel);
        return false;
    }
    
    std::string channel_name = pManager->GetChannelName();
    m_logger->debug("[Solo Sync] Synchronizing {} channel state:", channel_name);
    m_logger->debug("[Solo Sync]   Node unified height: {}", unified_height);
    m_logger->debug("[Solo Sync]   Node channel height: {}", channel_height);
    
    // Step 1: Update channel manager with new heights from GET_ROUND
    pManager->UpdateFromGetRound(unified_height, channel_height);
    
    // Step 2: Check for fork detection (height regression)
    if (pManager->IsForkDetected()) {
        handle_fork_detected(pManager, unified_height);
        return false;  // Template was invalidated
    }
    
    // Step 3: Finalize template channel height if needed
    if (m_template_interface && m_template_interface->needs_channel_height_finalization()) {
        uint32_t template_channel_height = channel_height + 1;
        m_template_interface->set_channel_height(template_channel_height);
        m_logger->info("[Solo Sync] ✓ Template finalized: mining for channel height {}", 
            template_channel_height);
    }
    
    // Step 4: Validate current template
    return validate_current_template();
}

bool Solo::validate_current_template()
{
    auto* pManager = get_channel_manager();
    if (!pManager) {
        return false;
    }
    
    if (!m_template_interface || !m_template_interface->has_valid_template()) {
        return true;  // No template to validate - that's OK
    }
    
    // Get expected heights from channel manager (single source of truth)
    auto [expectedUnified, expectedChannel] = pManager->GetExpectedHeights();
    
    // Get template height
    uint32_t templateHeight = m_template_interface->get_template_height();
    
    // Validation 1: Unified height (mirrors Block::Accept)
    if (templateHeight != expectedUnified) {
        m_logger->warn("[Solo Validate] Unified height mismatch: template={}, expected={}",
            templateHeight, expectedUnified);
        m_template_interface->discard_template("Unified height stale");
        return false;
    }
    
    // Note: Age timeout validation (60s safety net) is handled internally by
    // MiningTemplateInterface. No additional validation needed here.
    
    m_logger->debug("[Solo Validate] ✓ Template valid (height={}, channel={})", 
        templateHeight, pManager->GetChannelName());
    return true;
}

void Solo::handle_fork_detected(mining::ClientChannelManager* pManager, uint32_t current_height)
{
    if (!pManager) return;
    
    auto prevHeights = pManager->GetPreviousHeights();
    uint32_t nPrevHeight = prevHeights.first;
    uint32_t nRollback = (nPrevHeight > current_height) ? (nPrevHeight - current_height) : 0;
    
    m_logger->warn("[Solo Fork] ⚠ FORK DETECTED on {} channel!", pManager->GetChannelName());
    m_logger->warn("[Solo Fork]    Previous unified height: {}", nPrevHeight);
    m_logger->warn("[Solo Fork]    Current unified height:  {}", current_height);
    m_logger->warn("[Solo Fork]    Blocks rolled back:      {}", nRollback);
    
    // Auto-invalidate template in MiningTemplateInterface
    if (m_template_interface && m_template_interface->has_valid_template()) {
        m_template_interface->discard_template("Fork detected - blockchain rollback");
        m_logger->info("[Solo Fork] ✗ Template invalidated due to fork");
    }
    
    // Clear fork flag
    pManager->ClearForkFlag();
}

void Solo::handle_reward_result(const Packet& packet)
{
    m_logger->info("[Solo Reward] Received MINER_REWARD_RESULT");
    
    // Validate packet data
    if (!packet.m_data || packet.m_length < 1) {
        m_logger->error("[Solo Reward] Invalid MINER_REWARD_RESULT packet - no data");
        m_reward_bound = false;
        return;
    }
    
    std::vector<uint8_t> result_data;
    
    // Decrypt if ChaCha20 is enabled
    if (m_enable_chacha20 && m_chacha20_wrapper && packet.m_length > 13)
    {
        // Load genesis for decryption
        std::vector<uint8_t> tritium_genesis = load_tritium_genesis();
        if (is_valid_genesis(tritium_genesis))
        {
            try {
                auto session_key = derive_chacha20_session_key(tritium_genesis);
                
                // Extract nonce (first 12 bytes)
                std::vector<uint8_t> nonce(packet.m_data->begin(), packet.m_data->begin() + 12);
                std::vector<uint8_t> ciphertext(packet.m_data->begin() + 12, packet.m_data->end());
                
                // Decrypt response using matching AAD
                auto decrypt_result = m_chacha20_wrapper->decrypt(ciphertext, session_key, nonce, AAD_REWARD_RESULT);
                
                if (decrypt_result.success) {
                    result_data = decrypt_result.data;
                    m_logger->debug("[Solo Reward] Decrypted with AAD: REWARD_RESULT ({} bytes)", AAD_REWARD_RESULT.size());
                } else {
                    m_logger->error("[Solo Reward] Failed to decrypt result: {}", decrypt_result.error_message);
                    m_reward_bound = false;
                    return;
                }
            }
            catch (const std::exception& e) {
                m_logger->error("[Solo Reward] Decryption failed: {}", e.what());
                m_reward_bound = false;
                return;
            }
        }
        else
        {
            // No genesis, try unencrypted
            result_data.assign(packet.m_data->begin(), packet.m_data->end());
        }
    }
    else
    {
        // Unencrypted result
        result_data.assign(packet.m_data->begin(), packet.m_data->end());
    }
    
    if (result_data.empty()) {
        m_logger->error("[Solo Reward] Empty result data after processing");
        m_reward_bound = false;
        return;
    }
    
    // Parse status byte
    uint8_t status = result_data[0];
    
    if (status == 0x01)  // Success
    {
        m_logger->info("╔═════════════════════════════════════════════════════════╗");
        m_logger->info("║       REWARD ADDRESS BINDING SUCCESSFUL                 ║");
        m_logger->info("╠═════════════════════════════════════════════════════════╣");
        m_logger->info("║ Address: {}                                              ║", 
            m_reward_address.substr(0, std::min(m_reward_address.length(), ADDRESS_DISPLAY_TRUNCATE)));
        m_logger->info("╚═════════════════════════════════════════════════════════╝");
        
        m_reward_bound = true;
        
        // CONTINUE MINING FLOW: Now send SET_CHANNEL and GET_BLOCK
        if (m_connection)
        {
            m_logger->info("[Solo Phase 2] Reward bound - continuing with mining flow");
            m_logger->info("[Solo Phase 2] Sending SET_CHANNEL");
            send_set_channel(m_connection);
            
            // Note: GET_BLOCK will be sent after receiving CHANNEL_ACK
            // This is handled in the existing CHANNEL_ACK handler
        }
        else
        {
            m_logger->error("[Solo Reward] Cannot continue - no connection available");
        }
    }
    else
    {
        // Parse optional error message
        std::string error_message = "Unknown error";
        if (result_data.size() >= 2)
        {
            uint8_t msg_len = result_data[1];
            if (result_data.size() >= 2 + msg_len)
            {
                error_message = std::string(result_data.begin() + 2, result_data.begin() + 2 + msg_len);
            }
        }
        
        m_logger->error("╔═════════════════════════════════════════════════════════╗");
        m_logger->error("║       REWARD ADDRESS BINDING FAILED                     ║");
        m_logger->error("╠═════════════════════════════════════════════════════════╣");
        m_logger->error("║ Error: {}                                                ║", error_message);
        m_logger->error("╚═════════════════════════════════════════════════════════╝");
        
        m_reward_bound = false;
        
        // Reward binding failed - cannot proceed with mining
        m_logger->error("[Solo Reward] Cannot mine without reward address bound");
        
        // Close connection to prevent further issues
        if (m_connection)
        {
            m_logger->error("[Solo Reward] Closing connection due to reward binding failure");
            m_connection->close();
            m_connection = nullptr;  // Reset to prevent use-after-close
        }
    }
}

void Solo::handle_initial_template_response(const char* opcode_name)
{
    // Check if we're waiting for the initial template after MINER_READY
    if (!m_waiting_for_stateless_response) {
        return;  // Not waiting, nothing to do
    }
    
    // Activate stateless protocol and clear waiting flag
    m_stateless_protocol_active = true;
    m_waiting_for_stateless_response = false;
    
    // Calculate response time
    auto now_ns = std::chrono::steady_clock::now().time_since_epoch().count();
    auto sent_ns = m_miner_ready_sent_time_ns.load();
    auto elapsed_ms = (now_ns - sent_ns) / 1000000;  // Convert nanoseconds to milliseconds
    
    // Log successful template reception
    m_logger->info("[Solo Protocol] ═══════════════════════════════════════");
    m_logger->info("[Solo Protocol] ✅ INITIAL TEMPLATE RECEIVED ({})", opcode_name);
    m_logger->info("[Solo Protocol]   Response time: {}ms", elapsed_ms);
    m_logger->info("[Solo Protocol]   Stateless protocol activated");
    m_logger->info("[Solo Protocol] ═══════════════════════════════════════");
}

// ═══════════════════════════════════════════════════════════════════════
// INTELLIGENT GET_ROUND POLLING IMPLEMENTATION
// ═══════════════════════════════════════════════════════════════════════

bool Solo::should_poll_get_round()
{
    // CRITICAL: Do not send GET_ROUND before authentication completes
    // The node will reject unauthenticated GET_ROUND requests
    if (!m_authenticated) {
        // Log only occasionally to avoid spam (every 10 seconds)
        static auto last_auth_warning = std::chrono::steady_clock::now();
        auto now = std::chrono::steady_clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - last_auth_warning).count();
        
        if (elapsed >= 10) {
            m_logger->debug("[Solo Poll] Waiting for authentication before sending GET_ROUND (state: {})",
                static_cast<int>(m_auth_state));
            last_auth_warning = now;
        }
        return false;
    }
    
    auto now = std::chrono::steady_clock::now();
    auto elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        now - m_last_get_round_time).count();
    
    // Case 1: Need initial round check after new template (wait 100ms)
    if (m_needs_initial_round_check && elapsed_ms >= POST_TEMPLATE_POLL_DELAY_MS) {
        m_logger->debug("[Solo Poll] Initial round check after new template");
        m_last_get_round_time = now;
        m_needs_initial_round_check = false;
        return true;
    }
    
    // Case 2: Current interval elapsed (exponential backoff)
    if (elapsed_ms >= m_current_poll_interval_ms) {
        m_logger->debug("[Solo Poll] Interval elapsed ({}ms), polling GET_ROUND", 
            m_current_poll_interval_ms);
        m_last_get_round_time = now;
        return true;
    }
    
    return false;  // Not time to poll yet
}

void Solo::on_new_round_received(uint32_t new_unified_height)
{
    // NEW_ROUND = block was found, reset to fast polling
    m_current_poll_interval_ms = POLL_INTERVAL_MIN_MS;
    m_logger->info("[Solo Poll] 🔔 NEW_ROUND received! Reset poll interval to {}ms", 
        m_current_poll_interval_ms);
    
    // Check unified height delta
    check_unified_height_delta(new_unified_height);
}

void Solo::on_old_round_received()
{
    // OLD_ROUND = nothing changed, back off polling
    uint32_t old_interval = m_current_poll_interval_ms;
    // Integer arithmetic for 1.5x: interval + (interval / 2)
    // This avoids floating-point precision issues
    uint32_t new_interval = m_current_poll_interval_ms + (m_current_poll_interval_ms >> 1);
    m_current_poll_interval_ms = std::min(new_interval, POLL_INTERVAL_MAX_MS);
    
    if (m_current_poll_interval_ms != old_interval) {
        m_logger->debug("[Solo Poll] OLD_ROUND: backing off interval {}ms → {}ms",
            old_interval, m_current_poll_interval_ms);
    }
}

void Solo::on_template_received(uint32_t template_height)
{
    // New template received, need to poll GET_ROUND once to finalize channel height
    m_needs_initial_round_check = true;
    m_template_unified_height = template_height;
    m_last_get_round_time = std::chrono::steady_clock::now();  // Reset timer
    m_logger->debug("[Solo Poll] Template received (height {}), will poll GET_ROUND in {}ms",
        template_height, POST_TEMPLATE_POLL_DELAY_MS);
}

void Solo::check_unified_height_delta(uint32_t current_unified_height)
{
    if (m_template_unified_height == 0) {
        return;  // No template yet
    }
    
    // Check if unified height moved significantly (other channel found blocks)
    if (current_unified_height > m_template_unified_height) {
        uint32_t delta = current_unified_height - m_template_unified_height;
        
        if (delta >= UNIFIED_HEIGHT_DELTA_TRIGGER) {
            m_logger->warn("[Solo Poll] ⚠️ Unified height moved {} blocks ({} → {})",
                delta, m_template_unified_height, current_unified_height);
            m_logger->warn("[Solo Poll]    Other channel(s) found blocks - requesting fresh template");
            
            // Request fresh template
            if (m_template_interface) {
                m_template_interface->discard_template("Unified height delta exceeded");
            }
            
            // Reset template height to prevent repeated triggers
            m_template_unified_height = 0;
            
            // Trigger GET_BLOCK request
            // (The main loop will see no valid template and request one)
        }
    }
}

void Solo::check_stateless_protocol_timeout(std::shared_ptr<network::Connection> connection)
{
    // Only check if we're waiting for a stateless response
    if (!m_waiting_for_stateless_response) {
        return;
    }
    
    // Calculate elapsed time since MINER_READY was sent
    auto now_ns = std::chrono::steady_clock::now().time_since_epoch().count();
    auto sent_ns = m_miner_ready_sent_time_ns.load();
    auto elapsed_seconds = (now_ns - sent_ns) / 1000000000;  // Convert nanoseconds to seconds
    
    // Check if timeout expired
    if (elapsed_seconds >= STATELESS_PROTOCOL_TIMEOUT_SECONDS) {
        // Timeout: Node doesn't support stateless protocol
        m_waiting_for_stateless_response = false;
        m_stateless_protocol_active = false;
        
        m_logger->warn("[Solo Protocol] ═══════════════════════════════════════");
        m_logger->warn("[Solo Protocol] ⏱️  STATELESS_GET_BLOCK timeout ({}s)", 
                      STATELESS_PROTOCOL_TIMEOUT_SECONDS);
        m_logger->warn("[Solo Protocol] Node doesn't support stateless protocol");
        m_logger->info("[Solo Protocol] Falling back to legacy GET_ROUND polling");
        m_logger->warn("[Solo Protocol] ═══════════════════════════════════════");
        
        // Start legacy polling by sending initial GET_ROUND
        if (connection) {
            m_logger->info("[Solo Protocol] Sending initial GET_ROUND (0x85) - polling mode");
            auto get_round_payload = send_get_round();
            if (get_round_payload && !get_round_payload->empty()) {
                connection->transmit(get_round_payload);
                m_logger->info("[Solo Protocol] ✓ GET_ROUND transmitted - legacy polling active");
            } else {
                m_logger->error("[Solo Protocol] Failed to encode GET_ROUND packet");
            }
        } else {
            m_logger->error("[Solo Protocol] No connection available for fallback GET_ROUND");
        }
    }
}

}
}
