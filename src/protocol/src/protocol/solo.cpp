#include "protocol/solo.hpp"
#include "protocol/protocol.hpp"
#include "protocol/falcon_constants.hpp"
#include "protocol/protocol_constants.hpp"
#include "protocol/push_notification_handler.hpp"
#include "protocol/packet_builder.hpp"
#include "protocol/genesis_utils.hpp"
#include "protocol/hex_prefix_utils.hpp"
#include "protocol/serialization_helpers.hpp"
#include "protocol/session_status_policy.hpp"
#include "protocol/session_start_parser.hpp"
#include "packet.hpp"
#include "network/connection.hpp"
#include "stats/stats_collector.hpp"
#include "LLP/block_utils.hpp"
#include "LLP/llp_logging.hpp"
#include "LLP/utils.hpp"
#include "include/stateless_block_utility.hpp"
#include "../miner_keys.hpp"
#include "hex_utils.h"
#include <openssl/sha.h>
#include <chrono>
#include <algorithm>
#include <sstream>
#include <iomanip>
#include <stdexcept>
#include <cstring>

namespace nexusminer
{
namespace protocol
{

namespace {

bool is_expected_cached_session_resync(bool local_has_state, bool authoritative_has_state)
{
    return !local_has_state && authoritative_has_state;
}

}

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

// Helper function to parse uint32 from big-endian bytes
static uint32_t read_uint32_be(const std::vector<uint8_t>& src, size_t offset = 0) {
    if (src.size() < offset + 4) {
        return 0;
    }
    return (static_cast<uint32_t>(src[offset]) << 24) |
           (static_cast<uint32_t>(src[offset + 1]) << 16) |
           (static_cast<uint32_t>(src[offset + 2]) << 8) |
           static_cast<uint32_t>(src[offset + 3]);
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

Solo::Solo(std::uint8_t channel, std::shared_ptr<stats::Collector> stats_collector,
           std::shared_ptr<NodeSessionContext> session_context)
: m_channel{channel}
, m_logger{spdlog::get("logger")}
, m_current_height{0}
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
, m_chacha20_wrapper{nullptr}  // Lazy initialization when needed
, m_enable_chacha20{true}  // ALWAYS ON - Core implementation (localhost miners, SessionID protection, etc.)
, m_session_context{std::move(session_context)}
, m_template_interface{nullptr}
, m_connection{nullptr}
, m_reward_address{""}  // Empty until configured
, m_reward_bound{false}  // Not bound until successful MINER_REWARD_RESULT
, m_last_round_status{false, 0, 0, 0, 0, 0, false}  // Initialize GET_ROUND status (with difficulty and channel heights)
, m_last_get_round_time{std::chrono::steady_clock::now()}  // Initialize to now
, m_current_poll_interval_ms{POLL_INTERVAL_MIN_MS}  // Start at minimum interval (configured)
, m_needs_initial_round_check{false}  // No template yet
, m_template_unified_height{0}  // No template yet
, m_protocol_lane{ProtocolLane::UNKNOWN}  // Will be determined from connection port
{
    if (!m_logger) {
        m_logger = spdlog::default_logger();
    }
   // Log constructor call with requested channel value
    m_logger->info("Solo::Solo: ctor called, channel={}", static_cast<int>(m_channel));

    // Clamp channel to valid LLL-TAO channels: 1 = prime, 2 = hash
    if (m_channel != 1 && m_channel != 2) {
        m_logger->warn("Invalid channel {} specified. Valid channels: 1 (prime), 2 (hash). Defaulting to 2 (hash).",
            static_cast<int>(m_channel));
        m_channel = 2;
    }

    // Initialize unified push notification handler
    m_push_handler = std::make_unique<PushNotificationHandler>(m_logger, m_channel);

    // Initialize Colin AI Diagnostic PING/PONG handler with the shared logger
    m_colin_ping_handler.set_logger(m_logger);
    m_colin_ping_handler.set_channel(m_channel);

    // Note: ChaCha20 wrapper is lazily initialized when enable_chacha20_wrapping() is called
    // This avoids unnecessary resource allocation when ChaCha20 is not needed

    // Session manager is now provided via NodeSessionContext (shared across primary/secondary protocols)
    if (!get_session_manager()) {
        m_logger->error("[Solo] Session manager not available from NodeSessionContext - session management disabled");
    } else {
        m_logger->info("[Solo] Using shared session manager from NodeSessionContext");
    }

    // Initialize client-side channel managers (mirrors NODE's PR #136)
    m_prime_manager = std::make_unique<mining::PrimeClientManager>();
    m_hash_manager = std::make_unique<mining::HashClientManager>();
    m_logger->info("[Solo] Client channel managers initialized (Prime + Hash)");
    
    // Initialize the Mining Template Interface for unified READ/FEED operations
    // Session ID starts at 0 (unauthenticated) and will be updated after MINER_AUTH_RESULT
    // The session ID binds the template interface to the FALCON authenticated tunnel
    m_template_interface = std::make_unique<MiningTemplateInterface>(m_channel, 0);
    m_logger->info("[Solo] Mining Template Interface initialized for unified READ/FEED system");
    
    // Wire centralized HeightTracker into MiningTemplateInterface (non-owning pointer)
    m_template_interface->set_height_tracker(&m_height_tracker);
    if (m_session_context) {
        m_session_epoch = m_session_context->get_session_epoch();
        m_has_seen_session_epoch = true;
    }
    // Keep MTI/HeightTracker aligned with the authoritative session epoch even
    // before authentication. With no session context the epoch remains 0,
    // which is the explicit "no active session ownership" baseline.
    m_template_interface->set_session_epoch(m_session_epoch);
    m_height_tracker.set_session_epoch(m_session_epoch);
    m_logger->info("[Solo] HeightTracker wired into MiningTemplateInterface");
    
    // Setup template feed handler - called automatically when templates are validated
    m_template_interface->set_template_feed_handler(
        [this](const MiningTemplateInterface::MiningTemplate& tmpl, uint32_t nBits) {
            // Log new template (infrequent: once per block, typically every few minutes)
            m_logger->info("[Solo] ═══════════════════════════════════════");
            m_logger->info("[Solo] 🆕 NEW MINING TEMPLATE RECEIVED");
            m_logger->info("[Solo]   Channel:         {} ({})", tmpl.block.nChannel, 
                get_channel_name(tmpl.block.nChannel));
            
            // block.nHeight is the UNIFIED blockchain height (tStateBest.nHeight + 1).
            // After the node fix, this is correct — do NOT treat it as channel-specific height.
            m_logger->info("[Solo]   Template height: {} (unified blockchain height)", tmpl.block.nHeight);
            
            // Show unified height from last GET_ROUND (reference only - other channels may differ)
            if (m_last_round_status.height > 0) {
                m_logger->info("[Solo]   Unified height:  {} (reference only)", m_last_round_status.height);
            }
            
            if (tmpl.nChannelHeight > 0) {
                m_logger->info("[Solo]   Channel height:  {} (current chain tip)", tmpl.nChannelHeight);
            } else {
                m_logger->info("[Solo]   Channel height:  (pending finalization via GET_ROUND)");
            }
            m_logger->info("[Solo]   Difficulty:      0x{:08x}", nBits);
            m_logger->info("[Solo] ═══════════════════════════════════════");
            
            // Feed to worker threads via set_block_handler
            // Note: Debounce is now handled in MiningTemplateInterface::feed_current_template()
            // This handler is only invoked if the template passes the unified debounce gate
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

    // Register template-cleared callback: zero prevblock_suffix in SESSION_KEEPALIVE
    // so the node sees a clean slate when a template is discarded.
    m_template_interface->set_template_cleared_callback(
        [this]() {
            if (get_session_manager()) {
                get_session_manager()->set_prevblock_suffix({0, 0, 0, 0});
                m_logger->debug("[Solo] Template cleared — prevblock_suffix zeroed in session keepalive");
            }
        }
    );
}

std::vector<uint8_t> Solo::derive_chacha20_session_key(const std::vector<uint8_t>& genesis)
{
    // IMPORTANT: Use genesis bytes exactly as parsed/configured; do not reverse them
    // before the KDF step. This must match the node's hashGenesis.GetBytes() ordering.
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
        m_logger->info("║ Genesis (hex, configured order / no reversal): {}", nexusminer::keys::to_hex(genesis_truncated));
    }
    
    // Log derived key for comparison with node's "Derived Key (32 bytes):" log
    m_logger->info("║ Derived Key (hex): {}", nexusminer::keys::to_hex(key));
    m_logger->info("╚═══════════════════════════════════════════════════════════╝");
    
    return key;
}

std::vector<uint8_t> Solo::load_tritium_genesis()
{
    // Try to get genesis from session manager first
    if (get_session_manager() && !get_session_manager()->get_tritium_genesis().empty()) 
    {
        m_logger->info("[Solo Auth] Using genesis from session manager");
        return get_session_manager()->get_tritium_genesis();
    }
    
    // If session manager doesn't have it, reload from persistent storage (handles reconnection)
    if (!m_persistent_tritium_genesis.empty())
    {
        auto genesis = m_persistent_tritium_genesis;
        
        // Restore to session manager for future use
        if (get_session_manager())
        {
            get_session_manager()->set_tritium_genesis(genesis);
        }
        
        if (genesis.size() >= 4)
            m_logger->info("[Solo Auth] Reloaded tritium_genesis from persistent storage ({} bytes), first 4 bytes: {:02x}{:02x}{:02x}{:02x}",
                genesis.size(), genesis[0], genesis[1], genesis[2], genesis[3]);
        else
            m_logger->info("[Solo Auth] Reloaded tritium_genesis from persistent storage ({} bytes)", genesis.size());
        return genesis;
    }
    
    // No genesis configured
    m_logger->warn("[Solo Auth] No tritium_genesis configured - using zero genesis");
    m_logger->warn("[Solo Auth] ChaCha20 encryption unavailable without valid genesis");
    return std::vector<uint8_t>(GENESIS_HASH_SIZE, 0);  // 32 zero bytes
}

void Solo::reset()
{
    m_current_height = 0;
    m_current_reward = 0;
    m_authenticated = false;
    m_session_id = 0;
    m_auth_timestamp = 0;
    m_auth_state = AuthState::NOT_AUTHENTICATED;
    m_auth_in_flight_since = {};
    m_reward_bound = false;  // Reset reward binding for new session
    m_subscribed_to_notifications = false;  // Reset push notification subscription
    m_pending_push_after_auth = false;
    clear_push_ingress_lifeline();

    // Note: m_chacha20_wrapper is intentionally NOT cleared here — the wrapper object
    // is stateless (no per-session state) and can be reused across reconnects.

    // Reset session manager
    if (m_session_context) {
        m_session_context->set_chacha20_session_key({}, "", false);
        m_session_context->clear_for_disconnect(m_reward_address,
                                                m_reward_address.empty() ? "" : "config",
                                                "solo session reset");
    }

    // Reset template interface for new session
    if (m_template_interface) {
        propagate_session_to_template_interface("Solo Reset");
        m_logger->info("[Solo] MiningTemplateInterface session ID cleared for session reset");
        m_template_interface->reset_stats();
        m_template_interface->clear_template_channel_height_snapshot();
    }
}

bool Solo::session_context_is_authenticated() const
{
    return m_session_context && m_session_context->is_authenticated();
}

void Solo::propagate_session_to_template_interface(const char* log_scope)
{
    if (!m_template_interface) {
        return;
    }

    m_template_interface->set_session_epoch(m_session_epoch);
    m_template_interface->set_session_id(m_session_id);
    m_logger->debug("[{}] Propagated session binding to MiningTemplateInterface: session_id=0x{:08x}, epoch={}",
                    log_scope, m_session_id, m_session_epoch);
}

void Solo::resync_auth_from_session_context(const char* log_scope)
{
    if (m_authenticated || !session_context_is_authenticated()) {
        return;
    }

    m_authenticated = true;
    m_auth_state = AuthState::AUTHENTICATED;
    m_auth_in_flight_since = {};
    m_logger->warn("[{}] Resynced m_authenticated from session_context — local flag was stale",
                   log_scope);

    refresh_cached_session_state(log_scope);
    if (m_session_id != 0) {
        propagate_session_to_template_interface(log_scope);
    }
}

void Solo::refresh_cached_session_state(const char* log_scope)
{
    if (!m_session_context) {
        return;
    }

    const auto session = m_session_context->get_runtime_snapshot();

    if (!m_has_seen_session_epoch || m_session_epoch != session.session_epoch) {
        if (!m_has_seen_session_epoch) {
            m_logger->info("[{}] Resyncing local session epoch from authoritative session container: local={} authoritative={}",
                           log_scope, m_session_epoch, session.session_epoch);
        } else {
            m_logger->warn("[{}] Session epoch advanced: local={} authoritative={} — invalidating generation-bound cached state",
                           log_scope, m_session_epoch, session.session_epoch);
            clear_generation_bound_state("authoritative session epoch advanced");
        }

        m_session_epoch = session.session_epoch;
        m_has_seen_session_epoch = true;
        m_height_tracker.set_session_epoch(m_session_epoch);
    }

    if (m_authenticated != session.authenticated) {
        if (is_expected_cached_session_resync(m_authenticated, session.authenticated)) {
            m_logger->info("[{}] Resyncing local auth flag from authoritative session container after reconnect: local={} authoritative={}",
                           log_scope, m_authenticated ? "true" : "false", session.authenticated ? "true" : "false");
        } else {
            m_logger->warn("[{}] Local auth flag drifted from authoritative session container mid-session: local={} authoritative={}",
                           log_scope, m_authenticated ? "true" : "false", session.authenticated ? "true" : "false");
        }
        m_authenticated = session.authenticated;
    }

    if (m_session_id != session.session_id) {
        if (is_expected_cached_session_resync(m_session_id != 0, session.session_id != 0)) {
            m_logger->info("[{}] Resyncing local session_id from authoritative session container after reconnect: local=0x{:08x} authoritative=0x{:08x}",
                           log_scope, m_session_id, session.session_id);
        } else {
            m_logger->warn("[{}] Local session_id drifted from authoritative session container mid-session: local=0x{:08x} authoritative=0x{:08x}",
                           log_scope, m_session_id, session.session_id);
        }
        m_session_id = session.session_id;
    }

    if (session.authenticated && session.session_id != 0) {
        propagate_session_to_template_interface(log_scope);
    }

    if (m_reward_bound != session.reward_bound) {
        if (is_expected_cached_session_resync(m_reward_bound, session.reward_bound)) {
            m_logger->info("[{}] Resyncing local reward_bound from authoritative session container after reconnect: local={} authoritative={}",
                           log_scope, m_reward_bound ? "true" : "false", session.reward_bound ? "true" : "false");
        } else {
            m_logger->warn("[{}] Local reward_bound drifted from authoritative session container mid-session: local={} authoritative={}",
                           log_scope, m_reward_bound ? "true" : "false", session.reward_bound ? "true" : "false");
        }
        m_reward_bound = session.reward_bound;
    }

    if (m_protocol_lane != session.active_lane &&
        session.active_lane != ProtocolLane::UNKNOWN &&
        m_protocol_lane == ProtocolLane::UNKNOWN) {
        m_logger->info("[{}] Resyncing protocol lane from authoritative session container after reconnect because local lane was UNKNOWN: authoritative={}",
                       log_scope, get_lane_name(session.active_lane));
        m_protocol_lane = session.active_lane;
    }
}

SessionOwnershipStamp Solo::capture_session_ownership() const
{
    if (!m_session_context) {
        // No authoritative session context means there is no correlatable owner.
        // Callers treat the zero-initialized stamp as "ownership unavailable".
        return {};
    }

    const auto session = m_session_context->get_runtime_snapshot();
    return { SessionId(session.session_id), SessionEpoch(session.session_epoch) };
}

SubmitContext Solo::capture_submit_context(uint32_t template_height,
                                           uint32_t chain_height) const
{
    SubmitContext context;
    context.template_height = template_height;
    context.chain_height = chain_height;

    if (!m_session_context) {
        return context;
    }

    const auto session = m_session_context->get_runtime_snapshot();
    context.session_id = SessionId(session.session_id);
    context.session_epoch = SessionEpoch(session.session_epoch);
    return context;
}

void Solo::record_session_event(SessionManager::SessionEventKind kind,
                                const std::string& detail) const
{
    if (m_session_context) {
        m_session_context->record_session_event(kind, detail);
    }
}

void Solo::finalize_keepalive_ack(const char* detail)
{
    if (m_session_context) {
        m_session_context->note_keepalive_ack(true, detail ? detail : "keepalive ack accepted");
    }
    if (auto* session_manager = get_session_manager()) {
        session_manager->record_keepalive();
    }
}

void Solo::clear_generation_bound_state(const char* reason)
{
    m_last_keepalive_request_owner.clear();
    m_last_session_status_request_owner.clear();
    m_last_reward_request_owner.clear();
    m_last_get_block_request_owner.clear();
    m_last_submitted_owner.clear();
    m_last_submitted_valid = false;
    m_last_submitted_nonce = 0;
    m_last_submitted_prev_hash = uint1024_t(0);
    m_last_submitted_height = 0;
    m_last_submitted_channel = 0;
    m_session_id_mismatch_count = 0;
    m_last_session_status_ack = {};
    m_last_session_status_ack_time = {};
    m_last_known_hash_prev_block = uint1024_t(0);
    m_last_keepalive_prevhash_lo32 = 0;

    if (m_template_interface) {
        m_template_interface->discard_template(reason);
        m_template_interface->clear_template_channel_height_snapshot();
    }
}

bool Solo::finalize_and_feed_current_template(uint32_t unified_height,
                                              uint32_t effective_channel_height,
                                              const char* log_scope,
                                              bool snapshot_round_channel_height)
{
    if (!m_template_interface) {
        return false;
    }

    if (effective_channel_height > 0) {
        m_template_interface->set_channel_height(effective_channel_height + 1);
    }

    auto const* tmpl = m_template_interface->get_current_template();
    if (!tmpl) {
        m_logger->error("[{}] No valid template available after finalization", log_scope);
        return false;
    }

    // Clear the push tip anchor now that a fresh BLOCK_DATA template is in hand.
    // This must happen BEFORE validate_current_template() so that any residual
    // push_hash_prev_block from a prior same-height push does not cause
    // validate_current_template() to log a spurious "push tip-anchor differs" note.
    // The anchor was already used in the push handler to trigger the soft refresh;
    // at this point BLOCK_DATA is authoritative and the anchor is stale.
    m_height_tracker.ClearPushTipAnchor();

    if (!validate_current_template()) {
        m_logger->warn("[{}] Template invalidated by final adoption gate before worker feed", log_scope);
        return false;
    }

    m_current_height = unified_height;

    auto format_hex8 = [](const uint1024_t& h) -> std::string {
        auto bytes = h.GetBytes();
        std::string s;
        for (size_t i = 0; i < std::min(bytes.size(), size_t(8)); ++i) {
            char buf[3];
            snprintf(buf, sizeof(buf), "%02x", bytes[i]);
            s += buf;
        }
        return s;
    };

    if (m_last_known_hash_prev_block != uint1024_t(0)) {
        if (tmpl->block.hashPrevBlock != m_last_known_hash_prev_block) {
            m_logger->warn("[TEMPLATE ANCHOR] ⚡ CHAIN TIP CHANGED: old={} new={}",
                format_hex8(m_last_known_hash_prev_block), format_hex8(tmpl->block.hashPrevBlock));
        } else {
            m_logger->info("[TEMPLATE ANCHOR] ✅ Chain tip unchanged (channel advanced, same tip)");
        }
    }

    m_last_known_hash_prev_block = tmpl->block.hashPrevBlock;
    m_height_tracker.UpdateWithHashPrevBlock(tmpl->block.hashPrevBlock);
    m_height_tracker.ClearPushTipAnchor();

    if (get_session_manager()) {
        auto prev_bytes = m_last_known_hash_prev_block.GetBytes();
        std::array<uint8_t, 4> suffix{};
        if (prev_bytes.size() >= 4) {
            suffix = { prev_bytes[0], prev_bytes[1], prev_bytes[2], prev_bytes[3] };
        }
        get_session_manager()->set_prevblock_suffix(suffix);
        m_last_keepalive_prevhash_lo32 =
            (uint32_t(suffix[0]) << 24) | (uint32_t(suffix[1]) << 16)
          | (uint32_t(suffix[2]) <<  8) | uint32_t(suffix[3]);
    }

    m_logger->info("[TEMPLATE ANCHOR] hashPrevBlock = {}... (tip anchor at template creation)",
                   format_hex8(m_last_known_hash_prev_block));
    m_logger->info("[TEMPLATE ANCHOR] block.nHeight = {} (unified blockchain height)", tmpl->block.nHeight);

    if (snapshot_round_channel_height && m_last_round_status.has_channel_heights) {
        uint32_t snapshot_height = m_last_round_status.get_channel_height(m_channel);
        if (snapshot_height > 0) {
            m_template_interface->set_template_channel_height_snapshot(snapshot_height);
            m_logger->info("[Solo] 📸 Snapshot: {} at height {} (template is for height {})",
                get_channel_name(m_channel), snapshot_height, tmpl->block.nHeight);
        }
    }

    on_template_received(tmpl->block.nHeight);

    if (m_template_interface->needs_channel_height_finalization()) {
        m_logger->debug("[{}] Template pending channel height finalization", log_scope);
    }

    if (!m_set_block_handler) {
        m_logger->error("[{}] CRITICAL: No block handler set - cannot process template", log_scope);
        return false;
    }

    if (!m_template_interface->feed_current_template()) {
        m_logger->debug("[{}] Template feed suppressed by unified debounce gate", log_scope);
    }

    auto stats = m_template_interface->get_stats();
    if (stats.templates_received % 10 == 0) {
        m_logger->debug("[Solo Template Stats] Received: {}, Validated: {}, Rejected: {}, Fed: {}",
            stats.templates_received, stats.templates_validated,
            stats.templates_rejected, stats.templates_fed);
    }

    return true;
}

void Solo::mark_authoritative_soft_refresh(const std::string& reason)
{
    if (m_session_context) {
        m_session_context->mark_soft_refresh_requested(reason);
    }
}

void Solo::mark_authoritative_recovery_required(const std::string& reason)
{
    if (m_session_context) {
        m_session_context->mark_recovery_required(reason);
    }
}

void Solo::mark_authoritative_recovery_healthy(const std::string& reason)
{
    if (m_session_context) {
        m_session_context->mark_recovery_healthy(reason);
    }
}

const Solo::PacketIngressPreflightOptions Solo::kDefaultPacketIngressPreflightOptions{};

bool Solo::run_packet_ingress_preflight(const char* log_scope,
                                        const PacketIngressPreflightOptions& options) const
{
    if (!m_session_context) {
        return true;
    }

    std::string validation_reason;
    const bool session_valid = m_session_context->validate_miner_session(&validation_reason);
    const auto session = m_session_context->get_runtime_snapshot();
    const auto decision = PacketIngressPreflight::evaluate({
        true,
        session_valid,
        session,
        m_protocol_lane,
        options.validate_lane,
        options.allow_without_active_session,
        options.require_crypto_ready,
        options.require_reward_binding,
        SessionId(options.packet_session_id),
        options.owner ? *options.owner : SessionOwnershipStamp{}
    });

    if (decision.allow_processing) {
        return true;
    }

    m_logger->warn("[{}] Session ingress preflight rejected packet: {}", log_scope, decision.reason);
    if (decision.drop_as_stale) {
        const auto kind = decision.stale_reason == PacketStaleReason::OWNERSHIP_EPOCH_MISMATCH
                        ? SessionManager::SessionEventKind::EPOCH_MISMATCH
                        : SessionManager::SessionEventKind::STALE_PACKET_DROPPED;
        record_session_event(kind, std::string(log_scope) + ": " + decision.reason);
    }
    if (!session_valid) {
        m_logger->warn("[{}] Authoritative session validation failed: {}", log_scope, validation_reason);
        m_logger->warn("[{}] {}", log_scope, m_session_context->build_miner_session_diagnostics());
    }

    if (decision.force_reauth && options.trigger_reauth && m_session_expired_handler) {
        record_session_event(SessionManager::SessionEventKind::FORCED_REAUTH,
                             std::string(log_scope) + ": " + decision.reason);
        m_logger->warn("[{}] Triggering session-expired handler after preflight rejection", log_scope);
        m_session_expired_handler();
    }

    return false;
}

bool Solo::ensure_session_ready_for_ingress(const char* log_scope,
                                            const char* packet_name,
                                            bool queue_post_auth_get_block)
{
    // Derive ingress readiness from authoritative session state first.
    // The local m_authenticated flag is a cache that may lag behind the
    // authoritative SessionManager; the policy treats authoritative state as
    // the primary authority and local_auth_stale as a secondary indicator
    // to trigger a cache resync before accepting the packet.
    const bool authoritative_authenticated =
        m_session_context && m_session_context->is_authenticated();
    const auto decision = SessionRecoveryPolicy::evaluate_ingress_readiness({
        m_session_context != nullptr,                              // has_session_context
        authoritative_authenticated,                               // authoritative_authenticated
        !m_authenticated && authoritative_authenticated,           // local_auth_stale
        m_auth_state == AuthState::NOT_AUTHENTICATED               // auth_not_in_flight
    });

    if (!decision.allow_ingress) {
        if (queue_post_auth_get_block && can_use_push_ingress_lifeline()) {
            m_logger->warn("[{}] Accepting {} during auth-in-flight using preserved push lifeline "
                           "(session_id=0x{:08x}, epoch={})",
                           log_scope,
                           packet_name,
                           m_push_ingress_lifeline.session_id,
                           m_push_ingress_lifeline.session_epoch);
            return true;
        }

        if (queue_post_auth_get_block && decision.queue_deferred_push) {
            queue_pending_push_after_auth(log_scope);
        }

        const std::string reason = std::string(packet_name) + " deferred: " + decision.reason;
        m_logger->warn("[{}] Session ingress deferred: {} (auth_state={})",
                       log_scope, reason, static_cast<int>(m_auth_state));

        // Always check whether an in-flight auth has timed out before deciding
        // whether to trigger recovery; this may advance m_auth_state.
        check_auth_in_flight_timeout(log_scope);
        if (decision.trigger_recovery && m_session_expired_handler) {
            record_session_event(SessionManager::SessionEventKind::FORCED_REAUTH,
                                 std::string(log_scope) + ": " + decision.reason);
            m_logger->warn("[{}] Triggering session-expired handler after ingress readiness failure",
                           log_scope);
            m_session_expired_handler();
        }
        return false;
    }

    if (decision.resync_local_cache) {
        m_logger->info("[{}] Session ingress resyncing stale local auth cache before processing {}",
                       log_scope, packet_name);
        resync_auth_from_session_context(log_scope);
        if (!m_authenticated) {
            m_logger->warn("[{}] Session ingress deferred: failed to resync local auth cache for {}",
                           log_scope, packet_name);
            if (m_session_context) {
                m_logger->warn("[{}] {}", log_scope, m_session_context->build_miner_session_diagnostics());
            }
            return false;
        }
    }

    return true;
}

void Solo::queue_pending_push_after_auth(const char* log_scope)
{
    if (m_pending_push_after_auth) {
        return;
    }

    m_pending_push_after_auth = true;
    m_logger->info("[{}] Queued GET_BLOCK to run after authentication flow completes", log_scope);
}

void Solo::capture_push_ingress_lifeline(const char* log_scope)
{
    clear_push_ingress_lifeline();

    if (!m_session_context) {
        return;
    }

    const auto session = m_session_context->get_runtime_snapshot();
    if (!session.authenticated || session.session_id == 0 || !session.ready_for_get_block) {
        return;
    }

    if (!session.reward_address_string.empty() && !session.reward_bound) {
        return;
    }

    m_push_ingress_lifeline.active = true;
    m_push_ingress_lifeline.session_id = session.session_id;
    m_push_ingress_lifeline.session_epoch = session.session_epoch;
    m_push_ingress_lifeline.reward_bound = session.reward_bound;
    m_push_ingress_lifeline.ready_for_get_block = session.ready_for_get_block;

    m_logger->info("[{}] Preserving mining-lane push lifeline across in-band auth "
                   "(session_id=0x{:08x}, epoch={}, ready_for_get_block={}, reward_bound={})",
                   log_scope,
                   m_push_ingress_lifeline.session_id,
                   m_push_ingress_lifeline.session_epoch,
                   m_push_ingress_lifeline.ready_for_get_block ? "yes" : "no",
                   m_push_ingress_lifeline.reward_bound ? "yes" : "no");
}

void Solo::clear_push_ingress_lifeline()
{
    // Reset all preserved pre-auth mining-lane readiness fields.
    m_push_ingress_lifeline = {};
}

bool Solo::can_use_push_ingress_lifeline() const
{
    return m_push_ingress_lifeline.active &&
           is_auth_in_progress() &&
           m_push_ingress_lifeline.ready_for_get_block &&
           m_push_ingress_lifeline.session_id != 0;
}

void Solo::flush_pending_push_after_auth(const std::shared_ptr<network::Connection>& connection,
                                         const char* log_scope)
{
    if (!m_pending_push_after_auth) {
        return;
    }

    if (!connection) {
        m_logger->warn("[{}] Pending post-auth GET_BLOCK still queued: no connection available", log_scope);
        return;
    }

    refresh_cached_session_state(log_scope);

    if (!m_authenticated) {
        m_logger->info("[{}] Pending post-auth GET_BLOCK still queued: canonical session not authenticated yet",
                       log_scope);
        return;
    }

    if (!validate_authoritative_session(log_scope, !m_reward_address.empty())) {
        m_logger->info("[{}] Pending post-auth GET_BLOCK still queued: authoritative session is not ready yet",
                       log_scope);
        return;
    }

    if (!m_reward_address.empty() && !m_reward_bound) {
        m_logger->info("[{}] Pending post-auth GET_BLOCK still queued: reward binding not finished yet",
                       log_scope);
        return;
    }

    m_logger->info("[{}] Push arrived during auth handshake — sending queued GET_BLOCK now", log_scope);

    auto work_payload = get_work();
    if (work_payload && !work_payload->empty()) {
        m_pending_push_after_auth = false;
        connection->transmit(work_payload);
        return;
    }

    if (m_last_get_block_request_status.load() == GetBlockRequestStatus::DUPLICATE_WINDOW) {
        m_pending_push_after_auth = false;
        m_logger->info("[{}] Queued post-auth GET_BLOCK already satisfied by a recent request", log_scope);
        return;
    }

    m_logger->warn("[{}] Queued post-auth GET_BLOCK is still pending after readiness check", log_scope);
}

void Solo::update_connection_metadata(const std::shared_ptr<network::Connection>& connection)
{
    if (!m_session_context) {
        return;
    }

    if (!connection) {
        m_session_context->set_connection_metadata("", "", false);
        return;
    }

    const auto& remote_ep = connection->remote_endpoint();
    const auto& local_ep = connection->local_endpoint();
    m_session_context->set_connection_metadata(local_ep.to_string(), remote_ep.to_string(), true);
}

bool Solo::validate_authoritative_session(const char* log_scope, bool require_reward_binding) const
{
    if (!m_session_context) {
        return true;
    }

    std::string reason;
    if (!m_session_context->validate_miner_session(&reason)) {
        m_logger->error("[{}] Authoritative miner session container consistency failure: {}", log_scope, reason);
        m_logger->error("[{}] {}", log_scope, m_session_context->build_miner_session_diagnostics());
        return false;
    }

    const auto session = m_session_context->get_runtime_snapshot();
    if (require_reward_binding && !session.reward_address_string.empty() && !session.reward_bound) {
        m_logger->error("[{}] Authoritative miner session container requires reward binding before continuing", log_scope);
        m_logger->error("[{}] {}", log_scope, m_session_context->build_miner_session_diagnostics());
        return false;
    }

    return true;
}

void Solo::log_session_container_summary(const char* log_scope) const
{
    if (!m_session_context) {
        return;
    }

    m_logger->info("[{}] {}", log_scope, m_session_context->build_miner_session_diagnostics());
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
    
    if (m_protocol_lane == ProtocolLane::UNKNOWN) {
        m_logger->warn("[Solo Auth] Protocol lane unknown - defaulting to legacy auth opcode");
    }
    
    // Build MINER_AUTH_INIT payload
    network::Payload auth_payload;
    
    // ═══════════════════════════════════════════════════════════
    // STEP 1: hashGenesis FIRST (32 bytes) - enables key derivation
    // ═══════════════════════════════════════════════════════════
    std::vector<uint8_t> tritium_genesis = load_tritium_genesis();
    if (m_session_context) {
        m_session_context->set_tritium_genesis(tritium_genesis);
        m_session_context->set_falcon_identity(m_miner_pubkey, format_hex_prefix(m_miner_pubkey, 16), false);
        m_session_context->set_channel_state(m_channel, false, false);
        m_session_context->mark_activity();
    }
    
    // Genesis goes FIRST in the packet
    auth_payload.insert(auth_payload.end(), tritium_genesis.begin(), tritium_genesis.end());
    
    // ═══════════════════════════════════════════════════════════
    // STEP 2: Prepare pubkey (optionally ChaCha20 wrapped)
    // ═══════════════════════════════════════════════════════════
    std::vector<uint8_t> pubkey_to_send = m_miner_pubkey;
    bool wrapped = false;

    // Only wrap if we have a valid genesis (non-zero)
    bool has_valid_genesis = genesis_utils::is_valid_genesis(tritium_genesis);

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

                m_logger->info("[Solo Auth] ChaCha20 key fingerprint (first 8 bytes): {}",
                               format_hex_prefix(session_key, 8));
                if (m_session_context) {
                    m_session_context->set_chacha20_session_key(session_key,
                                                                format_hex_prefix(session_key, 8),
                                                                true);
                    m_logger->info("[Solo Auth] ✓ Session key stored in authoritative session container");
                } else {
                    m_logger->error("[Solo Auth] Unable to store session key: session context not initialized");
                }

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
    auth_payload.push_back(static_cast<uint8_t>((pubkey_len >> 8) & 0xFF));
    auth_payload.push_back(static_cast<uint8_t>(pubkey_len & 0xFF));
    auth_payload.insert(auth_payload.end(), pubkey_to_send.begin(), pubkey_to_send.end());
    
    // ═══════════════════════════════════════════════════════════
    // STEP 4: miner_id_len + miner_id
    // ═══════════════════════════════════════════════════════════
    std::string miner_id = m_miner_id.empty() ? "NexusMiner" : m_miner_id;
    uint16_t miner_id_len = static_cast<uint16_t>(miner_id.size());
    auth_payload.push_back(static_cast<uint8_t>((miner_id_len >> 8) & 0xFF));
    auth_payload.push_back(static_cast<uint8_t>(miner_id_len & 0xFF));
    auth_payload.insert(auth_payload.end(), miner_id.begin(), miner_id.end());
    
    m_logger->debug("[Solo Auth] Packet built: length={}", auth_payload.size());
    
    auto bytes = PacketBuilder::build(m_protocol_lane, LLP::MINER_AUTH_INIT, auth_payload);
    if (!bytes || bytes->empty())
    {
        m_logger->error("[Solo Auth] CRITICAL: PacketBuilder::build returned null/empty!");
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
    m_logger->info("  Total Size:  {} bytes", auth_payload.size());
    m_logger->info("═══════════════════════════════════════════════════════════");
    m_logger->info("");
    
    // Set state to waiting for challenge
    m_auth_state = AuthState::WAITING_FOR_CHALLENGE;
    m_auth_in_flight_since = std::chrono::steady_clock::now();
    if (m_session_context) {
        capture_push_ingress_lifeline("Solo Auth");
        m_session_context->begin_auth_handshake("falcon auth handshake started");
    }
    
    // Login handler will be called after successful authentication in MINER_AUTH_RESULT
    // For now, mark as "in progress"
    handler(true);
    
    return bytes;
}

network::Shared_payload Solo::get_work()
{
    return get_work(false);
}

network::Shared_payload Solo::get_work(bool bypass_dedup)
{
    /// Request a fresh mining template via GET_BLOCK.
    /// Authentication-guarded; returns null if not authenticated or reward not bound.
    /// No miner-side rate limiting — the node's 2-second AutoCoolDown enforces the server-side floor.

    refresh_cached_session_state("Solo GET_BLOCK");
    const bool using_push_lifeline = can_use_push_ingress_lifeline();

    /* Validate prerequisites */
    if (!m_authenticated && !using_push_lifeline) {
        m_last_get_block_request_status.store(GetBlockRequestStatus::UNAUTHENTICATED);
        m_logger->error("[Solo] Cannot request work - not authenticated");
        m_logger->error("[Solo]   Current auth state: {}",
            m_auth_state == AuthState::NOT_AUTHENTICATED ? "NOT_AUTHENTICATED" :
            m_auth_state == AuthState::WAITING_FOR_CHALLENGE ? "WAITING_FOR_CHALLENGE" :
            m_auth_state == AuthState::WAITING_FOR_RESULT ? "WAITING_FOR_RESULT" :
            "AUTHENTICATED");
        m_logger->error("[Solo]   Waiting for Falcon authentication to complete");
        return nullptr;
    }

    if (!using_push_lifeline &&
        !validate_authoritative_session("Solo GET_BLOCK", !m_reward_address.empty())) {
        m_last_get_block_request_status.store(GetBlockRequestStatus::SESSION_INVALID);
        return nullptr;
    }

    // Only validate reward binding if a reward address was configured
    // (Reward binding is optional for localhost/testing, but required for production)
    if (!m_reward_address.empty() &&
        !m_reward_bound &&
        !(using_push_lifeline && m_push_ingress_lifeline.reward_bound)) {
        m_last_get_block_request_status.store(GetBlockRequestStatus::REWARD_NOT_BOUND);
        m_logger->error("[Solo] Cannot request work - reward address not bound");
        return nullptr;
    }

    // ── GET_BLOCK deduplication guard ────────────────────────────────────────
    // Prevent duplicate GET_BLOCK requests from push_notification_handler and
    // Worker_manager when both independently respond to the same staleness event.
    // Deduplicate within GET_BLOCK_DEDUP_MS (100ms) window.
    auto now_tp = std::chrono::steady_clock::now();
    if (bypass_dedup) {
        m_logger->info("[Solo] GET_BLOCK deduplication bypass active for degraded recovery retry");
    }
    if (!bypass_dedup && m_last_get_block_transmitted_tp != std::chrono::steady_clock::time_point{}) {
        auto elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
            now_tp - m_last_get_block_transmitted_tp).count();
        if (elapsed_ms < GET_BLOCK_DEDUP_MS) {
            m_last_get_block_request_status.store(GetBlockRequestStatus::DUPLICATE_WINDOW);
            m_logger->info("[Solo] GET_BLOCK deduplication: suppressing duplicate request "
                          "({}ms since last transmission, threshold {}ms)",
                          elapsed_ms, GET_BLOCK_DEDUP_MS);
            return nullptr;  // Suppress duplicate
        }
    }

    m_logger->info("[Solo] Requesting mining template via GET_BLOCK");
    m_logger->info("[Solo]   Session ID: 0x{:08x}", m_session_id);
    m_logger->info("[Solo]   Authenticated: {}", (m_authenticated || using_push_lifeline) ? "YES" : "NO");
    m_logger->info("[Solo]   Reward bound: {}",
                   (m_reward_bound || (using_push_lifeline && m_push_ingress_lifeline.reward_bound)) ? "YES" : "NO");
    if (using_push_lifeline) {
        m_logger->warn("[Solo] GET_BLOCK using preserved push lifeline during auth-in-flight "
                       "(session_id=0x{:08x}, epoch={})",
                       m_push_ingress_lifeline.session_id,
                       m_push_ingress_lifeline.session_epoch);
    } else if (m_session_context) {
        m_session_context->set_channel_state(m_channel, false, true);
        m_session_context->mark_activity();
    }

    /* Build GET_BLOCK packet via PacketBuilder (header-only, no payload) */
    auto payload = PacketBuilder::build(m_protocol_lane, LLP::GET_BLOCK);

    if (payload && !payload->empty()) {
        if (using_push_lifeline) {
            m_last_get_block_request_owner = {
                SessionId(m_push_ingress_lifeline.session_id),
                SessionEpoch(m_push_ingress_lifeline.session_epoch)
            };
        } else {
            m_last_get_block_request_owner = capture_session_ownership();
        }
        // Record transmission timestamp for deduplication
        m_last_get_block_transmitted_tp = now_tp;
        m_last_get_block_request_status.store(GetBlockRequestStatus::SENT);

        m_logger->debug("[Solo] GET_BLOCK encoded payload size: {} bytes", payload->size());
        // TRAINING WHEELS: Show GET_BLOCK packet (should be just header byte)
        m_logger->info("[Solo] GET_BLOCK packet hex dump:");
        m_logger->info("\n{}", format_llp_payload_hexdump(payload, 16));
    } else {
        m_last_get_block_request_status.store(GetBlockRequestStatus::BUILD_EMPTY);
        m_logger->error("[Solo] GET_BLOCK PacketBuilder::build returned null or empty payload!");
    }

    return payload;
}

void Solo::reset_get_block_dedup_state()
{
    // Clear the deduplication timestamp so the next get_work() call is not suppressed.
    // This must be called when the canonical tip-anchor changes (same-height chain reorg)
    // or a new degraded-recovery epoch begins — the prior outstanding request was for the
    // old canonical state and is no longer a valid duplicate guard.
    m_last_get_block_transmitted_tp = {};
    m_logger->info("[Solo] ⚡ GET_BLOCK dedup state reset — tip-anchor or recovery epoch changed; next request will not be suppressed");
}

network::Shared_payload Solo::send_get_round()
{
    // GET_ROUND — pure informational/sanity probe.
    //
    // Sends GET_ROUND (legacy: opcode 0x85; stateless: mirror-mapped 0xD085) on
    // all lanes.  The node responds with NEW_ROUND or OLD_ROUND containing height
    // and difficulty info — it does NOT push a block template.
    //
    // To request a fresh mining template use send_recovery_work_request() instead.

    if (!m_authenticated) {
        m_logger->warn("[Solo GET_ROUND] Cannot send GET_ROUND - not authenticated yet");
        m_logger->debug("[Solo GET_ROUND]   Current auth state: {}",
            m_auth_state == AuthState::NOT_AUTHENTICATED ? "NOT_AUTHENTICATED" :
            m_auth_state == AuthState::WAITING_FOR_CHALLENGE ? "WAITING_FOR_CHALLENGE" :
            m_auth_state == AuthState::WAITING_FOR_RESULT ? "WAITING_FOR_RESULT" :
            "AUTHENTICATED");
        return nullptr;
    }

    // Always send GET_ROUND on all lanes (legacy: 0x85, stateless: 0xD085).
    m_logger->debug("[Solo GET_ROUND] Sending GET_ROUND ({} lane)",
        m_protocol_lane == ProtocolLane::STATELESS ? "stateless 0xD085" : "legacy 0x85");
    auto payload = PacketBuilder::build(m_protocol_lane, LLP::GET_ROUND);
    if (payload && !payload->empty()) {
        m_logger->debug("[Solo GET_ROUND] Encoded payload size: {} bytes (header-only)", payload->size());
    } else {
        m_logger->error("[Solo GET_ROUND] PacketBuilder::build returned null or empty payload!");
    }
    return payload;
}

network::Shared_payload Solo::send_recovery_work_request()
{
    // Recovery work request — requests a fresh mining template via GET_BLOCK.
    //
    // Sends GET_BLOCK on all lanes (legacy: 0x81; stateless: mirror-mapped 0xD081).
    // Delegates to get_work() which enforces the miner-side 1s rate limiter and
    // the authentication / reward-binding guards.  Callers must check for a null
    // or empty return value (rate-limited or not yet authenticated).
    //
    // Use this method — not send_get_round() — whenever the goal is to force a
    // template refresh (e.g. Timer_manager recovery, Worker_manager emergency).

    m_logger->debug("[Solo Recovery] Requesting fresh template via GET_BLOCK ({} lane)",
        m_protocol_lane == ProtocolLane::STATELESS ? "stateless 0xD081" : "legacy 0x81");
    return get_work();
}

network::Shared_payload Solo::submit_block(std::vector<std::uint8_t> const& block_data, std::uint64_t nonce)
{
    refresh_cached_session_state("Solo Submit");

    if (block_data.empty()) {
        m_logger->error("[Solo Submit] CRITICAL: block_data is empty! Cannot submit block.");
        return network::Shared_payload{};
    }

    if (!validate_authoritative_session("Solo Submit", !m_reward_address.empty())) {
        return network::Shared_payload{};
    }

    // ── Delegate to StatelessBlockUtility::encode_submit() ──────────────────
    // encode_submit() handles all pre-checks (nonce, channel, height, staleness),
    // Disposable Falcon signing, and PacketBuilder framing (0xD001 vs 0x01).
    // Solo::submit_block() adds ChaCha20 encryption on top of the signed payload.
    if (!m_template_interface || !m_template_interface->has_valid_template()) {
        m_logger->error("[Solo Submit] No valid template — cannot submit block");
        return network::Shared_payload{};
    }

    const auto* tmpl = m_template_interface->get_current_template();
    if (!tmpl) {
        m_logger->error("[Solo Submit] get_current_template() returned null");
        return network::Shared_payload{};
    }

    // Reconstruct the block to submit: current template + found nonce.
    // block_data[0:216] was serialized from the same template by prepare_block_submission().
    ::LLP::CBlock block_to_submit = tmpl->block;
    block_to_submit.nNonce = nonce;
    const auto submit_snapshot = m_height_tracker.GetSnapshot();
    const auto submit_context = capture_submit_context(tmpl->block.nHeight, submit_snapshot.unified_height);
    const auto tracker_channel_tip = submit_snapshot.channel_tip_height.get();
    const auto template_channel_target = tmpl->nChannelHeight;
    const auto template_age_seconds = m_template_interface ? m_template_interface->get_template_age() : 0u;
    const auto prev_hash_bytes = block_to_submit.hashPrevBlock.GetBytes();
    std::array<uint8_t, 4> prevblock_suffix{};
    const auto prevblock_suffix_size = static_cast<std::ptrdiff_t>(prevblock_suffix.size());
    if (prev_hash_bytes.size() >= prevblock_suffix.size()) {
        std::copy(prev_hash_bytes.end() - prevblock_suffix_size,
                  prev_hash_bytes.end(),
                  prevblock_suffix.begin());
    }

    m_logger->info("[Solo Submit][Authoritative]");
    m_logger->info("[Solo Submit][Authoritative]   template_height      = {}", submit_context.template_height);
    m_logger->info("[Solo Submit][Authoritative]   central_tracker_height = {}", submit_context.chain_height);
    m_logger->info("[Solo Submit][Authoritative]   submit_height        = {}", block_to_submit.nHeight);
    m_logger->info("[Solo Submit][Authoritative]   prevblock_hash       = {}", format_hex_prefix(prev_hash_bytes, 8));
    m_logger->info("[Solo Submit][Authoritative]   prevblock_suffix     = {}", format_hex_prefix(prevblock_suffix, 4));
    m_logger->info("[Solo Submit][Authoritative]   session_epoch        = {}", submit_context.session_epoch.get());
    m_logger->info("[Solo Submit][Authoritative]   template_age         = {}s", template_age_seconds);

    if (!submit_context.matches_submit_height(block_to_submit.nHeight)) {
        const std::string detail =
            "template_height=" + std::to_string(submit_context.template_height) +
            " submit_height=" + std::to_string(block_to_submit.nHeight) +
            " chain_height=" + std::to_string(submit_context.chain_height) +
            " session_epoch=" + std::to_string(submit_context.session_epoch.get());
        m_logger->error("[Solo Submit] Authoritative submit-height validation failed: {}", detail);
        record_session_event(SessionManager::SessionEventKind::SUBMIT_REJECTED, detail);
        return network::Shared_payload{};
    }

    if (!tmpl->height_guard.matches(block_to_submit)) {
        const std::string detail =
            "unified_height=" + std::to_string(block_to_submit.nHeight) +
            " expected_unified_height=" + std::to_string(tmpl->height_guard.unified_height.get()) +
            " channel_height=" + std::to_string(tracker_channel_tip) +
            " channel_target=" + std::to_string(template_channel_target) +
            " channel_height_marker=" +
            std::string(is_channel_height(submit_snapshot.channel_tip_height) ? "true" : "false");
        m_logger->error("[Solo Submit] Height guard rejected submission: {}", detail);
        record_session_event(SessionManager::SessionEventKind::SUBMIT_REJECTED, detail);
        return network::Shared_payload{};
    }

    // Snapshot submitted block state for the ACCEPT/GOOD_BLOCK handler
    // so it doesn't need to re-read from a potentially-replaced template.
    m_last_submitted_valid     = true;
    m_last_submitted_owner     = capture_session_ownership();
    m_last_submitted_nonce     = nonce;
    m_last_submitted_prev_hash = tmpl->block.hashPrevBlock;
    m_last_submitted_height    = tmpl->block.nHeight;
    m_last_submitted_channel   = tmpl->block.nChannel;

    // Extract Prime channel vOffsets from block_data (bytes after 216-byte Tritium body).
    // For Hash channel block_data is exactly 216 bytes so this is always empty.
    std::vector<uint8_t> vOffsets;
    if (block_data.size() > StatelessBlockUtility::BLOCK_BODY_SIZE)
        vOffsets.assign(block_data.begin() + StatelessBlockUtility::BLOCK_BODY_SIZE, block_data.end());

    auto submit_result = StatelessBlockUtility::encode_submit(
        *m_template_interface, block_to_submit, vOffsets,
        m_falcon_wrapper.get(), m_protocol_lane,
        submit_snapshot, m_logger, submit_context);

    if (!submit_result.valid) {
        m_logger->error("[Solo Submit] encode_submit() rejected block: {}",
                        submit_result.rejection_reason);
        record_session_event(SessionManager::SessionEventKind::SUBMIT_REJECTED,
                             submit_result.rejection_reason);
        return network::Shared_payload{};
    }

    // ── Extract plaintext payload from PacketBuilder-framed wire_bytes ────────
    // STATELESS wire format: [opcode(2 BE)][length(4 BE)][plaintext_payload]
    // LEGACY wire format:    [opcode(1)   ][length(4 BE)][plaintext_payload]
    const size_t header_size = (m_protocol_lane == ProtocolLane::STATELESS) ? 6u : 5u;
    const auto& framed = *submit_result.wire_bytes;
    if (framed.size() <= header_size) {
        m_logger->error("[Solo Submit] Wire frame too small: {} bytes (header={})",
                        framed.size(), header_size);
        return network::Shared_payload{};
    }
    std::vector<uint8_t> plaintextPayload(framed.begin() + header_size, framed.end());
    record_session_event(SessionManager::SessionEventKind::SUBMIT_SENT,
                         "unified_height=" + std::to_string(m_last_submitted_height) +
                         " channel_height=" + std::to_string(tracker_channel_tip) +
                         " channel_target=" + std::to_string(template_channel_target) +
                         " channel=" + std::to_string(m_last_submitted_channel) +
                         " channel_height_marker=" +
                         std::string(is_channel_height(submit_snapshot.channel_tip_height) ? "true" : "false"));

    // ── Channel-aware payload diagnostics ────────────────────────────────────
    // Compute payload metadata from live data — offset_bytes_count is derived
    // from real block_data, not defaulted to 0.
    const size_t live_offset_bytes = vOffsets.size();
    // Signature size: in the signed path, plaintext includes
    // block + offsets + timestamp(8) + sig_len(2) + signature.
    // If unsigned (no Falcon), signature_size = 0 and plaintext = block + offsets only.
    const size_t block_plus_offsets = StatelessBlockUtility::BLOCK_BODY_SIZE + live_offset_bytes;
    // Minimum signed overhead = timestamp(8) + sig_len_field(2) = 10 bytes
    constexpr size_t MIN_SIGNED_OVERHEAD = 8 + 2;
    const size_t sig_size = (plaintextPayload.size() > block_plus_offsets + MIN_SIGNED_OVERHEAD)
        ? (plaintextPayload.size() - block_plus_offsets - 8 - 2)  // signed: subtract ts + sig_len
        : 0;  // unsigned or too small for signature fields

    auto payload_info = StatelessBlockUtility::compute_submit_payload_info(
        tmpl->block.nChannel, block_plus_offsets, sig_size);

    m_logger->info("[Solo Submit] Channel-aware payload diagnostics:");
    m_logger->info("[Solo Submit]   channel            = {} ({})",
                   payload_info.channel,
                   payload_info.channel == 1 ? "Prime" : "Hash");
    m_logger->info("[Solo Submit]   base_block_size    = {} bytes", payload_info.base_block_size);
    m_logger->info("[Solo Submit]   offset_bytes_count = {} bytes", payload_info.offset_bytes_count);
    m_logger->info("[Solo Submit]   timestamp_size     = {} bytes", payload_info.timestamp_size);
    m_logger->info("[Solo Submit]   sig_len_field_size = {} bytes", payload_info.sig_len_field_size);
    m_logger->info("[Solo Submit]   signature_size     = {} bytes", payload_info.signature_size);
    m_logger->info("[Solo Submit]   plaintext (actual) = {} bytes", plaintextPayload.size());
    m_logger->info("[Solo Submit]   plaintext (expect) = {} bytes", payload_info.expected_plaintext_size());
    m_logger->info("[Solo Submit]   encrypted (expect) = {} bytes", payload_info.expected_encrypted_size());

    // ── ChaCha20-Poly1305 encryption ─────────────────────────────────────────
    if (!m_enable_chacha20) {
        m_logger->error("[Solo Submit] ChaCha20 not enabled");
        return network::Shared_payload{};
    }

    const auto session = m_session_context ? m_session_context->get_runtime_snapshot()
                                           : SessionManager::SessionInfo{};
    const auto& submit_session_key = session.chacha20_session_key;

    // Use the authoritative session key from the session container.
    if (submit_session_key.empty()) {
        m_logger->critical("[Solo Submit] CRITICAL: authoritative session.chacha20_session_key is empty");
        return network::Shared_payload{};
    }

    try {
        if (!m_chacha20_wrapper)
            m_chacha20_wrapper = std::make_unique<ChaCha20Wrapper>();

        // Canonical wrapper path: nonce generation, size validation, and
        // [nonce(12)][ciphertext][tag(16)] assembly are all internal.
        auto enc_result = m_chacha20_wrapper->encrypt_submit_block_payload(
            plaintextPayload, submit_session_key, payload_info);

        if (!enc_result.success || enc_result.data.empty()) {
            m_logger->error("[Solo Submit] ChaCha20 encryption failed: {}",
                            enc_result.error_message);
            return network::Shared_payload{};
        }

        // enc_result.data is already [nonce(12)][ciphertext(plaintext.size())][tag(16)]
        const auto& encryptedPayload = enc_result.data;

        m_logger->info("[Solo Submit] Encrypted payload: {} bytes "
                       "(expected {} from payload_info) → SUBMIT_BLOCK",
                       encryptedPayload.size(),
                       payload_info.expected_encrypted_size());

        auto result = PacketBuilder::build(m_protocol_lane, LLP::SUBMIT_BLOCK, encryptedPayload);
        if (!result || result->empty()) {
            m_logger->error("[Solo Submit] PacketBuilder::build() returned empty packet");
            return network::Shared_payload{};
        }

        m_logger->info("[Solo Submit] {} wire format: {} bytes",
            (m_protocol_lane == ProtocolLane::STATELESS)
                ? "STATELESS_SUBMIT_BLOCK (0xD001)" : "SUBMIT_BLOCK (0x01)",
            result->size());
        if (m_session_context) {
            m_session_context->set_channel_state(m_channel, true, true);
            m_session_context->mark_activity();
        }
        return result;
    }
    catch (const std::exception& e) {
        m_logger->error("[Solo Submit] Exception during encryption: {}", e.what());
        return network::Shared_payload{};
    }
}

void Solo::process_messages(Packet packet, std::shared_ptr<network::Connection> connection)  
{
    // Store connection for multi-packet authentication flow
    if (connection) {
        set_connection(connection);
        update_connection_metadata(connection);
        
        // Initialize protocol lane from connection port (once, on first message)
        if (m_protocol_lane == ProtocolLane::UNKNOWN) {
            initialize_protocol_lane(connection);
        }
    }

    refresh_cached_session_state("Solo ProcessMessages");

    // ═══════════════════════════════════════════════════════════════════════
    // STRICT LANE VALIDATION (NO FALLBACK)
    // ═══════════════════════════════════════════════════════════════════════
    // Validate that received packet matches expected lane framing
    if (m_protocol_lane != ProtocolLane::UNKNOWN) {
        bool expected_uint16 = (m_protocol_lane == ProtocolLane::STATELESS);
        bool received_uint16 = packet.m_is_uint16_opcode;
        
        if (expected_uint16 != received_uint16) {
            // LANE MISMATCH: Server speaking wrong protocol on this port
            auto const& remote_ep = connection->remote_endpoint();
            m_logger->error("═══════════════════════════════════════════════════════════");
            m_logger->error("PROTOCOL LANE MISMATCH - DISCONNECTING");
            m_logger->error("═══════════════════════════════════════════════════════════");
            m_logger->error("Remote:          {}", remote_ep.to_string());
            m_logger->error("Remote Port:     {}", remote_ep.port());
            m_logger->error("Expected Lane:   {} ({}-bit header)", 
                get_lane_name(m_protocol_lane), expected_uint16 ? 16 : 8);
            m_logger->error("Received Header: {} (0x{:04x}) - {}-bit format",
                get_llp_header_name(packet.m_header), packet.m_header, 
                received_uint16 ? 16 : 8);
            m_logger->error("═══════════════════════════════════════════════════════════");
            m_logger->error("Server is speaking the WRONG protocol on this port!");
            m_logger->error("- Port {} should use {} lane", remote_ep.port(), 
                get_lane_name(m_protocol_lane));
            m_logger->error("- NO FALLBACK AVAILABLE (strict port-lane separation)");
            m_logger->error("═══════════════════════════════════════════════════════════");
            
            // Close connection and abort processing
            if (connection) {
                connection->close();
            }
            return;
        }
    }
    
    // Protocol lane is strictly determined by port at connection time (no negotiation/timeout)
    
    // Reject invalid packets at the start
    if (!packet.m_is_valid) {
        m_logger->warn("Solo::process_messages: Received invalid packet - header=0x{:04X} ({}), length={}", 
            packet.m_header, get_llp_header_name(packet.m_header), packet.m_length);
        return;
    }
    
    /* Guard: Un-mirrored stateless opcodes must never arrive on legacy lane */
    if(m_protocol_lane == ProtocolLane::LEGACY &&
       ::LLP::IsUnmirroredDataOpcode(static_cast<uint16_t>(packet.m_header)))
    {
        m_logger->error("[Colin] REJECTED un-mirrored stateless opcode 0x{:04x} ({}) on legacy lane"
                        " — stateless port required",
            packet.m_header, ::LLP::GetUnmirroredOpcodeName(static_cast<uint16_t>(packet.m_header)));
        if(connection) connection->close();
        return;
    }

    // Template-lifeline packets (push notifications and template deliveries) must
    // stay open even when older session-debugging logic would otherwise defer or
    // stale-drop ingress. Dedicated handlers apply their own template validity
    // checks; authoritative-session preflight remains reserved for packets whose
    // semantics truly depend on the currently active session.
    if (requires_active_session_packet(packet)) {
        PacketIngressPreflightOptions preflight;
        preflight.validate_lane = true;
        preflight.trigger_reauth = true;
        if (!run_packet_ingress_preflight("Solo ProcessMessages", preflight)) {
            return;
        }
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
    
    const bool is_block_accepted_compat =
        packet.m_is_uint16_opcode &&
        packet.m_header == LLP::StatelessMining::BLOCK_ACCEPTED_COMPAT &&
        packet.m_length == 0;
    // Some nodes include a 1-byte rejection reason with 0xD003.
    const bool is_block_rejected_compat =
        packet.m_is_uint16_opcode &&
        packet.m_header == LLP::StatelessMining::BLOCK_REJECTED_COMPAT &&
        packet.m_length <= 1;
    
    // 0xD002/0xD003 may be used as stateless response aliases by some nodes.
    // Exclude those compatibility responses from normal BLOCK_HEIGHT parsing.
    if (matches_opcode(packet, Packet::BLOCK_HEIGHT) &&
        !is_block_accepted_compat &&
        !is_block_rejected_compat)
    {
        // Validate packet data before processing
        if (!packet.m_data || packet.m_length < 4) {
            m_logger->warn("Solo::process_messages: BLOCK_HEIGHT packet has invalid data or length < 4");
            return;
        }
        
        auto const height = bytes2uint(*packet.m_data);
        
        // Log the received height information
        m_logger->info("[Solo] Received BLOCK_HEIGHT: height={}", height);
        
        // Use HeightTracker snapshot for comparison (single source of truth).
        // Fall back to m_current_height only during startup before any GET_ROUND/push
        // notification has been received (unified_height == 0 in that case).
        // m_current_height is kept as a diagnostic-only reference.
        auto snap = m_height_tracker.GetSnapshot();
        uint32_t known_height = snap.unified_height > 0 ? snap.unified_height : m_current_height;
        
        if (height > known_height)
        {
            m_logger->info("Nexus Network: New height {} (old height: {})", height, known_height);
            m_current_height = height;  // diagnostic only
            
            // After receiving height, request actual work via GET_BLOCK
            m_logger->info("[Solo] Height updated, requesting work via GET_BLOCK");
            auto work_payload = get_work();
            if (work_payload && !work_payload->empty()) {
                connection->transmit(work_payload);
            } else {
                m_logger->warn("[Solo] GET_BLOCK rate-limited or unavailable — will wait for next node push");
            }
        }
        else
        {
            // Height is unchanged or older than current
            if (height == known_height) {
                m_logger->debug("[Solo] Height unchanged ({}), no action needed", height);
            } else {
                m_logger->warn("[Solo] Received older height {} (current: {})", height, known_height);
            }
        }
    }
    // Handle BLOCK_REWARD response
    else if (matches_opcode(packet, Packet::BLOCK_REWARD))
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
    else if (matches_opcode(packet, Packet::BLOCK_DATA))
    {
        on_block_data(packet, connection);
    }
    else if (matches_opcode(packet, Packet::ACCEPT) || is_block_accepted_compat ||
             matches_opcode(packet, LLP::GOOD_BLOCK))
    {
        on_block_accepted(packet, connection);
    }
    else if (matches_opcode(packet, Packet::REJECT) || is_block_rejected_compat ||
             matches_opcode(packet, LLP::ORPHAN_BLOCK))
    {
        on_block_rejected(packet, connection);
    }
    else if (matches_opcode(packet, Packet::NEW_ROUND) || matches_opcode(packet, Packet::OLD_ROUND))
    {
        on_get_round_response(packet, connection);
    }
    else if (matches_opcode(packet, Packet::MINER_AUTH_CHALLENGE) ||
             matches_opcode(packet, Packet::MINER_AUTH_RESULT)    ||
             matches_opcode(packet, Packet::CHANNEL_ACK)          ||
             matches_opcode(packet, Packet::SESSION_START)        ||
             matches_opcode(packet, Packet::SESSION_KEEPALIVE)    ||
             matches_opcode(packet, Packet::MINER_REWARD_RESULT))
    {
        on_miner_auth_response(packet, connection);
    }
    else if (matches_opcode(packet, Packet::SESSION_EXPIRED))
    {
        on_session_expired(packet, connection);
    }
    else if (matches_opcode(packet, Packet::PRIME_BLOCK_AVAILABLE))
    {
        on_push_notification(packet, connection, mining::CHANNEL_PRIME);
    }
    else if (matches_opcode(packet, Packet::HASH_BLOCK_AVAILABLE))
    {
        on_push_notification(packet, connection, mining::CHANNEL_HASH);
    }
    else if (matches_stateless_opcode(packet, Packet::GET_BLOCK))
    {
        on_stateless_get_block(packet, connection);
    }
    else if (matches_opcode(packet, 0xE0))
    {
        on_ping_diag(packet, connection);
    }
    else if (packet.m_is_uint16_opcode &&
             packet.m_header == ::LLP::KeepAliveV2Opcodes::KEEPALIVE_V2_ACK)
    {
        on_keepalive_ack(packet, connection);
    }
    else if (packet.m_header == static_cast<uint32_t>(::LLP::SessionStatusOpcodes::SESSION_STATUS_ACK)
          || packet.m_header == static_cast<uint32_t>(::LLP::SessionStatusOpcodes::SESSION_STATUS_ACK_LEGACY))
    {
        on_session_status_ack(packet, connection);
    }
    // ═══════════════════════════════════════════════════════════════════════
    // NODE_SHUTDOWN (0xD0FF / legacy 0xFF) — graceful shutdown notice from node
    // ═══════════════════════════════════════════════════════════════════════
    else if(matches_opcode(packet, Packet::NODE_SHUTDOWN))
    {
        ::LLP::NodeShutdownFrame frame;
        std::vector<uint8_t> payload = packet.m_data ? *packet.m_data : std::vector<uint8_t>{};
        if(frame.Parse(payload))
        {
            m_logger->warn("[Solo] ════════════════════════════════════════════════");
            m_logger->warn("[Solo] Node sent graceful shutdown notice (reason={}) — stopping workers",
                frame.ReasonString());
            m_logger->warn("[Solo] Reconnect backoff: {}s", NODE_SHUTDOWN_BACKOFF_S);
            m_logger->warn("[Solo] ════════════════════════════════════════════════");
        }
        else
        {
            m_logger->warn("[Solo] ════════════════════════════════════════════════");
            m_logger->warn("[Solo] Node sent graceful shutdown notice (reason=UNKNOWN, no payload) — stopping workers");
            m_logger->warn("[Solo] Reconnect backoff: {}s", NODE_SHUTDOWN_BACKOFF_S);
            m_logger->warn("[Solo] ════════════════════════════════════════════════");
        }

        // Notify Worker_manager to stop workers and set reconnect backoff
        if(m_node_shutdown_handler)
            m_node_shutdown_handler(frame.reason);
    }
    else
    {
        m_logger->debug("Invalid header received: 0x{:04x}", packet.m_header);
    } 
}

bool Solo::matches_opcode(Packet const& packet, uint16_t legacy_opcode)
{
    if (packet.m_is_uint16_opcode) {
        return packet.m_header == LLP::MirrorOpcode(static_cast<uint8_t>(legacy_opcode));
    }
    return packet.m_header == legacy_opcode;
}

bool Solo::matches_stateless_opcode(Packet const& packet, uint16_t legacy_opcode)
{
    return packet.m_is_uint16_opcode &&
        packet.m_header == LLP::MirrorOpcode(static_cast<uint8_t>(legacy_opcode));
}

bool Solo::requires_active_session_packet(Packet const& packet)
{
    return matches_opcode(packet, Packet::ACCEPT) ||
           matches_opcode(packet, LLP::GOOD_BLOCK) ||
           matches_opcode(packet, Packet::REJECT) ||
           matches_opcode(packet, LLP::ORPHAN_BLOCK) ||
           matches_opcode(packet, Packet::NEW_ROUND) ||
           matches_opcode(packet, Packet::OLD_ROUND) ||
           matches_opcode(packet, Packet::MINER_REWARD_RESULT) ||
           (packet.m_is_uint16_opcode &&
            packet.m_header == ::LLP::KeepAliveV2Opcodes::KEEPALIVE_V2_ACK) ||
           packet.m_header == static_cast<uint32_t>(::LLP::SessionStatusOpcodes::SESSION_STATUS_ACK) ||
           packet.m_header == static_cast<uint32_t>(::LLP::SessionStatusOpcodes::SESSION_STATUS_ACK_LEGACY);
}

void Solo::on_block_data(Packet const& packet, std::shared_ptr<network::Connection> connection)
{
        // Enhanced diagnostics: Check payload is non-null
        if (!packet.m_data) {
            m_logger->error("[Solo] CRITICAL: BLOCK_DATA received with null payload");
            m_logger->error("[Solo] Recovery: Empty BLOCK_DATA indicates node issue — exiting recovery and retrying");

            // Notify Worker_manager to re-initiate recovery (exit current recovery epoch
            // and start a new one with backoff). This prevents staying stuck in recovery
            // mode indefinitely when the node sends empty responses.
            if (m_recovery_handler) {
                m_logger->info("[Solo] Invoking recovery handler to retry GET_BLOCK after backoff");
                m_recovery_handler();
            }

            // Immediate retry after notifying recovery handler
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
        // Node sends BLOCK_DATA (opcode 0) instead of STATELESS_GET_BLOCK (0xD081)
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
        m_logger->info("[Solo Template Delivery]   Protocol Lane: {}", 
            get_lane_name(m_protocol_lane));
        m_logger->info("[Solo Template Delivery] ═══════════════════════════════════");
        
        // TRAINING WHEELS: Full hex dump of BLOCK_DATA payload for debugging
        m_logger->info("[Solo] BLOCK_DATA hex dump:");
        m_logger->info("\n{}", format_llp_payload_hexdump(packet.m_data, 256));
        
        // Validate packet has minimum required data
        if (packet.m_length < MIN_BLOCK_HEADER_SIZE) {
            m_logger->error("[Solo] CRITICAL: BLOCK_DATA packet has invalid length {} < minimum {}",
                packet.m_length, MIN_BLOCK_HEADER_SIZE);
            m_logger->error("[Solo]   - This indicates corrupted or incomplete block data");
            m_logger->error("[Solo] Recovery: Invalid BLOCK_DATA — exiting recovery and retrying");

            // Notify Worker_manager to re-initiate recovery (same as null payload case)
            if (m_recovery_handler) {
                m_logger->info("[Solo] Invoking recovery handler to retry GET_BLOCK after backoff");
                m_recovery_handler();
            }

            // Immediate retry after notifying recovery handler
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

        // Extract 12-byte metadata prefix (big-endian) and strip it before parsing
        uint32_t nUnifiedHeight = 0, nChannelHeight = 0, nBitsMeta = 0;
        {
            const auto& d = *packet.m_data;
            nUnifiedHeight = (uint32_t(d[0]) << 24) | (uint32_t(d[1]) << 16)
                           | (uint32_t(d[2]) <<  8) |  uint32_t(d[3]);
            nChannelHeight = (uint32_t(d[4]) << 24) | (uint32_t(d[5]) << 16)
                           | (uint32_t(d[6]) <<  8) |  uint32_t(d[7]);
            nBitsMeta      = (uint32_t(d[8]) << 24) | (uint32_t(d[9]) << 16)
                           | (uint32_t(d[10]) << 8) |  uint32_t(d[11]);
        }
        // ── HeightTracker BLOCK_DATA feed (Step 1/2) ───────────────────────────────
        // Feed unified_height, channel_height, nBits from the authoritative node
        // BLOCK_DATA metadata prefix.  This is the canonical source of truth for
        // staleness detection — validate_current_template() reads HeightTracker
        // exclusively (not block.nHeight, which is the unified height for ProofHash).
        // Use TEMPLATE source (not PUSH) so last_template_update timestamp is set,
        // enabling the post-push guard in check_template_health() to suppress false-positive
        // emergency stops when the GET_BLOCK response arrives after a push notification.
        update_height_state(nUnifiedHeight, nChannelHeight, nBitsMeta, HeightTracker::UpdateSource::TEMPLATE);

        // ── HeightTracker BLOCK_DATA feed (Step 2/2) ───────────────────────────────
        // Record channel_target = channel_height + 1 so is_template_stale() can
        // detect when the node's channel tip reaches or passes this template's target.
        // Skip genesis (channel_height == 0) to avoid false-positive staleness at startup.
        //
        // Use the effective channel height (max of metadata and tracker) to prevent
        // a stale GET_BLOCK response from setting a channel_target below what push
        // notifications have already established.
        uint32_t effectiveChannelHeight = nChannelHeight;
        {
            auto ht_snap = m_height_tracker.GetSnapshot();
            if (ht_snap.channel_height > effectiveChannelHeight) {
                m_logger->info("[Solo BLOCK_DATA] Metadata channel_height={} stale vs tracker={} — using tracker value",
                    nChannelHeight, ht_snap.channel_height);
                effectiveChannelHeight = ht_snap.channel_height;
            }
        }
        if (effectiveChannelHeight > 0) {
            m_height_tracker.OnTemplateReceived(m_channel, effectiveChannelHeight + 1);
            m_logger->info("[Solo BLOCK_DATA] HeightTracker fed: unified={} channel={} nBits=0x{:08x} → channel_target={}",
                nUnifiedHeight, effectiveChannelHeight, nBitsMeta, effectiveChannelHeight + 1);
        }

        // Strip the 12-byte prefix; pass only the 216-byte Block::Serialize() output to read_template
        auto block_serial = std::make_shared<network::Payload>(
            packet.m_data->begin() + BLOCK_METADATA_PREFIX_SIZE, packet.m_data->end());

        if (m_template_interface) {
            m_logger->info("[Solo READ/FEED] Processing template via Mining Template Interface");
            
            auto validation_result = m_template_interface->read_template(block_serial, source_endpoint, false);
            
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
            if (!finalize_and_feed_current_template(nUnifiedHeight,
                                                    effectiveChannelHeight,
                                                    "Solo FEED",
                                                    true)) {
                m_logger->error("[Solo FEED] Recovery: Block will be discarded, requesting new work");
                if (connection) {
                    auto work_payload = get_work();
                    if (work_payload && !work_payload->empty()) {
                        connection->transmit(work_payload);
                    }
                }
                return;
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
                    m_current_height = block.nHeight;  // diagnostic only
                    
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

void Solo::on_block_accepted(Packet const& packet, std::shared_ptr<network::Connection> connection)
{
    PacketIngressPreflightOptions preflight;
    preflight.owner = &m_last_submitted_owner;
    if (!run_packet_ingress_preflight("Solo BlockAccepted", preflight)) {
        return;
    }

    const bool is_block_accepted_compat =
        packet.m_is_uint16_opcode &&
        packet.m_header == LLP::StatelessMining::BLOCK_ACCEPTED_COMPAT &&
        packet.m_length == 0;

    if (matches_opcode(packet, Packet::ACCEPT) || is_block_accepted_compat)
    {
        stats::Global global_stats{};
        global_stats.m_accepted_blocks = 1;
        m_stats_collector->update_global_stats(global_stats);
        ++m_blocks_accepted;

        // Use submitted block state (snapshotted at submit_block time) so we
        // don't depend on a template that may have been replaced since submission.
        const bool had_last_submitted = m_last_submitted_valid;
        m_last_submitted_valid = false;
        uint32_t accepted_height  = m_last_submitted_height;
        uint32_t accepted_channel = m_last_submitted_channel;
        if (!had_last_submitted) {
            // Fallback: submission state not populated (e.g. legacy path).
            // Warning: template may have been replaced since submission.
            m_logger->warn("BLOCK_ACCEPTED fallback: m_last_submitted_valid=false — "
                           "reading height/channel from current template (may reflect a newer block)");
            if (m_template_interface) {
                auto const* tmpl = m_template_interface->get_current_template();
                if (tmpl) {
                    accepted_height  = tmpl->block.nHeight;
                    accepted_channel = tmpl->block.nChannel;
                }
            }
        }
        m_logger->info("✅ BLOCK ACCEPTED by node — height={} channel={}", accepted_height, accepted_channel);
        m_logger->info("Block Accepted By Nexus Network.");
        record_session_event(SessionManager::SessionEventKind::SUBMIT_ACCEPTED,
                             "height=" + std::to_string(accepted_height) +
                             " channel=" + std::to_string(accepted_channel));

        // Notify Worker_manager to record in the mined-block cache.
        // Use submitted prev_hash and nonce rather than re-reading from template.
        if (m_block_accepted_handler) {
            m_block_accepted_handler(accepted_height, m_last_submitted_prev_hash,
                                     accepted_channel, m_last_submitted_nonce);
        }
        
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
    // Handle legacy GOOD_BLOCK (opcode 6): some legacy nodes send this for valid-but-not-best blocks.
    // Treat as accepted for counter purposes.
    else if (matches_opcode(packet, LLP::GOOD_BLOCK))
    {
        stats::Global global_stats{};
        global_stats.m_accepted_blocks = 1;
        m_stats_collector->update_global_stats(global_stats);
        ++m_blocks_accepted;

        // Use submitted block state (snapshotted at submit_block time).
        const bool had_last_submitted = m_last_submitted_valid;
        m_last_submitted_valid = false;
        uint32_t accepted_height  = m_last_submitted_height;
        uint32_t accepted_channel = m_last_submitted_channel;
        if (!had_last_submitted) {
            m_logger->warn("GOOD_BLOCK fallback: m_last_submitted_valid=false — "
                           "reading height/channel from current template (may reflect a newer block)");
            if (m_template_interface) {
                auto const* tmpl = m_template_interface->get_current_template();
                if (tmpl) {
                    accepted_height  = tmpl->block.nHeight;
                    accepted_channel = tmpl->block.nChannel;
                }
            }
        }
        m_logger->info("✅ BLOCK ACCEPTED by node (Legacy Lane, GOOD_BLOCK) — height={} channel={}",
            accepted_height, accepted_channel);
        record_session_event(SessionManager::SessionEventKind::SUBMIT_ACCEPTED,
                             "height=" + std::to_string(accepted_height) +
                             " channel=" + std::to_string(accepted_channel) +
                             " via GOOD_BLOCK");

        // Notify Worker_manager to record in the mined-block cache.
        // Use submitted prev_hash and nonce rather than re-reading from template.
        if (m_block_accepted_handler) {
            m_block_accepted_handler(accepted_height, m_last_submitted_prev_hash,
                                     accepted_channel, m_last_submitted_nonce);
        }

        auto work_payload = get_work();
        if (work_payload && !work_payload->empty()) {
            connection->transmit(work_payload);
        }
    }
}

void Solo::on_block_rejected(Packet const& packet, std::shared_ptr<network::Connection> connection)
{
    PacketIngressPreflightOptions preflight;
    preflight.owner = &m_last_submitted_owner;
    if (!run_packet_ingress_preflight("Solo BlockRejected", preflight)) {
        return;
    }

    const bool is_block_rejected_compat =
        packet.m_is_uint16_opcode &&
        packet.m_header == LLP::StatelessMining::BLOCK_REJECTED_COMPAT &&
        packet.m_length <= 1;

    if (matches_opcode(packet, Packet::REJECT) || is_block_rejected_compat)
    {
        stats::Global global_stats{};
        global_stats.m_rejected_blocks = 1;
        m_stats_collector->update_global_stats(global_stats);
        ++m_blocks_rejected;

        // Retrieve height and channel from last template for the diagnostic log.
        uint32_t rejected_height = 0;
        uint32_t rejected_channel = m_channel;
        if (m_template_interface) {
            auto const* tmpl = m_template_interface->get_current_template();
            if (tmpl) {
                rejected_height = tmpl->block.nHeight;
                rejected_channel = tmpl->block.nChannel;
            }
        }

        // Parse rejection reason byte if present (stateless lane sends it in payload).
        std::string reason_str = "NONE";
        bool is_fork_rejection = false;
        if (packet.m_data && !packet.m_data->empty()) {
            uint8_t reason_byte = (*packet.m_data)[0];
            switch (reason_byte) {
                case static_cast<uint8_t>(LLP::StatelessMining::RejectionReason::STALE):       reason_str = "STALE"; break;
                case static_cast<uint8_t>(LLP::StatelessMining::RejectionReason::INVALID_POW): reason_str = "INVALID_POW"; break;
                case static_cast<uint8_t>(LLP::StatelessMining::RejectionReason::INVALID_SIG): reason_str = "INVALID_SIG"; break;
                case static_cast<uint8_t>(LLP::StatelessMining::RejectionReason::DUPLICATE):   reason_str = "DUPLICATE"; break;
                case static_cast<uint8_t>(LLP::StatelessMining::RejectionReason::FORK):
                    reason_str = "FORK";
                    is_fork_rejection = true;
                    break;
                default: { char buf[16]; snprintf(buf, sizeof(buf), "0x%02x", reason_byte); reason_str = buf; break; }
            }
        }
        m_logger->warn("❌ BLOCK REJECTED by node — height={} channel={} reason={}", rejected_height, rejected_channel, reason_str);
        m_logger->warn("Block Rejected by Nexus Network.");
        record_session_event(SessionManager::SessionEventKind::SUBMIT_REJECTED,
                             "height=" + std::to_string(rejected_height) +
                             " channel=" + std::to_string(rejected_channel) +
                             " reason=" + reason_str);

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

        // Special handling for FORK rejections: invalidate template and trigger recovery
        if (is_fork_rejection) {
            m_logger->warn("[Solo FORK] FORK rejection detected — invalidating template and initiating recovery");

            // Get current height for fork detection handler
            auto snap = m_height_tracker.GetSnapshot();
            uint32_t unified_height = snap.unified_height;

            // Call handle_fork_detected to invalidate the template
            auto* pManager = get_channel_manager();
            if (pManager) {
                handle_fork_detected(pManager, unified_height);
            } else {
                // Fallback: Invalidate template directly if no channel manager
                if (m_template_interface && m_template_interface->has_valid_template()) {
                    m_template_interface->discard_template("Fork detected - BLOCK_REJECTED:FORK");
                    m_logger->info("[Solo FORK] ✗ Template invalidated due to fork rejection");
                }
            }

            // Notify Worker_manager to mark recovery initiated (same pattern as push handler)
            if (m_recovery_handler) {
                m_logger->info("[Solo FORK] Recovery initiated (fork_rejection) — notifying Worker_manager");
                m_recovery_handler();
            }
        }

        // Request new work with recovery logic
        auto work_payload = get_work();
        if (!work_payload || work_payload->empty()) {
            m_logger->error("[Solo] CRITICAL: GET_BLOCK request after REJECT returned empty payload!");
            m_logger->error("[Solo] Recovery: Retrying work request");
            // Retry once
            work_payload = get_work();
            if (!work_payload || work_payload->empty()) {
                m_logger->error("[Solo] CRITICAL: GET_BLOCK retry also failed - will wait for next node push");
                // NOTE: Do NOT send MINER_READY here. MINER_READY is a one-time subscription
                // handshake; the node keeps the miner subscribed for the session lifetime.
                // The next push from the node will trigger a fresh GET_BLOCK request.
            } else {
                connection->transmit(work_payload);
            }
        } else {
            connection->transmit(work_payload);
        }
    }
    // Handle legacy ORPHAN_BLOCK (opcode 7): some legacy nodes send this for orphaned blocks.
    // Treat as rejected for counter purposes.
    else if (matches_opcode(packet, LLP::ORPHAN_BLOCK))
    {
        stats::Global global_stats{};
        global_stats.m_rejected_blocks = 1;
        m_stats_collector->update_global_stats(global_stats);
        ++m_blocks_rejected;

        uint32_t rejected_height = 0;
        uint32_t rejected_channel = m_channel;
        if (m_template_interface) {
            auto const* tmpl = m_template_interface->get_current_template();
            if (tmpl) {
                rejected_height = tmpl->block.nHeight;
                rejected_channel = tmpl->block.nChannel;
            }
        }
        m_logger->warn("❌ BLOCK REJECTED by node (Legacy Lane, ORPHAN_BLOCK) — height={} channel={}",
            rejected_height, rejected_channel);

        auto work_payload = get_work();
        if (work_payload && !work_payload->empty()) {
            connection->transmit(work_payload);
        }
    }
}

void Solo::on_get_round_response(Packet const& packet, std::shared_ptr<network::Connection> connection)
{
    if (matches_opcode(packet, Packet::NEW_ROUND))
    {
        m_logger->info("[Solo GET_ROUND] NEW_ROUND response received");

        if (get_session_manager()) {
            if (!get_session_manager()->is_active()) {
                m_logger->error("[Solo GET_ROUND] NEW_ROUND received but no active session");
            } else {
                auto session_id = get_session_manager()->get_session_id();
                m_logger->info("[Solo GET_ROUND] NEW_ROUND received, keeping session 0x{:08X}", session_id);
            }
        }
        
        bool get_block_sent_in_handler = false;  // Track whether GET_BLOCK was already requested in this handler
        
        bool legacy_lane = (m_protocol_lane == ProtocolLane::LEGACY);
        bool valid_length = (packet.m_length == 12) || (legacy_lane && packet.m_length == 16);
        
        // ✅ ACCEPTED FORMATS: 12 bytes (preferred) or 16 bytes (legacy multi-channel, legacy lane only)
        if (!packet.m_data || !valid_length) {
            m_logger->error("[Solo GET_ROUND] ❌ PROTOCOL ERROR: Invalid packet length");
            if (legacy_lane) {
                m_logger->error("[Solo GET_ROUND]   Expected:  12 bytes (unified + channel + difficulty)");
                m_logger->error("[Solo GET_ROUND]              16 bytes (unified + prime + hash + stake)");
            } else {
                m_logger->error("[Solo GET_ROUND]   Expected:  12 bytes (unified + channel + difficulty)");
                m_logger->error("[Solo GET_ROUND]   Lane:      {}", get_lane_name(m_protocol_lane));
            }
            m_logger->error("[Solo GET_ROUND]   Received:  {} bytes", packet.m_length);
            m_logger->error("[Solo GET_ROUND]   Node may be running incompatible version");
            m_logger->error("[Solo GET_ROUND]   Required:  LLL-TAO PR #151 or later");
            return;
        }
        
        uint32_t unified_height = 0;
        uint32_t channel_height = 0;
        uint32_t difficulty = m_last_round_status.difficulty;
        uint32_t prime_height = 0;
        uint32_t hash_height = 0;
        uint32_t stake_height = 0;
        bool has_difficulty = false;
        bool is_legacy_multichannel = legacy_lane && (packet.m_length == 16);
        
        if (packet.m_length == 12) {
            // Parse 12-byte response (all big-endian)
            unified_height = bytes2uint(*packet.m_data, 0);
            channel_height = bytes2uint(*packet.m_data, 4);
            difficulty = bytes2uint(*packet.m_data, 8);
            has_difficulty = true;
        } else {
            // Parse 16-byte legacy response (all big-endian)
            unified_height = bytes2uint(*packet.m_data, 0);
            prime_height = bytes2uint(*packet.m_data, 4);
            hash_height = bytes2uint(*packet.m_data, 8);
            stake_height = bytes2uint(*packet.m_data, 12);
            
            if (m_channel == mining::CHANNEL_PRIME) {
                channel_height = prime_height;
            } else if (m_channel == mining::CHANNEL_HASH) {
                channel_height = hash_height;
            } else {
                m_logger->error("[Solo GET_ROUND] Invalid channel: {}", m_channel);
                m_logger->error("[Solo GET_ROUND] Expected 1 (Prime) or 2 (Hash), got {}", m_channel);
                return;
            }
        }
        
        uint32_t previous_channel_height = m_last_round_status.get_channel_height(m_channel);

        // Determine channel name for logging
        std::string channel_name = get_channel_name(m_channel);
        
        // Log response details
        if (is_legacy_multichannel) {
            m_logger->info("[Solo GET_ROUND] 🔔 NEW_ROUND (legacy 16-byte format):");
            m_logger->info("[Solo GET_ROUND]   Unified height:  {} (reference)", unified_height);
            m_logger->info("[Solo GET_ROUND]   Prime height:    {}", prime_height);
            m_logger->info("[Solo GET_ROUND]   Hash height:     {}", hash_height);
            m_logger->info("[Solo GET_ROUND]   Stake height:    {}", stake_height);
            m_logger->info("[Solo GET_ROUND]   {} height:      {} (derived)", channel_name, channel_height);
            m_logger->info("[Solo GET_ROUND]   Difficulty:      (unchanged; not in 16-byte payload)");
        } else {
            m_logger->info("[Solo GET_ROUND] 🔔 NEW_ROUND (12-byte format):");
            m_logger->info("[Solo GET_ROUND]   Unified height:  {} (reference)", unified_height);
            m_logger->info("[Solo GET_ROUND]   {} height:      {}", channel_name, channel_height);
            m_logger->info("[Solo GET_ROUND]   Difficulty:      0x{:08x}", difficulty);
        }
        
        // Update RoundStatus
        m_last_round_status.is_new_round = true;
        m_last_round_status.height = unified_height;
        if (has_difficulty) {
            m_last_round_status.difficulty = difficulty;
        }
        m_last_round_status.has_channel_heights = true;
        
        // Update HeightTracker and ClientChannelManager from GET_ROUND response (single call)
        update_height_state(unified_height, channel_height,
                            has_difficulty ? difficulty : m_last_round_status.difficulty,
                            HeightTracker::UpdateSource::GET_ROUND);
        
        // Set channel-specific height based on miner's channel
        // Reset all channels first, then set only the active channel
        if (is_legacy_multichannel) {
            m_last_round_status.prime_height = prime_height;
            m_last_round_status.hash_height = hash_height;
            m_last_round_status.stake_height = stake_height;
        } else {
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
        }
        
        // Pass channel height to template interface for staleness validation
        if (m_template_interface) {
            m_template_interface->update_channel_height(m_channel, channel_height);
            
            // Check staleness using delta-based detection
            bool is_stale = m_template_interface->check_staleness_by_channel_delta(channel_height);
            
            if (is_stale) {
                m_logger->warn("[Solo GET_ROUND] ⚠️  Template STALE: {} channel advanced", 
                    get_channel_name(m_channel));

                m_logger->info("[Solo GET_ROUND] Requesting fresh template via GET_BLOCK...");
                if (connection) {
                    auto work_payload = get_work();
                    if (work_payload && !work_payload->empty()) {
                        connection->transmit(work_payload);
                        get_block_sent_in_handler = true;
                        m_logger->info("[Solo GET_ROUND] ✓ GET_BLOCK request sent - waiting for new template...");
                    } else {
                        m_logger->error("[Solo GET_ROUND] Failed to generate GET_BLOCK request");
                    }
                } else {
                    m_logger->error("[Solo GET_ROUND] Cannot request fresh template - connection is null");
                }
                return;
            }
            
            m_logger->debug("[Solo] Channel height for staleness validation: {} ({})",
                channel_height, get_channel_name(m_channel));
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
                m_logger->info("[Solo GET_ROUND] ⚠️  Template stale, requesting fresh template via GET_BLOCK...");
            } else {
                m_logger->info("[Solo GET_ROUND] ℹ️  NEW_ROUND received but no template - requesting work");
                m_logger->info("[Solo GET_ROUND]   This handles legacy nodes that send NEW_ROUND without BLOCK_DATA");
            }
            
            // Request template via legacy GET_BLOCK
            if (connection) {
                auto work_payload = get_work();
                if (work_payload && !work_payload->empty()) {
                    connection->transmit(work_payload);
                    get_block_sent_in_handler = true;
                    m_logger->info("[Solo GET_ROUND] ✓ GET_BLOCK request sent - waiting for new template...");
                } else {
                    m_logger->error("[Solo GET_ROUND] Failed to generate GET_BLOCK request");
                }
            }
        } else {
            m_logger->debug("[Solo GET_ROUND] ✓ Template valid, continuing to mine");
        }

        // Event-driven: only request GET_BLOCK when template is actually stale (handled above).
        // No unconditional GET_BLOCK here - avoids feedback loop with template reception.
        if (!get_block_sent_in_handler) {
            m_logger->debug("[Solo GET_ROUND] ✓ Template valid after NEW_ROUND, no GET_BLOCK needed");
        }
        
        // Update intelligent polling state
        if (channel_height == 0 || channel_height == previous_channel_height) {
            m_logger->info("[Solo GET_ROUND] NEW_ROUND received but channel height unchanged; treating as OLD_ROUND/backoff");
            on_old_round_received();
        } else {
            on_new_round_received(unified_height);
        }
    }
    else if (matches_opcode(packet, Packet::OLD_ROUND))
    {
        m_logger->info("[Solo GET_ROUND] OLD_ROUND response received");
        
        bool get_block_sent_in_handler = false;  // Track whether GET_BLOCK was already requested in this handler
        bool legacy_lane = (m_protocol_lane == ProtocolLane::LEGACY);
        bool valid_length = (packet.m_length == 12) || (legacy_lane && packet.m_length == 16);
        
        // ✅ ACCEPTED FORMATS: 12 bytes (preferred) or 16 bytes (legacy multi-channel, legacy lane only)
        if (!packet.m_data || !valid_length) {
            m_logger->error("[Solo GET_ROUND] ❌ PROTOCOL ERROR: Invalid packet length");
            if (legacy_lane) {
                m_logger->error("[Solo GET_ROUND]   Expected:  12 bytes (unified + channel + difficulty)");
                m_logger->error("[Solo GET_ROUND]              16 bytes (unified + prime + hash + stake)");
            } else {
                m_logger->error("[Solo GET_ROUND]   Expected:  12 bytes (unified + channel + difficulty)");
                m_logger->error("[Solo GET_ROUND]   Lane:      {}", get_lane_name(m_protocol_lane));
            }
            m_logger->error("[Solo GET_ROUND]   Received:  {} bytes", packet.m_length);
            return;
        }
        
        uint32_t unified_height = 0;
        uint32_t channel_height = 0;
        uint32_t difficulty = m_last_round_status.difficulty;
        uint32_t prime_height = 0;
        uint32_t hash_height = 0;
        uint32_t stake_height = 0;
        bool has_difficulty = false;
        bool is_legacy_multichannel = legacy_lane && (packet.m_length == 16);
        
        if (packet.m_length == 12) {
            // Parse 12-byte response (all big-endian)
            unified_height = bytes2uint(*packet.m_data, 0);
            channel_height = bytes2uint(*packet.m_data, 4);
            difficulty = bytes2uint(*packet.m_data, 8);
            has_difficulty = true;
        } else {
            // Parse 16-byte legacy response (all big-endian)
            unified_height = bytes2uint(*packet.m_data, 0);
            prime_height = bytes2uint(*packet.m_data, 4);
            hash_height = bytes2uint(*packet.m_data, 8);
            stake_height = bytes2uint(*packet.m_data, 12);
            
            if (m_channel == mining::CHANNEL_PRIME) {
                channel_height = prime_height;
            } else if (m_channel == mining::CHANNEL_HASH) {
                channel_height = hash_height;
            } else {
                m_logger->error("[Solo GET_ROUND] Invalid channel: {}", m_channel);
                m_logger->error("[Solo GET_ROUND] Expected 1 (Prime) or 2 (Hash), got {}", m_channel);
                return;
            }
        }
        
        std::string channel_name = get_channel_name(m_channel);
        
        if (is_legacy_multichannel) {
            m_logger->info("[Solo GET_ROUND] ✓ OLD_ROUND (legacy 16-byte format):");
            m_logger->info("[Solo GET_ROUND]   Unified:       {}", unified_height);
            m_logger->info("[Solo GET_ROUND]   Prime height:  {}", prime_height);
            m_logger->info("[Solo GET_ROUND]   Hash height:   {}", hash_height);
            m_logger->info("[Solo GET_ROUND]   Stake height:  {}", stake_height);
            m_logger->info("[Solo GET_ROUND]   {} height:   {} (derived)", channel_name, channel_height);
            m_logger->info("[Solo GET_ROUND]   Difficulty:    (unchanged; not in 16-byte payload)");
        } else {
            m_logger->info("[Solo GET_ROUND] ✓ OLD_ROUND (12-byte format):");
            m_logger->info("[Solo GET_ROUND]   Unified:  {}", unified_height);
            m_logger->info("[Solo GET_ROUND]   {} height: {} (unchanged)", channel_name, channel_height);
            m_logger->info("[Solo GET_ROUND]   Difficulty: 0x{:08x}", difficulty);
        }
        
        // Update RoundStatus
        m_last_round_status.is_new_round = false;
        m_last_round_status.height = unified_height;
        if (has_difficulty) {
            m_last_round_status.difficulty = difficulty;
        }
        m_last_round_status.has_channel_heights = true;
        
        // Update HeightTracker and ClientChannelManager from OLD_ROUND response
        update_height_state(unified_height, channel_height,
                            has_difficulty ? difficulty : m_last_round_status.difficulty,
                            HeightTracker::UpdateSource::GET_ROUND);
        
        // Set channel-specific height based on miner's channel
        // Reset all channels first, then set only the active channel
        if (is_legacy_multichannel) {
            m_last_round_status.prime_height = prime_height;
            m_last_round_status.hash_height = hash_height;
            m_last_round_status.stake_height = stake_height;
        } else {
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
        }
        
        // Pass channel height to template interface for staleness validation
        if (m_template_interface) {
            m_template_interface->update_channel_height(m_channel, channel_height);
            
            // Check staleness using delta-based detection
            bool is_stale = m_template_interface->check_staleness_by_channel_delta(channel_height);
            
            if (is_stale) {
                m_logger->warn("[Solo GET_ROUND] ⚠️  Template STALE: {} channel advanced", 
                    get_channel_name(m_channel));

                m_logger->info("[Solo GET_ROUND] Requesting fresh template via GET_BLOCK...");
                if (connection) {
                    auto work_payload = get_work();
                    if (work_payload && !work_payload->empty()) {
                        connection->transmit(work_payload);
                        get_block_sent_in_handler = true;
                        m_logger->info("[Solo GET_ROUND] ✓ GET_BLOCK request sent - waiting for new template...");
                    } else {
                        m_logger->error("[Solo GET_ROUND] Failed to generate GET_BLOCK request");
                    }
                } else {
                    m_logger->error("[Solo GET_ROUND] Cannot request fresh template - connection is null");
                }
                return;
            }
            
            m_logger->debug("[Solo] Channel height for staleness validation: {} ({})",
                channel_height, get_channel_name(m_channel));
        }
        
        // Use sync_template_state to handle: channel manager updates, fork detection,
        // template finalization, and template validation
        bool template_valid = sync_template_state(unified_height, channel_height);
        
        if (!template_valid && m_template_interface) {
            m_logger->warn("[Solo GET_ROUND] Unexpected: Template invalidated on OLD_ROUND");
            m_logger->info("[Solo GET_ROUND] Requesting fresh template via GET_BLOCK...");
            
            // Request fresh template
            if (connection) {
                auto work_payload = get_work();
                if (work_payload && !work_payload->empty()) {
                    connection->transmit(work_payload);
                    get_block_sent_in_handler = true;
                    m_logger->info("[Solo GET_ROUND] ✓ GET_BLOCK request sent - waiting for new template...");
                }
            }
        }
        
        // Event-driven: only request GET_BLOCK when template is actually stale (handled above).
        // OLD_ROUND means nothing changed - no need to request a new template.
        if (!get_block_sent_in_handler) {
            m_logger->debug("[Solo GET_ROUND] ✓ OLD_ROUND: no change, no GET_BLOCK needed");
        }
        
        // Update intelligent polling state
        on_old_round_received();
    }
}

void Solo::on_miner_auth_response(Packet const& packet, std::shared_ptr<network::Connection> connection)
{
    if (matches_opcode(packet, Packet::MINER_AUTH_CHALLENGE))
    {
        // Phase 2 Challenge-Response Protocol:
        // Handle MINER_AUTH_CHALLENGE from node and respond with signed nonce
        m_logger->info("[Solo Auth] Received MINER_AUTH_CHALLENGE from node");
        handle_miner_auth_challenge(packet);
    }
    else if (matches_opcode(packet, Packet::MINER_AUTH_RESULT))
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
            m_auth_state = AuthState::AUTHENTICATED;
            m_auth_in_flight_since = {};  // Auth complete — clear in-flight timestamp
            clear_push_ingress_lifeline();

            // Extract session ID if present (4 bytes, little-endian)
            if (packet.m_length >= 5) {
                // Read little-endian uint32
                m_session_id = static_cast<uint32_t>((*packet.m_data)[1]) |
                               (static_cast<uint32_t>((*packet.m_data)[2]) << 8) |
                               (static_cast<uint32_t>((*packet.m_data)[3]) << 16) |
                               (static_cast<uint32_t>((*packet.m_data)[4]) << 24);

                // Validate session ID: must be non-zero for a valid session
                // Zero session ID indicates a protocol error or node-side issue
                if (m_session_id == 0) {
                    m_logger->error("[Solo Auth] CRITICAL: Node sent session_id = 0 (invalid)");
                    m_logger->error("[Solo Auth] This indicates a node-side bug or protocol violation");
                    m_logger->error("[Solo Auth] Valid session IDs must be non-zero");
                    m_logger->error("[Solo Auth] Cannot proceed with mining - session establishment failed");

                    // Reset authentication state
                    m_authenticated = false;
                    m_auth_state = AuthState::NOT_AUTHENTICATED;
                    m_auth_in_flight_since = {};
                    m_pending_push_after_auth = false;
                    clear_push_ingress_lifeline();
                    if (m_session_context) {
                        m_session_context->reset_session_credentials();
                        m_session_context->set_falcon_identity(
                            m_miner_pubkey,
                            format_hex_prefix(m_miner_pubkey, 16),
                            false);
                        m_session_context->set_chacha20_session_key({}, "", false);
                    }

                    // Close connection to force re-authentication
                    if (connection) {
                        connection->close();
                    }
                    return;
                }

                // Visual box logging for success
                std::string genesis_status = (get_session_manager() && !get_session_manager()->get_tritium_genesis().empty())
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

                propagate_session_to_template_interface("Solo Auth");

                // Start session in session manager
                if (m_session_context) {
                    m_session_context->commit_authenticated_session(
                        m_session_id,
                        m_miner_pubkey,
                        format_hex_prefix(m_miner_pubkey, 16),
                        load_tritium_genesis());
                    refresh_cached_session_state("Solo Auth");
                    m_session_context->set_channel_state(m_channel, false, false);
                    m_session_context->start_keepalive_timer();
                    m_session_context->mark_activity();
                    m_logger->info("[Solo Session] Session started in session manager");
                    m_logger->info("[Solo Session] Keepalive timer started (early ping + regular cadence)");
                }
                clear_push_ingress_lifeline();

                // Update template interface with authenticated session ID (FALCON tunnel established)
                if (m_template_interface) {
                    m_template_interface->clear_template_channel_height_snapshot();
                    m_logger->info("[Solo Phase 2] FALCON tunnel established - Template interface bound to session");
                }

                // BUG FIX (Bug 2): Invoke session_authenticated handler AFTER session_id is fully set.
                // This allows Worker_manager to check session_id=0 and trigger retry at the correct time
                // (after MINER_AUTH_RESULT processing, not at login callback which fires too early).
                if (m_session_authenticated_handler) {
                    m_session_authenticated_handler(m_session_id);
                }

                if (!validate_authoritative_session("Solo Auth", false)) {
                    if (connection) {
                        connection->close();
                    }
                    return;
                }
                log_session_container_summary("Solo Auth");
            } else {
                m_logger->info("[Solo Phase 2] ✓ Authentication SUCCEEDED");
                m_logger->warn("[Solo Auth]   - WARNING: No session ID provided by node (expected 5 bytes, got {})",
                    packet.m_length);
                if (m_session_context) {
                    m_session_context->set_falcon_identity(m_miner_pubkey, format_hex_prefix(m_miner_pubkey, 16), true);
                    m_session_context->set_channel_state(m_channel, false, false);
                }

                // BUG FIX (Bug 2): Invoke handler even when no session ID provided (session_id will be 0).
                if (m_session_authenticated_handler) {
                    m_session_authenticated_handler(m_session_id);
                }
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
            m_auth_state = AuthState::NOT_AUTHENTICATED;
            m_auth_in_flight_since = {};
            m_pending_push_after_auth = false;
            clear_push_ingress_lifeline();
            if (m_session_context) {
                m_session_context->reset_session_credentials();
                m_session_context->set_falcon_identity(
                    m_miner_pubkey,
                    format_hex_prefix(m_miner_pubkey, 16),
                    false);
                m_session_context->set_chacha20_session_key({}, "", false);
                m_session_context->set_channel_state(m_channel, false, false);
            }
            
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
    else if (matches_opcode(packet, Packet::CHANNEL_ACK))
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
        
        // ═══════════════════════════════════════════════════════════════════
        // LANE-BASED PROTOCOL FLOW (NO NEGOTIATION)
        // ═══════════════════════════════════════════════════════════════════
        
        if (m_protocol_lane == ProtocolLane::STATELESS) {
            // STATELESS LANE: Send MINER_READY to subscribe to push notifications
            m_logger->info("[Solo Protocol] ═══════════════════════════════════════");
            m_logger->info("[Solo Protocol] STATELESS LANE: Using push protocol");
            m_logger->info("[Solo Protocol] ═══════════════════════════════════════");
            m_logger->info("[Solo Protocol] Sending STATELESS_MINER_READY (0xD0D8)");
            
            auto miner_ready_payload = send_miner_ready();
            if (!miner_ready_payload || miner_ready_payload->empty()) {
                m_logger->error("[Solo Protocol] Failed to encode STATELESS_MINER_READY");
                if (connection) {
                    connection->close();
                }
                return;
            }
            
            if (connection) {
                connection->transmit(miner_ready_payload);
                m_logger->info("[Solo Protocol] ✓ STATELESS_MINER_READY transmitted");
                m_logger->info("[Solo Protocol] Waiting for STATELESS_GET_BLOCK (0xD081) pushes...");
                flush_pending_push_after_auth(connection, "Solo Protocol");
            } else {
                m_logger->error("[Solo Protocol] No connection available");
                return;
            }
        } else if (m_protocol_lane == ProtocolLane::LEGACY) {
            // LEGACY LANE: Send MINER_READY to subscribe to push notifications
            m_logger->info("[Solo Protocol] ═══════════════════════════════════════");
            m_logger->info("[Solo Protocol] LEGACY LANE: Using push protocol");
            m_logger->info("[Solo Protocol] ═══════════════════════════════════════");
            m_logger->info("[Solo Protocol] Sending MINER_READY (0xD8)");
            
            auto miner_ready_payload = send_miner_ready();
            if (!miner_ready_payload || miner_ready_payload->empty()) {
                m_logger->error("[Solo Protocol] Failed to encode MINER_READY");
                if (connection) {
                    connection->close();
                }
                return;
            }
            
            if (connection) {
                connection->transmit(miner_ready_payload);
                m_logger->info("[Solo Protocol] ✓ MINER_READY transmitted");
                m_logger->info("[Solo Protocol] Waiting for PRIME_BLOCK_AVAILABLE/HASH_BLOCK_AVAILABLE pushes...");
                flush_pending_push_after_auth(connection, "Solo Protocol");
            } else {
                m_logger->error("[Solo Protocol] No connection available");
                return;
            }
        } else {
            m_logger->error("[Solo Protocol] UNKNOWN protocol lane - cannot proceed");
            if (connection) {
                connection->close();
            }
            return;
        }
    }
    else if (matches_opcode(packet, Packet::SESSION_START))
    {
        // LLL-TAO SESSION_START handler (session parameters from node)
        // ACTUAL Wire Format: [success(1B: 0x01)][session_id(4B, LE)][timeout(4B, LE)][optional: genesis_hash(32B)]
        // NOTE: Earlier documentation incorrectly stated success byte was only in MINER_AUTH_RESULT.
        //       The node actually sends it again in SESSION_START along with the session_id.
        m_logger->info("[Solo Session] Received SESSION_START from node");

        // Defensive check: SESSION_START should only be processed after successful authentication
        // This guards against node-side bugs where SESSION_START might be sent after auth rejection
        if (!m_authenticated) {
            m_logger->error("[Solo Session] Rejecting SESSION_START - not authenticated");
            m_logger->error("[Solo Session] This indicates a node-side protocol violation");
            m_logger->error("[Solo Session] SESSION_START should only be sent after MINER_AUTH_RESULT success");
            return;
        }

        // Parse SESSION_START packet using dedicated parser
        if (!packet.m_data) {
            m_logger->error("[Solo Session] SESSION_START packet has null data");
            return;
        }

        auto parsed = parse_session_start(packet.m_data->data(), packet.m_length);
        if (!parsed) {
            m_logger->error("[Solo Session] Failed to parse SESSION_START packet");
            m_logger->error("[Solo Session]   - Packet length: {} bytes", packet.m_length);
            m_logger->error("[Solo Session]   - Expected: minimum 9 bytes (success+session_id+timeout), or 41 bytes (with genesis)");
            return;
        }

        // Validate success byte
        if (parsed->success != 0x01) {
            m_logger->error("[Solo Session] Invalid success byte in SESSION_START: 0x{:02x} (expected 0x01)",
                          parsed->success);
            return;
        }

        // Validate session ID matches what we received in MINER_AUTH_RESULT
        if (parsed->session_id != m_session_id) {
            m_logger->error("[Solo Session] Session ID mismatch in SESSION_START:");
            m_logger->error("[Solo Session]   - Expected: 0x{:08x} (from MINER_AUTH_RESULT)", m_session_id);
            m_logger->error("[Solo Session]   - Received: 0x{:08x} (from SESSION_START)", parsed->session_id);
            return;
        }

        // Log parsed session parameters
        m_logger->info("[Solo Session] Session parameters:");
        m_logger->info("[Solo Session]   - Success: 0x{:02x}", parsed->success);
        m_logger->info("[Solo Session]   - Session ID: 0x{:08x}", parsed->session_id);
        m_logger->info("[Solo Session]   - Timeout: {} seconds ({} hours)",
                      parsed->timeout_seconds, parsed->timeout_seconds / 3600);

        if (parsed->has_genesis_hash()) {
            m_logger->info("[Solo Session]   - Tritium Genesis from node: {} bytes",
                          parsed->genesis_hash->size());
            if (m_session_context) {
                m_session_context->set_tritium_genesis(*parsed->genesis_hash);
            }
        }

        // Adjust keepalive interval based on timeout (ping at 1/N of timeout)
        // Using KEEPALIVE_SAFETY_DIVISOR=2 ensures 2 keepalives per node timeout window.
        // Division by 2 is safer: less timer load, larger per-ping safety margin.
        // Example: 24h node timeout → keepalive every 12h (2 pings/window)
        if (parsed->timeout_seconds > 0 && get_session_manager()) {
            uint16_t keepalive_hours = calculate_keepalive_hours(
                parsed->timeout_seconds, ProtocolConstants::KEEPALIVE_SAFETY_DIVISOR);
            get_session_manager()->set_keepalive_interval(keepalive_hours);
            m_logger->info("[Solo Session] Keepalive interval adjusted to {} hours (node timeout={}s, {} pings/window)",
                          keepalive_hours, parsed->timeout_seconds, ProtocolConstants::KEEPALIVE_SAFETY_DIVISOR);
            if (m_session_start_handler) {
                m_session_start_handler(keepalive_hours);
            }
        }

        refresh_cached_session_state("Solo SessionStart");
        if (!validate_authoritative_session("Solo SessionStart", false)) {
            return;
        }
        log_session_container_summary("Solo SessionStart");
    }
    else if (matches_opcode(packet, Packet::SESSION_KEEPALIVE))
    {
        // KEEPALIVE receive handler: branch by payload length
        //   32 bytes → unified keepalive reply (v2): KeepAliveV2AckFrame; provides
        //              unified_height / prime_height / hash_height / stake_height / fork_score
        //   4 bytes  → v1 reply (legacy nodes only): remaining session timeout (LE u32)
        //              heights NOT updated — HeightTracker must rely on push notifications instead
        m_logger->debug("[Solo Session] Received SESSION_KEEPALIVE response ({} bytes)", packet.m_length);

        if (packet.m_data && packet.m_length == 32) {
            // ── Unified 32-byte keepalive reply — parse using KeepAliveV2AckFrame ──
            ::LLP::KeepAliveV2AckFrame unified;
            if (unified.Parse(*packet.m_data))
            {
                PacketIngressPreflightOptions preflight;
                preflight.owner = &m_last_keepalive_request_owner;
                preflight.packet_session_id = unified.session_id;
                if (!run_packet_ingress_preflight("Solo SessionKeepalive", preflight)) {
                    return;
                }

                m_height_tracker.OnKeepaliveResponse(unified.unified_height,
                                                      unified.prime_height,
                                                      unified.hash_height,
                                                      unified.stake_height,
                                                      unified.hash_tip_lo32,
                                                      unified.fork_score);

                m_logger->debug("[Solo Keepalive] Unified reply received:"
                               " session=0x{:08x}"
                               " unified={} prime={} hash={} stake={}"
                               " hash_tip_lo32=0x{:08x} fork_score={}",
                    unified.session_id,
                    unified.unified_height, unified.prime_height,
                    unified.hash_height, unified.stake_height,
                    unified.hash_tip_lo32, unified.fork_score);

                finalize_keepalive_ack("keepalive ack accepted");

                // Fork canary cross-check (legacy path: hash_tip_lo32 and fork_score will be 0)
                // Diagnostic-only: PUSH notification system handles real chain tip advances.
                if (unified.IsForkDetected(m_last_keepalive_prevhash_lo32))
                {
                    m_logger->warn("[SESSION_KEEPALIVE] Fork canary triggered:"
                                   " miner_prevHash_lo32=0x{:08x} node_tip_lo32=0x{:08x} fork_score={}",
                        m_last_keepalive_prevhash_lo32, unified.hash_tip_lo32, unified.fork_score);
                }

            }
        } else if (packet.m_data && packet.m_length == 4) {
            // ── KEEPALIVE v1: remaining timeout (4 bytes LE) ─────────────────────
            uint32_t remaining_timeout = serialization::read_uint32_le(*packet.m_data);
            m_logger->debug("[Solo Session] Session keepalive acknowledged - {} seconds remaining", remaining_timeout);

            finalize_keepalive_ack("keepalive ack accepted");
        } else if (packet.m_length != 0) {
            // Unexpected payload length — ignore gracefully
            m_logger->debug("[Solo Session] Unexpected KEEPALIVE payload length {} — ignored", packet.m_length);
        }
    }
    else if (matches_opcode(packet, Packet::MINER_REWARD_RESULT))
    {
        // Phase 2: Handle MINER_REWARD_RESULT (reward binding result from node)
        handle_reward_result(packet);
    }
}

void Solo::on_session_expired(Packet const& packet, std::shared_ptr<network::Connection> connection)
{
        // SESSION_EXPIRED handler (LLL-TAO PR #354)
        // Node notifies miner that session has expired (inactivity timeout)
        // Wire format: [session_id(4B, LE)][reason(1B)]
        m_logger->info("[Solo Session] Received SESSION_EXPIRED from node");

        // Validate payload size
        if (!packet.m_data || packet.m_length < 5) {
            m_logger->error("[Solo Session] SESSION_EXPIRED packet too small: {} bytes (expected 5)",
                          packet.m_length);
            m_logger->error("[Solo Session]   Expected: [session_id(4B LE)][reason(1B)]");
            return;
        }

        // Parse session_id (little-endian uint32)
        uint32_t expired_sid = static_cast<uint32_t>((*packet.m_data)[0]) |
                               (static_cast<uint32_t>((*packet.m_data)[1]) << 8) |
                               (static_cast<uint32_t>((*packet.m_data)[2]) << 16) |
                               (static_cast<uint32_t>((*packet.m_data)[3]) << 24);

        // Parse reason code
        uint8_t reason = (*packet.m_data)[4];

        // Delegate to handler
        handle_session_expired(expired_sid, reason, connection);
}

void Solo::on_push_notification(Packet const& packet, std::shared_ptr<network::Connection> connection, uint32_t channel)
{
    const char* push_opcode_name = (channel == mining::CHANNEL_PRIME) ? "PRIME_BLOCK_AVAILABLE" : "HASH_BLOCK_AVAILABLE";
        m_push_handler->handle_push_notification(
            packet, channel, m_protocol_lane,
            m_template_interface.get(),
            &m_height_tracker,
            [this](uint32_t u, uint32_t c, uint32_t d) {
                update_height_state(u, c, d, HeightTracker::UpdateSource::PUSH);
            },
            [connection, this, push_opcode_name]() {
                if (!ensure_session_ready_for_ingress("Solo Push", push_opcode_name, true)) {
                    return;
                }
                if (connection) {
                    auto work_payload = get_work();
                    if (work_payload && !work_payload->empty()) {
                        connection->transmit(work_payload);
                    } else {
                        m_logger->warn("[Solo] GET_BLOCK unavailable — will wait for next node push");
                    }
                    // NOTE: Do NOT send MINER_READY here. MINER_READY is a one-time subscription
                    // handshake sent only during initial login. The node keeps the miner subscribed
                    // for the lifetime of the session. GET_BLOCK (0xD081) is the correct recovery
                    // request — it asks for a fresh template without resetting the subscription state.
                }
            },
            [this]() {
                if (m_recovery_handler) {
                    mark_authoritative_recovery_required("push_channel_stale_recovery");
                    m_logger->info("[Solo] ⚡ Unified Tip-Anchor Changed — recovery initiated (push-triggered template replacement), resetting dedup state and notifying Worker_manager");
                    // Reset dedup state so the recovery GET_BLOCK is not blocked by stale
                    // timestamp from the prior request that targeted the old canonical tip.
                    reset_get_block_dedup_state();
                    m_recovery_handler();
                }
            },
            [this]() {
                mark_authoritative_soft_refresh("same_height_push_tip_replacement");
                m_logger->info("[Solo] ⚡ Same-height PUSH hashPrevBlock replacement — soft refresh requested; awaiting fresh template cross-check before degraded-mode decisions");
                reset_get_block_dedup_state();
                if (m_soft_refresh_handler) {
                    m_soft_refresh_handler();
                }
            });
}

void Solo::on_stateless_get_block(Packet const& packet, std::shared_ptr<network::Connection> connection)
{
    // ═══════════════════════════════════════════════════════════════════
    // STATELESS PROTOCOL AUTO-NEGOTIATION: Success!
    // ═══════════════════════════════════════════════════════════════════
    
    // Unified handler for initial template response
    handle_initial_template_response("STATELESS_GET_BLOCK (0xD081)");
    
    // ═══════════════════════════════════════════════════════════════════
    // ENHANCED DIAGNOSTICS: Template delivery tracking
    // ═══════════════════════════════════════════════════════════════════
    m_logger->info("[Solo Template Delivery] ═══════════════════════════════════");
    m_logger->info("[Solo Template Delivery] 📥 TEMPLATE RECEIVED VIA: STATELESS_GET_BLOCK (0xD081)");
        m_logger->info("[Solo Template Delivery]   Mirror-mapped from legacy GET_BLOCK (129)");
        m_logger->info("[Solo Template Delivery]   Delivery Method: Stateless 16-bit opcode");
        m_logger->info("[Solo Template Delivery]   Payload Size: {} bytes", packet.m_length);
        m_logger->info("[Solo Template Delivery]   Expected Format: 12 metadata + 216 block");
        m_logger->info("[Solo Template Delivery]   Protocol Mode: Stateless Push");
        m_logger->info("[Solo Template Delivery] ═══════════════════════════════════");
        
        m_logger->info("[Solo Stateless] ✨ STATELESS_GET_BLOCK (0xD081) received! {} bytes",
                       packet.m_length);

        if (!m_template_interface) {
            m_logger->error("[Solo Stateless] No template interface available!");
            return;
        }

        // ── Decode via StatelessBlockUtility::decode_template() ─────────────────
        // decode_template() validates the 228-byte size, extracts the 12-byte
        // metadata prefix (diagnostic: unified_height, channel_height, nBits), and
        // delegates the 216-byte block body decode to
        // MiningTemplateInterface::read_stateless_payload().  All canonical mining
        // state (nHeight, nChannel, nBits, hashPrevBlock) comes from the block body.
        if (!packet.m_data) {
            m_logger->error("[Solo Stateless] Null packet data — empty STATELESS_GET_BLOCK response");
            m_logger->error("[Solo Stateless] Recovery: Exiting recovery and retrying GET_BLOCK");

            // Notify Worker_manager to re-initiate recovery (same pattern as BLOCK_DATA)
            if (m_recovery_handler) {
                m_logger->info("[Solo Stateless] Invoking recovery handler to retry GET_BLOCK after backoff");
                m_recovery_handler();
            }

            // Immediate retry after notifying recovery handler
            if (connection) {
                auto work_payload = get_work();
                if (work_payload && !work_payload->empty()) {
                    connection->transmit(work_payload);
                } else {
                    m_logger->error("[Solo Stateless] Recovery failed - GET_BLOCK returned empty payload");
                }
            }
            return;
        }
        auto decoded = StatelessBlockUtility::decode_template(
            *m_template_interface, *packet.m_data, m_channel, m_logger, false);

        if (!decoded.valid) {
            m_logger->error("[Solo Stateless] Template decode failed: {}", decoded.error_message);
            m_logger->error("[Solo Stateless] Recovery: Invalid template — exiting recovery and retrying");

            // Notify Worker_manager to re-initiate recovery
            if (m_recovery_handler) {
                m_logger->info("[Solo Stateless] Invoking recovery handler to retry GET_BLOCK after backoff");
                m_recovery_handler();
            }

            // Immediate retry after notifying recovery handler
            if (connection) {
                auto work_payload = get_work();
                if (work_payload && !work_payload->empty()) {
                    connection->transmit(work_payload);
                } else {
                    m_logger->error("[Solo Stateless] Recovery failed - GET_BLOCK returned empty payload");
                }
            }
            return;
        }

        uint32_t unified_height = decoded.unified_height;
        uint32_t channel_height = decoded.channel_height;
        uint32_t difficulty     = decoded.difficulty_nbits;

        m_logger->info("[Solo Stateless] 📦 Metadata: unified={} channel={} nBits=0x{:08x}",
                       unified_height, channel_height, difficulty);
        if (!decoded.channel_consistent) {
            m_logger->warn("[Solo Stateless] ⚠️  Channel mismatch: block.nChannel={} vs mining channel={}",
                           decoded.block.nChannel, m_channel);
        }
        if (!decoded.metadata_consistent) {
            m_logger->warn("[Solo Stateless] ⚠️  Height mismatch: block.nHeight={} vs unified_height+1={}",
                           decoded.block.nHeight, unified_height + 1);
        }


        // ── HeightTracker feed (TEMPLATE source) ────────────────────────────────
        // Registers unified/channel heights as TEMPLATE source so last_template_update
        // timestamp is set — the post-push guard in check_template_health() uses this
        // to suppress false-positive emergency stops when a GET_BLOCK response arrives
        // after a push notification.
        update_height_state(unified_height, channel_height, difficulty,
                            HeightTracker::UpdateSource::TEMPLATE);

        // ── channel_target: use effective channel height (max of metadata + tracker) ─
        // Prevents a stale GET_BLOCK response from setting channel_target below what
        // push notifications have already established.
        uint32_t effectiveChannelHeight = channel_height;
        {
            auto ht_snap = m_height_tracker.GetSnapshot();
            if (ht_snap.channel_height > effectiveChannelHeight) {
                m_logger->info("[Solo Stateless] Metadata channel_height={} stale vs tracker={} — using tracker value",
                    channel_height, ht_snap.channel_height);
                effectiveChannelHeight = ht_snap.channel_height;
            }
        }
        if (effectiveChannelHeight > 0) {
            m_height_tracker.OnTemplateReceived(m_channel, effectiveChannelHeight + 1);
            m_logger->info("[Solo Stateless] HeightTracker fed: unified={} channel={} nBits=0x{:08x} → channel_target={}",
                unified_height, effectiveChannelHeight, difficulty, effectiveChannelHeight + 1);
        }

        if (!finalize_and_feed_current_template(unified_height,
                                                effectiveChannelHeight,
                                                "Solo Stateless",
                                                false)) {
            m_logger->error("[Solo Stateless] Failed to finalize decoded template");
            return;
        }

        m_logger->info("[Solo Stateless] 🎯 Template ready! Mining for height {} (channel {})",
                       unified_height, channel_height);
}

void Solo::on_ping_diag(Packet const& packet, std::shared_ptr<network::Connection> connection)
{
        /* PING_DIAG is stateless-only — reject on legacy lane */
        if(m_protocol_lane != ProtocolLane::STATELESS)
        {
            m_logger->warn("[Colin PING] PING_DIAG rejected on non-stateless lane — stateless port required");
            return;
        }

        /* Exact payload size enforcement for fixed-size PING_DIAG opcode */
        std::vector<uint8_t> payload = packet.m_data ? *packet.m_data : std::vector<uint8_t>{};
        uint32_t nExpected = ::LLP::GetExpectedPayloadSize(::LLP::ColinDiagOpcodes::PING_DIAG);
        if(payload.size() != nExpected)
        {
            m_logger->warn("[Colin PING] Payload size mismatch for PING_DIAG:"
                           " expected {} bytes, got {} — discarding",
                nExpected, payload.size());
            return;
        }

        /* Parse 64-byte PingFrame, build telemetry-enriched PongFrame, reply immediately */
        auto pong_bytes = m_colin_ping_handler.HandlePing(payload, true /* stateless */);
        if(!pong_bytes.empty() && connection)
        {
            /* PONG opcode: 0xD0E1 stateless (mirror-mapped by PacketBuilder) */
            connection->transmit(PacketBuilder::build(m_protocol_lane, 0xE1, pong_bytes));
            m_logger->debug("[Colin PING] PongFrame transmitted (seq #{})",
                m_colin_ping_handler.last_received_ping().sequence);
        }
}

void Solo::on_keepalive_ack(Packet const& packet, std::shared_ptr<network::Connection> connection)
{
        /* Exact payload size enforcement for KEEPALIVE_V2_ACK (32 bytes) */
        std::vector<uint8_t> payload = packet.m_data ? *packet.m_data : std::vector<uint8_t>{};
        uint32_t nExpected = ::LLP::GetExpectedPayloadSize(::LLP::KeepAliveV2Opcodes::KEEPALIVE_V2_ACK);
        if(payload.size() != nExpected)
        {
            m_logger->warn("[KEEPALIVE_V2] ACK payload size mismatch:"
                           " expected {} bytes, got {} — discarding",
                nExpected, payload.size());
            return;
        }
        ::LLP::KeepAliveV2AckFrame ack;
        if(ack.Parse(payload))
        {
            PacketIngressPreflightOptions preflight;
            preflight.owner = &m_last_keepalive_request_owner;
            preflight.packet_session_id = ack.session_id;
            if (!run_packet_ingress_preflight("Solo KeepaliveAck", preflight)) {
                return;
            }

            m_logger->debug("[KEEPALIVE_V2] ACK received: session_id=0x{:08x}"
                            " unified_height={} prime_height={} hash_height={} stake_height={}"
                            " hashPrevBlock_lo32=0x{:08x} hash_tip_lo32=0x{:08x} fork_score={}",
                ack.session_id,
                ack.unified_height, ack.prime_height, ack.hash_height, ack.stake_height,
                ack.hashPrevBlock_lo32, ack.hash_tip_lo32, ack.fork_score);

            // Session ID validation (Gap 1): detect stale ACKs from a previous session.
            // session_id == 0 means legacy / unset — skip check.
            if (handle_session_id_mismatch(ack.session_id))
                return;

            finalize_keepalive_ack("keepalive ack accepted");

            // Update HeightTracker with ACK chain-state heights.
            m_height_tracker.OnKeepaliveResponse(ack.unified_height,
                                                   ack.prime_height,
                                                  ack.hash_height,
                                                  ack.stake_height,
                                                  ack.hash_tip_lo32,
                                                  ack.fork_score);

            // Fork detection: compare node's chain tip against the miner's own locally
            // stored prevHash lo32 (NOT the echoed value from the ACK, which could be
            // tampered to mask a real fork).
            if(ack.IsForkDetected(m_last_keepalive_prevhash_lo32))
            {
                m_logger->warn("[KEEPALIVE_V2] Fork detected!"
                               " miner_prevHash_lo32=0x{:08x} node_tip_lo32=0x{:08x} fork_score={}",
                    m_last_keepalive_prevhash_lo32, ack.hash_tip_lo32, ack.fork_score);

                // Request a fresh template immediately to resolve the fork.
                // Node's 2-second AutoCoolDown is the sole rate limiter.
                if(connection)
                {
                    auto work_payload = get_work();
                    if(work_payload && !work_payload->empty())
                    {
                        connection->transmit(work_payload);
                        m_logger->info("[KEEPALIVE_V2] Fresh template requested for fork recovery");
                    }
                }
            }
        }
}

void Solo::on_session_status_ack(Packet const& packet, std::shared_ptr<network::Connection> connection)
{
        std::vector<uint8_t> data = packet.m_data ? *packet.m_data : std::vector<uint8_t>{};
        ::LLP::SessionStatusAckFrame ack;
        if(ack.Parse(data))
        {
            PacketIngressPreflightOptions preflight;
            preflight.owner = &m_last_session_status_request_owner;
            preflight.packet_session_id = ack.session_id;
            if (!run_packet_ingress_preflight("Solo SessionStatusAck", preflight)) {
                return;
            }

            m_logger->info("[Solo] SESSION_STATUS_ACK: lane_health=0x{:04x} uptime={}s "
                           "primary={} secondary={} simlink={} auth={}",
                           ack.lane_health_flags, ack.uptime_seconds,
                           ack.IsPrimaryAlive(), ack.IsSecondaryAlive(),
                           ack.IsSimLinkActive(), ack.IsAuthenticated());

            if (handle_session_id_mismatch(ack.session_id))
                return;

            if (m_session_context) {
                m_session_context->note_keepalive_ack(true, "session status ack accepted");
            }
            record_session_event(SessionManager::SessionEventKind::STATUS_ACK_ACCEPTED,
                                 "session status ack accepted");

            m_last_session_status_ack      = ack;
            m_last_session_status_ack_time = std::chrono::steady_clock::now();

            const auto decision = SessionStatusPolicy::evaluate_ack_health(
                { ack.uptime_seconds, ack.IsAuthenticated() });
            if (decision.force_reauth) {
                record_session_event(SessionManager::SessionEventKind::FORCED_REAUTH,
                                     "session status ack unhealthy: " + decision.reason);
                m_logger->warn("[Solo] SESSION_STATUS_ACK {} "
                               "(uptime={}s auth={}) — triggering in-band re-auth",
                               decision.reason, ack.uptime_seconds, ack.IsAuthenticated());
                if (m_session_expired_handler) {
                    m_session_expired_handler();
                }
            }
        }
        else
        {
            m_logger->warn("[Solo] SESSION_STATUS_ACK: malformed payload (size={})", data.size());
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
            m_logger->info("[Solo] ✓ Falcon wrapper initialized and valid");
            m_logger->info("[Solo]   Signature size: {} bytes", m_falcon_wrapper->get_signature_size());
        } else {
            m_logger->error("[Solo] ✗ Falcon wrapper NOT valid - block submission will fail!");
            m_logger->error("[Solo]   Check miner.conf for valid falcon_public_key and falcon_private_key");
            m_falcon_wrapper.reset();
        }
    } catch (const std::exception& e) {
        m_logger->error("[Solo] ✗ Failed to initialize Falcon Signature Wrapper: {}", e.what());
        m_logger->error("[Solo]   Check miner.conf for valid falcon_public_key and falcon_private_key");
        m_falcon_wrapper.reset();
    }
}

void Solo::set_protocol_lane(ProtocolLane lane)
{
    m_protocol_lane = lane;
    
    // Also set protocol lane in SessionManager for keepalive packet generation
    if (m_session_context) {
        m_session_context->set_protocol_lane(lane);
        m_session_context->mark_activity();
    }
}

network::Shared_payload Solo::send_session_keepalive()
{
    m_logger->debug("[Solo Session] Sending SESSION_KEEPALIVE for session 0x{:08x}", m_session_id);

    // Delegate to SessionManager which builds the correct 8-byte v2 payload:
    //   [0..3] session_id             (u32 little-endian)
    //   [4..7] miner_prevblock_suffix (last 4 bytes of hashPrevBlock, raw bytes;
    //                                  zeros when no valid template is available)
    // This causes the node to reply with the 32-byte unified KeepAliveV2AckFrame
    // (unified_height / prime_height / hash_height / stake_height / hash_tip_lo32 / fork_score).
    auto payload = get_session_manager()->build_keepalive_packet();
    if (payload && !payload->empty()) {
        m_last_keepalive_request_owner = capture_session_ownership();
    }
    return payload;
}

network::Shared_payload Solo::build_session_status_packet(
    bool degraded, bool workers_running, bool secondary_up) const
{
    bool has_tmpl = m_template_interface && m_template_interface->has_valid_template();
    auto payload = get_session_manager()->build_session_status_packet(
        degraded, has_tmpl, workers_running, secondary_up);
    if (payload && !payload->empty()) {
        m_last_session_status_request_owner = capture_session_ownership();
    }
    return payload;
}

void Solo::send_set_channel(std::shared_ptr<network::Connection> connection)
{
    std::string channel_name = (m_channel == 1) ? "prime" : "hash";
    m_logger->info("[Solo] Sending SET_CHANNEL channel={} ({})", static_cast<int>(m_channel), channel_name);
    if (m_session_context) {
        m_session_context->set_channel_state(m_channel, false, false);
        m_session_context->mark_activity();
    }
    
    std::vector<uint8_t> channel_data(1, m_channel);
    connection->transmit(PacketBuilder::build(m_protocol_lane, LLP::SET_CHANNEL, channel_data));
}

void Solo::set_tritium_genesis(std::vector<uint8_t> const& genesis)
{
    if (genesis.size() != 32) {
        m_logger->warn("[Solo] Invalid Tritium genesis size: {} (expected 32 bytes)", genesis.size());
        return;
    }
    
    // Store persistently to survive reconnections
    m_persistent_tritium_genesis = genesis;
    
    if (m_session_context) {
        m_session_context->set_tritium_genesis(genesis);
        m_logger->info("[Solo] Tritium genesis hash configured for reward binding");
    }
}

void Solo::set_reward_address(std::string const& address)
{
    m_reward_address = address;
    if (m_session_context) {
        m_session_context->set_reward_binding(address, {}, false, address.empty() ? "" : "config");
    }
}

bool Solo::has_tritium_genesis() const
{
    // Check persistent storage first
    if (!m_persistent_tritium_genesis.empty()) {
        return true;
    }
    
    if (get_session_manager()) {
        return !get_session_manager()->get_tritium_genesis().empty();
    }
    return false;
}

void Solo::set_keepalive_interval(std::uint16_t hours)
{
    if (get_session_manager()) {
        get_session_manager()->set_keepalive_interval(hours);
        m_logger->info("[Solo] Keepalive interval set to {} hours", hours);
    }
}

std::uint32_t Solo::get_session_id() const
{
    if (get_session_manager()) {
        return get_session_manager()->get_session_id();
    }
    return m_session_id;  // Fallback to legacy session ID
}

bool Solo::is_session_active() const
{
    if (get_session_manager()) {
        return get_session_manager()->is_active();
    }
    return m_authenticated;  // Fallback to legacy auth status
}

void Solo::set_connection(std::shared_ptr<network::Connection> connection)
{
    m_connection = std::move(connection);
    if (m_session_context) {
        m_session_context->set_connection(m_connection);
        update_connection_metadata(m_connection);
    }
}

void Solo::reset_auth_state()
{
    capture_push_ingress_lifeline("Solo AuthReset");
    m_auth_state = AuthState::NOT_AUTHENTICATED;
    m_auth_in_flight_since = {};
    m_authenticated = false;
    if (m_session_context) {
        m_session_context->reset_session_credentials();
        m_session_context->set_falcon_identity(
            m_miner_pubkey,
            format_hex_prefix(m_miner_pubkey, 16),
            false);
    }
    m_logger->info("[Solo] Auth state reset (in-band re-auth prep)");
}

bool Solo::check_auth_in_flight_timeout(const char* context)
{
    if (is_auth_in_progress() &&
        m_auth_in_flight_since != std::chrono::steady_clock::time_point{} &&
        std::chrono::steady_clock::now() - m_auth_in_flight_since > std::chrono::seconds(AUTH_IN_FLIGHT_TIMEOUT_S)) {
        m_logger->warn("[{}] Auth in-flight timeout (>{}s) — resetting to NOT_AUTHENTICATED",
                       context, AUTH_IN_FLIGHT_TIMEOUT_S);
        m_auth_state = AuthState::NOT_AUTHENTICATED;
        m_auth_in_flight_since = {};
        clear_push_ingress_lifeline();
        return true;
    }
    return false;
}

bool Solo::handle_session_id_mismatch(uint32_t ack_session_id)
{
    auto* session_manager = get_session_manager();
    const uint32_t authoritative_session_id = session_manager ? session_manager->get_session_id() : 0;
    const auto decision = SessionStatusPolicy::validate_ack({
        session_manager != nullptr,
        authoritative_session_id,
        ack_session_id,
        m_session_id_mismatch_count,
        protocol::ProtocolConstants::SESSION_MISMATCH_EXPIRE_THRESHOLD
    });

    m_session_id_mismatch_count = decision.mismatch_count;
    if (decision.accept_ack) {
        return false;
    }

    record_session_event(SessionManager::SessionEventKind::STATUS_ACK_REJECTED, decision.reason);
    if (m_session_context) {
        m_session_context->note_keepalive_ack(false, decision.reason);
    }

    m_logger->warn("[KEEPALIVE_V2] {} #{}: ack=0x{:08x} != authoritative=0x{:08x}"
                   " — possible stale ACK or race condition (not self-expiring yet)",
        decision.reason, m_session_id_mismatch_count, ack_session_id, authoritative_session_id);

    if (decision.expire_session) {
        record_session_event(SessionManager::SessionEventKind::FORCED_REAUTH,
                             "ack mismatch expiry threshold reached");
        m_logger->error("[KEEPALIVE_V2] {} after {} consecutive mismatches — session presumed stale, expiring",
                        decision.reason, m_session_id_mismatch_count);
        m_session_id_mismatch_count = 0;
        session_manager->mark_session_expired("ack mismatch expiry threshold reached");
        if (m_session_expired_handler)
            m_session_expired_handler();
        return true;
    }
    return true;  // mismatch detected — caller must return to skip further ACK processing,
                  // even though the session is not yet expired (threshold not reached)
}

void Solo::handle_session_expired(uint32_t expired_sid, uint8_t reason, std::shared_ptr<network::Connection> connection)
{
    // ═══════════════════════════════════════════════════════════════════════════
    // SESSION_EXPIRED HANDLER (5-step response flow per LLL-TAO PR #354)
    // ═══════════════════════════════════════════════════════════════════════════

    // STEP 1: LOG & VERIFY session_id against authoritative session state.
    // Use SessionRecoveryPolicy to make the stale-replay guard explicit and
    // consistent with the authoritative session machine.
    m_logger->warn("[Solo] SESSION_EXPIRED received: session_id=0x{:08x} reason=0x{:02x}",
                   expired_sid, reason);

    const uint32_t authoritative_session_id = get_session_id();
    const auto recovery_decision = SessionRecoveryPolicy::evaluate_session_expired({
        m_session_context != nullptr,  // has_authoritative_session
        expired_sid,                   // expired_session_id
        authoritative_session_id,      // authoritative_session_id
        reason                         // reason_code
    });

    if (recovery_decision.is_stale_replay) {
        m_logger->warn("[Solo] SESSION_EXPIRED stale or replay — ignoring: {} "
                       "(expired=0x{:08x} authoritative=0x{:08x})",
                       recovery_decision.reason, expired_sid, authoritative_session_id);
        return;
    }

    // Log reason code
    const char* reason_str = "UNKNOWN";
    if (reason == static_cast<uint8_t>(LLP::StatelessMining::SessionExpiredReason::EXPIRED_INACTIVITY)) {
        reason_str = "EXPIRED_INACTIVITY";
    }
    m_logger->warn("[Solo] Session 0x{:08x} expired: reason={} ({}) — {}",
                  authoritative_session_id, reason_str, reason, recovery_decision.reason);

    // STEP 2: CLEAR LOCAL SESSION STATE (mirror reset_auth_state)
    m_logger->info("[Solo] Clearing local session state");
    m_session_id = 0;
    m_authenticated = false;
    m_auth_state = AuthState::NOT_AUTHENTICATED;
    m_auth_in_flight_since = {};
    m_reward_bound = false;  // Reward binding dies with session
    m_subscribed_to_notifications = false;
    clear_push_ingress_lifeline();

    // Clear the authoritative session context
    if (m_session_context) {
        m_session_context->set_chacha20_session_key({}, "", false);
        m_session_context->set_falcon_identity(m_miner_pubkey, format_hex_prefix(m_miner_pubkey, 16), false);
        m_session_context->clear_for_reauth(m_reward_address,
                                            m_reward_address.empty() ? "" : "config",
                                            "node signalled session expiry");
        m_logger->info("[Solo] Session context cleared");
    }

    // DO NOT close the connection — the node kept it open deliberately
    // (The whole point of PR-C is to re-auth on the same TCP connection)

    // STEP 3: STOP WORKERS (via callback)
    // The m_session_expired_handler is registered by Worker_manager to pause workers
    // (no valid template/session to work on)
    if (m_session_expired_handler) {
        m_logger->info("[Solo] Invoking session_expired_handler to stop workers");
        m_session_expired_handler();
    }

    // STEP 4 & 5: EXPONENTIAL BACKOFF THEN RE-AUTH
    // The Worker_manager's session_expired_handler callback will handle:
    // - Exponential backoff using MAX_SESSION_AUTH_RETRIES / BASE_SESSION_RETRY_MS / MAX_SESSION_RETRY_MS
    // - Incrementing retry counter
    // - Scheduling io_context timer to delay re-auth
    // - Calling login(m_login_handler) to re-send MINER_AUTH_INIT on same TCP connection
    //
    // The retry counter will be reset to 0 on next successful SESSION_START (handled separately)

    m_logger->warn("[Solo] SESSION_EXPIRED handling complete — waiting for Worker_manager to re-authenticate");
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

    if (nonce_len == 0) {
        m_logger->error("[Solo Phase 2] MINER_AUTH_CHALLENGE: nonce_len is zero (invalid)");
        reset_auth_state();
        return;
    }
    
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
    
    // Build MINER_AUTH_RESPONSE packet using PacketBuilder
    network::Payload response_payload;
    
    // NOTE: MINER_AUTH_RESPONSE uses little-endian encoding per protocol specification
    // sig_len (2 bytes, little-endian)
    uint16_t sig_len = static_cast<uint16_t>(sign_result.signature.size());
    response_payload.push_back(static_cast<uint8_t>(sig_len & 0xFF));
    response_payload.push_back(static_cast<uint8_t>((sig_len >> 8) & 0xFF));
    
    // signature
    response_payload.insert(response_payload.end(), 
                             sign_result.signature.begin(), 
                             sign_result.signature.end());
    
    // Debug: Verify payload size before transmission
    m_logger->debug("[Solo Auth] MINER_AUTH_RESPONSE payload: length={}", response_payload.size());
    
    m_logger->info("[Solo Phase 2] Sending MINER_AUTH_RESPONSE: sig_len={}, total_size={}", 
                   sig_len, response_payload.size());
    
    // Build and validate the response packet
    auto bytes = PacketBuilder::build(m_protocol_lane, LLP::MINER_AUTH_RESPONSE, response_payload);
    if (!bytes || bytes->empty()) {
        m_logger->error("[Solo Auth] CRITICAL: MINER_AUTH_RESPONSE PacketBuilder::build returned null/empty!");
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
    refresh_cached_session_state("Solo RewardSend");

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
    if (m_session_context) {
        m_session_context->begin_reward_binding(m_reward_address, vHash, "config");
        m_session_context->mark_activity();
    }
    
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
    if (m_enable_chacha20)
    {
        if (!m_chacha20_wrapper)
        {
            m_logger->error("[Solo Reward] ChaCha20 enabled but wrapper not initialized — cannot send reward unencrypted");
            return nullptr;  // hard fail — do NOT send unencrypted
        }
        // Use the authoritative session key from the session container.
        const auto reward_readiness = m_session_context
            ? m_session_context->get_reward_bind_readiness()
            : SessionManager::RewardBindReadiness{false, "session context unavailable"};
        if (!reward_readiness.ready) {
            m_logger->error("[Solo Reward] Cannot send MINER_SET_REWARD: {}",
                            reward_readiness.reason);
            return nullptr;
        }
        const auto session = m_session_context ? m_session_context->get_runtime_snapshot()
                                               : SessionManager::SessionInfo{};
        const auto& reward_session_key = session.chacha20_session_key;

        try {
            auto nonce = ChaCha20Wrapper::generate_nonce();

            // Encrypt the 32-byte hash (NOT the 37-byte address!)
            auto encrypt_result = m_chacha20_wrapper->encrypt(vHash, reward_session_key, nonce, AAD_REWARD_ADDRESS);

            if (encrypt_result.success)
            {
                // Build encrypted format: nonce(12) + ciphertext+tag
                payload_data.insert(payload_data.end(), nonce.begin(), nonce.end());
                payload_data.insert(payload_data.end(), encrypt_result.data.begin(), encrypt_result.data.end());

                m_logger->info("[Solo Reward] Address encrypted: {} → {} bytes (using authoritative session key)",
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
        // Send unencrypted (only valid for localhost connections)
        m_logger->warn("[Solo Reward] ChaCha20 not enabled - sending reward address unencrypted");
        payload_data = vHash;
    }
    
    if (!validate_authoritative_session("Solo RewardSend", false)) {
        return nullptr;
    }
    log_session_container_summary("Solo RewardSend");

    // Build the MINER_SET_REWARD packet via PacketBuilder only after the
    // authoritative session guard passes, so invalid session state cannot
    // silently prepare an outbound reward packet.
    m_logger->info("[Solo Reward] MINER_SET_REWARD packet built: {} bytes", payload_data.size());
    auto payload = PacketBuilder::build(m_protocol_lane, LLP::MINER_SET_REWARD, payload_data);
    if (payload && !payload->empty()) {
        m_last_reward_request_owner = capture_session_ownership();
        record_session_event(SessionManager::SessionEventKind::REWARD_BIND_SENT,
                             "reward bind request sent");
    }
    return payload;
}

network::Shared_payload Solo::send_miner_ready()
{
    bool use_stateless = (m_protocol_lane == ProtocolLane::STATELESS);
    
    if (use_stateless) {
        m_logger->info("[Solo Push] Sending STATELESS_MINER_READY (subscribe to push notifications)");
        m_logger->info("[Solo Push]   Opcode: 0xD0D8 (mirror-mapped from legacy MINER_READY 216)");
    } else {
        m_logger->info("[Solo Push] Sending MINER_READY (subscribe to push notifications)");
        m_logger->info("[Solo Push]   Opcode: 0xD8 (legacy MINER_READY 216)");
    }
    m_logger->info("[Solo Push]   Channel: {} ({})", 
                   m_channel, 
                   m_channel == mining::CHANNEL_PRIME ? "Prime" : "Hash");
    
    // MINER_READY is a header-only packet (no payload); use PacketBuilder for lane-aware framing
    auto payload = PacketBuilder::build(m_protocol_lane, LLP::MINER_READY);
    if (payload && !payload->empty()) {
        m_subscribed_to_notifications = true;
        if (use_stateless) {
            m_logger->info("[Solo Push] ✓ Subscribed to push notifications (stateless protocol)");
            m_logger->info("[Solo Push]   Node will send immediate STATELESS_GET_BLOCK (0xD081)");
            m_logger->info("[Solo Push]   Then push STATELESS_GET_BLOCK on every block validation");
        } else {
            m_logger->info("[Solo Push] ✓ MINER_READY sent - subscribed to channel {}", m_channel);
            m_logger->info("[Solo Push]   Node will send PRIME_BLOCK_AVAILABLE (0xD9) or HASH_BLOCK_AVAILABLE (0xDA)");
            m_logger->info("[Solo Push]   Then push notifications on every block validation");
        }
        
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
    
    // Sets MiningTemplate::nChannelHeight metadata for staleness detection only.
    // DOES NOT modify block.nHeight (which must remain unified height from 216-byte template bytes).
    if (m_template_interface->needs_channel_height_finalization()) {
        // Template builds NEXT block, so channel height = node height + 1
        uint32_t template_channel_height = node_channel_height + 1;
        m_template_interface->set_channel_height(template_channel_height);
        m_logger->info("[Solo GET_ROUND] ✓ Template channel metadata set to {} ({})", 
            template_channel_height, context);
        
        // Diagnostic: confirm block.nHeight (unified) was NOT overwritten by set_channel_height()
        auto const* tmpl = m_template_interface->get_current_template();
        if (tmpl)
        {
            m_logger->debug("[Solo GET_ROUND]   block.nHeight = {} (unified, unchanged)", tmpl->block.nHeight);
            m_logger->debug("[Solo GET_ROUND]   nChannelHeight = {} (metadata only, NOT in block bytes)", template_channel_height);

            // Gap 1 (legacy lane): snapshot hashPrevBlock for parity with stateless lane.
            m_last_known_hash_prev_block = tmpl->block.hashPrevBlock;
            m_height_tracker.UpdateWithHashPrevBlock(tmpl->block.hashPrevBlock);

            // Gap 3: Update session keepalive prevblock_suffix on legacy GET_ROUND lane
            // (mirrors the stateless lane at BLOCK_DATA parse time) so the fork-canary
            // suffix is always current regardless of which protocol lane delivered the template.
            if (get_session_manager()) {
                auto suffix_bytes = m_last_known_hash_prev_block.GetBytes();
                std::array<uint8_t, 4> suffix{};
                if (suffix_bytes.size() >= 4) {
                    // BUG FIX: Use bytes 0-3 (same as node's hash_tip_lo32) for fork canary alignment
                    suffix = { suffix_bytes[0], suffix_bytes[1], suffix_bytes[2], suffix_bytes[3] };
                }
                get_session_manager()->set_prevblock_suffix(suffix);
                m_last_keepalive_prevhash_lo32 =
                    (uint32_t(suffix[0]) << 24) | (uint32_t(suffix[1]) << 16)
                  | (uint32_t(suffix[2]) <<  8) | uint32_t(suffix[3]);
            }

            auto prev_bytes = m_last_known_hash_prev_block.GetBytes();
            std::string prev_hex;
            for (size_t i = 0; i < std::min(prev_bytes.size(), size_t(8)); ++i) {
                char buf[3];
                snprintf(buf, sizeof(buf), "%02x", prev_bytes[i]);
                prev_hex += buf;
            }
            m_logger->info("[TEMPLATE ANCHOR] hashPrevBlock = {}... (tip anchor at template creation)", prev_hex);
            m_logger->info("[TEMPLATE ANCHOR] block.nHeight = {} (unified blockchain height)", tmpl->block.nHeight);
        }
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
    
    // Note: Heights are updated in update_height_state() before this is called.
    // Fork detection flag is set there too; check and handle it here.
    
    // Step 1: Check for fork detection (height regression detected by update_height_state)
    if (pManager->IsForkDetected()) {
        handle_fork_detected(pManager, unified_height);
        return false;  // Template was invalidated
    }
    
    // Step 2: Finalize template channel height if needed
    if (m_template_interface && m_template_interface->needs_channel_height_finalization()) {
        uint32_t template_channel_height = channel_height + 1;
        m_template_interface->set_channel_height(template_channel_height);
        m_logger->info("[Solo Sync] ✓ Template finalized: channel metadata set to {} (NOT written to block.nHeight)", 
            template_channel_height);
        
        // Diagnostic: confirm block.nHeight (unified) was NOT overwritten
        auto const* tmpl_ptr = m_template_interface->get_current_template();
        if (tmpl_ptr)
        {
            m_logger->debug("[Solo Sync]   block.nHeight = {} (unified, unchanged)", tmpl_ptr->block.nHeight);
            m_logger->debug("[Solo Sync]   nChannelHeight = {} (metadata only, NOT in block bytes)", template_channel_height);
        }
    }
    
    // Step 3: Validate current template using HeightTracker (single source of truth)
    return validate_current_template();
}

bool Solo::validate_current_template()
{
    if (!m_template_interface || !m_template_interface->has_valid_template()) {
        return true;  // No template to validate - that's OK
    }
    
    // Get current template
    auto const* tmpl = m_template_interface->get_current_template();
    if (!tmpl) {
        return true;
    }
    
    // Use HeightTracker snapshot for staleness decision (single source of truth).
    // ClientChannelManager heights are kept in sync by update_height_state() but
    // are NOT used for staleness decisions; only HeightTracker is authoritative here.
    auto snap = m_height_tracker.GetSnapshot();
    uint32_t expectedChannel = snap.expected_template_target();
    
    // Validation: Channel height only (unified height may advance due to other channels)
    if (expectedChannel != 0 && tmpl->nChannelHeight != 0 && tmpl->nChannelHeight != expectedChannel) {
        m_logger->warn("[Solo Validate] Channel height mismatch: template={}, expected={}",
            tmpl->nChannelHeight, expectedChannel);
        m_logger->warn("[Solo Validate] Unified height mismatch is expected when other channels advance");
        m_template_interface->discard_template("Channel height stale");
        return false;
    }

    // NOTE: The has_same_height_push_tip_replacement() check was intentionally removed
    // from this gate.  Keeping it here created an infinite soft-refresh / template-swap
    // pending loop: a push set push_hash_prev_block = H_new, but the BLOCK_DATA response
    // to the subsequent GET_BLOCK returned a template with hashPrevBlock = H_old (the node's
    // canonical template, which may legitimately differ from the push hint when the push was
    // premature or from a competing chain tip).  The veto prevented adoption, ClearPushTipAnchor()
    // was never reached, and each new GET_BLOCK response was rejected by the same check,
    // looping indefinitely while Worker_manager reported valid_template=no.
    //
    // Architecture rule: BLOCK_DATA is canonical; push is a hint to request a refresh.
    // Once the node responds to GET_BLOCK with BLOCK_DATA, that template is the ground truth.
    // The push handler already discarded the prior template and triggered the soft refresh;
    // there is no need to veto the replacement here.
    //
    // A push that genuinely represents a same-height chain reorg will be caught by the NEXT
    // push notification after the new template is adopted (the push handler checks
    // has_same_height_push_tip_replacement against the ACTIVE template at that point).
    if (snap.has_same_height_push_tip_replacement(tmpl->block.hashPrevBlock, tmpl->nChannelHeight)) {
        m_logger->info("[Solo Validate] ℹ️  Push tip-anchor differs from incoming BLOCK_DATA "
                       "(push_channel_height={} template_channel_target={}) — "
                       "accepting BLOCK_DATA as canonical (push was a hint, not authoritative)",
                       snap.push_channel_height, tmpl->nChannelHeight);
        // Accept the template — do not discard, do not re-trigger soft refresh.
        // The push anchor will be cleared by ClearPushTipAnchor() in finalize_and_feed_current_template()
        // after successful adoption, preventing this informational log from repeating.
    }

    // Optional: hashPrevBlock staleness check (primary anchor, StakeMinter pattern).
    // Only active when HeightTracker has a known hashPrevBlock (non-zero).
    // Warn-and-continue (compat mode) — node Guard 2 is the final arbiter.
    if (snap.hash_prev_block != uint1024_t(0) &&
        tmpl->block.hashPrevBlock != snap.hash_prev_block) {
        m_logger->warn("[ValidateTemplate] ⚡ Unified Tip-Anchor Changed — hashPrevBlock mismatch (warn-and-continue, node Guard 2 is final arbiter)");
    }
    
    // Note: Age timeout validation (60s safety net) is handled internally by
    // MiningTemplateInterface. No additional validation needed here.
    
    m_logger->debug("[Solo Validate] ✓ Template valid (channel_target={}, unified_height={})", 
        tmpl->nChannelHeight, snap.unified_height);
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

void Solo::update_height_state(uint32_t unified_height, uint32_t channel_height,
                                uint32_t difficulty_nbits, HeightTracker::UpdateSource source)
{
    // Update HeightTracker (single source of truth for staleness decisions)
    if (source == HeightTracker::UpdateSource::PUSH) {
        m_height_tracker.OnPushNotification(unified_height, channel_height, difficulty_nbits);
    } else if (source == HeightTracker::UpdateSource::GET_ROUND) {
        m_height_tracker.OnGetRound(unified_height, channel_height, difficulty_nbits);
    } else if (source == HeightTracker::UpdateSource::TEMPLATE) {
        // Template metadata may arrive after pushes/keepalives have already
        // advanced the tracker beyond the metadata heights.  Use the monotonic
        // OnTemplateMetadata() so that stale BLOCK_DATA metadata cannot regress
        // unified_height / channel_height, which would hide true staleness from
        // is_template_stale() and is_tip_moved().
        // OnTemplateReceived() is called separately by the handler (after read_template()
        // succeeds) to set channel_target — see the STATELESS_GET_BLOCK handler in
        // process_messages() and the legacy BLOCK_DATA handler.
        m_height_tracker.OnTemplateMetadata(unified_height, channel_height, difficulty_nbits);
    } else {
        m_logger->warn("[Solo] update_height_state: unexpected source {}, defaulting to GET_ROUND",
                       static_cast<int>(source));
        m_height_tracker.OnGetRound(unified_height, channel_height, difficulty_nbits);
    }

    // Update active ClientChannelManager with the same parsed values so that
    // fork detection reflects both GET_ROUND and push-notification events.
    auto* pManager = get_channel_manager();
    if (pManager) {
        pManager->UpdateFromGetRound(unified_height, channel_height);
        if (pManager->IsForkDetected()) {
            handle_fork_detected(pManager, unified_height);
        }
    }
}

void Solo::handle_reward_result(const Packet& packet)
{
    m_logger->info("[Solo Reward] Received MINER_REWARD_RESULT");
    refresh_cached_session_state("Solo RewardResult");

    PacketIngressPreflightOptions preflight;
    preflight.owner = &m_last_reward_request_owner;
    preflight.require_crypto_ready = m_enable_chacha20;
    if (!run_packet_ingress_preflight("Solo RewardResult", preflight)) {
        m_reward_bound = false;
        return;
    }
    
    // Validate packet data
    if (!packet.m_data || packet.m_length < 1) {
        m_logger->error("[Solo Reward] Invalid MINER_REWARD_RESULT packet - no data");
        m_reward_bound = false;
        if (m_session_context) {
            m_session_context->commit_reward_rejected(m_reward_address,
                                                      m_reward_address.empty() ? "" : "live bind",
                                                      "empty reward result payload");
        }
        return;
    }
    
    std::vector<uint8_t> result_data;
    
    // Decrypt if ChaCha20 is enabled
    if (m_enable_chacha20 && m_chacha20_wrapper && packet.m_length > 13)
    {
        const auto session = m_session_context ? m_session_context->get_runtime_snapshot()
                                               : SessionManager::SessionInfo{};
        const auto& reward_session_key = session.chacha20_session_key;
        if (!reward_session_key.empty())
        {
            try {
                // Extract nonce (first 12 bytes)
                std::vector<uint8_t> nonce(packet.m_data->begin(), packet.m_data->begin() + 12);
                std::vector<uint8_t> ciphertext(packet.m_data->begin() + 12, packet.m_data->end());
                
                // Decrypt response using matching AAD
                auto decrypt_result = m_chacha20_wrapper->decrypt(ciphertext, reward_session_key, nonce, AAD_REWARD_RESULT);
                
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
        std::vector<uint8_t> reward_hash;
        const auto decoded = decode_base58(m_reward_address);
        if (decoded.size() >= 33) {
            reward_hash.assign(decoded.begin() + 1, decoded.begin() + 33);
        }
        if (m_session_context) {
            m_session_context->commit_reward_bound(m_reward_address, reward_hash, "live bind");
            m_session_context->set_channel_state(m_channel, false, true);
            m_session_context->mark_activity();
        }
        validate_authoritative_session("Solo RewardResult", false);
        log_session_container_summary("Solo RewardResult");
        
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
        if (m_session_context) {
            m_session_context->commit_reward_rejected(m_reward_address, "live bind", error_message);
            m_session_context->set_channel_state(m_channel, false, false);
        }
        
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
    // Log template reception for diagnostic purposes
    // No timing or state tracking - lane is authoritative, determined at connection time
    m_logger->info("[Solo Protocol] ✅ Template received via {}", opcode_name);
    m_logger->debug("[Solo Protocol]   Protocol lane: {}", get_lane_name(m_protocol_lane));
}

// ═══════════════════════════════════════════════════════════════════════
// INTELLIGENT GET_ROUND POLLING IMPLEMENTATION
// ═══════════════════════════════════════════════════════════════════════

bool Solo::should_poll_get_round()
{
    // GET_ROUND polling is DISABLED by default.
    // Push notifications are the primary mechanism for height detection:
    // - Legacy: PRIME_BLOCK_AVAILABLE (0xD9) / HASH_BLOCK_AVAILABLE (0xDA)
    // - Stateless: STATELESS_PRIME_BLOCK_AVAILABLE (0xD0D9) / STATELESS_HASH_BLOCK_AVAILABLE (0xD0DA)
    // Event-driven GET_BLOCK handles template requests on demand.
    // Template health monitor (300s timeout) provides emergency safety net.
    if (!POLLING_ENABLED) {
        return false;
    }

    auto now = std::chrono::steady_clock::now();
    auto elapsed_ms = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(
            now - m_last_get_round_time).count());

    if (elapsed_ms < static_cast<uint64_t>(m_current_poll_interval_ms)) {
        return false;
    }

    m_last_get_round_time = now;
    m_logger->debug("[Solo Poll] GET_ROUND sanity-check poll (interval {}ms)", m_current_poll_interval_ms);
    return true;
}

void Solo::on_new_round_received(uint32_t new_unified_height)
{
    // NEW_ROUND = block was found, reset to fast polling
    m_current_poll_interval_ms = POLL_INTERVAL_MIN_MS;
    // Hard clamp: never allow polling below configured minimum
    m_current_poll_interval_ms = std::max(m_current_poll_interval_ms, POLL_INTERVAL_MIN_MS);
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
    // Hard clamp: never allow polling below configured minimum
    m_current_poll_interval_ms = std::max(m_current_poll_interval_ms, POLL_INTERVAL_MIN_MS);
    
    if (m_current_poll_interval_ms != old_interval) {
        m_logger->debug("[Solo Poll] OLD_ROUND: backing off interval {}ms → {}ms",
            old_interval, m_current_poll_interval_ms);
    }
}

void Solo::on_template_received(uint32_t template_height)
{
    // Track template reception for height delta detection
    m_needs_initial_round_check = true;
    m_template_unified_height = template_height;
    m_last_get_round_time = std::chrono::steady_clock::now();  // Reset timer
    m_logger->debug("[Solo Poll] Template received (height {})", template_height);
}

void Solo::check_unified_height_delta(uint32_t current_unified_height)
{
    if (m_template_unified_height == 0) {
        return;  // No template yet
    }
    
    // When the unified tip moves, hashPrevBlock in the current template becomes
    // stale even if the channel height hasn't changed. Request a fresh template
    // so mining doesn't waste work on an orphan-prone block.
    // Rate limiting in get_work() (6500ms) prevents spamming the node.
    if (current_unified_height > m_template_unified_height) {
        uint32_t delta = current_unified_height - m_template_unified_height;
        
        m_logger->info("[Solo Poll] ↑ Unified tip moved {} blocks ({} → {}) [reason: tip_moved] — requesting fresh template",
            delta, m_template_unified_height, current_unified_height);
        // Update to avoid repeated log spam
        m_template_unified_height = current_unified_height;

        // Request fresh template via GET_BLOCK (rate-limited)
        if (m_connection) {
            auto work = get_work();
            if (work && !work->empty()) {
                m_connection->transmit(work);
                m_logger->info("[Solo Poll] ✓ GET_BLOCK sent for tip refresh");
            } else {
                m_logger->debug("[Solo Poll] GET_BLOCK rate-limited — tip refresh deferred");
            }
        }
    }
}

void Solo::initialize_protocol_lane(std::shared_ptr<network::Connection> connection)
{
    if (!connection) {
        m_logger->error("[Lane Init] No connection available - cannot determine protocol lane");
        return;
    }
    
    auto const& remote_ep = connection->remote_endpoint();
    uint16_t remote_port = remote_ep.port();
    
    // Determine lane from port (authoritative)
    m_protocol_lane = determine_lane_from_port(remote_port);
    
    // Log lane selection with loud formatting
    m_logger->info("═══════════════════════════════════════════════════════════");
    m_logger->info("PROTOCOL LANE INITIALIZATION (Solo Protocol Layer)");
    m_logger->info("═══════════════════════════════════════════════════════════");
    m_logger->info("Remote:          {}", remote_ep.to_string());
    m_logger->info("Remote Port:     {}", remote_port);
    m_logger->info("Selected Lane:   {}", get_lane_name(m_protocol_lane));
    m_logger->info("Lane Source:     Port-determined (authoritative)");
    
    if (m_protocol_lane == ProtocolLane::LEGACY) {
        m_logger->info("Framing:         8-bit header (legacy)");
        m_logger->info("Behavior:        Polling (GET_ROUND / GET_BLOCK)");
        m_logger->info("Authentication:  Falcon + ChaCha20 (required)");
    } else if (m_protocol_lane == ProtocolLane::STATELESS) {
        m_logger->info("Framing:         16-bit header (0xD000-0xD0FF)");
        m_logger->info("Behavior:        Push (STATELESS_GET_BLOCK)");
        m_logger->info("Authentication:  Falcon + ChaCha20 (required)");
    }
    
    m_logger->info("═══════════════════════════════════════════════════════════");
    m_logger->info("STRICT LANE SEPARATION: NO FALLBACK BETWEEN LANES");
    m_logger->info("═══════════════════════════════════════════════════════════");
}

}
}
