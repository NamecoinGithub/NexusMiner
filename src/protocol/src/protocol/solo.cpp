#include "protocol/solo.hpp"
#include "protocol/protocol.hpp"
#include "protocol/falcon_constants.hpp"
#include "packet.hpp"
#include "network/connection.hpp"
#include "stats/stats_collector.hpp"
#include "LLP/block_utils.hpp"
#include "LLP/llp_logging.hpp"
#include "../miner_keys.hpp"
#include <openssl/sha.h>
#include <chrono>
#include <sstream>
#include <iomanip>

namespace nexusminer
{
namespace protocol
{

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
, m_block_signing_enabled{false}  // Disabled by default for performance
, m_chacha20_wrapper{nullptr}  // Lazy initialization when needed
, m_enable_chacha20{false}  // Auto-detect based on connection type
, m_session_manager{nullptr}
, m_template_interface{nullptr}
, m_connection{nullptr}
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
    
    // Initialize the Mining Template Interface for unified READ/FEED operations
    // Session ID starts at 0 (unauthenticated) and will be updated after MINER_AUTH_RESULT
    // The session ID binds the template interface to the FALCON authenticated tunnel
    m_template_interface = std::make_unique<MiningTemplateInterface>(m_channel, 0);
    m_logger->info("[Solo] Mining Template Interface initialized for unified READ/FEED system");
}

std::vector<uint8_t> Solo::derive_chacha20_session_key(const std::vector<uint8_t>& genesis)
{
    static const std::string DOMAIN = "nexus-mining-chacha20-v1";
    
    std::vector<uint8_t> preimage;
    preimage.insert(preimage.end(), DOMAIN.begin(), DOMAIN.end());
    preimage.insert(preimage.end(), genesis.begin(), genesis.end());
    
    // Use OpenSSL SHA256
    std::vector<uint8_t> key(32);
    SHA256(preimage.data(), preimage.size(), key.data());
    return key;
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
    
    Packet packet;
    packet.m_header = Packet::MINER_AUTH_INIT;  // 207
    packet.m_data = std::make_shared<network::Payload>();
    
    // ═══════════════════════════════════════════════════════════
    // STEP 1: hashGenesis FIRST (32 bytes) - enables key derivation
    // ═══════════════════════════════════════════════════════════
    std::vector<uint8_t> tritium_genesis;
    if (m_session_manager && !m_session_manager->get_tritium_genesis().empty()) 
    {
        tritium_genesis = m_session_manager->get_tritium_genesis();
        m_logger->info("[Solo Phase 2] Using hashGenesis for ChaCha20 key derivation");
    }
    else
    {
        tritium_genesis.resize(32, 0);  // 32 zero bytes
        m_logger->warn("[Solo Phase 2] No genesis - ChaCha20 encryption unavailable");
    }
    
    // Genesis goes FIRST in the packet
    packet.m_data->insert(packet.m_data->end(), tritium_genesis.begin(), tritium_genesis.end());
    
    // ═══════════════════════════════════════════════════════════
    // STEP 2: Prepare pubkey (optionally ChaCha20 wrapped)
    // ═══════════════════════════════════════════════════════════
    std::vector<uint8_t> pubkey_to_send = m_miner_pubkey;
    bool wrapped = false;
    
    // Only wrap if we have a valid genesis (non-zero)
    bool has_valid_genesis = !tritium_genesis.empty() && 
        std::any_of(tritium_genesis.begin(), tritium_genesis.end(), [](uint8_t b){ return b != 0; });
    
    if (m_enable_chacha20 && has_valid_genesis)
    {
        m_logger->info("[Solo Auth] ChaCha20 wrapping ENABLED (genesis-derived key)");
        
        // Derive session key from genesis
        auto session_key = derive_chacha20_session_key(tritium_genesis);
        auto nonce = ChaCha20Wrapper::generate_nonce();  // Random 12 bytes
        
        if (!m_chacha20_wrapper)
            m_chacha20_wrapper = std::make_unique<ChaCha20Wrapper>();
        
        // Use "FALCON_PUBKEY" as AAD for domain separation
        std::vector<uint8_t> aad{'F','A','L','C','O','N','_','P','U','B','K','E','Y'};
        
        auto wrap_result = m_chacha20_wrapper->encrypt(m_miner_pubkey, session_key, nonce, aad);
        
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
    
    return packet.get_bytes();
}

network::Shared_payload Solo::get_work()
{
    m_logger->info("Get new block");

    // get new block from wallet
    Packet packet{ Packet::GET_BLOCK };
    
    // Debug logging to diagnose packet encoding
    m_logger->debug("[Solo Phase 2] GET_BLOCK packet: header=0x{:02x} length={} is_valid={}", 
                   static_cast<int>(packet.m_header),
                   packet.m_length, 
                   packet.is_valid());
    
    auto payload = packet.get_bytes();
    if (payload && !payload->empty()) {
        m_logger->debug("[Solo Phase 2] GET_BLOCK encoded payload size: {} bytes", payload->size());
    } else {
        m_logger->error("[Solo Phase 2] GET_BLOCK get_bytes() returned null or empty payload!");
    }
    
    return payload;     
}

network::Shared_payload Solo::get_height()
{
    m_logger->info("[Solo] Requesting blockchain height via GET_HEIGHT");
    
    // GET_HEIGHT is a header-only request packet (opcode 130, >= 128)
    Packet packet{ Packet::GET_HEIGHT };
    
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

network::Shared_payload Solo::submit_block(std::vector<std::uint8_t> const& block_data, std::uint64_t nonce)
{
    m_logger->info("Submitting Block...");

    // Enhanced diagnostics: Validate block_data before submission
    if (block_data.empty()) {
        m_logger->error("[Solo Submit] CRITICAL: block_data is empty! Cannot submit block.");
        m_logger->error("[Solo Submit] Recovery: Requesting new work to recover from empty payload scenario");
        return network::Shared_payload{};
    }
    
    // LLL-TAO SignedWorkSubmission format (from Disposable Falcon Wrapper - PR #20):
    // [merkle_root(64)][nonce(8)][timestamp(8)][sig_len(2)][signature]
    // 
    // CRITICAL: Signature is REQUIRED for authenticated session block submissions
    // Blocks without valid signatures will be rejected by the node
    
    // Verify Falcon wrapper is available (required for stateless sessions)
    if (!m_falcon_wrapper || !m_falcon_wrapper->is_valid()) {
        m_logger->error("[Solo Submit] CRITICAL: Falcon wrapper not available for block signing");
        m_logger->error("[Solo Submit] Stateless sessions REQUIRE signed block submissions per LLL-TAO protocol");
        m_logger->error("[Solo Submit] Block submission cannot proceed without valid Falcon keys");
        return network::Shared_payload{};
    }
    
    // Enhanced diagnostics: Log block submission structure
    m_logger->info("[Solo Submit] Block submission payload structure:");
    m_logger->info("[Solo Submit]   - Block data size: {} bytes", block_data.size());
    m_logger->info("[Solo Submit]   - Nonce: 0x{:016x}", nonce);
    
    // Get current timestamp for block submission (8 bytes, little-endian)
    uint64_t submission_timestamp = static_cast<uint64_t>(
        std::chrono::system_clock::to_time_t(std::chrono::system_clock::now()));
    
    m_logger->info("[Solo Submit]   - Timestamp: {} (0x{:016x})", submission_timestamp, submission_timestamp);
    
    // Build the complete submission payload: merkle_root + nonce + timestamp
    std::vector<uint8_t> message_to_sign;
    message_to_sign.reserve(block_data.size() + 16);  // block_data + nonce(8) + timestamp(8)
    message_to_sign.insert(message_to_sign.end(), block_data.begin(), block_data.end());
    append_uint64_le(message_to_sign, nonce);
    append_uint64_le(message_to_sign, submission_timestamp);
    
    // Generate Falcon signature for block submission
    m_logger->info("[Solo Submit] Generating required Falcon signature for SignedWorkSubmission");
    auto sig_result = m_falcon_wrapper->sign_payload(message_to_sign, 
        FalconSignatureWrapper::SignatureType::BLOCK);
    
    if (!sig_result.success) {
        m_logger->error("[Solo Submit] CRITICAL: Falcon signature generation failed: {}", sig_result.error_message);
        m_logger->error("[Solo Submit] Block submission cannot proceed without valid signature");
        return network::Shared_payload{};
    }
    
    // Build the packet payload
    Packet packet{ Packet::SUBMIT_BLOCK };
    packet.m_data = std::make_shared<network::Payload>();
    packet.m_data->reserve(block_data.size() + 16 + 2 + sig_result.signature.size());
    
    // Append merkle_root (64 bytes)
    packet.m_data->insert(packet.m_data->end(), block_data.begin(), block_data.end());
    
    // Append nonce (8 bytes LE)
    append_uint64_le(*packet.m_data, nonce);
    
    // Append timestamp (8 bytes LE)
    append_uint64_le(*packet.m_data, submission_timestamp);
    
    // Append signature length (2 bytes LE)
    uint16_t sig_len = static_cast<uint16_t>(sig_result.signature.size());
    append_uint16_le(*packet.m_data, sig_len);
    
    // Append signature bytes
    packet.m_data->insert(packet.m_data->end(), 
                         sig_result.signature.begin(), 
                         sig_result.signature.end());
    
    m_logger->info("[Solo Submit] SignedWorkSubmission signature appended");
    m_logger->info("[Solo Submit]   - Signature length: {} bytes", sig_len);
    m_logger->info("[Solo Submit]   - Generation time: {} μs", sig_result.generation_time.count());
    
    // Set packet length to actual data size
    packet.m_length = packet.m_data->size();
    
    // Validate final payload size using FalconConstants
    // Determine expected sizes based on configuration
    std::size_t expected_min_size;
    std::size_t expected_max_size;

    if (m_block_signing_enabled) {
        // Dual signature mode (Disposable + Physical Block Signature)
        // Format: [merkle_root(64)][nonce(8)][timestamp(8)][sig_len(2)][disposable_sig][physical_sig_len(2)][physical_sig]
        expected_min_size = FalconConstants::MERKLE_ROOT_SIZE + 
                            FalconConstants::NONCE_SIZE + 
                            FalconConstants::TIMESTAMP_SIZE + 
                            FalconConstants::LENGTH_FIELD_SIZE +
                            FalconConstants::FALCON512_SIG_MIN +
                            FalconConstants::LENGTH_FIELD_SIZE +
                            FalconConstants::FALCON512_SIG_MIN;
        
        if (m_enable_chacha20) {
            expected_max_size = FalconConstants::SUBMIT_BLOCK_DUAL_SIG_ENCRYPTED_MAX;  // 1,616 bytes
            m_logger->debug("[Solo Submit] Using DUAL_SIG_ENCRYPTED mode (max {} bytes)", expected_max_size);
        } else {
            expected_max_size = FalconConstants::SUBMIT_BLOCK_DUAL_SIG_MAX;  // 1,588 bytes
            m_logger->debug("[Solo Submit] Using DUAL_SIG mode (max {} bytes)", expected_max_size);
        }
    } else {
        // Single signature mode (Disposable Falcon only)
        // Format: [merkle_root(64)][nonce(8)][timestamp(8)][sig_len(2)][signature]
        expected_min_size = FalconConstants::MERKLE_ROOT_SIZE + 
                            FalconConstants::NONCE_SIZE + 
                            FalconConstants::TIMESTAMP_SIZE + 
                            FalconConstants::LENGTH_FIELD_SIZE +
                            FalconConstants::FALCON512_SIG_MIN;
        
        if (m_enable_chacha20) {
            expected_max_size = FalconConstants::SUBMIT_BLOCK_WRAPPER_ENCRYPTED_MAX;  // 862 bytes
            m_logger->debug("[Solo Submit] Using WRAPPER_ENCRYPTED mode (max {} bytes)", expected_max_size);
        } else {
            expected_max_size = FalconConstants::SUBMIT_BLOCK_WRAPPER_MAX;  // 834 bytes
            m_logger->debug("[Solo Submit] Using WRAPPER mode (max {} bytes)", expected_max_size);
        }
    }

    // Validate payload size
    std::size_t actual_size = packet.m_data->size();

    if (actual_size < expected_min_size) {
        m_logger->error("[Solo Submit] Payload too small: {} bytes < minimum {} bytes", 
            actual_size, expected_min_size);
        m_logger->error("[Solo Submit]   - Mode: {}", 
            m_block_signing_enabled ? "DUAL_SIG" : "SINGLE_SIG");
        m_logger->error("[Solo Submit]   - ChaCha20: {}", 
            m_enable_chacha20 ? "ENABLED" : "DISABLED");
    }

    if (actual_size > expected_max_size) {
        m_logger->warn("[Solo Submit] Payload larger than expected: {} bytes > max {} bytes",
            actual_size, expected_max_size);
        m_logger->warn("[Solo Submit]   - This may indicate serialization issues");
        m_logger->warn("[Solo Submit]   - Mode: {}", 
            m_block_signing_enabled ? "DUAL_SIG" : "SINGLE_SIG");
    }
    
    m_logger->info("[Solo Phase 2] Submitting SignedWorkSubmission (session: 0x{:08x})", m_session_id);
    m_logger->info("[Solo Submit]   - Signature mode: {}", 
        m_block_signing_enabled ? "DUAL (Disposable + Physical)" : "SINGLE (Disposable only)");
    m_logger->info("[Solo Submit]   - ChaCha20 encryption: {}", 
        m_enable_chacha20 ? "ENABLED" : "DISABLED");
    m_logger->info("[Solo Submit]   - Total submission payload: {} bytes", actual_size);
    m_logger->info("[Solo Submit]   - Expected max: {} bytes", expected_max_size);
    
    if (m_block_signing_enabled) {
        m_logger->info("[Solo Submit]   - Format: [merkle_root(64)][nonce(8)][timestamp(8)][sig_len(2)][signature][phys_sig_len(2)][phys_signature]");
    } else {
        m_logger->info("[Solo Submit]   - Format: [merkle_root(64)][nonce(8)][timestamp(8)][sig_len(2)][signature]");
    }
    
    auto result = packet.get_bytes();
    
    // Enhanced diagnostics: Validate packet encoding
    if (!result || result->empty()) {
        m_logger->error("[Solo Submit] CRITICAL: SUBMIT_BLOCK packet encoding failed! get_bytes() returned empty.");
        m_logger->error("[Solo Submit] Recovery: Will retry work request after failed submission");
        return network::Shared_payload{};
    }
    
    m_logger->debug("[Solo Submit] SUBMIT_BLOCK packet successfully encoded: {} bytes wire format", result->size());

    return result;  
}

void Solo::process_messages(Packet packet, std::shared_ptr<network::Connection> connection)  
{
    // Store connection for multi-packet authentication flow
    if (connection) {
        m_connection = connection;
    }
    
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
        m_logger->debug("[Solo] Processing packet: header={} ({}) length={} | Remote: {} | Local: {}", 
            static_cast<int>(packet.m_header), get_llp_header_name(packet.m_header), 
            packet.m_length, remote_ep.to_string(), local_ep.to_string());
    } else {
        m_logger->debug("[Solo] Processing packet: header={} ({}), length={}", 
            static_cast<int>(packet.m_header), get_llp_header_name(packet.m_header), packet.m_length);
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
        
        // Enhanced diagnostics: Log payload size information
        m_logger->info("[Solo] BLOCK_DATA payload diagnostics:");
        m_logger->info("[Solo]   - Payload size: {} bytes", packet.m_data->size());
        m_logger->info("[Solo]   - Packet length field: {} bytes", packet.m_length);
        
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
            
            // Now send SET_CHANNEL since we're authenticated
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
        
        // Stateless mining with Falcon authentication: Request work directly (no GET_HEIGHT polling)
        m_logger->info("[Solo Phase 2] Channel set successfully, requesting initial work via GET_BLOCK");
        auto work_payload = get_work();
        if (!work_payload || work_payload->empty()) {
            m_logger->error("[Solo] CRITICAL: GET_BLOCK request returned empty payload!");
            m_logger->error("[Solo] This may indicate a packet encoding issue");
        } else {
            connection->transmit(work_payload);
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
    else
    {
        m_logger->debug("Invalid header received: 0x{:02x}", packet.m_header);
    } 
}

void Solo::set_miner_keys(std::vector<uint8_t> const& pubkey, std::vector<uint8_t> const& privkey)
{
    m_miner_pubkey = pubkey;
    m_miner_privkey = privkey;
    m_logger->info("[Solo] Miner Falcon keys configured (pubkey: {} bytes, privkey: {} bytes)", 
        pubkey.size(), privkey.size());
    
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
    
    Packet packet{ Packet::SESSION_KEEPALIVE, std::make_shared<network::Payload>(keepalive_data) };
    return packet.get_bytes();
}

void Solo::send_set_channel(std::shared_ptr<network::Connection> connection)
{
    std::string channel_name = (m_channel == 1) ? "prime" : "hash";
    m_logger->info("[Solo] Sending SET_CHANNEL channel={} ({})", static_cast<int>(m_channel), channel_name);
    
    std::vector<uint8_t> channel_data(1, m_channel);
    Packet set_channel_packet{ Packet::SET_CHANNEL, std::make_shared<network::Payload>(channel_data) };
    connection->transmit(set_channel_packet.get_bytes());
}

void Solo::set_tritium_genesis(std::vector<uint8_t> const& genesis)
{
    if (genesis.size() != 32) {
        m_logger->warn("[Solo] Invalid Tritium genesis size: {} (expected 32 bytes)", genesis.size());
        return;
    }
    
    if (m_session_manager) {
        m_session_manager->set_tritium_genesis(genesis);
        m_logger->info("[Solo] Tritium genesis hash configured for reward binding");
    }
}

bool Solo::has_tritium_genesis() const
{
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
    
    if (packet.m_data->size() < static_cast<size_t>(2 + nonce_len)) {
        m_logger->error("[Solo Phase 2] MINER_AUTH_CHALLENGE: incomplete nonce (expected {} bytes, got {})", 
                       2 + nonce_len, packet.m_data->size());
        reset_auth_state();
        return;
    }
    
    // Extract nonce
    std::vector<uint8_t> nonce(packet.m_data->begin() + 2, packet.m_data->begin() + 2 + nonce_len);
    
    m_logger->info("[Solo Phase 2] Received nonce, {} bytes", nonce.size());
    
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
    
    m_logger->info("[Solo Phase 2] Signed nonce, signature {} bytes", sign_result.signature.size());
    
    // Build MINER_AUTH_RESPONSE packet
    Packet response_packet;
    response_packet.m_header = Packet::MINER_AUTH_RESPONSE;  // 209
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
    
    m_logger->info("[Solo Phase 2] Sending MINER_AUTH_RESPONSE: sig_len={}, total_size={}", 
                   sig_len, response_packet.m_length);
    
    // Validate packet serialization
    auto bytes = response_packet.get_bytes();
    if (!bytes || bytes->empty()) {
        m_logger->error("[Solo Phase 2] Failed to serialize MINER_AUTH_RESPONSE packet");
        reset_auth_state();
        return;
    }
    
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

}
}
