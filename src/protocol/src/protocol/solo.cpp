#include "protocol/solo.hpp"
#include "protocol/protocol.hpp"
#include "packet.hpp"
#include "network/connection.hpp"
#include "stats/stats_collector.hpp"
#include "LLP/block_utils.hpp"
#include "LLP/llp_logging.hpp"
#include "../miner_keys.hpp"
#include <chrono>

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
, m_falcon_wrapper{nullptr}
, m_block_signing_enabled{false}  // Disabled by default for performance
, m_template_interface{nullptr}
{
   // Log constructor call with requested channel value
    m_logger->info("Solo::Solo: ctor called, channel={}", static_cast<int>(m_channel));
    
    // Clamp channel to valid LLL-TAO channels: 1 = prime, 2 = hash
    if (m_channel != 1 && m_channel != 2) {
        m_logger->warn("Invalid channel {} specified. Valid channels: 1 (prime), 2 (hash). Defaulting to 2 (hash).", 
            static_cast<int>(m_channel));
        m_channel = 2;
    }
    
    // Initialize the Mining Template Interface for unified READ/FEED operations
    // Session ID starts at 0 (unauthenticated) and will be updated after MINER_AUTH_RESULT
    // The session ID binds the template interface to the FALCON authenticated tunnel
    m_template_interface = std::make_unique<MiningTemplateInterface>(m_channel, 0);
    m_logger->info("[Solo] Mining Template Interface initialized for unified READ/FEED system");
}

void Solo::reset()
{
    m_current_height = 0;
    m_current_difficulty = 0;
    m_current_reward = 0;
    m_authenticated = false;
    m_session_id = 0;
    m_auth_timestamp = 0;
    
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
    
    m_logger->info("[Solo Phase 2] Starting Direct Falcon authentication (MINER_AUTH_RESPONSE protocol)");
    m_logger->info("[Solo Auth] Using public key ({} bytes)", m_miner_pubkey.size());
    
    // Phase 2 Direct MINER_AUTH_RESPONSE protocol:
    // 1. Build auth message: address + timestamp
    // 2. Sign with Falcon private key  
    // 3. Send MINER_AUTH_RESPONSE directly with pubkey + signature
    
    // Get current timestamp (8-byte little-endian Unix timestamp)
    m_auth_timestamp = static_cast<uint64_t>(std::chrono::system_clock::to_time_t(std::chrono::system_clock::now()));
    
    m_logger->info("[Solo Auth] Auth message parameters:");
    m_logger->info("[Solo Auth]   - Address: '{}' ({} bytes)", m_address, m_address.size());
    m_logger->info("[Solo Auth]   - Timestamp: {} (0x{:016x})", m_auth_timestamp, m_auth_timestamp);
    
    // Use Falcon Signature Wrapper for authentication signature
    std::vector<uint8_t> signature;
    if (m_falcon_wrapper && m_falcon_wrapper->is_valid()) {
        m_logger->info("[Solo Auth] Using Falcon Signature Wrapper for authentication");
        auto sig_result = m_falcon_wrapper->sign_authentication(m_address, m_auth_timestamp);
        
        if (!sig_result.success) {
            m_logger->error("[Solo Auth] CRITICAL: Falcon Wrapper signature failed: {}", sig_result.error_message);
            m_logger->error("[Solo Auth] Falling back to direct signature method");
            
            // Fallback to direct signing if wrapper fails
            std::vector<uint8_t> auth_message;
            auth_message.insert(auth_message.end(), m_address.begin(), m_address.end());
            for (int i = 0; i < 8; ++i) {
                auth_message.push_back((m_auth_timestamp >> (i * 8)) & 0xFF);
            }
            
            if (!keys::falcon_sign(m_miner_privkey, auth_message, signature)) {
                m_logger->error("[Solo Auth] CRITICAL: Fallback signature also failed");
                handler(false);
                return network::Shared_payload{};
            }
        } else {
            signature = std::move(sig_result.signature);
            m_logger->info("[Solo Auth] Wrapper signature generated in {} μs", sig_result.generation_time.count());
        }
    } else {
        m_logger->warn("[Solo Auth] Falcon Wrapper not available, using direct signature method");
        
        // Build auth message: address + timestamp
        std::vector<uint8_t> auth_message;
        auth_message.insert(auth_message.end(), m_address.begin(), m_address.end());
        
        // Append timestamp (8 bytes, little-endian)
        for (int i = 0; i < 8; ++i) {
            auth_message.push_back((m_auth_timestamp >> (i * 8)) & 0xFF);
        }
        
        // Sign the auth message with Falcon private key
        if (!keys::falcon_sign(m_miner_privkey, auth_message, signature)) {
            m_logger->error("[Solo Auth] CRITICAL: Failed to sign auth message with Falcon private key");
            m_logger->error("[Solo Auth]   - Private key size: {} bytes", m_miner_privkey.size());
            m_logger->error("[Solo Auth] Possible causes:");
            m_logger->error("[Solo Auth]   - Invalid or corrupted private key");
            m_logger->error("[Solo Auth]   - Falcon signature library error");
            handler(false);
            return network::Shared_payload{};
        }
    }
    
    m_logger->info("[Solo Auth] Successfully signed auth message");
    m_logger->info("[Solo Auth]   - Signature size: {} bytes", signature.size());
    
    // Build MINER_AUTH_RESPONSE packet payload (little-endian per Phase 2 spec)
    // Format: [pubkey_len(2, LE)][pubkey][sig_len(2, LE)][signature]
    // Note: Genesis hash binding (32 bytes) is optional and not yet implemented
    std::vector<uint8_t> payload;
    
    // Public key length (2 bytes, little-endian)
    uint16_t pubkey_len = static_cast<uint16_t>(m_miner_pubkey.size());
    payload.push_back(pubkey_len & 0xFF);         // Low byte
    payload.push_back((pubkey_len >> 8) & 0xFF);  // High byte
    
    // Public key bytes
    payload.insert(payload.end(), m_miner_pubkey.begin(), m_miner_pubkey.end());
    
    // Signature length (2 bytes, little-endian)
    uint16_t sig_len = static_cast<uint16_t>(signature.size());
    payload.push_back(sig_len & 0xFF);         // Low byte
    payload.push_back((sig_len >> 8) & 0xFF);  // High byte
    
    // Signature bytes
    payload.insert(payload.end(), signature.begin(), signature.end());
    
    // Note: Genesis hash binding is optional and not implemented yet
    
    m_logger->info("[Solo Auth] MINER_AUTH_RESPONSE payload structure:");
    m_logger->info("[Solo Auth]   - Public key length: {} bytes (offset: 0-1, LE)", pubkey_len);
    m_logger->info("[Solo Auth]   - Public key data: {} bytes (offset: 2-{})", pubkey_len, 1 + pubkey_len);
    m_logger->info("[Solo Auth]   - Signature length: {} bytes (offset: {}-{}, LE)", 
        sig_len, 2 + pubkey_len, 3 + pubkey_len);
    m_logger->info("[Solo Auth]   - Signature data: {} bytes (offset: {}-{})", 
        sig_len, 4 + pubkey_len, 3 + pubkey_len + sig_len);
    m_logger->info("[Solo Auth]   - Total payload size: {} bytes", payload.size());
    
    // Validate payload is properly constructed
    if (payload.empty()) {
        m_logger->error("[Solo Auth] CRITICAL: MINER_AUTH_RESPONSE payload is empty!");
        m_logger->error("[Solo Auth] Error type: PAYLOAD_CONSTRUCTION_FAILURE");
        m_logger->error("[Solo Auth] Possible causes:");
        m_logger->error("[Solo Auth]   - Empty public key (size: {} bytes)", m_miner_pubkey.size());
        m_logger->error("[Solo Auth]   - Empty signature (size: {} bytes)", signature.size());
        m_logger->error("[Solo Auth]   - Memory allocation failure during payload construction");
        handler(false);
        return network::Shared_payload{};
    }
    
    // Create and send MINER_AUTH_RESPONSE packet directly
    Packet packet{ Packet::MINER_AUTH_RESPONSE, std::make_shared<network::Payload>(payload) };
    
    // Log packet details for debugging - use is_auth_packet() helper for consistency
    m_logger->debug("[Solo Auth] Packet created: header=0x{:02x} ({}) length={} is_valid={}", 
                   static_cast<int>(packet.m_header),
                   packet.is_auth_packet() ? "AUTH_PACKET" : "UNKNOWN",
                   packet.m_length, 
                   packet.is_valid());
    
    // Validate packet encoding
    auto packet_bytes = packet.get_bytes();
    if (!packet_bytes || packet_bytes->empty()) {
        m_logger->error("[Solo Auth] CRITICAL: MINER_AUTH_RESPONSE packet encoding failed! get_bytes() returned empty.");
        m_logger->error("[Solo Auth] Error type: {}", 
                       !packet.is_valid() ? "PACKET_VALIDATION_FAILURE" : "SERIALIZATION_FAILURE");
        m_logger->error("[Solo Auth] Diagnostic details:");
        m_logger->error("[Solo Auth]   - Packet header: 0x{:02x} ({})", 
                       static_cast<int>(packet.m_header), 
                       packet.m_header);
        m_logger->error("[Solo Auth]   - Packet length: {} bytes", packet.m_length);
        m_logger->error("[Solo Auth]   - Packet is_valid: {}", packet.is_valid());
        m_logger->error("[Solo Auth]   - Packet is_auth_packet: {}", packet.is_auth_packet());
        m_logger->error("[Solo Auth]   - Data pointer valid: {}", packet.m_data != nullptr);
        if (!packet.is_valid()) {
            m_logger->error("[Solo Auth] Possible causes:");
            m_logger->error("[Solo Auth]   - Packet header not in valid range for payload packets");
            m_logger->error("[Solo Auth]   - Authentication packet not properly recognized (expected {}-{})", 
                           Packet::MINER_AUTH_INIT, Packet::SESSION_KEEPALIVE);
        }
        handler(false);
        return network::Shared_payload{};
    }
    
    m_logger->debug("[Solo Auth] MINER_AUTH_RESPONSE packet successfully encoded: {} bytes wire format", packet_bytes->size());
    m_logger->info("[Solo Auth] Sending direct MINER_AUTH_RESPONSE (no challenge-response needed)");
    
    // Login handler will be called after successful authentication in MINER_AUTH_RESULT
    // For now, mark as "in progress"
    handler(true);
    
    return packet_bytes;
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
    
    // Validate final payload size
    // Format: merkle_root(64) + nonce(8) + timestamp(8) + sig_len(2) + signature(~690) = ~772 bytes
    std::size_t actual_size = packet.m_data->size();
    std::size_t expected_min_size = 82;  // merkle_root(64) + nonce(8) + timestamp(8) + sig_len(2)
    
    if (actual_size < expected_min_size) {
        m_logger->error("[Solo Submit] Payload size too small: expected at least {} bytes, got {} bytes", 
            expected_min_size, actual_size);
    }
    
    m_logger->info("[Solo Phase 2] Submitting SignedWorkSubmission (session: 0x{:08x})", m_session_id);
    m_logger->info("[Solo Submit]   - Total submission payload: {} bytes", actual_size);
    m_logger->info("[Solo Submit]   - Format: [merkle_root(64)][nonce(8)][timestamp(8)][sig_len(2)][signature]");
    
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
        // Phase 2 Direct MINER_AUTH_RESPONSE Protocol:
        // MINER_AUTH_CHALLENGE is NOT used in the direct protocol.
        // Authentication message (address + timestamp) is signed upfront during login.
        // If the node is sending a challenge, it's using the old challenge-response flow.
        
        m_logger->warn("[Solo Auth] WARNING: Received MINER_AUTH_CHALLENGE from node");
        m_logger->warn("[Solo Auth] This miner uses DIRECT MINER_AUTH_RESPONSE protocol (no challenge-response)");
        m_logger->warn("[Solo Auth] The node may be using an incompatible authentication flow");
        m_logger->warn("[Solo Auth] Expected flow: MINER_AUTH_RESPONSE -> MINER_AUTH_RESULT");
        m_logger->warn("[Solo Auth] Node is using: MINER_AUTH_INIT -> MINER_AUTH_CHALLENGE -> MINER_AUTH_RESPONSE");
        m_logger->error("[Solo Auth] Authentication protocol mismatch - cannot proceed");
        m_logger->error("[Solo Auth] Please ensure node supports Phase 2 Direct MINER_AUTH_RESPONSE protocol");
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
                m_logger->info("[Solo Phase 2] ✓ Authentication SUCCEEDED - Session ID: 0x{:08x}", m_session_id);
                m_logger->info("[Solo Auth]   - Session ID bytes (LE): {:02x} {:02x} {:02x} {:02x}",
                    (*packet.m_data)[1], (*packet.m_data)[2], (*packet.m_data)[3], (*packet.m_data)[4]);
                
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
            m_logger->error("[Solo Phase 2] ✗ Authentication FAILED");
            m_logger->error("[Solo Auth] Possible causes:");
            m_logger->error("[Solo Auth]   - Public key not whitelisted on node (check nexus.conf -minerallowkey)");
            m_logger->error("[Solo Auth]   - Invalid key format in miner.conf (must be valid hex strings)");
            m_logger->error("[Solo Auth]   - Falcon signature verification failed (key mismatch or corruption)");
            m_logger->error("[Solo Auth]   - Node missing Phase 2 stateless miner support");
            m_logger->error("[Solo Auth] Mining cannot proceed without valid authentication");
            m_logger->error("[Solo Auth] Please verify:");
            m_logger->error("[Solo Auth]   1. Your public key is whitelisted: nexus.conf -minerallowkey=<pubkey>");
            m_logger->error("[Solo Auth]   2. Keys in miner.conf match the whitelisted key");
            m_logger->error("[Solo Auth]   3. Node is running LLL-TAO with Phase 2 miner support");
            
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

}
}
