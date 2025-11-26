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
, m_auth_retry_count{0}
, m_last_auth_attempt_time{0}
, m_payload_validation_failures{0}
, m_empty_payload_recoveries{0}
{
   // Log constructor call with requested channel value
    m_logger->info("Solo::Solo: ctor called, channel={}", static_cast<int>(m_channel));
    
    // Clamp channel to valid LLL-TAO channels: 1 = prime, 2 = hash
    if (m_channel != 1 && m_channel != 2) {
        m_logger->warn("Invalid channel {} specified. Valid channels: 1 (prime), 2 (hash). Defaulting to 2 (hash).", 
            static_cast<int>(m_channel));
        m_channel = 2;
    }
}

void Solo::reset()
{
    m_current_height = 0;
    m_current_difficulty = 0;
    m_current_reward = 0;
    m_authenticated = false;
    m_session_id = 0;
    m_auth_timestamp = 0;
    m_auth_retry_count = 0;
    m_last_auth_attempt_time = 0;
    m_payload_validation_failures = 0;
    m_empty_payload_recoveries = 0;
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
    
    m_logger->info("[Solo Phase 2] Starting Falcon authentication handshake");
    m_logger->info("[Solo] Initiating MINER_AUTH_INIT with public key ({} bytes)", m_miner_pubkey.size());
    
    // Build MINER_AUTH_INIT packet payload (big-endian length fields per LLL-TAO protocol)
    // Format: [pubkey_len(2, BE)][pubkey][miner_id_len(2, BE)][miner_id]
    std::vector<uint8_t> payload;
    
    // Public key length (2 bytes, big-endian)
    uint16_t pubkey_len = static_cast<uint16_t>(m_miner_pubkey.size());
    payload.push_back((pubkey_len >> 8) & 0xFF);  // High byte
    payload.push_back(pubkey_len & 0xFF);         // Low byte
    
    // Public key bytes
    payload.insert(payload.end(), m_miner_pubkey.begin(), m_miner_pubkey.end());
    
    // Miner ID (can be hostname, IP, or custom identifier)
    // Using address as miner ID for now
    std::string miner_id = m_address;
    uint16_t miner_id_len = static_cast<uint16_t>(miner_id.size());
    
    // Miner ID length (2 bytes, big-endian)
    payload.push_back((miner_id_len >> 8) & 0xFF);  // High byte
    payload.push_back(miner_id_len & 0xFF);         // Low byte
    
    // Miner ID string bytes
    payload.insert(payload.end(), miner_id.begin(), miner_id.end());
    
    // Enhanced diagnostics: Log payload structure details
    m_logger->info("[Solo Auth] MINER_AUTH_INIT payload structure:");
    m_logger->info("[Solo Auth]   - Public key length: {} bytes (offset: 0-1)", pubkey_len);
    m_logger->info("[Solo Auth]   - Public key data: {} bytes (offset: 2-{})", pubkey_len, 1 + pubkey_len);
    m_logger->info("[Solo Auth]   - Miner ID length: {} bytes (offset: {}-{})", 
        miner_id_len, 2 + pubkey_len, 3 + pubkey_len);
    m_logger->info("[Solo Auth]   - Miner ID: '{}' ({} bytes, offset: {}-{})", 
        miner_id, miner_id_len, 4 + pubkey_len, 3 + pubkey_len + miner_id_len);
    m_logger->info("[Solo Auth]   - Total payload size: {} bytes", payload.size());
    
    // Validate payload is properly constructed
    if (payload.empty()) {
        m_logger->error("[Solo Auth] CRITICAL: MINER_AUTH_INIT payload is empty! Cannot proceed with authentication.");
        m_logger->error("[Solo Auth] This may indicate an issue with key configuration or an internal error.");
        m_logger->error("[Solo Auth] Please verify:");
        m_logger->error("[Solo Auth]   1. Keys are properly formatted hex strings in miner.conf");
        m_logger->error("[Solo Auth]   2. Keys were generated with ./NexusMiner --create-keys");
        m_logger->error("[Solo Auth] If problem persists, regenerate keys and update configuration");
        handler(false);
        return network::Shared_payload{};
    }
    
    // Create and send MINER_AUTH_INIT packet
    Packet packet{ Packet::MINER_AUTH_INIT, std::make_shared<network::Payload>(payload) };
    
    // Validate packet encoding
    auto packet_bytes = packet.get_bytes();
    if (!packet_bytes || packet_bytes->empty()) {
        m_logger->error("[Solo Auth] CRITICAL: MINER_AUTH_INIT packet encoding failed! get_bytes() returned empty.");
        m_logger->error("[Solo Auth] This indicates a packet serialization error - please check system resources and try again");
        handler(false);
        return network::Shared_payload{};
    }
    
    m_logger->debug("[Solo Auth] MINER_AUTH_INIT packet successfully encoded: {} bytes total", packet_bytes->size());
    
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
        ++m_payload_validation_failures;
        ++m_empty_payload_recoveries;
        m_logger->debug("[Solo Stats] Payload validation failures: {}, Empty payload recoveries: {}", 
            m_payload_validation_failures, m_empty_payload_recoveries);
        return network::Shared_payload{};
    }
    
    // Enhanced diagnostics: Log block submission structure
    m_logger->info("[Solo Submit] Block submission payload structure:");
    m_logger->info("[Solo Submit]   - Block data size: {} bytes", block_data.size());
    m_logger->info("[Solo Submit]   - Nonce: 0x{:016x}", nonce);
    
    Packet packet{ Packet::SUBMIT_BLOCK };
    packet.m_data = std::make_shared<network::Payload>(block_data);
    auto const nonce_data = uint2bytes64(nonce);
    packet.m_data->insert(packet.m_data->end(), nonce_data.begin(), nonce_data.end());
    
    // Phase 2: Block submission doesn't need signing - the session is already authenticated
    // Expected format: merkle_root (64 bytes) + nonce (8 bytes) = 72 bytes total
    packet.m_length = 72;
    
    // Validate final payload size
    std::size_t expected_size = 72;
    std::size_t actual_size = packet.m_data ? packet.m_data->size() : 0;
    
    if (actual_size != expected_size) {
        m_logger->warn("[Solo Submit] Payload size mismatch: expected {} bytes, got {} bytes", 
            expected_size, actual_size);
        ++m_payload_validation_failures;
        m_logger->debug("[Solo Stats] Payload validation failures: {}", m_payload_validation_failures);
    }
    
    m_logger->info("[Solo Phase 2] Submitting authenticated block (session: 0x{:08x})", m_session_id);
    m_logger->info("[Solo Submit]   - Total submission payload: {} bytes (merkle_root + nonce)", actual_size);
    
    auto result = packet.get_bytes();
    
    // Enhanced diagnostics: Validate packet encoding
    if (!result || result->empty()) {
        m_logger->error("[Solo Submit] CRITICAL: SUBMIT_BLOCK packet encoding failed! get_bytes() returned empty.");
        m_logger->error("[Solo Submit] Recovery: Will retry work request after failed submission");
        ++m_payload_validation_failures;
        ++m_empty_payload_recoveries;
        m_logger->debug("[Solo Stats] Payload validation failures: {}, Empty payload recoveries: {}", 
            m_payload_validation_failures, m_empty_payload_recoveries);
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
        // Phase 2: Handle MINER_AUTH_CHALLENGE from node
        // The node sends: [nonce_len(2, BE)][nonce bytes]
        m_logger->info("[Solo Phase 2] Received MINER_AUTH_CHALLENGE from node");
        
        // Enhanced diagnostics: Validate packet structure
        if (!packet.m_data || packet.m_length < 2) {
            m_logger->error("[Solo Auth] CRITICAL: MINER_AUTH_CHALLENGE packet has invalid data or length < 2");
            m_logger->error("[Solo Auth]   - Packet data null: {}", packet.m_data == nullptr);
            m_logger->error("[Solo Auth]   - Packet length: {}", packet.m_length);
            m_logger->error("[Solo Auth] Cannot proceed with authentication - protocol error");
            return;
        }
        
        // Extract nonce length (2 bytes, big-endian)
        uint16_t nonce_len = (static_cast<uint16_t>((*packet.m_data)[0]) << 8) | 
                             static_cast<uint16_t>((*packet.m_data)[1]);
        
        m_logger->info("[Solo Auth] Challenge nonce structure:");
        m_logger->info("[Solo Auth]   - Nonce length: {} bytes", nonce_len);
        m_logger->info("[Solo Auth]   - Total packet length: {} bytes", packet.m_length);
        
        if (packet.m_length < 2 + nonce_len) {
            m_logger->error("[Solo Auth] CRITICAL: MINER_AUTH_CHALLENGE packet too short for declared nonce length");
            m_logger->error("[Solo Auth]   - Expected: {} bytes minimum", 2 + nonce_len);
            m_logger->error("[Solo Auth]   - Actual: {} bytes", packet.m_length);
            m_logger->error("[Solo Auth] Cannot proceed with authentication - malformed packet");
            return;
        }
        
        // Extract nonce bytes
        std::vector<uint8_t> nonce(packet.m_data->begin() + 2, packet.m_data->begin() + 2 + nonce_len);
        
        m_logger->debug("[Solo Auth] Received challenge nonce ({} bytes): {:02x} {:02x} {:02x} {:02x}...", 
            nonce.size(), 
            nonce.size() > 0 ? nonce[0] : 0,
            nonce.size() > 1 ? nonce[1] : 0,
            nonce.size() > 2 ? nonce[2] : 0,
            nonce.size() > 3 ? nonce[3] : 0);
        
        // Validate nonce is not empty
        if (nonce.empty()) {
            m_logger->error("[Solo Auth] CRITICAL: Challenge nonce is empty!");
            m_logger->error("[Solo Auth] Cannot proceed with authentication - invalid challenge");
            return;
        }
        
        // Sign the nonce with miner's Falcon private key
        std::vector<uint8_t> signature;
        if (!keys::falcon_sign(m_miner_privkey, nonce, signature)) {
            m_logger->error("[Solo Auth] CRITICAL: Failed to sign challenge nonce with Falcon private key");
            m_logger->error("[Solo Auth]   - Private key size: {} bytes", m_miner_privkey.size());
            m_logger->error("[Solo Auth]   - Nonce size: {} bytes", nonce.size());
            m_logger->error("[Solo Auth] Possible causes:");
            m_logger->error("[Solo Auth]   - Invalid or corrupted private key");
            m_logger->error("[Solo Auth]   - Falcon signature library error");
            m_logger->error("[Solo Auth] Cannot proceed with authentication");
            return;
        }
        
        m_logger->info("[Solo Auth] Successfully signed challenge nonce");
        m_logger->info("[Solo Auth]   - Signature size: {} bytes", signature.size());
        
        // Build MINER_AUTH_RESPONSE packet payload (big-endian)
        // Format: [sig_len(2, BE)][signature bytes]
        std::vector<uint8_t> payload;
        
        // Signature length (2 bytes, big-endian)
        uint16_t sig_len = static_cast<uint16_t>(signature.size());
        payload.push_back((sig_len >> 8) & 0xFF);  // High byte
        payload.push_back(sig_len & 0xFF);         // Low byte
        
        // Signature bytes
        payload.insert(payload.end(), signature.begin(), signature.end());
        
        m_logger->info("[Solo Auth] MINER_AUTH_RESPONSE payload structure:");
        m_logger->info("[Solo Auth]   - Signature length: {} bytes (offset: 0-1)", sig_len);
        m_logger->info("[Solo Auth]   - Signature data: {} bytes (offset: 2-{})", sig_len, 1 + sig_len);
        m_logger->info("[Solo Auth]   - Total payload size: {} bytes", payload.size());
        
        // Validate payload before sending
        if (payload.empty()) {
            m_logger->error("[Solo Auth] CRITICAL: MINER_AUTH_RESPONSE payload is empty!");
            m_logger->error("[Solo Auth] Cannot proceed with authentication - payload construction failed");
            return;
        }
        
        // Create and send MINER_AUTH_RESPONSE packet
        Packet response_packet{ Packet::MINER_AUTH_RESPONSE, std::make_shared<network::Payload>(payload) };
        auto response_bytes = response_packet.get_bytes();
        
        if (!response_bytes || response_bytes->empty()) {
            m_logger->error("[Solo Auth] CRITICAL: MINER_AUTH_RESPONSE packet encoding failed!");
            m_logger->error("[Solo Auth] Cannot proceed with authentication - packet serialization failed");
            return;
        }
        
        m_logger->debug("[Solo Auth] MINER_AUTH_RESPONSE packet successfully encoded: {} bytes wire format", response_bytes->size());
        connection->transmit(response_bytes);
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
    else
    {
        m_logger->debug("Invalid header received.");
    } 
}

void Solo::set_miner_keys(std::vector<uint8_t> const& pubkey, std::vector<uint8_t> const& privkey)
{
    m_miner_pubkey = pubkey;
    m_miner_privkey = privkey;
    m_logger->info("[Solo] Miner Falcon keys configured (pubkey: {} bytes, privkey: {} bytes)", 
        pubkey.size(), privkey.size());
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
