#include "protocol/solo.hpp"
#include "protocol/protocol.hpp"
#include "packet.hpp"
#include "network/connection.hpp"
#include "stats/stats_collector.hpp"
#include "LLP/block_utils.hpp"
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
}

network::Shared_payload Solo::login(Login_handler handler)
{
    // Clamp channel to valid values as safety net
    if (m_channel != 1 && m_channel != 2) {
        m_logger->warn("Solo::login: Invalid channel {}, clamping to 2 (hash)", static_cast<int>(m_channel));
        m_channel = 2;
    }
    
    // Phase 2: Check if we have Falcon miner keys configured
    if (!m_miner_pubkey.empty() && !m_miner_privkey.empty()) {
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
        
        m_logger->debug("[Solo] MINER_AUTH_INIT payload: pubkey_len={}, miner_id_len={}, total={} bytes", 
            pubkey_len, miner_id_len, payload.size());
        
        // Create and send MINER_AUTH_INIT packet
        Packet packet{ Packet::MINER_AUTH_INIT, std::make_shared<network::Payload>(payload) };
        
        // Login handler will be called after successful authentication in MINER_AUTH_RESULT
        // For now, mark as "in progress"
        handler(true);
        
        return packet.get_bytes();
    }
    else {
        // No Falcon keys configured - use legacy path (direct SET_CHANNEL)
        m_logger->info("[Solo Legacy] No Falcon keys configured, using legacy authentication");
        
        std::string channel_name = (m_channel == 1) ? "prime" : "hash";
        m_logger->info("[Solo] Sending SET_CHANNEL channel={} ({})", static_cast<int>(m_channel), channel_name);
        
        // LLL-TAO expects 1-byte payload for SET_CHANNEL (Phase 2 update)
        std::vector<uint8_t> channel_data(1, m_channel);
        Packet packet{ Packet::SET_CHANNEL, std::make_shared<network::Payload>(channel_data) };
        
        m_logger->info("[Solo] Waiting for server response after SET_CHANNEL");
        
        // call the login handler here because for solo mining this is always a "success"
        handler(true);
        return packet.get_bytes();
    }
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

    // Phase 2: Implement packet wrapper architecture - keep block data at 72 bytes
    // Send Falcon signature in a separate proof-of-work wrapper packet to avoid blockchain bloat
    
    auto const nonce_data = uint2bytes64(nonce);
    
    // For authenticated sessions with Falcon keys, create a proof-of-work signature packet first
    if (m_authenticated && !m_miner_privkey.empty()) {
        m_logger->info("[Solo Phase 2] Creating proof-of-work signature wrapper for nonce");
        
        // Sign the nonce data with the miner's Falcon private key
        std::vector<uint8_t> signature;
        if (keys::falcon_sign(m_miner_privkey, nonce_data, signature)) {
            // Validate signature size
            if (signature.size() <= 65535) {
                // Create proof-of-work wrapper packet
                // Using MINER_AUTH_RESPONSE format as a reusable signature packet
                // Format: [sig_len(2, BE)][signature bytes]
                std::vector<uint8_t> proof_payload;
                uint16_t sig_len = static_cast<uint16_t>(signature.size());
                proof_payload.push_back((sig_len >> 8) & 0xFF);  // High byte
                proof_payload.push_back(sig_len & 0xFF);         // Low byte
                proof_payload.insert(proof_payload.end(), signature.begin(), signature.end());
                
                // Create the proof packet (using MINER_AUTH_RESPONSE as wrapper)
                Packet proof_packet{ Packet::MINER_AUTH_RESPONSE, std::make_shared<network::Payload>(proof_payload) };
                
                // Create the actual SUBMIT_BLOCK packet (72 bytes: merkle_root + nonce)
                Packet submit_packet{ Packet::SUBMIT_BLOCK };
                submit_packet.m_data = std::make_shared<network::Payload>(block_data);
                submit_packet.m_data->insert(submit_packet.m_data->end(), nonce_data.begin(), nonce_data.end());
                submit_packet.m_length = 72;
                
                // Combine both packets into a single transmission
                // The node will receive proof packet first, then the block submission
                auto proof_bytes = proof_packet.get_bytes();
                auto submit_bytes = submit_packet.get_bytes();
                
                network::Payload combined;
                combined.insert(combined.end(), proof_bytes->begin(), proof_bytes->end());
                combined.insert(combined.end(), submit_bytes->begin(), submit_bytes->end());
                
                m_logger->info("[Solo Phase 2] Submitting block with proof-of-work wrapper (proof: {} bytes, block: 72 bytes, session: 0x{:08x})", 
                              proof_payload.size(), m_session_id);
                
                return std::make_shared<network::Payload>(combined);
            } else {
                m_logger->error("[Solo] Signature size {} exceeds maximum uint16_t value (65535)", signature.size());
            }
        } else {
            m_logger->error("[Solo] Failed to sign nonce with Falcon private key");
        }
        
        // If signing failed, fall through to standard submission
        m_logger->warn("[Solo] Submitting block without proof-of-work signature (may be rejected by node)");
    }
    
    // Standard SUBMIT_BLOCK packet (72 bytes: merkle_root + nonce)
    // Used for legacy mode or if signing failed
    Packet packet{ Packet::SUBMIT_BLOCK };
    packet.m_data = std::make_shared<network::Payload>(block_data);
    packet.m_data->insert(packet.m_data->end(), nonce_data.begin(), nonce_data.end());
    packet.m_length = 72;
    
    if (m_authenticated) {
        m_logger->info("[Solo Phase 2] Submitting standard block (session: 0x{:08x})", m_session_id);
    } else {
        m_logger->info("[Solo] Submitting block (legacy mode - no authentication)");
    }

    return packet.get_bytes();  
}

void Solo::process_messages(Packet packet, std::shared_ptr<network::Connection> connection)  
{
    // Reject invalid packets at the start
    if (!packet.m_is_valid) {
        m_logger->warn("Solo::process_messages: Received invalid packet - header={}, length={}", 
            static_cast<int>(packet.m_header), packet.m_length);
        return;
    }
    
    // Log received packet for diagnostics
    m_logger->debug("[Solo] Processing packet: header={} ({}), length={}", 
        static_cast<int>(packet.m_header), get_packet_header_name(packet.m_header), packet.m_length);
    
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
        // Check payload is non-null
        if (!packet.m_data) {
            m_logger->error("[Solo] BLOCK_DATA received with null payload");
            return;
        }
        
        // Validate packet has minimum required data
        if (packet.m_length < MIN_BLOCK_HEADER_SIZE) {
            m_logger->warn("[Solo] BLOCK_DATA packet has invalid length {} < minimum {}", 
                packet.m_length, MIN_BLOCK_HEADER_SIZE);
            return;
        }
        
        try {
            // Use centralized deserializer
            auto block = nexusminer::llp_utils::deserialize_block_header(*packet.m_data);
            
            // Log parsed header fields
            m_logger->info("[Solo] Received block - nVersion={}, nChannel={}, nHeight={}, nBits=0x{:08x}, nNonce={}", 
                block.nVersion, block.nChannel, block.nHeight, block.nBits, block.nNonce);
            
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
                    m_logger->error("[Solo] No block handler set - cannot process BLOCK_DATA");
                    return;
                }
                
                // Invoke block handler with nBits from the block
                m_set_block_handler(block, block.nBits);
            }
            else
            {
                m_logger->warn("[Solo] Block height mismatch: received height={}, current_height={}. Requesting new work.", 
                    block.nHeight, m_current_height);
                connection->transmit(get_work());
            }
        }
        catch (const std::exception& e) {
            m_logger->error("[Solo] Failed to deserialize BLOCK_DATA: {}", e.what());
            return;
        }
    }
    else if(packet.m_header == Packet::ACCEPT)
    {
        stats::Global global_stats{};
        global_stats.m_accepted_blocks = 1;
        m_stats_collector->update_global_stats(global_stats);
        m_logger->info("Block Accepted By Nexus Network.");
        connection->transmit(get_work());
    }
    else if(packet.m_header == Packet::REJECT)
    {
        stats::Global global_stats{};
        global_stats.m_rejected_blocks = 1;
        m_stats_collector->update_global_stats(global_stats);
        m_logger->warn("Block Rejected by Nexus Network.");
        connection->transmit(get_work());
    }
    else if (packet.m_header == Packet::MINER_AUTH_CHALLENGE)
    {
        // Phase 2: Handle MINER_AUTH_CHALLENGE from node
        // The node sends: [nonce_len(2, BE)][nonce bytes]
        m_logger->info("[Solo Phase 2] Received MINER_AUTH_CHALLENGE from node");
        
        if (!packet.m_data || packet.m_length < 2) {
            m_logger->error("MINER_AUTH_CHALLENGE packet has invalid data or length < 2");
            return;
        }
        
        // Extract nonce length (2 bytes, big-endian)
        uint16_t nonce_len = (static_cast<uint16_t>((*packet.m_data)[0]) << 8) | 
                             static_cast<uint16_t>((*packet.m_data)[1]);
        
        m_logger->info("[Solo] Challenge nonce length: {} bytes", nonce_len);
        
        if (packet.m_length < 2 + nonce_len) {
            m_logger->error("MINER_AUTH_CHALLENGE packet too short for declared nonce length");
            return;
        }
        
        // Extract nonce bytes
        std::vector<uint8_t> nonce(packet.m_data->begin() + 2, packet.m_data->begin() + 2 + nonce_len);
        
        m_logger->debug("[Solo] Received challenge nonce ({} bytes): {:02x} {:02x} {:02x} {:02x}...", 
            nonce.size(), 
            nonce.size() > 0 ? nonce[0] : 0,
            nonce.size() > 1 ? nonce[1] : 0,
            nonce.size() > 2 ? nonce[2] : 0,
            nonce.size() > 3 ? nonce[3] : 0);
        
        // Sign the nonce with miner's Falcon private key
        std::vector<uint8_t> signature;
        if (!keys::falcon_sign(m_miner_privkey, nonce, signature)) {
            m_logger->error("[Solo] Failed to sign challenge nonce with Falcon private key");
            return;
        }
        
        m_logger->info("[Solo] Signed challenge nonce (signature: {} bytes)", signature.size());
        
        // Build MINER_AUTH_RESPONSE packet payload (big-endian)
        // Format: [sig_len(2, BE)][signature bytes]
        std::vector<uint8_t> payload;
        
        // Signature length (2 bytes, big-endian)
        uint16_t sig_len = static_cast<uint16_t>(signature.size());
        payload.push_back((sig_len >> 8) & 0xFF);  // High byte
        payload.push_back(sig_len & 0xFF);         // Low byte
        
        // Signature bytes
        payload.insert(payload.end(), signature.begin(), signature.end());
        
        m_logger->info("[Solo] Sending MINER_AUTH_RESPONSE: sig_len={}, total payload={} bytes", 
            sig_len, payload.size());
        
        // Create and send MINER_AUTH_RESPONSE packet
        Packet response_packet{ Packet::MINER_AUTH_RESPONSE, std::make_shared<network::Payload>(payload) };
        connection->transmit(response_packet.get_bytes());
    }
    else if (packet.m_header == Packet::MINER_AUTH_RESULT)
    {
        // Phase 2: Handle MINER_AUTH_RESULT (auth result from node)
        // The node sends: [status(1)][session_id(4, optional, LE)]
        m_logger->info("[Solo Phase 2] Received MINER_AUTH_RESULT from node");
        
        if (!packet.m_data || packet.m_length < 1) {
            m_logger->error("MINER_AUTH_RESULT packet has invalid data");
            return;
        }
        
        bool auth_success = (*packet.m_data)[0] != 0;
        
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
            } else {
                m_logger->info("[Solo Phase 2] ✓ Authentication SUCCEEDED");
            }
            
            // Now send SET_CHANNEL since we're authenticated
            std::string channel_name = (m_channel == 1) ? "prime" : "hash";
            m_logger->info("[Solo] Sending SET_CHANNEL channel={} ({})", static_cast<int>(m_channel), channel_name);
            
            // Phase 2: Send 1-byte payload for SET_CHANNEL
            std::vector<uint8_t> channel_data(1, m_channel);
            Packet set_channel_packet{ Packet::SET_CHANNEL, std::make_shared<network::Payload>(channel_data) };
            connection->transmit(set_channel_packet.get_bytes());
        }
        else {
            m_authenticated = false;
            m_logger->error("[Solo Phase 2] ✗ Authentication FAILED");
            m_logger->error("[Solo] Possible causes:");
            m_logger->error("[Solo]   - Public key not whitelisted on node (check nexus.conf -minerallowkey)");
            m_logger->error("[Solo]   - Invalid key format in miner.conf (must be valid hex strings)");
            m_logger->error("[Solo]   - Falcon signature verification failed (key mismatch or corruption)");
            m_logger->error("[Solo]   - Node missing Phase 2 stateless miner support");
        }
    }
    else if (packet.m_header == Packet::CHANNEL_ACK)
    {
        // Phase 2: Handle CHANNEL_ACK response
        m_logger->info("[Solo Phase 2] Received CHANNEL_ACK from node");
        
        if (packet.m_data && packet.m_length >= 1) {
            uint8_t acked_channel = (*packet.m_data)[0];
            m_logger->info("[Solo] Channel acknowledged: {} ({})", 
                static_cast<int>(acked_channel), 
                (acked_channel == 1) ? "prime" : "hash");
        }
        
        // Channel is set, now request height/difficulty before requesting work
        m_logger->info("[Solo Phase 2] Channel set successfully, requesting blockchain height");
        connection->transmit(get_height());
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

}
}
