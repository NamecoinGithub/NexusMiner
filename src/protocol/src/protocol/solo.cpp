#include "protocol/solo.hpp"
#include "protocol/protocol.hpp"
#include "packet.hpp"
#include "network/connection.hpp"
#include "stats/stats_collector.hpp"
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
        m_logger->info("[Solo] Public key size: {} bytes", m_miner_pubkey.size());
        
        // Get current timestamp (using system time in seconds since epoch)
        auto now = std::chrono::system_clock::now();
        m_auth_timestamp = std::chrono::duration_cast<std::chrono::seconds>(now.time_since_epoch()).count();
        
        // Build auth message: address + timestamp (matching LLL-TAO's BuildAuthMessage)
        std::vector<uint8_t> auth_message;
        auth_message.insert(auth_message.end(), m_address.begin(), m_address.end());
        
        // Append timestamp as 8 bytes, little-endian
        uint64_t ts = m_auth_timestamp;
        for(int i = 0; i < 8; ++i) {
            auth_message.push_back(static_cast<uint8_t>(ts & 0xFF));
            ts >>= 8;
        }
        
        m_logger->debug("[Solo] Auth message: address='{}' + timestamp={} ({} bytes total)", 
            m_address, m_auth_timestamp, auth_message.size());
        
        // Sign the auth message with miner's Falcon private key
        std::vector<uint8_t> signature;
        if (!keys::falcon_sign(m_miner_privkey, auth_message, signature)) {
            m_logger->error("[Solo] Failed to sign auth message with Falcon private key");
            handler(false);
            return nullptr;
        }
        
        m_logger->info("[Solo] Signed auth message (signature: {} bytes)", signature.size());
        
        // Build MINER_AUTH_RESPONSE packet payload:
        // Format: [pubkey_len(2)][pubkey][sig_len(2)][signature][optional_genesis(32)]
        std::vector<uint8_t> payload;
        
        // Public key length (2 bytes, little-endian)
        uint16_t pubkey_len = static_cast<uint16_t>(m_miner_pubkey.size());
        payload.push_back(pubkey_len & 0xFF);
        payload.push_back((pubkey_len >> 8) & 0xFF);
        
        // Public key bytes
        payload.insert(payload.end(), m_miner_pubkey.begin(), m_miner_pubkey.end());
        
        // Signature length (2 bytes, little-endian)
        uint16_t sig_len = static_cast<uint16_t>(signature.size());
        payload.push_back(sig_len & 0xFF);
        payload.push_back((sig_len >> 8) & 0xFF);
        
        // Signature bytes
        payload.insert(payload.end(), signature.begin(), signature.end());
        
        // Optional: genesis hash (32 bytes) - for now, omit unless configured
        // If we had a genesis to bind, we would append it here
        
        m_logger->info("[Solo] Sending MINER_AUTH_RESPONSE (payload: {} bytes)", payload.size());
        m_logger->debug("[Solo] Payload breakdown: pubkey_len={}, pubkey={}, sig_len={}, sig={}", 
            pubkey_len, pubkey_len, sig_len, sig_len);
        
        // Create and send the packet
        Packet packet{ Packet::MINER_AUTH_RESPONSE, std::make_shared<network::Payload>(payload) };
        
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
    return packet.get_bytes();     
}

network::Shared_payload Solo::submit_block(std::vector<std::uint8_t> const& block_data, std::uint64_t nonce)
{
    m_logger->info("Submitting Block...");

    Packet packet{ Packet::SUBMIT_BLOCK };
    packet.m_data = std::make_shared<network::Payload>(block_data);
    auto const nonce_data = uint2bytes64(nonce);
    packet.m_data->insert(packet.m_data->end(), nonce_data.begin(), nonce_data.end());
    
    // Phase 2: Block submission doesn't need signing - the session is already authenticated
    // Expected format: merkle_root (64 bytes) + nonce (8 bytes) = 72 bytes total
    packet.m_length = 72;
    
    if (m_authenticated) {
        m_logger->info("[Solo Phase 2] Submitting authenticated block (session: 0x{:08x})", m_session_id);
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
        if (height > m_current_height)
        {
            m_logger->info("Nexus Network: New height {} (old height: {})", height, m_current_height);
            m_current_height = height;
            connection->transmit(get_work());          
        }			
    }
    // Block from wallet received
    else if(packet.m_header == Packet::BLOCK_DATA)
    {
        // Validate packet data and length
        if (!packet.m_data || packet.m_length < MIN_BLOCK_HEADER_SIZE) {
            m_logger->warn("Solo::process_messages: BLOCK_DATA packet has invalid data (null={}) or length {} < minimum {}", 
                !packet.m_data, packet.m_length, MIN_BLOCK_HEADER_SIZE);
            return;
        }
        
        try {
            auto block = deserialize_block(std::move(packet.m_data));
            
            // Log parsed header fields
            m_logger->info("Solo::process_messages: Received block - nVersion={}, nChannel={}, nHeight={}, nBits={}, nNonce={}", 
                block.nVersion, block.nChannel, block.nHeight, block.nBits, block.nNonce);
            
            if (block.nHeight == m_current_height)
            {
                if(m_set_block_handler)
                {
                    m_set_block_handler(block, 0);
                }
                else
                {
                    m_logger->error("No Block handler set");
                }
            }
            else
            {
                m_logger->warn("Block height mismatch: received height={}, current_height={}. Requesting new work.", 
                    block.nHeight, m_current_height);
                connection->transmit(get_work());
            }
        }
        catch (const std::exception& e) {
            m_logger->warn("Solo::process_messages: Failed to deserialize block: {}", e.what());
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
    else if (packet.m_header == Packet::MINER_AUTH_RESPONSE)
    {
        // Phase 2: Handle MINER_AUTH_RESPONSE (actually the node's response to our auth)
        // The node sends back: [status(1)][session_id(4)]
        m_logger->info("[Solo Phase 2] Received MINER_AUTH_RESPONSE (auth result) from node");
        
        if (!packet.m_data || packet.m_length < 1) {
            m_logger->error("MINER_AUTH_RESPONSE packet has invalid data");
            return;
        }
        
        bool auth_success = (*packet.m_data)[0] != 0;
        
        if (auth_success) {
            m_authenticated = true;
            
            // Extract session ID if present (4 bytes, little-endian)
            if (packet.m_length >= 5) {
                m_session_id = (*packet.m_data)[1] | 
                               ((*packet.m_data)[2] << 8) | 
                               ((*packet.m_data)[3] << 16) | 
                               ((*packet.m_data)[4] << 24);
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
            m_logger->error("[Solo] Check your Falcon keys in miner config");
            m_logger->error("[Solo] Ensure node has Phase 2 stateless miner support");
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
        
        // Channel is set, now we can request work
        m_logger->info("[Solo] Channel set successfully, requesting initial work");
        connection->transmit(get_work());
    }
    else if (packet.m_header == Packet::MINER_AUTH_CHALLENGE)
    {
        // Legacy auth flow (kept for backward compatibility)
        m_logger->warn("[Solo Legacy] Received MINER_AUTH_CHALLENGE - this is legacy flow");
        m_logger->warn("[Solo] Phase 2 nodes should not send MINER_AUTH_CHALLENGE");
        m_logger->warn("[Solo] Ensure node is running Phase 2 stateless miner implementation");
    }
    else if (packet.m_header == Packet::MINER_AUTH_RESULT)
    {
        // Legacy auth result (kept for backward compatibility)
        m_logger->warn("[Solo Legacy] Received MINER_AUTH_RESULT - this is legacy flow");
        m_logger->warn("[Solo] Phase 2 uses MINER_AUTH_RESPONSE (209) for auth results");
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
