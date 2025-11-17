#include "protocol/solo.hpp"
#include "protocol/protocol.hpp"
#include "packet.hpp"
#include "network/connection.hpp"
#include "stats/stats_collector.hpp"
#include "../miner_keys.hpp"

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
    m_auth_nonce.clear();
}

network::Shared_payload Solo::login(Login_handler handler)
{
    // Clamp channel to valid values as safety net
    if (m_channel != 1 && m_channel != 2) {
        m_logger->warn("Solo::login: Invalid channel {}, clamping to 2 (hash)", static_cast<int>(m_channel));
        m_channel = 2;
    }
    
    // Check if we have Falcon miner keys configured
    if (!m_miner_pubkey.empty() && !m_miner_privkey.empty()) {
        m_logger->info("[Solo] Starting Falcon miner authentication handshake");
        m_logger->info("[Solo] Sending MINER_AUTH_INIT with public key ({} bytes)", m_miner_pubkey.size());
        
        // Send MINER_AUTH_INIT with our public key
        Packet packet{ Packet::MINER_AUTH_INIT, m_miner_pubkey };
        
        // Login handler will be called after successful authentication in MINER_AUTH_RESULT handler
        // For now, mark as "success" since the auth process has started
        handler(true);
        
        return packet.get_bytes();
    }
    else {
        // No Falcon keys configured - use legacy path
        m_logger->info("[Solo] No Falcon keys configured, using legacy authentication");
        
        std::string channel_name = (m_channel == 1) ? "prime" : "hash";
        m_logger->info("[Solo] Sending SET_CHANNEL channel={} ({})", static_cast<int>(m_channel), channel_name);
        
        Packet packet{ Packet::SET_CHANNEL, std::make_shared<network::Payload>(uint2bytes(m_channel)) };
        
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
    packet.m_length = 72;  

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
    else if (packet.m_header == Packet::MINER_AUTH_CHALLENGE)
    {
        m_logger->info("[Solo] Received MINER_AUTH_CHALLENGE from node");
        
        // Extract the nonce from the challenge
        if (!packet.m_data || packet.m_length < 32) {
            m_logger->error("MINER_AUTH_CHALLENGE packet has invalid data or length < 32");
            return;
        }
        
        m_auth_nonce.assign(packet.m_data->begin(), packet.m_data->begin() + 32);
        m_logger->debug("[Solo] Challenge nonce: {} bytes", m_auth_nonce.size());
        
        // Sign the nonce with our private key
        std::vector<uint8_t> signature;
        if (!keys::falcon_sign(m_miner_privkey, m_auth_nonce, signature)) {
            m_logger->error("Failed to sign auth challenge with Falcon private key");
            return;
        }
        
        m_logger->info("[Solo] Sending MINER_AUTH_RESPONSE with signature ({} bytes)", signature.size());
        
        // Send the signature back
        Packet response_packet{ Packet::MINER_AUTH_RESPONSE, signature };
        connection->transmit(response_packet.get_bytes());
    }
    else if (packet.m_header == Packet::MINER_AUTH_RESULT)
    {
        // Check if auth succeeded
        if (!packet.m_data || packet.m_length < 1) {
            m_logger->error("MINER_AUTH_RESULT packet has invalid data");
            return;
        }
        
        bool auth_success = (*packet.m_data)[0] != 0;
        
        if (auth_success) {
            m_authenticated = true;
            m_logger->info("[Solo] ✓ Miner authentication SUCCEEDED");
            m_logger->info("[Solo] Now sending SET_CHANNEL channel={} ({})", 
                static_cast<int>(m_channel), 
                (m_channel == 1) ? "prime" : "hash");
            
            // Now send SET_CHANNEL since we're authenticated
            Packet packet{ Packet::SET_CHANNEL, std::make_shared<network::Payload>(uint2bytes(m_channel)) };
            connection->transmit(packet.get_bytes());
        }
        else {
            m_authenticated = false;
            m_logger->error("[Solo] ✗ Miner authentication FAILED");
            m_logger->error("[Solo] Check your Falcon keys in miner.conf");
            m_logger->error("[Solo] Ensure node has whitelisted your public key with -minerallowkey=");
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

}
}
