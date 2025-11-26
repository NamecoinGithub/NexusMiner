#ifndef NEXUSMINER_PROTOCOL_SOLO_HPP
#define NEXUSMINER_PROTOCOL_SOLO_HPP

#include "protocol/protocol.hpp"
#include "spdlog/spdlog.h"

namespace nexusminer {
namespace network { class Connection; }
namespace stats { class Collector; }
namespace protocol
{

class Solo : public Protocol {
public:

    Solo(std::uint8_t channel, std::shared_ptr<stats::Collector> stats_collector);

    void reset() override;
    network::Shared_payload login(Login_handler handler) override;
    network::Shared_payload get_work() override;
    network::Shared_payload get_height();
    network::Shared_payload submit_block(std::vector<std::uint8_t> const& block_data, std::uint64_t nonce) override;
    void set_block_handler(Set_block_handler handler) override { m_set_block_handler = std::move(handler); }

    void process_messages(Packet packet, std::shared_ptr<network::Connection> connection) override;
    
    // Falcon miner authentication
    void set_miner_keys(std::vector<uint8_t> const& pubkey, std::vector<uint8_t> const& privkey);
    bool is_authenticated() const { return m_authenticated; }
    void set_address(std::string const& address) { m_address = address; }

private:
    
    // Helper method to send SET_CHANNEL packet
    void send_set_channel(std::shared_ptr<network::Connection> connection);

    std::uint8_t m_channel;
    std::shared_ptr<spdlog::logger> m_logger;
    std::uint32_t m_current_height;
    std::uint32_t m_current_difficulty;
    std::uint64_t m_current_reward;
    Set_block_handler m_set_block_handler;
    std::shared_ptr<stats::Collector> m_stats_collector;
    
    // Falcon miner authentication state (Phase 2)
    std::vector<uint8_t> m_miner_pubkey;
    std::vector<uint8_t> m_miner_privkey;
    bool m_authenticated;
    std::uint32_t m_session_id;
    std::string m_address;  // Miner's network address for auth message
    std::uint64_t m_auth_timestamp;  // Timestamp for auth message
    
    // Authentication robustness - retry and recovery state
    int m_auth_retry_count;
    std::uint64_t m_last_auth_attempt_time;
    static constexpr int MAX_AUTH_RETRIES = 3;
    static constexpr std::uint64_t AUTH_RETRY_DELAY_MS = 5000;  // 5 seconds
    
    // Payload validation statistics
    std::uint64_t m_payload_validation_failures;
    std::uint64_t m_empty_payload_recoveries;
};

}
}
#endif