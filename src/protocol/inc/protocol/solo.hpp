#ifndef NEXUSMINER_PROTOCOL_SOLO_HPP
#define NEXUSMINER_PROTOCOL_SOLO_HPP

#include "protocol/protocol.hpp"
#include "protocol/falcon_wrapper.hpp"
#include "protocol/chacha20_wrapper.hpp"
#include "protocol/session_manager.hpp"
#include "protocol/mining_template_interface.hpp"
#include "mining/client_channel_manager.h"
#include "spdlog/spdlog.h"
#include <atomic>
#include <memory>

namespace nexusminer {
namespace network { class Connection; }
namespace stats { class Collector; }
namespace mining { class PrimeClientManager; class HashClientManager; }
namespace protocol
{

enum class AuthState {
    NOT_AUTHENTICATED,
    WAITING_FOR_CHALLENGE,
    WAITING_FOR_RESULT,
    AUTHENTICATED
};

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
    
    // GET_ROUND protocol support (12-byte response from LLL-TAO PR #151)
    struct RoundStatus {
        bool is_new_round;          // true if NEW_ROUND (204), false if OLD_ROUND (205)
        uint32_t height;            // Unified blockchain height (reference only)
        uint32_t difficulty;        // Mining difficulty in compact nBits format (big-endian)
        
        // Channel-specific heights (miner's channel only)
        uint32_t prime_height;      // Prime channel height (if mining Prime)
        uint32_t hash_height;       // Hash channel height (if mining Hash)
        uint32_t stake_height;      // Stake channel height (unused by stateless miners)
        bool has_channel_heights;   // True if 12-byte response parsed successfully
        
        /**
         * @brief Get channel-specific height
         * @param channel Channel number (1=Prime, 2=Hash, 3=Stake)
         * @return Channel height, or 0 if not set
         */
        uint32_t get_channel_height(uint32_t channel) const {
            switch(channel) {
                case 1:  return prime_height;
                case 2:  return hash_height;
                case 3:  return stake_height;
                default: return 0;
            }
        }
    };
    network::Shared_payload send_get_round();
    RoundStatus get_last_round_status() const { return m_last_round_status; }
    
    // Intelligent polling: Check if GET_ROUND should be sent now
    // Note: This modifies internal timing state, so cannot be truly const
    bool should_send_get_round() { return should_poll_get_round(); }
    
    // Falcon miner authentication
    void set_miner_keys(std::vector<uint8_t> const& pubkey, std::vector<uint8_t> const& privkey);
    bool is_authenticated() const { return m_authenticated; }
    void set_address(std::string const& address) { m_address = address; }
    
    // Tritium GenesisHash for reward binding
    void set_tritium_genesis(std::vector<uint8_t> const& genesis);
    bool has_tritium_genesis() const;
    
    // Session management configuration
    void set_keepalive_interval(std::uint16_t hours);
    void enable_chacha20_wrapping(bool enable) { m_enable_chacha20 = enable; }
    bool is_chacha20_enabled() const { return m_enable_chacha20; }
    
    // Disposable Falcon is ALWAYS ON (core protocol) - method kept for backward compatibility only
    void enable_disposable_falcon(bool enable) { m_disposable_falcon_enabled = enable; }
    bool is_disposable_falcon_enabled() const { return m_disposable_falcon_enabled; }
    
    // Legacy method names (deprecated - kept for backward compatibility)
    void enable_block_signing(bool enable) { m_disposable_falcon_enabled = enable; }
    bool is_block_signing_enabled() const { return m_disposable_falcon_enabled; }
    
    // Enable/disable Physical Falcon signatures (default: disabled per lazy miner economics)
    void enable_physical_falcon(bool enable) { m_physical_falcon_enabled = enable; }
    bool is_physical_falcon_enabled() const { return m_physical_falcon_enabled; }
    
    // Session management (LLL-TAO PR #22)
    network::Shared_payload send_session_keepalive();
    std::uint32_t get_session_id() const;
    bool is_session_active() const;
    
    // Check if keep-alive ping is due
    bool is_keepalive_due() const;
    
    // Mining Template Interface access (unified READ/FEED system)
    MiningTemplateInterface* get_template_interface() { return m_template_interface.get(); }
    const MiningTemplateInterface* get_template_interface() const { return m_template_interface.get(); }
    
    // Stateless mining reward address binding (MINER_SET_REWARD protocol)
    void set_reward_address(std::string const& address) { m_reward_address = address; }
    bool has_reward_address() const { return !m_reward_address.empty(); }
    bool is_reward_bound() const { return m_reward_bound; }
    network::Shared_payload send_set_reward();
    
    // Push notification subscription (LLL-TAO PR #156)
    network::Shared_payload send_miner_ready();

private:
    
    // Derive ChaCha20 session key from genesis hash
    std::vector<uint8_t> derive_chacha20_session_key(const std::vector<uint8_t>& genesis);
    
    // Load tritium genesis (session manager or persistent storage)
    std::vector<uint8_t> load_tritium_genesis();
    
    // Helper method to send SET_CHANNEL packet
    void send_set_channel(std::shared_ptr<network::Connection> connection);
    
    // Challenge-response authentication methods
    void handle_miner_auth_challenge(const Packet& packet);
    
    // Helper to reset authentication state on errors
    void reset_auth_state();
    
    // Handle reward result response from node (MINER_REWARD_RESULT)
    void handle_reward_result(const Packet& packet);
    
    // Unified handler for initial template reception (called by both BLOCK_DATA and STATELESS_GET_BLOCK handlers)
    void handle_initial_template_response(const char* opcode_name);
    
    // Helper method to finalize template with channel height
    // Returns true if template was finalized, false if already finalized or no template
    bool finalize_template_with_channel_height(uint32_t node_channel_height, const std::string& context);
    
    // Helper method to get channel manager for current channel
    mining::ClientChannelManager* get_channel_manager() const;
    mining::ClientChannelManager* get_channel_manager(uint32_t channel) const;
    
    // Integration helper functions (bridge MiningTemplateInterface and ClientChannelManager)
    /**
     * @brief Synchronize channel manager state with template interface
     * 
     * Called after GET_ROUND response to:
     * 1. Update channel manager heights
     * 2. Check for forks (auto-invalidate template if detected)
     * 3. Finalize template channel height if needed
     * 4. Validate current template against channel manager state
     * 
     * @param unified_height Current unified height from GET_ROUND
     * @param channel_height Current channel height from GET_ROUND (for THIS channel)
     * @return true if template is still valid, false if invalidated
     */
    bool sync_template_state(uint32_t unified_height, uint32_t channel_height);
    
    /**
     * @brief Check if current template is valid using channel manager state
     * 
     * Performs dual-height validation mirroring NODE's Block::Accept():
     * - Unified height: template.nHeight == node_unified + 1
     * - Channel height: template.nChannelHeight == node_channel + 1
     * - Age timeout: template age < 60 seconds
     * 
     * @return true if template valid, false if stale/invalid
     */
    bool validate_current_template();
    
    /**
     * @brief Handle fork detection and template invalidation
     * 
     * Called when fork is detected to:
     * - Log rollback information
     * - Invalidate current template in MiningTemplateInterface
     * - Clear fork flag in channel manager
     * 
     * @param pManager Channel manager that detected the fork
     * @param current_height Current unified height after rollback
     */
    void handle_fork_detected(mining::ClientChannelManager* pManager, uint32_t current_height);

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
    AuthState m_auth_state;  // Authentication state machine
    std::string m_miner_id;  // Miner identifier (optional)
    
    // Unified Falcon Signature Wrapper (Phase 2 enhancement)
    std::unique_ptr<FalconSignatureWrapper> m_falcon_wrapper;
    bool m_disposable_falcon_enabled;     // Disposable Falcon signing (ALWAYS ON - core protocol, 0 blockchain overhead)
    bool m_physical_falcon_enabled;       // Physical Falcon signing (CONFIGURABLE - future blockchain integration, adds signature to chain)
    
    // ChaCha20 encryption wrapper for Falcon pubkey protection
    std::unique_ptr<ChaCha20Wrapper> m_chacha20_wrapper;
    bool m_enable_chacha20;  // ChaCha20 encryption (ALWAYS ON - core security for localhost + SessionID)
    
    // Session manager for adaptive cache management
    std::unique_ptr<SessionManager> m_session_manager;
    
    // Mining Template Interface for unified READ/FEED operations
    std::unique_ptr<MiningTemplateInterface> m_template_interface;
    
    // Connection for multi-packet authentication flow
    std::shared_ptr<network::Connection> m_connection;
    
    // Persistent tritium genesis (preserved across reconnections)
    std::vector<uint8_t> m_persistent_tritium_genesis;
    
    // Stateless mining reward address binding (MINER_SET_REWARD protocol)
    std::string m_reward_address;  // NXS account address for mining rewards
    bool m_reward_bound;  // True after successful MINER_REWARD_RESULT
    
    // GET_ROUND status tracking (Template Staleness Prevention - LLL-TAO PR #131)
    RoundStatus m_last_round_status;  // Last received round status
    
    // Client-side fork-aware channel managers (mirrors NODE's PR #136)
    // INTEGRATION PATTERN:
    // - MiningTemplateInterface (m_template_interface): Manages template storage and worker distribution
    // - ClientChannelManagers (m_prime_manager, m_hash_manager): Track heights and detect forks
    // 
    // Division of Responsibilities:
    // 1. MiningTemplateInterface:
    //    - Stores current mining template (MiningTemplate with LLP::CBlock)
    //    - Feeds templates to worker threads
    //    - Handles template age tracking (for 60s timeout)
    //    - Manages channel height (set via set_channel_height())
    // 
    // 2. ClientChannelManagers:
    //    - Track node heights from GET_ROUND (unified + channel)
    //    - Detect blockchain forks (height regression)
    //    - Provide validation logic (ValidateTemplate mirrors NODE's Block::Accept)
    //    - Do NOT store templates in production (use MiningTemplateInterface instead)
    // 
    // Fork Detection Flow:
    //   GET_ROUND response → Update managers → Fork detected? → Clear MiningTemplateInterface
    // 
    // This separation mirrors NODE's architecture where ChannelStateManager tracks state
    // but doesn't duplicate Block storage - blocks live in the blockchain database.
    std::unique_ptr<mining::PrimeClientManager> m_prime_manager;
    std::unique_ptr<mining::HashClientManager> m_hash_manager;
    
    // ═══════════════════════════════════════════════════════════════════════
    // GET_ROUND INTELLIGENT POLLING STATE
    // ═══════════════════════════════════════════════════════════════════════
    
    // Timing state
    std::chrono::steady_clock::time_point m_last_get_round_time;
    uint32_t m_current_poll_interval_ms;  // Current interval (adaptive)
    
    // Configuration constants
    static constexpr uint32_t POLL_INTERVAL_MIN_MS = 5000;     // 5 seconds minimum
    static constexpr uint32_t POLL_INTERVAL_MAX_MS = 60000;    // 60 seconds maximum
    static constexpr uint32_t UNIFIED_HEIGHT_DELTA_TRIGGER = 5; // Trigger fresh template if unified moves 5+ blocks
    static constexpr uint32_t POST_TEMPLATE_POLL_DELAY_MS = 100; // Wait 100ms after template before polling
    // Note: Backoff multiplier is 1.5x, implemented via integer arithmetic: interval + (interval >> 1)
    
    // State flags
    bool m_needs_initial_round_check;  // Set true when new template received
    uint32_t m_template_unified_height;    // Unified height when template was created
    
    // Helper methods for intelligent polling
    bool should_poll_get_round();
    void on_new_round_received(uint32_t new_unified_height);
    void on_old_round_received();
    void on_template_received(uint32_t template_height);
    void check_unified_height_delta(uint32_t current_unified_height);
    
    // ═══════════════════════════════════════════════════════════════════════
    // STATELESS PROTOCOL AUTO-NEGOTIATION STATE
    // ═══════════════════════════════════════════════════════════════════════
    
    // Protocol mode tracking (atomic for thread safety)
    // These are accessed from multiple threads:
    // - I/O thread: process_messages() -> check_stateless_protocol_timeout()
    // - Worker threads: submit_block() reads m_stateless_protocol_active
    std::atomic<bool> m_stateless_protocol_active;           // True when using stateless protocol (0xD008/0xD009)
    std::atomic<bool> m_waiting_for_stateless_response;      // True after MINER_READY sent, waiting for GET_BLOCK
    std::atomic<int64_t> m_miner_ready_sent_time_ns;         // Timestamp when MINER_READY sent (nanoseconds since epoch, atomic for thread safety)
    
    // Configuration constants for stateless protocol negotiation
    static constexpr uint32_t STATELESS_PROTOCOL_TIMEOUT_SECONDS = 5;  // 5 second timeout
    
    // Helper method for timeout checking
    void check_stateless_protocol_timeout(std::shared_ptr<network::Connection> connection);
};

}
}
#endif