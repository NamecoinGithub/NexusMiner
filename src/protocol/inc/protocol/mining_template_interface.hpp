#ifndef NEXUSMINER_PROTOCOL_MINING_TEMPLATE_INTERFACE_HPP
#define NEXUSMINER_PROTOCOL_MINING_TEMPLATE_INTERFACE_HPP

#include <vector>
#include <cstdint>
#include <memory>
#include <string>
#include <chrono>
#include <functional>
#include <atomic>
#include <mutex>
#include "LLP/block.hpp"
#include "network/types.hpp"
#include "protocol/height_tracker.hpp"
#include "spdlog/spdlog.h"

namespace nexusminer {
namespace protocol {

class SessionCoordinator;

/**
 * @brief Mining Template Interface for unified READ/FEED operations
 * 
 * This class provides a reliable interface between NexusMiner and LLL-TAO Node
 * for reading and feeding mining templates. It implements the stateless mining
 * protocol with support for:
 * 
 * - Reliable template reading (GET_BLOCK responses / BLOCK_DATA)
 * - Template feeding to worker threads
 * - Template verification and validation
 * - FALCON Handshake session management integration
 * 
 * The interface is designed for VPN-like tunnel reliability with LLL-TAO nodes.
 */
class MiningTemplateInterface {
public:
    
    /**
     * @brief Template state for tracking lifecycle
     */
    enum class TemplateState {
        INVALID,    // No valid template: empty, stale, or submitted
        PENDING,    // Template requested, data in transit
        VALID,      // Template received and ready for mining
    };
    
    /**
     * @brief Template validation result
     */
    struct ValidationResult {
        bool is_valid;
        std::string error_message;
        bool is_stale;              // Template is older than current height
        bool merkle_valid;          // Merkle root is valid format
        bool height_valid;          // Height is valid (> current)
        bool bits_valid;            // Difficulty bits are valid
        bool channel_valid;         // Channel matches expected
        std::chrono::microseconds validation_time;
    };
    
    /**
     * @brief Block format type for serialization
     */
    enum class BlockFormat {
        TRITIUM,    // 216 bytes
        LEGACY,     // 220 bytes
        COMPACT     // 92 bytes (pool format)
    };

    /**
     * @brief Captures the unified GET_BLOCK height that owns a template.
     *
     * The guard is initialized when a template is decoded from the node and
     * checked again immediately before submission. This prevents later
     * channel-height bookkeeping from silently overwriting block.nHeight,
     * which would make the node's ProofHash() check reject the block.
     */
    struct BlockTemplateHeightGuard {
        UnifiedHeight unified_height{};
        ChannelHeight channel_height{};

        constexpr void capture_unified_height(uint32_t height) noexcept {
            unified_height = UnifiedHeight{height};
        }

        constexpr void capture_channel_height(uint32_t height) noexcept {
            channel_height = ChannelHeight{height};
        }

        constexpr bool matches(uint32_t block_height) const noexcept {
            return block_height == unified_height.get();
        }

        constexpr bool matches(const ::LLP::CBlock& block) const noexcept {
            return matches(block.nHeight);
        }
    };
     
    /**
     * @brief Mining template data structure
     */
    struct MiningTemplate {
        ::LLP::CBlock block;        // Block header template
        uint32_t nBits;             // Difficulty bits
        uint64_t timestamp_received;// When template was received
        TemplateState state;        // Current state
        uint32_t session_id;        // Falcon session ID
        uint64_t session_epoch{0};  // Authoritative session epoch that owns this template
        std::string source_endpoint;// Node endpoint that sent template
        BlockFormat format;         // Block format (Tritium/Legacy/Compact)
        
        // Multi-channel height tracking (LLL-TAO PR #135 client-side integration)
        uint32_t nChannelHeight;    // Channel-specific height (CRITICAL for staleness detection)
                                    // Only increments when THIS channel mines a block
                                    // Examples: Prime channel: 2165443, Hash channel: 4165001

        // Stateless-lane metadata (12-byte prefix, big-endian; diagnostic only)
        uint32_t nUnifiedHeightMeta{0};  // unified_height from STATELESS_GET_BLOCK prefix
        uint32_t nChannelHeightMeta{0};  // channel_height from STATELESS_GET_BLOCK prefix
        BlockTemplateHeightGuard height_guard{};
    };
    
    /**
     * @brief Template feed callback type
     */
    using TemplateFeedHandler = std::function<void(const MiningTemplate& tmpl, uint32_t nBits)>;
    
    /**
     * @brief Template validation failure callback type
     */
    using ValidationFailureHandler = std::function<void(const ValidationResult& result)>;

    /**
     * @brief Callback invoked whenever the current template is discarded
     *
     * Registered via set_template_cleared_callback(). Called at the end of
     * discard_template() (outside the mutex) so callers can zero any
     * derived state (e.g. SESSION_KEEPALIVE prevblock_suffix).
     */
    using TemplateClearedCallback = std::function<void()>;

    /**
     * @brief Register a callback to be invoked on every discard_template() call
     * @param cb Callback function (may be nullptr to clear)
     */
    void set_template_cleared_callback(TemplateClearedCallback cb);
    
    /**
     * @brief Constructor
     * @param channel Mining channel (1 = Prime, 2 = Hash)
     * @param session_id Falcon authentication session ID
     */
    MiningTemplateInterface(uint8_t channel, uint32_t session_id = 0);
    
    /**
     * @brief Destructor
     */
    ~MiningTemplateInterface();
    
    // Disable copy to prevent template duplication issues
    MiningTemplateInterface(const MiningTemplateInterface&) = delete;
    MiningTemplateInterface& operator=(const MiningTemplateInterface&) = delete;
    
    // =========================================================================
    // READ Operations - Receiving templates from node
    // =========================================================================
    
    /**
     * @brief Read and process a BLOCK_DATA packet
     * 
     * This is the primary READ operation - processes incoming block templates
     * from the LLL-TAO node. The template is validated before being accepted.
     * 
     * @param data Raw packet data (block header bytes)
     * @param source_endpoint Node endpoint source for logging
     * @return ValidationResult with validation status
     */
    ValidationResult read_template(const network::Payload& data,
                                   const std::string& source_endpoint = "",
                                   bool auto_feed = true);
    
    /**
     * @brief Read template from shared payload (convenience overload)
     * @param data Shared pointer to payload data
     * @param source_endpoint Node endpoint source
     * @return ValidationResult
     */
    ValidationResult read_template(network::Shared_payload data,
                                   const std::string& source_endpoint = "",
                                   bool auto_feed = true);
    
    /**
     * @brief Read and process a STATELESS_GET_BLOCK / BLOCK_DATA payload (228 bytes)
     *
     * Handles the stateless lane's 228-byte BLOCK_DATA format:
     *   [0-3]   unified_height (BE) — diagnostic, stored in MiningTemplate::nUnifiedHeightMeta
     *   [4-7]   channel_height (BE) — diagnostic, stored in MiningTemplate::nChannelHeightMeta
     *   [8-11]  difficulty_nbits (BE) — echoed for convenience
     *   [12-227] 216-byte Tritium Block::Serialize() — delegated to read_template()
     *
     * The 12-byte metadata prefix is DIAGNOSTIC only; the canonical mining state
     * (nHeight, nChannel, nBits, hashPrevBlock) comes exclusively from the 216-byte block body.
     *
     * @param payload228   The full 228-byte STATELESS_GET_BLOCK payload.
     *                     Returns invalid ValidationResult if size != 228.
     * @param source_endpoint Node endpoint for logging
     * @return ValidationResult from the underlying read_template() call
     */
    ValidationResult read_stateless_payload(const network::Payload& payload228,
                                            const std::string& source_endpoint = "",
                                            bool auto_feed = true);
    
    /**
     * @brief Check if a valid template is available for mining
     * @return true if template is validated and ready
     */
    bool has_valid_template() const;
    
    /**
     * @brief Get the current template (if valid)
     * @return Pointer to current template, nullptr if none available
     */
    const MiningTemplate* get_current_template() const;
    
    // =========================================================================
    // FEED Operations - Providing templates to workers
    // =========================================================================
    
    /**
     * @brief Register a handler to receive template feeds
     * 
     * The handler will be called whenever a new validated template is received.
     * This is the FEED part of the READ/FEED mechanism.
     * 
     * @param handler Callback function to receive templates
     */
    void set_template_feed_handler(TemplateFeedHandler handler);
    
    /**
     * @brief Register a handler to receive validation failure notifications
     * 
     * The handler will be called whenever template validation fails.
     * This allows the worker manager to stop mining and request fresh templates.
     * 
     * @param handler Callback function to receive validation failures
     */
    void set_validation_failure_handler(ValidationFailureHandler handler);
    
    /**
     * @brief Feed the current template to registered handlers
     * 
     * Called automatically after successful template validation, but can also
     * be called manually to re-feed the current template.
     * 
     * @return true if template was fed to handlers
     */
    bool feed_current_template();
    
    /**
     * @brief Mark current template as stale
     * 
     * Called when a new block is found or height increases, invalidating
     * the current template.
     * 
     * @param reason Optional reason for staleness
     */
    void mark_template_stale(const std::string& reason = "");
    
    // =========================================================================
    // Template Staleness Prevention (LLL-TAO PR #131 Client-Side Integration)
    // =========================================================================
    
    /**
     * @brief Check if template is stale (age > 200s)
     * 
     * Push-driven era last-resort timeout: node delivers a fresh template within
     * ~2 s of every tip advance, so 200 s only fires as a dead-connection detector.
     * Above Hash block time (~120 s avg) but below Prime block time (~5-10 min)
     * where the node will push before 200 s elapses in normal operation.
     * 
     * @return true if template age exceeds 200 seconds
     */
    bool is_template_stale() const;
    
    /**
     * @brief Check if template is old (age > 50s, warning threshold)
     * 
     * Proactive warning threshold to request fresh template before
     * hard expiration at MAX_TEMPLATE_AGE, reducing wasted mining work.
     * 
     * @return true if template age exceeds 50 seconds
     */
    bool is_template_old() const;
    
    /**
     * @brief Get template age in seconds
     * 
     * @return Age of current template in seconds, 0 if no template
     */
    uint64_t get_template_age() const;
    
    /**
     * @brief Update blockchain height (auto-discards if height mismatch)
     * 
     * Called from GET_ROUND polling thread when NEW_ROUND is detected.
     * Automatically discards current template if height has advanced.
     * 
     * @param new_height Current blockchain height from GET_ROUND
     * @return true if template was discarded due to height change
     */
    bool update_height(uint32_t new_height);
    
    /**
     * @brief Update channel-specific height (multi-channel staleness detection)
     * 
     * Called from GET_ROUND polling with enhanced response (LLL-TAO PR #135).
     * Checks if template's channel height has advanced, auto-discards if stale.
     * 
     * This is the PRIMARY staleness detection method for multi-channel mining.
     * Templates should only be discarded when THEIR SPECIFIC CHANNEL advances.
     * 
     * @param channel Channel number (1=Prime, 2=Hash, 3=Stake)
     * @param new_channel_height Current channel height from node
     * @return true if template was discarded due to channel height change
     */
    bool update_channel_height(uint32_t channel, uint32_t new_channel_height);

    /**
     * @brief Store channel height snapshot when template is received
     *
     * Used for legacy GET_ROUND delta staleness checks when template
     * channel height is still pending (nChannelHeight == 0).
     *
     * **Invariant:** Must NOT be called once the template has been finalized
     * via set_channel_height() (i.e., when nChannelHeight > 0). Calling this
     * after set_channel_height() re-poisons the guard with a stale value and
     * causes false staleness detection on the very next GET_ROUND, even when
     * the active template is 100% valid.
     *
     * @param channel_height Current channel height from last GET_ROUND
     */
    void set_template_channel_height_snapshot(uint32_t channel_height);

    /**
     * @brief Clear template channel height snapshot
     */
    void clear_template_channel_height_snapshot();

    /**
     * @brief Check staleness by comparing current channel height against the mining target
     *
     * When nChannelHeight is finalized (> 0), stale is defined as:
     *   current_channel_height >= nChannelHeight  (chain met or passed our mining target)
     *
     * When nChannelHeight is still pending (== 0), falls back to a snapshot-based
     * delta check: stale if current_channel_height > m_template_channel_height_snapshot.
     *
     * The snapshot fallback is only active before the first GET_ROUND response
     * finalizes the template.  Once nChannelHeight is known the snapshot is
     * bypassed entirely, preventing false-stale detection when the chain tip
     * advances within the valid mining window (tip < target).
     *
     * @param current_channel_height Current channel height from GET_ROUND
     * @return true if template is stale due to channel advance
     */
    bool check_staleness_by_channel_delta(uint32_t current_channel_height);
    
    /**
     * @brief Set the node channel height for the current template
     * 
     * Called when template is finalized after receiving GET_ROUND response.
     * Template builds NEXT block, so template channel height = node height + 1.
     * 
     * @param channel_height Node channel height from GET_ROUND
     */
    void set_channel_height(uint32_t channel_height);
    
    /**
     * @brief Check if template needs channel height finalization
     * 
     * Returns true if template is valid but channel height not yet set.
     * This indicates we need to request GET_ROUND to finalize the template.
     * 
     * @return true if template needs channel height set
     */
    bool needs_channel_height_finalization() const;
    
    /**
     * @brief Discard current template with reason
     * 
     * Explicitly discard the current template and log the reason.
     * 
     * @param reason Reason for discarding template
     */
    void discard_template(const std::string& reason);
    
    /**
     * @brief Get current template height
     * 
     * @return Height of current template, 0 if no template
     */
    uint32_t get_template_height() const;
    
    // =========================================================================
    // Create Block Verification
    // =========================================================================
    
    /**
     * @brief Verify block creation from template is valid
     * 
     * Validates that a block created from the current template has:
     * - Correct merkle root format
     * - Valid nonce range
     * - Proper header structure
     * 
     * @param merkle_root Block's merkle root
     * @param nonce Block's nonce value
     * @return true if block is valid for submission
     */
    bool verify_block_creation(const std::vector<uint8_t>& merkle_root, 
                               uint64_t nonce) const;
    
    /**
     * @brief Prepare block for submission
     * 
     * Creates the submission payload from template and solved block.
     * 
     * @param merkle_root Block's merkle root
     * @param nonce Block's nonce value
     * @return Submission payload bytes, empty if invalid
     */
    std::vector<uint8_t> prepare_block_submission(const std::vector<uint8_t>& merkle_root,
                                                   uint64_t nonce);

    /**
     * @brief Prepare block for submission, appending Prime channel vOffsets
     *
     * For the Prime channel (nChannel == 1), the Cunningham-chain offsets computed
     * by ValidatePrimeCandidate() must be appended to the serialized block bytes so
     * the node can verify the prime cluster. For the Hash channel, vOffsets is ignored.
     *
     * @param merkle_root Block's merkle root
     * @param nonce Block's nonce value
     * @param vOffsets Prime chain offsets (empty for Hash channel)
     * @return Submission payload bytes (block bytes + vOffsets for Prime), empty if invalid
     */
    std::vector<uint8_t> prepare_block_submission(const std::vector<uint8_t>& merkle_root,
                                                   uint64_t nonce,
                                                   const std::vector<uint8_t>& vOffsets);
    
    // =========================================================================
    // Session Management (FALCON Tunnel Integration)
    // =========================================================================
    
    /**
     * @brief Set the Falcon session ID
     * 
     * Called after successful MINER_AUTH_RESULT with session ID.
     * 
     * @param session_id Authenticated session ID
     */
    void set_session_id(uint32_t session_id);

    /**
     * @brief Set the authoritative session epoch that owns subsequent templates
     *
     * @param session_epoch Session epoch/generation from SessionManager
     */
    void set_session_epoch(uint64_t session_epoch);

    /**
     * @brief Wire a SessionCoordinator as the authoritative session-epoch source.
     *
     * Seeds the local session_epoch from the coordinator's current value so
     * MiningTemplateInterface and the coordinator stay aligned without manual propagation.
     *
     * @param coordinator Shared coordinator instance
     */
    void set_coordinator(std::shared_ptr<SessionCoordinator> coordinator);

    /**
     * @brief Get current session ID
     * @return Session ID
     */
    uint32_t get_session_id() const { return m_session_id; }
    
    /**
     * @brief Check if session is authenticated
     * @return true if session has valid session ID
     */
    bool is_session_authenticated() const { return m_session_id != 0; }
    
    /**
     * @brief Set the mining channel
     * @param channel 1 = Prime, 2 = Hash
     */
    void set_channel(uint8_t channel);
    
    /**
     * @brief Get current mining channel
     * @return channel value
     */
    uint8_t get_channel() const { return m_channel; }
    
    // =========================================================================
    // Statistics and Diagnostics
    // =========================================================================
    
    /**
     * @brief Performance and reliability statistics
     */
    struct TemplateStats {
        uint64_t templates_received;
        uint64_t templates_validated;
        uint64_t templates_rejected;
        uint64_t templates_stale;
        uint64_t templates_fed;
        uint64_t blocks_verified;
        uint64_t blocks_submitted;
        uint64_t total_read_time_us;
        uint64_t total_validation_time_us;
        uint64_t templates_expired_age;       // Templates expired due to age (>200s)
        uint64_t templates_expired_height;    // Templates expired due to height change
    };
    
    /**
     * @brief Get template interface statistics
     * @return Statistics structure
     */
    TemplateStats get_stats() const;
    
    /**
     * @brief Reset statistics counters
     */
    void reset_stats();
    
    /**
     * @brief Get current template state as string
     * @return Human-readable state string
     */
    static const char* state_to_string(TemplateState state);

    /**
     * @brief Attach a HeightTracker for centralized height tracking (non-owning)
     *
     * When set, read_template() will call HeightTracker::OnTemplateReceived()
     * after successfully parsing a template, providing drift diagnostics.
     *
     * @param tracker Non-owning pointer to the HeightTracker (may be nullptr)
     */
    void set_height_tracker(HeightTracker* tracker);

private:
    
    /**
     * @brief Validate a mining template
     * @param tmpl Template to validate
     * @return ValidationResult
     */
    ValidationResult validate_template(const MiningTemplate& tmpl);
    uint32_t get_node_channel_height() const;
    
    /**
     * @brief Parse block header from raw bytes
     * @param data Raw bytes
     * @param block Output block structure
     * @return true if parsing succeeded
     */
    bool parse_block_header(const network::Payload& data, ::LLP::CBlock& block);
    
    // Thread-unsafe helper methods (must be called with m_template_mutex locked)
    bool has_valid_template_unsafe() const;
    uint64_t get_template_age_unsafe() const;
    void mark_template_stale_unsafe(const std::string& reason);
    void discard_template_unsafe(const std::string& reason);
    
    // Member variables
    uint8_t m_channel;
    uint32_t m_session_id;
    uint64_t m_session_epoch{0};
    uint32_t m_current_unified_height;
    uint32_t m_current_channel_height;
    uint32_t m_template_channel_height_snapshot;
    bool m_has_snapshot;
    uint32_t m_last_unified_height;  // Track last unified height from GET_BLOCK for submission guards
    std::chrono::steady_clock::time_point m_template_received_time;  // Track template age
    
    MiningTemplate m_current_template;
    TemplateFeedHandler m_feed_handler;
    ValidationFailureHandler m_validation_failure_handler;
    TemplateClearedCallback m_template_cleared_callback;
    mutable std::mutex m_template_mutex;  // Protects m_current_template access
    
    HeightTracker* m_height_tracker{nullptr};  // Non-owning; for centralized height tracking
    
    std::shared_ptr<spdlog::logger> m_logger;
    
    // Template staleness prevention constants (push-driven era)
    static constexpr uint64_t MAX_TEMPLATE_AGE = 600;      // Dead-connection detector: safely above 5-min Prime block max
    static constexpr uint64_t WARNING_TEMPLATE_AGE = 300;  // Warn after Prime block window expires
    
    // Thread-safe statistics (atomic for multi-worker safety)
    std::atomic<uint64_t> m_templates_received;
    std::atomic<uint64_t> m_templates_validated;
    std::atomic<uint64_t> m_templates_rejected;
    std::atomic<uint64_t> m_templates_stale;
    std::atomic<uint64_t> m_templates_fed;
    std::atomic<uint64_t> m_blocks_verified;
    std::atomic<uint64_t> m_blocks_submitted;
    std::atomic<uint64_t> m_total_read_time_us;
    std::atomic<uint64_t> m_total_validation_time_us;
    
    // Template expiration tracking
    std::atomic<uint64_t> m_templates_expired_age{0};      // Templates expired due to age
    std::atomic<uint64_t> m_templates_expired_height{0};   // Templates expired due to height change

    // Template feed debounce tracking (unified dedup gate)
    // Prevents duplicate template distribution when the same block arrives via
    // multiple paths (e.g., push notification + GET_BLOCK response, or automatic
    // feed from read_template() + manual BLOCK_DATA handler re-push).
    std::chrono::steady_clock::time_point m_last_feed_tp{};
    uint32_t m_last_feed_height{0};
    uint1024_t m_last_feed_prev_hash{0};
};

} // namespace protocol
} // namespace nexusminer

#endif // NEXUSMINER_PROTOCOL_MINING_TEMPLATE_INTERFACE_HPP
