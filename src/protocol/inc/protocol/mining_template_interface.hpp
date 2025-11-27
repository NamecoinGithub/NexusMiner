#ifndef NEXUSMINER_PROTOCOL_MINING_TEMPLATE_INTERFACE_HPP
#define NEXUSMINER_PROTOCOL_MINING_TEMPLATE_INTERFACE_HPP

#include <vector>
#include <cstdint>
#include <memory>
#include <string>
#include <chrono>
#include <functional>
#include <atomic>
#include "LLP/block.hpp"
#include "network/types.hpp"
#include "spdlog/spdlog.h"

namespace nexusminer {
namespace protocol {

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
        EMPTY,          // No template loaded
        PENDING,        // Template requested, waiting for response
        RECEIVED,       // Template received from node
        VALIDATED,      // Template validated and ready for mining
        ACTIVE,         // Template is being mined
        STALE,          // Template has expired (new height/block found)
        SUBMITTED       // Block found and submitted to node
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
     * @brief Mining template data structure
     */
    struct MiningTemplate {
        ::LLP::CBlock block;        // Block header template
        uint32_t nBits;             // Difficulty bits
        uint64_t timestamp_received;// When template was received
        TemplateState state;        // Current state
        uint32_t session_id;        // Falcon session ID
        std::string source_endpoint;// Node endpoint that sent template
    };
    
    /**
     * @brief Template feed callback type
     */
    using TemplateFeedHandler = std::function<void(const MiningTemplate& tmpl, uint32_t nBits)>;
    
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
                                   const std::string& source_endpoint = "");
    
    /**
     * @brief Read template from shared payload (convenience overload)
     * @param data Shared pointer to payload data
     * @param source_endpoint Node endpoint source
     * @return ValidationResult
     */
    ValidationResult read_template(network::Shared_payload data,
                                   const std::string& source_endpoint = "");
    
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

private:
    
    /**
     * @brief Validate a mining template
     * @param tmpl Template to validate
     * @return ValidationResult
     */
    ValidationResult validate_template(const MiningTemplate& tmpl);
    
    /**
     * @brief Parse block header from raw bytes
     * @param data Raw bytes
     * @param block Output block structure
     * @return true if parsing succeeded
     */
    bool parse_block_header(const network::Payload& data, ::LLP::CBlock& block);
    
    // Member variables
    uint8_t m_channel;
    uint32_t m_session_id;
    uint32_t m_current_height;
    
    MiningTemplate m_current_template;
    TemplateFeedHandler m_feed_handler;
    
    std::shared_ptr<spdlog::logger> m_logger;
    
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
};

} // namespace protocol
} // namespace nexusminer

#endif // NEXUSMINER_PROTOCOL_MINING_TEMPLATE_INTERFACE_HPP
