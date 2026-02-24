#include "protocol/mining_template_interface.hpp"
#include "LLP/block_utils.hpp"
#include <chrono>
#include <cstring>
#include <sstream>
#include <iomanip>

namespace nexusminer {
namespace protocol {

MiningTemplateInterface::MiningTemplateInterface(uint8_t channel, uint32_t session_id)
    : m_channel(channel)
    , m_session_id(session_id)
    , m_current_height(0)
    , m_current_channel_height(0)
    , m_template_channel_height_snapshot(0)
    , m_has_snapshot(false)
    , m_last_unified_height(0)
    , m_template_received_time(std::chrono::steady_clock::now())
    , m_feed_handler(nullptr)
    , m_logger(spdlog::get("logger"))
    , m_templates_received(0)
    , m_templates_validated(0)
    , m_templates_rejected(0)
    , m_templates_stale(0)
    , m_templates_fed(0)
    , m_blocks_verified(0)
    , m_blocks_submitted(0)
    , m_total_read_time_us(0)
    , m_total_validation_time_us(0)
{
    if (!m_logger) {
        m_logger = spdlog::default_logger();
    }
    
    // Initialize template as empty
    m_current_template.state = TemplateState::EMPTY;
    m_current_template.session_id = session_id;
    m_current_template.timestamp_received = 0;
    m_current_template.nChannelHeight = 0;
    m_template_channel_height_snapshot = 0;
    m_has_snapshot = false;
    
    // Validate channel
    if (m_channel != 1 && m_channel != 2) {
        m_logger->warn("[TemplateInterface] Invalid channel {} specified, defaulting to 2 (hash)", 
            static_cast<int>(m_channel));
        m_channel = 2;
    }
    
    m_logger->info("[TemplateInterface] Initialized for channel {} ({})", 
        static_cast<int>(m_channel), 
        (m_channel == 1) ? "prime" : "hash");
}

MiningTemplateInterface::~MiningTemplateInterface()
{
    m_logger->debug("[TemplateInterface] Destroyed");
}

MiningTemplateInterface::ValidationResult 
MiningTemplateInterface::read_template(const network::Payload& data,
                                        const std::string& source_endpoint)
{
    auto start_time = std::chrono::high_resolution_clock::now();
    
    ValidationResult result;
    result.is_valid = false;
    result.is_stale = false;
    result.merkle_valid = false;
    result.height_valid = false;
    result.bits_valid = false;
    result.channel_valid = false;
    
    m_templates_received.fetch_add(1, std::memory_order_relaxed);
    
    m_logger->debug("[TemplateInterface] READ: Processing template ({} bytes) from {}", 
        data.size(), source_endpoint.empty() ? "unknown" : source_endpoint);
    
    // Parse the block header
    MiningTemplate tmpl;
    tmpl.state = TemplateState::PENDING;
    tmpl.session_id = m_session_id;
    tmpl.source_endpoint = source_endpoint;
    tmpl.timestamp_received = static_cast<uint64_t>(
        std::chrono::system_clock::to_time_t(std::chrono::system_clock::now()));
    
    // Determine block format based on size
    if (data.size() == 216) {
        tmpl.format = BlockFormat::TRITIUM;
    } else if (data.size() >= 220) {
        tmpl.format = BlockFormat::LEGACY;
    } else {
        tmpl.format = BlockFormat::COMPACT;
    }
    
    if (!parse_block_header(data, tmpl.block)) {
        result.error_message = "Failed to parse block header from template data";
        m_templates_rejected.fetch_add(1, std::memory_order_relaxed);
        m_logger->error("[TemplateInterface] READ FAILED: {}", result.error_message);
        
        auto end_time = std::chrono::high_resolution_clock::now();
        result.validation_time = std::chrono::duration_cast<std::chrono::microseconds>(
            end_time - start_time);
        return result;
    }
    
    // ═══════════════════════════════════════════════════════════════════════
    // 📥 TEMPLATE RECEIVED FROM NODE - Trust Node's nChannel Value
    // ═══════════════════════════════════════════════════════════════════════
    
    // Helper lambda for hex preview formatting (reduces code duplication)
    auto format_hash_preview = [](const std::vector<uint8_t>& bytes, size_t preview_len = 8) -> std::string {
        std::ostringstream hex;
        hex << std::hex << std::setfill('0');
        for (size_t i = 0; i < std::min(preview_len, bytes.size()); ++i) {
            hex << std::setw(2) << static_cast<unsigned int>(bytes[i]);
        }
        return hex.str();
    };
    
    m_logger->info("[TemplateInterface] 📥 Template received from node:");
    m_logger->info("[TemplateInterface]   nVersion: {}", tmpl.block.nVersion);
    m_logger->info("[TemplateInterface]   nHeight: {}", tmpl.block.nHeight);
    m_logger->info("[TemplateInterface]   nChannel: {} ({})", 
        tmpl.block.nChannel,
        (tmpl.block.nChannel == 1) ? "Prime" : 
        (tmpl.block.nChannel == 2) ? "Hash" : "INVALID");
    m_logger->info("[TemplateInterface]   nBits: 0x{:08x}", tmpl.block.nBits);
    
    auto merkle_bytes = tmpl.block.hashMerkleRoot.GetBytes();
    m_logger->info("[TemplateInterface]   hashMerkleRoot: {}... ({} bytes)", 
        format_hash_preview(merkle_bytes), merkle_bytes.size());
    
    auto prev_bytes = tmpl.block.hashPrevBlock.GetBytes();
    m_logger->info("[TemplateInterface]   hashPrevBlock: {}... ({} bytes)", 
        format_hash_preview(prev_bytes), prev_bytes.size());
    
    // ✅ VALIDATION: Check if node's channel matches our connection
    // Node is authoritative for all template fields, but we should validate
    // that what the node sent matches what we expect based on our connection.
    
    if (tmpl.block.nChannel != m_channel) {
        m_logger->warn("[TemplateInterface] ⚠️  WARNING: Channel mismatch detected!");
        m_logger->warn("[TemplateInterface]   - Node sent: {} ({})", 
            tmpl.block.nChannel,
            (tmpl.block.nChannel == 1) ? "Prime" : "Hash");
        m_logger->warn("[TemplateInterface]   - Connection expects: {} ({})",
            static_cast<int>(m_channel), (m_channel == 1) ? "Prime" : "Hash");
        m_logger->warn("[TemplateInterface]   - Mining what node sent (node is authoritative)");
    } else {
        m_logger->info("[TemplateInterface] ✓ Channel validation passed: {} ({})",
            tmpl.block.nChannel, (tmpl.block.nChannel == 1) ? "Prime" : "Hash");
    }
    
    // Initialize channel height (will be set later when GET_ROUND response arrives)
    tmpl.nChannelHeight = 0;
    
    tmpl.state = TemplateState::RECEIVED;
    tmpl.nBits = tmpl.block.nBits;
    
    // Validate the template
    result = validate_template(tmpl);
    
    auto end_time = std::chrono::high_resolution_clock::now();
    auto read_time = std::chrono::duration_cast<std::chrono::microseconds>(
        end_time - start_time);
    m_total_read_time_us.fetch_add(read_time.count(), std::memory_order_relaxed);
    
    if (result.is_valid) {
        tmpl.state = TemplateState::VALIDATED;
        
        // Protect template assignment with mutex
        {
            std::lock_guard<std::mutex> lock(m_template_mutex);
            m_current_template = tmpl;
            m_current_height = tmpl.block.nHeight;
            m_template_channel_height_snapshot = 0;
            m_has_snapshot = false;
            
            // Update height tracking for sanity checks
            m_last_unified_height = tmpl.block.nHeight;
            
            // Update template received time for age monitoring
            m_template_received_time = std::chrono::steady_clock::now();
        }
        
        m_templates_validated.fetch_add(1, std::memory_order_relaxed);
        
        m_logger->info("[TemplateInterface] ═══════════════════════════════════════");
        m_logger->info("[TemplateInterface] ✅ TEMPLATE VALIDATION SUCCESS");
        m_logger->info("[TemplateInterface]   Height: {}", tmpl.block.nHeight);
        m_logger->info("[TemplateInterface]   Channel: {} ({})", tmpl.block.nChannel, 
            (tmpl.block.nChannel == 1) ? "Prime" : "Hash");
        m_logger->info("[TemplateInterface]   nBits: 0x{:08x}", tmpl.nBits);
        m_logger->info("[TemplateInterface]   Validation time: {} μs", read_time.count());
        m_logger->info("[TemplateInterface] ═══════════════════════════════════════");

        // Notify centralized height tracker (parallel, non-blocking)
        if (m_height_tracker) {
            m_height_tracker->OnTemplateReceived(
                tmpl.block.nChannel,
                tmpl.block.nHeight);
            std::string drift_msg = m_height_tracker->ExplainMismatch();
            if (!drift_msg.empty()) {
                m_logger->info("{}", drift_msg);
            }
        }

        // Auto-feed to registered handlers
        feed_current_template();
    } else {
        m_templates_rejected.fetch_add(1, std::memory_order_relaxed);
        
        m_logger->warn("[TemplateInterface] ═══════════════════════════════════════");
        m_logger->warn("[TemplateInterface] ❌ TEMPLATE VALIDATION FAILED");
        m_logger->warn("[TemplateInterface]   Reason: {}", result.error_message);
        m_logger->warn("[TemplateInterface]   Height valid: {}", result.height_valid);
        m_logger->warn("[TemplateInterface]   Merkle valid: {}", result.merkle_valid);
        m_logger->warn("[TemplateInterface]   Bits valid: {}", result.bits_valid);
        m_logger->warn("[TemplateInterface]   Channel valid: {}", result.channel_valid);
        m_logger->warn("[TemplateInterface]   Is stale: {}", result.is_stale);
        m_logger->warn("[TemplateInterface] ═══════════════════════════════════════");
        
        if (result.is_stale) {
            m_templates_stale.fetch_add(1, std::memory_order_relaxed);
        }
        
        // Notify validation failure handler (if registered)
        if (m_validation_failure_handler) {
            m_validation_failure_handler(result);
        }
    }
    
    result.validation_time = read_time;
    return result;
}

MiningTemplateInterface::ValidationResult 
MiningTemplateInterface::read_template(network::Shared_payload data,
                                        const std::string& source_endpoint)
{
    if (!data || data->empty()) {
        ValidationResult result;
        result.is_valid = false;
        result.error_message = "Empty or null template data";
        return result;
    }
    return read_template(*data, source_endpoint);
}

bool MiningTemplateInterface::has_valid_template() const
{
    std::lock_guard<std::mutex> lock(m_template_mutex);
    return has_valid_template_unsafe();
}

bool MiningTemplateInterface::has_valid_template_unsafe() const
{
    // ASSUMES: m_template_mutex is already locked by caller
    return m_current_template.state == TemplateState::VALIDATED ||
           m_current_template.state == TemplateState::ACTIVE;
}

uint32_t MiningTemplateInterface::get_node_channel_height() const
{
    return m_current_channel_height;
}

const MiningTemplateInterface::MiningTemplate* 
MiningTemplateInterface::get_current_template() const
{
    std::lock_guard<std::mutex> lock(m_template_mutex);
    
    if (has_valid_template_unsafe()) {
        return &m_current_template;
    }
    return nullptr;
}

void MiningTemplateInterface::set_template_feed_handler(TemplateFeedHandler handler)
{
    m_feed_handler = std::move(handler);
    m_logger->debug("[TemplateInterface] Feed handler registered");
}

void MiningTemplateInterface::set_validation_failure_handler(ValidationFailureHandler handler)
{
    m_validation_failure_handler = std::move(handler);
    m_logger->debug("[TemplateInterface] Validation failure handler registered");
}

bool MiningTemplateInterface::feed_current_template()
{
    std::lock_guard<std::mutex> lock(m_template_mutex);
    
    if (!has_valid_template_unsafe()) {
        m_logger->warn("[TemplateInterface] FEED: No valid template to feed");
        return false;
    }
    
    if (!m_feed_handler) {
        m_logger->debug("[TemplateInterface] FEED: No handler registered");
        return false;
    }
    
    m_logger->info("[TemplateInterface] FEED: Feeding template at height {} to workers",
        m_current_template.block.nHeight);
    
    // Update state to active since it's being fed to workers
    m_current_template.state = TemplateState::ACTIVE;
    
    // Feed to handlers
    m_feed_handler(m_current_template, m_current_template.nBits);
    
    m_templates_fed.fetch_add(1, std::memory_order_relaxed);
    
    return true;
}

void MiningTemplateInterface::mark_template_stale(const std::string& reason)
{
    std::lock_guard<std::mutex> lock(m_template_mutex);
    mark_template_stale_unsafe(reason);
}

void MiningTemplateInterface::mark_template_stale_unsafe(const std::string& reason)
{
    // ASSUMES: m_template_mutex is already locked by caller
    if (m_current_template.state != TemplateState::EMPTY &&
        m_current_template.state != TemplateState::STALE) {
        
        m_current_template.state = TemplateState::STALE;
        m_templates_stale.fetch_add(1, std::memory_order_relaxed);
        
        m_logger->info("[TemplateInterface] Template marked stale{}{}", 
            reason.empty() ? "" : ": ", reason);
        m_template_channel_height_snapshot = 0;
        m_has_snapshot = false;
    }
}

bool MiningTemplateInterface::verify_block_creation(const std::vector<uint8_t>& merkle_root,
                                                     uint64_t nonce) const
{
    if (!has_valid_template()) {
        m_logger->error("[TemplateInterface] VERIFY: No valid template for block verification");
        return false;
    }
    
    // Verify merkle root size
    if (merkle_root.size() != 32 && merkle_root.size() != 64) {
        m_logger->error("[TemplateInterface] VERIFY: Invalid merkle root size {} (expected 32 or 64)",
            merkle_root.size());
        return false;
    }
    
    // Note: Zero nonce is technically valid in cryptographic mining - the mining process
    // may legitimately produce a zero nonce as a solution. We log at debug level for
    // diagnostics but do not reject the block.
    if (nonce == 0) {
        m_logger->debug("[TemplateInterface] VERIFY: Zero nonce found - valid mining result");
    }
    
    m_logger->debug("[TemplateInterface] VERIFY: Block creation verified (merkle: {} bytes, nonce: 0x{:016x})",
        merkle_root.size(), nonce);
    
    return true;
}

std::vector<uint8_t> MiningTemplateInterface::prepare_block_submission(
    const std::vector<uint8_t>& merkle_root,
    uint64_t nonce)
{
    if (!verify_block_creation(merkle_root, nonce)) {
        return {};
    }
    
    if (!has_valid_template()) {
        m_logger->error("[TemplateInterface] Cannot prepare block submission: no valid template");
        return {};
    }
    
    std::lock_guard<std::mutex> lock(m_template_mutex);
    
    // Create a copy of the current block template with the solved merkle root and nonce
    ::LLP::CBlock solved_block = m_current_template.block;
    
    // Update with the mined merkle root
    solved_block.hashMerkleRoot.SetBytes(merkle_root);
    
    // Update with the found nonce
    solved_block.nNonce = nonce;
    
    // Determine serialization format from template
    bool is_tritium = (m_current_template.format == BlockFormat::TRITIUM);
    
    // Serialize the full block
    auto payload = llp_utils::serialize_full_block(solved_block, is_tritium);
    
    // SUBMISSION AUDIT: Log solved block fields for ProofHash cross-reference with node.
    // The node calls pBlock->ProofHash() on nVersion..nBits. These must match for
    // GetPrime() / prime validation to succeed.
    // CRITICAL: block.nHeight must be unified blockchain height, NOT channel height.
    {
        m_logger->info("[SUBMIT AUDIT]");
        m_logger->info("[SUBMIT AUDIT]   block.nVersion     = {}", solved_block.nVersion);
        auto prev_bytes = solved_block.hashPrevBlock.GetBytes();
        std::string prev_hex;
        for (size_t i = 0; i < std::min(prev_bytes.size(), size_t(8)); ++i)
        {
            char buf[3];
            snprintf(buf, sizeof(buf), "%02x", prev_bytes[i]);
            prev_hex += buf;
        }
        m_logger->info("[SUBMIT AUDIT]   block.hashPrevBlock = {}... (tip anchor)", prev_hex);
        m_logger->info("[SUBMIT AUDIT]   block.nChannel     = {}", solved_block.nChannel);
        m_logger->info("[SUBMIT AUDIT]   block.nHeight      = {} (unified blockchain height)", solved_block.nHeight);
        m_logger->info("[SUBMIT AUDIT]   nChannelHeight     = {} (metadata only, NOT in block bytes)", m_current_template.nChannelHeight);
        m_logger->info("[SUBMIT AUDIT]   block.nBits        = 0x{:08x}", solved_block.nBits);
        m_logger->info("[SUBMIT AUDIT]   block.nNonce       = 0x{:016x}", solved_block.nNonce);
        m_logger->info("[SUBMIT AUDIT]   serialized size    = {} bytes (expected 216 for Tritium)", payload.size());
        
        // Heuristic abort: if block.nHeight looks like channel height (far below unified),
        // it has been wrongly overwritten — abort to prevent submitting a corrupt block.
        if (m_last_unified_height > 0 && solved_block.nHeight < m_last_unified_height / 2)
        {
            m_logger->error("[SUBMIT AUDIT]   ❌ ABORT: block.nHeight {} appears to be channel height, not unified height ~{}",
                solved_block.nHeight, m_last_unified_height + 1);
            m_logger->error("[SUBMIT AUDIT]   ProofHash() would mismatch — block.nHeight must not be overwritten.");
            m_blocks_verified.fetch_add(1, std::memory_order_relaxed);
            return {};
        }
        
        // Verify nHeight survives serialization at offset 200 (Tritium: big-endian uint32 at [200-203])
        if (is_tritium && payload.size() >= 204)
        {
            uint32_t nHeightSerialized =
                (static_cast<uint32_t>(payload[200]) << 24) |
                (static_cast<uint32_t>(payload[201]) << 16) |
                (static_cast<uint32_t>(payload[202]) << 8) |
                static_cast<uint32_t>(payload[203]);
            if (nHeightSerialized != solved_block.nHeight)
                m_logger->error("[SUBMIT AUDIT]   ❌ CRITICAL: nHeight serialization mismatch! "
                    "block.nHeight={} but serialized[200-203]={}",
                    solved_block.nHeight, nHeightSerialized);
            else
                m_logger->info("[SUBMIT AUDIT]   ✅ nHeight verified in serialized payload: {}", nHeightSerialized);
        }
    }
    
    m_blocks_verified.fetch_add(1, std::memory_order_relaxed);
    
    m_logger->info("[TemplateInterface] Block submission prepared: {} bytes ({} format)",
        payload.size(), is_tritium ? "Tritium" : "Legacy");
    
    return payload;
}

void MiningTemplateInterface::set_session_id(uint32_t session_id)
{
    std::lock_guard<std::mutex> lock(m_template_mutex);
    
    m_session_id = session_id;
    m_current_template.session_id = session_id;
    m_logger->info("[TemplateInterface] Session ID set to 0x{:08x}", session_id);
}

void MiningTemplateInterface::set_channel(uint8_t channel)
{
    if (channel != 1 && channel != 2) {
        m_logger->warn("[TemplateInterface] Invalid channel {} specified, keeping current channel {}",
            static_cast<int>(channel), static_cast<int>(m_channel));
        return;
    }
    
    m_channel = channel;
    m_logger->info("[TemplateInterface] Channel set to {} ({})",
        static_cast<int>(m_channel), (m_channel == 1) ? "prime" : "hash");
}

MiningTemplateInterface::TemplateStats MiningTemplateInterface::get_stats() const
{
    TemplateStats stats;
    stats.templates_received = m_templates_received.load(std::memory_order_relaxed);
    stats.templates_validated = m_templates_validated.load(std::memory_order_relaxed);
    stats.templates_rejected = m_templates_rejected.load(std::memory_order_relaxed);
    stats.templates_stale = m_templates_stale.load(std::memory_order_relaxed);
    stats.templates_fed = m_templates_fed.load(std::memory_order_relaxed);
    stats.blocks_verified = m_blocks_verified.load(std::memory_order_relaxed);
    stats.blocks_submitted = m_blocks_submitted.load(std::memory_order_relaxed);
    stats.total_read_time_us = m_total_read_time_us.load(std::memory_order_relaxed);
    stats.total_validation_time_us = m_total_validation_time_us.load(std::memory_order_relaxed);
    stats.templates_expired_age = m_templates_expired_age.load(std::memory_order_relaxed);
    stats.templates_expired_height = m_templates_expired_height.load(std::memory_order_relaxed);
    return stats;
}

void MiningTemplateInterface::reset_stats()
{
    m_templates_received.store(0, std::memory_order_relaxed);
    m_templates_validated.store(0, std::memory_order_relaxed);
    m_templates_rejected.store(0, std::memory_order_relaxed);
    m_templates_stale.store(0, std::memory_order_relaxed);
    m_templates_fed.store(0, std::memory_order_relaxed);
    m_blocks_verified.store(0, std::memory_order_relaxed);
    m_blocks_submitted.store(0, std::memory_order_relaxed);
    m_total_read_time_us.store(0, std::memory_order_relaxed);
    m_total_validation_time_us.store(0, std::memory_order_relaxed);
    m_templates_expired_age.store(0, std::memory_order_relaxed);
    m_templates_expired_height.store(0, std::memory_order_relaxed);
    
    m_logger->debug("[TemplateInterface] Statistics reset");
}

const char* MiningTemplateInterface::state_to_string(TemplateState state)
{
    switch (state) {
        case TemplateState::EMPTY:      return "EMPTY";
        case TemplateState::PENDING:    return "PENDING";
        case TemplateState::RECEIVED:   return "RECEIVED";
        case TemplateState::VALIDATED:  return "VALIDATED";
        case TemplateState::ACTIVE:     return "ACTIVE";
        case TemplateState::STALE:      return "STALE";
        case TemplateState::SUBMITTED:  return "SUBMITTED";
        default:                        return "UNKNOWN";
    }
}

MiningTemplateInterface::ValidationResult 
MiningTemplateInterface::validate_template(const MiningTemplate& tmpl)
{
    auto start_time = std::chrono::high_resolution_clock::now();
    
    ValidationResult result;
    result.is_valid = true;
    result.is_stale = false;
    result.merkle_valid = true;
    result.height_valid = true;
    result.bits_valid = true;
    result.channel_valid = true;
    
    // TRAINING WHEELS: Show validation details
    m_logger->info("[TemplateInterface] ═══ TEMPLATE VALIDATION ═══");
    m_logger->info("[TemplateInterface] Template details:");
    m_logger->info("[TemplateInterface]   - Height: {}", tmpl.block.nHeight);
    m_logger->info("[TemplateInterface]   - Channel: {} (expected: {})", 
        tmpl.block.nChannel, m_channel);
    m_logger->info("[TemplateInterface]   - nBits: 0x{:08x}", tmpl.block.nBits);
    m_logger->info("[TemplateInterface]   - nVersion: {}", tmpl.block.nVersion);
    m_logger->info("[TemplateInterface]   - Unified height: {}", m_current_height);
    m_logger->info("[TemplateInterface]   - Node channel height: {}", m_current_channel_height);
    m_logger->info("[TemplateInterface]   - Channel height: {}",
        (tmpl.nChannelHeight != 0) ? std::to_string(tmpl.nChannelHeight) : "pending");
    
    // ═══════════════════════════════════════════════════════════════════════
    // VALIDATE nChannel (CRITICAL - Do NOT overwrite, only validate)
    // ═══════════════════════════════════════════════════════════════════════
    
    // Validation: Check if channel is valid (1=Prime or 2=Hash)
    // nChannel is now properly deserialized from all block formats (Tritium/Legacy/Compact)
    if (tmpl.block.nChannel != 1 && tmpl.block.nChannel != 2) {
        result.channel_valid = false;
        result.is_valid = false;
        result.error_message = "❌ Invalid channel value: " + 
            std::to_string(tmpl.block.nChannel);
        m_logger->error("[TemplateInterface] {}", result.error_message);
        m_logger->error("[TemplateInterface]   Expected: 1 (Prime) or 2 (Hash)");
        m_logger->error("[TemplateInterface]   Got: {}", tmpl.block.nChannel);
        m_logger->error("[TemplateInterface]   This indicates deserialization failed");
        return result;  // Reject template immediately
    }
    
    // Check if channel matches our connection preference (informational only)
    if (tmpl.block.nChannel != m_channel) {
        // NOTE: This is just informational logging - we don't reject the template
        // The node is authoritative, and we mine what it sends
        m_logger->info("[TemplateInterface] ℹ️  Channel info: Node sent channel {} but connection is for channel {}",
            tmpl.block.nChannel, static_cast<int>(m_channel));
        m_logger->info("[TemplateInterface]   Mining what node sent (node is authoritative)");
    }
    
    m_logger->info("[TemplateInterface] ✓ nChannel validation passed: {} ({})", 
        tmpl.block.nChannel,
        (tmpl.block.nChannel == 1) ? "Prime" : "Hash");
    
    // ═══════════════════════════════════════════════════════════════════════
    // VALIDATE UNIFIED HEIGHT (Sanity Check for Corrupted Height)
    // ═══════════════════════════════════════════════════════════════════════
    
    // Check for unreasonable height jumps (e.g., 6.5M → 1.9B) or deep reorgs
    // Normal height changes should be within ±100 blocks
    // - Forward jumps >100: likely corrupted height
    // - Backward jumps >100: likely corrupted height (normal reorgs are shallow)
    if (m_last_unified_height > 0) {
        // Calculate absolute height difference to handle both directions
        int64_t height_diff = static_cast<int64_t>(tmpl.block.nHeight) - static_cast<int64_t>(m_last_unified_height);
        uint32_t abs_height_delta = static_cast<uint32_t>(std::abs(height_diff));
        
        if (abs_height_delta > 100) {
            result.height_valid = false;
            result.is_valid = false;
            
            std::string direction = (height_diff > 0) ? "forward" : "backward";
            result.error_message = "Unified height " + direction + " jump exceeds sanity threshold: " + 
                std::to_string(m_last_unified_height) + " → " + 
                std::to_string(tmpl.block.nHeight) + " (delta: " + 
                std::to_string(abs_height_delta) + " blocks, max: 100)";
            
            m_logger->error("[TemplateInterface] ❌ CORRUPTED HEIGHT DETECTED");
            m_logger->error("[TemplateInterface]   Previous height: {}", m_last_unified_height);
            m_logger->error("[TemplateInterface]   New height: {}", tmpl.block.nHeight);
            m_logger->error("[TemplateInterface]   Delta: {} blocks {} (max allowed: 100)", 
                           abs_height_delta, direction);
            m_logger->error("[TemplateInterface]   This indicates corrupted template data or deep reorg");
            m_logger->error("[TemplateInterface]   Mining will be stopped to prevent wasted hashrate");
            return result;  // Reject template immediately
        }
        
        // Log direction of height change for diagnostics
        if (height_diff > 0) {
            m_logger->debug("[TemplateInterface] ✓ Height advanced {} blocks (forward)", abs_height_delta);
        } else if (height_diff < 0) {
            m_logger->info("[TemplateInterface] ℹ️  Height decreased {} blocks (reorg detected)", abs_height_delta);
        } else {
            m_logger->debug("[TemplateInterface] ℹ️  Height unchanged (duplicate template)");
        }
    } else {
        m_logger->debug("[TemplateInterface] ℹ️  First template - skipping height sanity check");
    }
    
    // Validate channel height if available (only mark stale when THIS channel advanced)
    // Use channel height from GET_ROUND - this is the CRITICAL staleness check
    uint32_t node_channel_height = get_node_channel_height();
    
    // Template semantics:
    //   - nChannelHeight = height of block being mined (node_height + 1)
    //   - node_channel_height = current height on blockchain for this channel
    // Template is stale only if node's channel reached or passed the height we're mining for
    if (tmpl.nChannelHeight != 0 && node_channel_height > 0) {
        if (node_channel_height >= tmpl.nChannelHeight) {
            result.is_stale = true;
            result.height_valid = false;
            result.is_valid = false;
            // Use template's actual channel for accurate error messages
            std::string channel_name = (tmpl.block.nChannel == 1) ? "Prime" : "Hash";
            result.error_message = channel_name + " channel stale: template for height " + 
                std::to_string(tmpl.nChannelHeight) + " but node already at " + 
                std::to_string(node_channel_height);
            
            m_logger->warn("[TemplateInterface] {}", result.error_message);
            return result;
        }
        
        // Log success - unified height can differ and that's NORMAL
        m_logger->debug("[TemplateInterface] ✓ Template valid: node channel height {} < template height {}",
            node_channel_height, tmpl.nChannelHeight);
        
        // If unified height differs, log informational message
        if (tmpl.block.nHeight != m_current_height) {
            m_logger->debug("[TemplateInterface] ℹ️  Unified height differs (template={}, current={})",
                tmpl.block.nHeight, m_current_height);
            m_logger->debug("[TemplateInterface]    This is NORMAL when other channels mine blocks");
        }
    } else {
        m_logger->info("[TemplateInterface] ✓ Channel height pending, skipping staleness check");
    }
    
    // Validate nBits (difficulty) is non-zero
    if (tmpl.block.nBits == 0) {
        result.bits_valid = false;
        result.is_valid = false;
        result.error_message = "Invalid nBits (difficulty) value: 0";
        m_logger->error("[TemplateInterface] ❌ VALIDATION FAILED: {}", result.error_message);
    } else {
        m_logger->info("[TemplateInterface] ✓ Difficulty validation passed");
    }
    
    // Validate merkle root is not all zeros (basic sanity check)
    bool merkle_all_zeros = true;
    auto merkle_bytes = tmpl.block.hashMerkleRoot.GetBytes();
    for (auto byte : merkle_bytes) {
        if (byte != 0) {
            merkle_all_zeros = false;
            break;
        }
    }
    if (merkle_all_zeros) {
        result.merkle_valid = false;
        result.is_valid = false;
        result.error_message = "Invalid merkle root: all zeros";
        m_logger->error("[TemplateInterface] ❌ VALIDATION FAILED: {}", result.error_message);
    } else {
        // Log first few bytes of merkle root for verification
        std::ostringstream merkle_hex;
        merkle_hex << std::hex << std::setfill('0');
        size_t preview_len = std::min(merkle_bytes.size(), static_cast<size_t>(16));
        for (size_t i = 0; i < preview_len; ++i) {
            merkle_hex << std::setw(2) << static_cast<unsigned int>(merkle_bytes[i]) << " ";
        }
        m_logger->info("[TemplateInterface] ✓ Merkle root validation passed");
        m_logger->debug("[TemplateInterface]   First {} bytes: {}", preview_len, merkle_hex.str());
    }
    
    auto end_time = std::chrono::high_resolution_clock::now();
    result.validation_time = std::chrono::duration_cast<std::chrono::microseconds>(
        end_time - start_time);
    m_total_validation_time_us.fetch_add(result.validation_time.count(), std::memory_order_relaxed);
    
    if (result.is_valid) {
        m_logger->info("[TemplateInterface] ✅ ALL VALIDATION CHECKS PASSED");
        m_logger->info("[TemplateInterface]   Validation time: {} μs", result.validation_time.count());
    } else {
        m_logger->error("[TemplateInterface] ❌ VALIDATION FAILED");
        m_logger->error("[TemplateInterface]   Reason: {}", result.error_message);
    }
    m_logger->info("[TemplateInterface] ═══════════════════════════");
    
    return result;
}

bool MiningTemplateInterface::parse_block_header(const network::Payload& data, 
                                                  ::LLP::CBlock& block)
{
    try {
        // Detect and log block type based on size
        std::string block_type;
        if (data.size() == 216) {
            block_type = "Tritium (216 bytes, nChannel at offset 211)";
        } else if (data.size() >= 220) {
            block_type = "Legacy (220+ bytes, nChannel at offset 196)";
        } else if (data.size() == 92) {
            block_type = "Compact (92 bytes, sequential format)";
        } else {
            block_type = "Unknown format (" + std::to_string(data.size()) + " bytes)";
        }
        
        m_logger->debug("[TemplateInterface] Parsing {} block header", block_type);
        
        block = llp_utils::deserialize_block_header(data);
        
        // Log parsed block details
        m_logger->debug("[TemplateInterface] Parsed block header successfully:");
        m_logger->debug("[TemplateInterface]   - Block type: {}", block_type);
        m_logger->debug("[TemplateInterface]   - nVersion: {}", block.nVersion);
        m_logger->debug("[TemplateInterface]   - nChannel: {}", block.nChannel);
        m_logger->debug("[TemplateInterface]   - nHeight: {}", block.nHeight);
        m_logger->debug("[TemplateInterface]   - nBits: 0x{:08x}", block.nBits);
        m_logger->debug("[TemplateInterface]   - nNonce: 0x{:016x}", block.nNonce);
        m_logger->debug("[TemplateInterface]   - nTime: {}", block.nTime);
        
        return true;
    }
    catch (const std::exception& e) {
        m_logger->error("[TemplateInterface] Failed to parse block header: {}", e.what());
        m_logger->error("[TemplateInterface]   - Payload size: {} bytes", data.size());
        
        // Log first few bytes for debugging using C++ stringstream
        if (data.size() > 0) {
            std::ostringstream hex_preview;
            hex_preview << std::hex << std::setfill('0');
            size_t preview_len = std::min(data.size(), static_cast<size_t>(32));
            for (size_t i = 0; i < preview_len; ++i) {
                hex_preview << std::setw(2) << static_cast<unsigned int>(data[i]) << " ";
            }
            m_logger->error("[TemplateInterface]   - First {} bytes: {}", preview_len, hex_preview.str());
        }
        
        return false;
    }
}

// =========================================================================
// Template Staleness Prevention (LLL-TAO PR #131 Client-Side Integration)
// =========================================================================

bool MiningTemplateInterface::is_template_stale() const
{
    std::lock_guard<std::mutex> lock(m_template_mutex);
    
    if (m_current_template.state == TemplateState::EMPTY ||
        m_current_template.state == TemplateState::STALE) {
        return true;
    }
    
    uint64_t age = get_template_age_unsafe();
    return age > MAX_TEMPLATE_AGE;
}

bool MiningTemplateInterface::is_template_old() const
{
    std::lock_guard<std::mutex> lock(m_template_mutex);
    
    if (m_current_template.state == TemplateState::EMPTY ||
        m_current_template.state == TemplateState::STALE) {
        return true;
    }
    
    uint64_t age = get_template_age_unsafe();
    return age > WARNING_TEMPLATE_AGE;
}

uint64_t MiningTemplateInterface::get_template_age() const
{
    std::lock_guard<std::mutex> lock(m_template_mutex);
    return get_template_age_unsafe();
}

uint64_t MiningTemplateInterface::get_template_age_unsafe() const
{
    // ASSUMES: m_template_mutex is already locked by caller
    if (m_current_template.state == TemplateState::EMPTY ||
        m_current_template.timestamp_received == 0) {
        return 0;
    }
    
    auto now = std::chrono::system_clock::now();
    uint64_t current_time = static_cast<uint64_t>(
        std::chrono::system_clock::to_time_t(now));
    
    // Handle clock skew - if current time is less than timestamp, treat as stale
    if (current_time < m_current_template.timestamp_received) {
        m_logger->warn("[TemplateInterface] Clock skew detected: current time < template timestamp");
        // Return a value greater than MAX_TEMPLATE_AGE to trigger staleness
        constexpr uint64_t CLOCK_SKEW_STALENESS_VALUE = MAX_TEMPLATE_AGE + 1;
        return CLOCK_SKEW_STALENESS_VALUE;
    }
    
    return current_time - m_current_template.timestamp_received;
}

bool MiningTemplateInterface::update_height(uint32_t new_height)
{
    std::lock_guard<std::mutex> lock(m_template_mutex);
    
    m_logger->debug("[TemplateInterface] Height update: {} -> {}", m_current_height, new_height);
    
    // Check if template should be discarded due to height change
    bool template_discarded = false;
    
    if (new_height > m_current_height && has_valid_template_unsafe()) {
        // Height has advanced - discard current template
        uint32_t old_height = m_current_template.block.nHeight;
        
        m_logger->info("[TemplateInterface] 🔔 Height changed: {} -> {} (template at height {})",
            m_current_height, new_height, old_height);
        
        if (old_height < new_height) {
            m_logger->info("[TemplateInterface] ❌ Template is now stale - discarding");
            discard_template_unsafe("Height changed");
            template_discarded = true;
            m_templates_expired_height.fetch_add(1, std::memory_order_relaxed);
        }
    }
    
    // Always update current height
    m_current_height = new_height;
    
    return template_discarded;
}

bool MiningTemplateInterface::update_channel_height(uint32_t channel, uint32_t new_channel_height)
{
    std::lock_guard<std::mutex> lock(m_template_mutex);
    
    m_current_channel_height = new_channel_height;

    m_logger->debug("[TemplateInterface] Channel {} height update: {}", 
        channel, new_channel_height);
    
    // Check if we have a valid template
    if (!has_valid_template_unsafe()) {
        m_logger->debug("[TemplateInterface] No active template to check");
        return false;
    }
    
    // Only check if this is the same channel as our template
    if (m_current_template.block.nChannel != channel) {
        m_logger->debug("[TemplateInterface] Template is for channel {}, update is for channel {} - no action needed",
            m_current_template.block.nChannel, channel);
        return false;
    }
    
    // Check if template is stale based on channel height
    // Template builds NEXT block, so template channel height = node height + 1
    // Template is stale if: node_channel_height != (template_channel_height - 1)
    if (m_current_template.nChannelHeight == 0) {
        m_logger->debug("[TemplateInterface] Template channel height not yet set (pending finalization)");
        return false;
    }
    
    uint32_t expected_node_height = m_current_template.nChannelHeight - 1;
    
    if (new_channel_height != expected_node_height) {
        m_logger->info("[TemplateInterface] ⚠ Channel {} height mismatch detected!", channel);
        m_logger->info("[TemplateInterface]   Expected node height: {}", expected_node_height);
        m_logger->info("[TemplateInterface]   Actual node height:   {}", new_channel_height);
        m_logger->info("[TemplateInterface]   → Another {} block was mined",
            (channel == 1) ? "Prime" : (channel == 2) ? "Hash" : "Stake");
        m_logger->info("[TemplateInterface] ✗ Discarding stale template (channel-specific staleness)");
        
        discard_template_unsafe("Channel height advanced");
        m_templates_expired_height.fetch_add(1, std::memory_order_relaxed);
        return true;
    }
    
    m_logger->debug("[TemplateInterface] ✓ Template is FRESH - channel height matches");
    return false;
}

void MiningTemplateInterface::set_template_channel_height_snapshot(uint32_t channel_height)
{
    std::lock_guard<std::mutex> lock(m_template_mutex);
    m_template_channel_height_snapshot = channel_height;
    m_has_snapshot = true;
    m_logger->debug("[TemplateInterface] Snapshot channel height set to {}", channel_height);
}

void MiningTemplateInterface::clear_template_channel_height_snapshot()
{
    std::lock_guard<std::mutex> lock(m_template_mutex);
    m_template_channel_height_snapshot = 0;
    m_has_snapshot = false;
    m_logger->debug("[TemplateInterface] Snapshot channel height cleared");
}

bool MiningTemplateInterface::check_staleness_by_channel_delta(uint32_t current_channel_height)
{
    std::lock_guard<std::mutex> lock(m_template_mutex);

    if (!m_has_snapshot) {
        m_logger->debug("[TemplateInterface] No snapshot, cannot check staleness");
        return false;
    }

    // Log the comparison for diagnostics
    m_logger->debug("[TemplateInterface] Staleness check: current={} snapshot={}",
        current_channel_height, m_template_channel_height_snapshot);

    if (current_channel_height > m_template_channel_height_snapshot) {
        m_logger->warn("[TemplateInterface] ⚠️  STALE: channel advanced {} → {}",
            m_template_channel_height_snapshot, current_channel_height);
        discard_template_unsafe("Channel height advanced past snapshot");
        m_templates_expired_height.fetch_add(1, std::memory_order_relaxed);
        return true;
    }

    m_logger->debug("[TemplateInterface] ✓ VALID: channel unchanged at {}",
        current_channel_height);
    return false;
}

void MiningTemplateInterface::set_channel_height(uint32_t channel_height)
{
    std::lock_guard<std::mutex> lock(m_template_mutex);
    
    if (m_current_template.state == TemplateState::EMPTY) {
        m_logger->warn("[TemplateInterface] Cannot set channel height - no active template");
        return;
    }
    
    m_current_template.nChannelHeight = channel_height;
    m_current_channel_height = (channel_height > 0) ? (channel_height - 1) : 0;
    m_template_channel_height_snapshot = 0;
    m_has_snapshot = false;
    m_logger->info("[TemplateInterface] ✓ Template channel height set to {}", channel_height);
}

void MiningTemplateInterface::discard_template(const std::string& reason)
{
    std::lock_guard<std::mutex> lock(m_template_mutex);
    discard_template_unsafe(reason);
}

void MiningTemplateInterface::discard_template_unsafe(const std::string& reason)
{
    // ASSUMES: m_template_mutex is already locked by caller
    if (m_current_template.state == TemplateState::EMPTY) {
        m_logger->debug("[TemplateInterface] No template to discard");
        return;
    }
    
    m_logger->info("[TemplateInterface] Discarding template: {}", reason);
    m_logger->info("[TemplateInterface]   - Height: {}", m_current_template.block.nHeight);
    m_logger->info("[TemplateInterface]   - Age: {}s", get_template_age_unsafe());
    m_logger->info("[TemplateInterface]   - State: {}", state_to_string(m_current_template.state));
    
    // Mark as stale
    mark_template_stale_unsafe(reason);
    m_template_channel_height_snapshot = 0;
    m_has_snapshot = false;
}

bool MiningTemplateInterface::needs_channel_height_finalization() const
{
    std::lock_guard<std::mutex> lock(m_template_mutex);
    
    // Template needs finalization if it's valid but channel height not set
    return has_valid_template_unsafe() && m_current_template.nChannelHeight == 0;
}

uint32_t MiningTemplateInterface::get_template_height() const
{
    std::lock_guard<std::mutex> lock(m_template_mutex);
    
    if (m_current_template.state == TemplateState::EMPTY) {
        return 0;
    }
    return m_current_template.block.nHeight;
}

void MiningTemplateInterface::set_height_tracker(HeightTracker* tracker)
{
    m_height_tracker = tracker;
}

} // namespace protocol
} // namespace nexusminer
