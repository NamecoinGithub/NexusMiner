#include "protocol/mining_template_interface.hpp"
#include "LLP/block_utils.hpp"
#include <chrono>
#include <cstring>
#include <cstdio>

namespace nexusminer {
namespace protocol {

MiningTemplateInterface::MiningTemplateInterface(uint8_t channel, uint32_t session_id)
    : m_channel(channel)
    , m_session_id(session_id)
    , m_current_height(0)
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
    
    if (!parse_block_header(data, tmpl.block)) {
        result.error_message = "Failed to parse block header from template data";
        m_templates_rejected.fetch_add(1, std::memory_order_relaxed);
        m_logger->error("[TemplateInterface] READ FAILED: {}", result.error_message);
        
        auto end_time = std::chrono::high_resolution_clock::now();
        result.validation_time = std::chrono::duration_cast<std::chrono::microseconds>(
            end_time - start_time);
        return result;
    }
    
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
        m_current_template = tmpl;
        m_current_height = tmpl.block.nHeight;
        m_templates_validated.fetch_add(1, std::memory_order_relaxed);
        
        m_logger->info("[TemplateInterface] READ SUCCESS: Template validated for height {} (channel: {}, nBits: 0x{:08x})",
            tmpl.block.nHeight, tmpl.block.nChannel, tmpl.nBits);
        
        // Auto-feed to registered handlers
        feed_current_template();
    } else {
        m_templates_rejected.fetch_add(1, std::memory_order_relaxed);
        m_logger->warn("[TemplateInterface] READ FAILED: {}", result.error_message);
        
        if (result.is_stale) {
            m_templates_stale.fetch_add(1, std::memory_order_relaxed);
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
    return m_current_template.state == TemplateState::VALIDATED ||
           m_current_template.state == TemplateState::ACTIVE;
}

const MiningTemplateInterface::MiningTemplate* 
MiningTemplateInterface::get_current_template() const
{
    if (has_valid_template()) {
        return &m_current_template;
    }
    return nullptr;
}

void MiningTemplateInterface::set_template_feed_handler(TemplateFeedHandler handler)
{
    m_feed_handler = std::move(handler);
    m_logger->debug("[TemplateInterface] Feed handler registered");
}

bool MiningTemplateInterface::feed_current_template()
{
    if (!has_valid_template()) {
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
    if (m_current_template.state != TemplateState::EMPTY &&
        m_current_template.state != TemplateState::STALE) {
        
        m_current_template.state = TemplateState::STALE;
        m_templates_stale.fetch_add(1, std::memory_order_relaxed);
        
        m_logger->info("[TemplateInterface] Template marked stale{}{}", 
            reason.empty() ? "" : ": ", reason);
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
    
    // Create submission payload: merkle_root + nonce (8 bytes LE)
    std::vector<uint8_t> payload;
    payload.reserve(merkle_root.size() + 8);
    
    // Add merkle root
    payload.insert(payload.end(), merkle_root.begin(), merkle_root.end());
    
    // Add nonce (little-endian)
    for (int i = 0; i < 8; ++i) {
        payload.push_back((nonce >> (i * 8)) & 0xFF);
    }
    
    m_blocks_verified.fetch_add(1, std::memory_order_relaxed);
    
    m_logger->info("[TemplateInterface] Block submission prepared ({} bytes)",
        payload.size());
    
    return payload;
}

void MiningTemplateInterface::set_session_id(uint32_t session_id)
{
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
    
    // Validate channel matches expected
    if (tmpl.block.nChannel != m_channel) {
        result.channel_valid = false;
        result.is_valid = false;
        result.error_message = "Channel mismatch: expected " + 
            std::to_string(static_cast<int>(m_channel)) + 
            " but got " + std::to_string(tmpl.block.nChannel);
        m_logger->warn("[TemplateInterface] VALIDATE: {}", result.error_message);
    }
    
    // Validate height is reasonable (not stale)
    // Stale templates are marked as invalid since we don't want to mine on old blocks
    if (m_current_height > 0 && tmpl.block.nHeight < m_current_height) {
        result.is_stale = true;
        result.height_valid = false;
        result.is_valid = false;
        result.error_message = "Template height " + std::to_string(tmpl.block.nHeight) + 
            " is stale (current: " + std::to_string(m_current_height) + ")";
        m_logger->warn("[TemplateInterface] VALIDATE: {}", result.error_message);
    }
    
    // Validate nBits (difficulty) is non-zero
    if (tmpl.block.nBits == 0) {
        result.bits_valid = false;
        result.is_valid = false;
        result.error_message = "Invalid nBits (difficulty) value: 0";
        m_logger->error("[TemplateInterface] VALIDATE: {}", result.error_message);
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
        m_logger->error("[TemplateInterface] VALIDATE: {}", result.error_message);
    }
    
    auto end_time = std::chrono::high_resolution_clock::now();
    result.validation_time = std::chrono::duration_cast<std::chrono::microseconds>(
        end_time - start_time);
    m_total_validation_time_us.fetch_add(result.validation_time.count(), std::memory_order_relaxed);
    
    if (result.is_valid) {
        m_logger->debug("[TemplateInterface] VALIDATE: Template passed all validation checks");
    }
    
    return result;
}

bool MiningTemplateInterface::parse_block_header(const network::Payload& data, 
                                                  ::LLP::CBlock& block)
{
    try {
        // Log payload details for debugging
        m_logger->debug("[TemplateInterface] Parsing block header from {} bytes", data.size());
        
        block = llp_utils::deserialize_block_header(data);
        
        // Log parsed block details
        m_logger->debug("[TemplateInterface] Parsed block header successfully:");
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
        
        // Log first few bytes for debugging
        if (data.size() > 0) {
            std::string hex_preview;
            size_t preview_len = std::min(data.size(), static_cast<size_t>(32));
            for (size_t i = 0; i < preview_len; ++i) {
                char buf[4];
                snprintf(buf, sizeof(buf), "%02x ", data[i]);
                hex_preview += buf;
            }
            m_logger->error("[TemplateInterface]   - First {} bytes: {}", preview_len, hex_preview);
        }
        
        return false;
    }
}

} // namespace protocol
} // namespace nexusminer
