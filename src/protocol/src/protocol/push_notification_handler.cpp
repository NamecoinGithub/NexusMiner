#include "protocol/push_notification_handler.hpp"
#include "LLP/utils.hpp"
#include "mining/client_block.h"

namespace nexusminer {
namespace protocol {

PushNotificationHandler::PushNotificationHandler(
    std::shared_ptr<spdlog::logger> logger,
    const std::uint8_t& current_channel)
: m_logger{std::move(logger)}
, m_current_channel{current_channel}
{
}

const char* PushNotificationHandler::channel_name(std::uint32_t channel)
{
    return (channel == mining::CHANNEL_PRIME) ? "Prime" : "Hash";
}

void PushNotificationHandler::handle_push_notification(
    const Packet& packet,
    std::uint32_t expected_channel,
    ProtocolLane lane,
    MiningTemplateInterface* template_interface,
    HeightTracker* height_tracker,
    std::function<void(uint32_t, uint32_t, uint32_t)> update_height_fn,
    std::function<void()> request_work_fn)
{
    const char* ch_name = channel_name(expected_channel);

    // Log reception with opcode
    if (lane == ProtocolLane::STATELESS) {
        m_logger->info("[Solo Push] ✉️  STATELESS_{}_BLOCK_AVAILABLE (0x{:04X}) received",
                       ch_name, packet.m_header);
    } else {
        m_logger->info("[Solo Push] ✉️  {}_BLOCK_AVAILABLE received", ch_name);
    }

    /* Validate channel (should only receive if mining the matching channel) */
    if (m_current_channel != expected_channel)
    {
        m_logger->error("[Solo Push] ❌ Received {}_BLOCK_AVAILABLE but mining {} channel!",
                       ch_name,
                       (m_current_channel == mining::CHANNEL_PRIME) ? "Prime" :
                       (m_current_channel == mining::CHANNEL_HASH)  ? "Hash"  : "Unknown");
        if (lane == ProtocolLane::LEGACY)
            m_logger->error("[Solo Push]    This should never happen (node filters by channel)");
        return;
    }

    /* Validate payload (must be 12 bytes) */
    if (!packet.m_data || packet.m_length != PAYLOAD_SIZE)
    {
        m_logger->error("[Solo Push] Invalid payload: {} bytes (expected {})",
                       packet.m_length, PAYLOAD_SIZE);
        return;
    }

    /* Parse notification (big-endian) */
    uint32_t unified_height  = bytes2uint(*packet.m_data, UNIFIED_HEIGHT_OFFSET);
    uint32_t channel_height  = bytes2uint(*packet.m_data, CHANNEL_HEIGHT_OFFSET);
    uint32_t difficulty      = bytes2uint(*packet.m_data, DIFFICULTY_OFFSET);

    if (lane == ProtocolLane::STATELESS) {
        m_logger->info("[Solo Push]   Unified: {}, {}: {}, Diff: 0x{:08x}",
                       unified_height, ch_name, channel_height, difficulty);
    } else {
        m_logger->info("[Solo Push]   Unified height: {}", unified_height);
        m_logger->info("[Solo Push]   {} height: {}", ch_name, channel_height);
        m_logger->info("[Solo Push]   Difficulty: 0x{:08x}", difficulty);
    }

    /* Update heights via unified callback (updates HeightTracker + ClientChannelManager) */
    if (update_height_fn) {
        update_height_fn(unified_height, channel_height, difficulty);
    }
    // height_tracker is used only for reads (ExplainMismatch, GetSnapshot for staleness).
    // Both update_height_fn and height_tracker* are expected to be non-null in production
    // (Solo always provides both); drift detection is advisory and safe to skip if null.
    if (height_tracker) {
        std::string drift_msg = height_tracker->ExplainMismatch();
        if (!drift_msg.empty()) {
            m_logger->info("{}", drift_msg);
        }
    }

    /* Check if current template is stale using HeightTracker snapshot */
    if (template_interface && template_interface->has_valid_template())
    {
        // Take one snapshot for all decisions in this block.
        auto snap = height_tracker ? height_tracker->GetSnapshot() : HeightTracker::Snapshot{};

        // Use HeightTracker as single source of truth for staleness decision.
        // is_template_stale() returns true when channel_height >= channel_target (both non-zero).
        bool stale = height_tracker && snap.is_template_stale();

        if (stale)
        {
            if (lane == ProtocolLane::STATELESS) {
                m_logger->info("[Solo Push] ✗ Stale (channel_height {} >= channel_target {}) [reason: channel_advanced]",
                              snap.channel_height, snap.channel_target);
            } else {
                m_logger->info("[Solo Push] ✗ Template stale (channel_height {} >= channel_target {}) [reason: channel_advanced]",
                              snap.channel_height, snap.channel_target);
            }
            m_logger->info("[Solo Push] Requesting fresh {} template...", ch_name);
            request_work_fn();
        }
        else
        {
            // Template is not channel-stale. Check if the unified tip has moved
            // (another channel found a block after this template was issued).
            // hashPrevBlock in the template is now stale even though the channel
            // height hasn't changed, so we need a fresh template.
            bool tip_moved = height_tracker && snap.is_tip_moved();

            if (tip_moved)
            {
                m_logger->info("[Solo Push] ↑ Tip moved (unified {} → {}) — requesting fresh {} template [reason: tip_moved]",
                              snap.template_unified_height, snap.unified_height, ch_name);
                request_work_fn();
            }
            else
            {
                // Log informational context (unified height may have advanced — that's OK)
                auto const* tmpl = template_interface->get_current_template();
                if (tmpl)
                {
                    // Use HeightTracker snapshot for unified height (not template header nHeight,
                    // which represents channel_target in stateless templates).
                    if (channel_height == tmpl->nChannelHeight)
                    {
                        uint32_t snap_unified = height_tracker ? snap.unified_height : unified_height;
                        m_logger->info("[Solo Push] ✓ {} channel_target={} unchanged, unified_height={}",
                                      ch_name, tmpl->nChannelHeight, snap_unified);
                        // Continue mining current template
                    }
                    else
                    {
                        m_logger->debug("[Solo Push] ✓ Template still valid");
                    }
                }
            }
        }
    }
    else
    {
        /* No template yet - request one */
        m_logger->info("[Solo Push] No template - requesting initial {} template", ch_name);
        request_work_fn();
    }
}

} // namespace protocol
} // namespace nexusminer
