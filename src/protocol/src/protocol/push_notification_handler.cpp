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

    /* Check if current template is stale */
    if (template_interface && template_interface->has_valid_template())
    {
        auto const* tmpl = template_interface->get_current_template();
        if (tmpl)
        {
            uint32_t current_channel_height = tmpl->nChannelHeight;
            uint32_t current_unified_height = tmpl->block.nHeight;

            m_logger->debug("[Solo Push] Current template: unified={}, {}={}",
                           current_unified_height, ch_name, current_channel_height);

            if (channel_height > current_channel_height)
            {
                if (lane == ProtocolLane::STATELESS) {
                    m_logger->info("[Solo Push] ✗ Stale (was {}, now {})",
                                  current_channel_height, channel_height);
                } else {
                    m_logger->info("[Solo Push] ✗ Template stale (was mining {}, new block {})",
                                  current_channel_height, channel_height);
                }
                m_logger->info("[Solo Push] Requesting fresh {} template...", ch_name);
                request_work_fn();
            }
            else if (channel_height == current_channel_height && unified_height > current_unified_height)
            {
                m_logger->info("[Solo Push] ✓ {} unchanged, unified advanced ({} → {})",
                              ch_name, current_unified_height, unified_height);
                // Continue mining current template
            }
            else
            {
                m_logger->debug("[Solo Push] ✓ Template still valid");
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
