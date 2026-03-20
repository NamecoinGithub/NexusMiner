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

    /* Validate channel — since node now broadcasts BOTH channels on every push update,
     * receiving a push for the non-subscribed channel is expected and informational.
     * Treat it as a no-op: update push-received timestamp (done by caller) but do not
     * refresh the template or stop workers. */
    if (m_current_channel != expected_channel)
    {
        m_logger->info("[Solo Push] ℹ️  {} push received on {} lane (mining {} channel) — informational only, ignoring",
                       ch_name,
                       (lane == ProtocolLane::STATELESS) ? "stateless" : "legacy",
                       (m_current_channel == mining::CHANNEL_PRIME) ? "Prime" :
                       (m_current_channel == mining::CHANNEL_HASH)  ? "Hash"  : "Unknown");
        return;
    }

    /* Validate payload (must be 12 or 140 bytes) */
    const bool is_compact  = (packet.m_length == PAYLOAD_SIZE_COMPACT);
    const bool is_extended = (packet.m_length == PAYLOAD_SIZE_EXTENDED);

    if (!packet.m_data || (!is_compact && !is_extended))
    {
        m_logger->error("[Solo Push] Invalid payload: {} bytes (expected {} or {})",
                       packet.m_length, PAYLOAD_SIZE_COMPACT, PAYLOAD_SIZE_EXTENDED);
        return;
    }

    m_logger->info("[Solo Push] {} payload received ({} bytes)",
                   is_extended ? "Extended stateless" : "Compact legacy",
                   packet.m_length);

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

    // Parse hashPrevBlock from extended payload for hash validation
    uint1024_t notification_hash_prev_block{0};
    bool has_hash_prev_block = false;

    if (is_extended)
    {
        // bytes [12-139]: hashPrevBlock (128 bytes, little-endian uint1024_t)
        // Extract the 128-byte hash for comparison with current template
        std::vector<uint8_t> hash_bytes(packet.m_data->begin() + 12,
                                        packet.m_data->begin() + 140);
        notification_hash_prev_block.SetBytes(hash_bytes);
        has_hash_prev_block = true;

        // Log first 8 bytes as hex for cross-reference with node Guard 2 logs
        std::string prev_hash_hex;
        for (std::size_t i = 12; i < std::min(packet.m_data->size(), std::size_t(20)); ++i) {
            char buf[3];
            snprintf(buf, sizeof(buf), "%02x", (*packet.m_data)[i]);
            prev_hash_hex += buf;
        }
        m_logger->info("[Solo Push]   hashPrevBlock (first 8 bytes): {}... (128 bytes, can pre-validate staleness)",
                       prev_hash_hex);
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

        // ═══════════════════════════════════════════════════════════════════════
        // STEP 1: HEIGHT-BASED STALENESS — authoritative, checked first
        // ═══════════════════════════════════════════════════════════════════════
        // Height is the single source of truth for staleness.  The hash check
        // (step 2) is irrelevant for stale templates: hashPrevBlock WILL differ
        // after any block advance — that is normal, not a reorg.
        bool stale = height_tracker && snap.is_template_stale();

        if (stale)
        {
            uint32_t blocks_behind = snap.blocks_behind();

            if (blocks_behind == 1)
            {
                // Normal case: exactly one block behind after a fresh block was found.
                // Just request a fresh template; workers keep mining the current one.
                m_logger->info("[Solo Push] ℹ️  Normal anchor update (blocks_behind=1) — requesting fresh {} template",
                               ch_name);
                request_work_fn();

                // Advance channel_target so subsequent pushes at the same height
                // do not re-trigger this path (doom-loop prevention).
                if (height_tracker) {
                    height_tracker->AdvanceChannelTarget(snap.channel_height + 1);
                }
                return;  // Early exit — hash check is irrelevant for stale templates
            }

            // blocks_behind >= 2: miner is multiple blocks behind — genuine recovery.
            // Height alone is sufficient to determine staleness; no hash check needed.
            m_logger->warn("[Solo Push] ⚠️  Template {} block(s) behind (channel_height {} >= channel_target {}) — discarding",
                           blocks_behind, snap.channel_height, snap.channel_target);
            template_interface->discard_template("multi_block_lag");
            request_work_fn();

            // Advance channel_target to prevent doom-loop.
            if (height_tracker) {
                height_tracker->AdvanceChannelTarget(snap.channel_height + 1);
            }
            return;  // Early exit — hash check is irrelevant for stale templates
        }

        // ═══════════════════════════════════════════════════════════════════════
        // STEP 2: HASH VALIDATION — only for templates that passed height check
        // ═══════════════════════════════════════════════════════════════════════
        // Height says the template is current (blocks_behind == 0).  A hash
        // mismatch at the same height means the chain reorganized at equal height.
        if (has_hash_prev_block)
        {
            auto const* tmpl = template_interface->get_current_template();
            if (tmpl && tmpl->block.hashPrevBlock != notification_hash_prev_block)
            {
                // Hash mismatch with current height: genuine same-height chain reorg.
                m_logger->warn("[Solo Push] ⚠️  Same-height chain reorg detected: hashPrevBlock changed");
                template_interface->discard_template("same_height_chain_reorg");
                request_work_fn();
                return;
            }
            else if (tmpl)
            {
                m_logger->debug("[Solo Push] ✓ hashPrevBlock matches current template");
            }
        }

        // ═══════════════════════════════════════════════════════════════════════
        // STEP 3: SOFT REFRESH — tip moved on another channel
        // ═══════════════════════════════════════════════════════════════════════
        // Template is current and hash validates.  Check if the unified tip has
        // advanced (another channel found a block).  Request a refresh
        // opportunistically but do NOT stop workers.
        bool tip_moved = height_tracker && snap.is_tip_moved();

        if (tip_moved)
        {
            m_logger->info("[Solo Push] ↑ Tip moved (unified {} → {}) — requesting fresh {} template [reason: tip_moved]",
                          snap.template_unified_height, snap.unified_height, ch_name);
            request_work_fn();  // rate-limited GET_BLOCK — OK if it doesn't fire
            m_logger->info("[Solo Push] ✓ Workers continue mining current template (channel not stale)");
        }
        else
        {
            // Template is fully current — log diagnostic and continue mining.
            auto const* tmpl = template_interface->get_current_template();
            if (tmpl)
            {
                if (channel_height == tmpl->nChannelHeight)
                {
                    uint32_t snap_unified = height_tracker ? snap.unified_height : unified_height;
                    m_logger->info("[Solo Push] ✓ {} channel_target={} unchanged, unified_height={}",
                                  ch_name, tmpl->nChannelHeight, snap_unified);
                }
                else
                {
                    m_logger->debug("[Solo Push] ✓ Template still valid");
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
