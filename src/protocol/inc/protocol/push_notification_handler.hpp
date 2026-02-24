#ifndef NEXUSMINER_PROTOCOL_PUSH_NOTIFICATION_HANDLER_HPP
#define NEXUSMINER_PROTOCOL_PUSH_NOTIFICATION_HANDLER_HPP

#include "protocol/mining_template_interface.hpp"
#include "protocol/height_tracker.hpp"
#include "protocol_lane.hpp"
#include "packet.hpp"
#include "network/connection.hpp"
#include "spdlog/spdlog.h"
#include <functional>
#include <memory>

namespace nexusminer {
namespace protocol {

/**
 * @brief Unified handler for push notification opcodes
 *
 * Consolidates the identical logic previously duplicated across four handlers:
 *   Legacy:    PRIME_BLOCK_AVAILABLE (0xD9), HASH_BLOCK_AVAILABLE (0xDA)
 *   Stateless: STATELESS_PRIME_BLOCK_AVAILABLE (0xD0D9), STATELESS_HASH_BLOCK_AVAILABLE (0xD0DA)
 *
 * Each notification carries either a 12-byte (compact/legacy) or 140-byte (extended/stateless) payload:
 *   [0..3]   Unified blockchain height
 *   [4..7]   Channel-specific height (Prime or Hash)
 *   [8..11]  Mining difficulty (nBits)
 *   [12..139] hashPrevBlock (uint1024_t, little-endian) — extended/stateless format only
 */
class PushNotificationHandler {
public:
    PushNotificationHandler(
        std::shared_ptr<spdlog::logger> logger,
        const std::uint8_t& current_channel
    );

    /**
     * @brief Handle a block-available push notification
     *
     * @param packet            Received LLP packet (must have 12-byte or 140-byte payload)
     * @param expected_channel  mining::CHANNEL_PRIME or mining::CHANNEL_HASH
     * @param lane              ProtocolLane::LEGACY or ProtocolLane::STATELESS
     * @param template_interface  Pointer to the active MiningTemplateInterface (may be nullptr)
     * @param height_tracker    Pointer to the active HeightTracker (may be nullptr; used for reads only)
     * @param update_height_fn  Callback invoked with (unified_height, channel_height, difficulty_nbits)
     *                          to update both HeightTracker and ClientChannelManager atomically.
     *                          If null, the update is skipped.
     * @param request_work_fn   Callback to request a fresh mining template
     */
    void handle_push_notification(
        const Packet& packet,
        std::uint32_t expected_channel,
        ProtocolLane lane,
        MiningTemplateInterface* template_interface,
        HeightTracker* height_tracker,
        std::function<void(uint32_t, uint32_t, uint32_t)> update_height_fn,
        std::function<void()> request_work_fn
    );

private:
    std::shared_ptr<spdlog::logger> m_logger;
    const std::uint8_t& m_current_channel;

    static constexpr std::size_t PAYLOAD_SIZE_COMPACT  = 12;   // legacy push (12 bytes)
    static constexpr std::size_t PAYLOAD_SIZE_EXTENDED = 140;  // stateless push (12 metadata + 128 hashPrevBlock)
    static constexpr std::size_t PAYLOAD_SIZE = PAYLOAD_SIZE_COMPACT; // backward-compat alias
    static constexpr std::size_t UNIFIED_HEIGHT_OFFSET = 0;
    static constexpr std::size_t CHANNEL_HEIGHT_OFFSET = 4;
    static constexpr std::size_t DIFFICULTY_OFFSET = 8;

    static const char* channel_name(std::uint32_t channel);
};

} // namespace protocol
} // namespace nexusminer

#endif // NEXUSMINER_PROTOCOL_PUSH_NOTIFICATION_HANDLER_HPP
