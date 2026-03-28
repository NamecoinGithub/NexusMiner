#ifndef NEXUSMINER_PROTOCOL_CHANNEL_UTILS_HPP
#define NEXUSMINER_PROTOCOL_CHANNEL_UTILS_HPP

#include "mining/client_block.h"
#include <cstdint>

namespace nexusminer {
namespace protocol {

/// Map a channel ID to its human-readable name.
/// 1 → "Prime", 2 → "Hash", 3 → "Stake", anything else → "Unknown".
constexpr const char* channel_name(uint32_t channel) {
    return (channel == mining::CHANNEL_PRIME) ? "Prime" :
           (channel == mining::CHANNEL_HASH)  ? "Hash" :
           (channel == mining::CHANNEL_STAKE) ? "Stake" :
                                                "Unknown";
}

/// Return true iff channel is a recognised LLL-TAO mining channel (1, 2, or 3).
constexpr bool is_valid_channel(uint32_t channel) {
    return channel >= mining::CHANNEL_PRIME && channel <= mining::CHANNEL_STAKE;
}

/// Select the height that corresponds to the given channel.
/// @param channel  1 = Prime, 2 = Hash, 3 = Stake.
/// @param prime    Prime-channel height value.
/// @param hash     Hash-channel height value.
/// @param stake    Stake-channel height value (default 0).
/// @return Matching height, or 0 for unknown channels.
template <typename T>
constexpr uint32_t select_channel_height(uint32_t channel, T prime, T hash, T stake = T{}) {
    return (channel == mining::CHANNEL_PRIME) ? static_cast<uint32_t>(prime) :
           (channel == mining::CHANNEL_HASH)  ? static_cast<uint32_t>(hash) :
           (channel == mining::CHANNEL_STAKE) ? static_cast<uint32_t>(stake) :
                                                uint32_t{0};
}

} // namespace protocol
} // namespace nexusminer

#endif // NEXUSMINER_PROTOCOL_CHANNEL_UTILS_HPP
