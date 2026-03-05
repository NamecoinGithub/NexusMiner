/**
 * @file session_start_parser.hpp
 * @brief SESSION_START packet parser for NexusMiner
 *
 * Parses SESSION_START packets received from the LLL-TAO node after successful
 * MINER_AUTH_RESULT. This packet contains session timeout, optional Falcon session
 * key, and optional genesis hash confirmation.
 *
 * Wire Format (from node):
 *   [timeout (4 bytes, LE)]
 *   [optional: session_key (32 bytes)]
 *   [optional: genesis_hash (32 bytes)]
 *
 * Minimum size: 4 bytes (timeout only)
 * With session key: 36 bytes (timeout + key, no genesis)
 * Full format: 68 bytes (timeout + key + genesis)
 *
 * NOTE: The 0x01 success byte is in MINER_AUTH_RESULT, NOT in SESSION_START.
 * MINER_AUTH_RESULT format: [status(1B: 0x00=fail, 0x01=pass)][session_id(4B, LE, if success)]
 * SESSION_START is a separate packet sent AFTER MINER_AUTH_RESULT.
 */

#ifndef NEXUSMINER_SESSION_START_PARSER_HPP
#define NEXUSMINER_SESSION_START_PARSER_HPP

#include <cstdint>
#include <vector>
#include <optional>

namespace nexusminer {
namespace protocol {

/**
 * @brief Parsed SESSION_START packet data
 */
struct SessionStartData {
    uint32_t timeout_seconds;                       ///< Session timeout in seconds (4 bytes LE)
    std::optional<std::vector<uint8_t>> session_key; ///< Optional Falcon session key (32 bytes)
    std::optional<std::vector<uint8_t>> genesis_hash; ///< Optional genesis hash (32 bytes)

    /// @brief Check if session key is present
    bool has_session_key() const { return session_key.has_value(); }

    /// @brief Check if genesis hash is present
    bool has_genesis_hash() const { return genesis_hash.has_value(); }
};

/**
 * @brief Parse SESSION_START packet from wire format
 *
 * Validates packet structure and extracts timeout, optional session key, and optional genesis hash.
 *
 * @param data Packet data (not including opcode/header, just payload)
 * @param length Packet data length
 * @return Parsed data on success, std::nullopt on parse error
 *
 * @note Returns nullopt if:
 *       - data is null
 *       - length < 4 (minimum: timeout field)
 *       - length is 5-35 (invalid: too short for session_key)
 *       - length is 37-67 (invalid: too short for genesis_hash if session_key present)
 *       - length > 68 (warning: excess data ignored)
 */
inline std::optional<SessionStartData> parse_session_start(const uint8_t* data, size_t length) {
    // Validate minimum packet size
    if (!data || length < 4) {
        return std::nullopt;
    }

    SessionStartData result;

    // Parse timeout (4 bytes, little-endian)
    result.timeout_seconds = static_cast<uint32_t>(data[0]) |
                            (static_cast<uint32_t>(data[1]) << 8) |
                            (static_cast<uint32_t>(data[2]) << 16) |
                            (static_cast<uint32_t>(data[3]) << 24);

    // Extract optional session key (32 bytes at offset 4)
    if (length >= 36) {
        // Session key is present
        std::vector<uint8_t> key(data + 4, data + 36);
        result.session_key = std::move(key);

        // Extract optional genesis hash (32 bytes at offset 36)
        if (length >= 68) {
            std::vector<uint8_t> genesis(data + 36, data + 68);
            result.genesis_hash = std::move(genesis);
        } else if (length > 36) {
            // Partial genesis data (invalid)
            return std::nullopt;
        }
    } else if (length > 4) {
        // Partial session key (invalid)
        return std::nullopt;
    }

    return result;
}

/**
 * @brief Parse SESSION_START packet from vector
 *
 * Convenience overload for std::vector<uint8_t>
 *
 * @param data Packet data vector
 * @return Parsed data on success, std::nullopt on parse error
 */
inline std::optional<SessionStartData> parse_session_start(const std::vector<uint8_t>& data) {
    return parse_session_start(data.data(), data.size());
}

/**
 * @brief Calculate keepalive interval in hours from session timeout
 *
 * Uses KEEPALIVE_SAFETY_DIVISOR (=2) to ensure 2 keepalive pings per timeout window.
 * Minimum keepalive interval is 1 hour.
 *
 * @param timeout_seconds Session timeout in seconds
 * @param safety_divisor Safety divisor (default: 2 for 2 pings per window)
 * @return Keepalive interval in hours (minimum 1)
 */
inline uint16_t calculate_keepalive_hours(uint32_t timeout_seconds, uint32_t safety_divisor = 2) {
    if (timeout_seconds == 0) {
        return 1;  // Minimum keepalive interval
    }
    uint32_t keepalive_hours = timeout_seconds / (safety_divisor * 3600u);
    return static_cast<uint16_t>(std::max(1u, keepalive_hours));
}

} // namespace protocol
} // namespace nexusminer

#endif // NEXUSMINER_SESSION_START_PARSER_HPP
