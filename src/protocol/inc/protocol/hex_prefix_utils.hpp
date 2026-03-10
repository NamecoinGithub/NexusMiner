#ifndef NEXUSMINER_PROTOCOL_HEX_PREFIX_UTILS_HPP
#define NEXUSMINER_PROTOCOL_HEX_PREFIX_UTILS_HPP

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace nexusminer {
namespace protocol {

inline std::string format_hex_prefix(const std::vector<uint8_t>& bytes, std::size_t prefix_bytes)
{
    const std::size_t prefix_size = std::min(bytes.size(), prefix_bytes);
    static const char* const HEX = "0123456789abcdef";

    std::string out;
    out.reserve(prefix_size * 2);

    for (std::size_t i = 0; i < prefix_size; ++i) {
        const uint8_t byte = bytes[i];
        out.push_back(HEX[(byte >> 4) & 0x0F]);
        out.push_back(HEX[byte & 0x0F]);
    }

    return out;
}

} // namespace protocol
} // namespace nexusminer

#endif // NEXUSMINER_PROTOCOL_HEX_PREFIX_UTILS_HPP
