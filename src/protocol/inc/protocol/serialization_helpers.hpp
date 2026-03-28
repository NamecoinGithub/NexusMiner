/*__________________________________________________________________________________________

            Hash(BEGIN(Satoshi[2010]), END(Sunny[2012])) == Videlicet[2014]++

            (c) Copyright The Nexus Developers 2014 - 2023

            Distributed under the MIT software license, see the accompanying
            file COPYING or http://www.opensource.org/licenses/mit-license.php.

            "ad vocem populi" - To the Voice of the People

____________________________________________________________________________________________*/

#pragma once

#include <vector>
#include <cstdint>

namespace serialization {

/**
 * @brief Appends a uint32_t value to a byte vector in little-endian format
 *
 * Serializes a 32-bit unsigned integer into 4 bytes in little-endian byte order
 * and appends them to the destination vector. Used for wire protocol serialization
 * where little-endian encoding is required (e.g., SESSION_KEEPALIVE packets).
 *
 * @param dest The destination byte vector to append to
 * @param value The uint32_t value to serialize
 */
inline void append_uint32_le(std::vector<uint8_t>& dest, uint32_t value) {
    for (uint32_t i = 0; i < 4; ++i) {
        dest.push_back((value >> (i * 8)) & 0xFF);
    }
}

/**
 * @brief Appends a uint64_t value to a byte vector in little-endian format
 *
 * Serializes a 64-bit unsigned integer into 8 bytes in little-endian byte order
 * and appends them to the destination vector. Used for wire protocol serialization
 * where little-endian encoding is required.
 *
 * @param dest The destination byte vector to append to
 * @param value The uint64_t value to serialize
 */
inline void append_uint64_le(std::vector<uint8_t>& dest, uint64_t value) {
    for (uint32_t i = 0; i < 8; ++i) {
        dest.push_back((value >> (i * 8)) & 0xFF);
    }
}

/**
 * @brief Appends a uint16_t value to a byte vector in little-endian format
 *
 * Serializes a 16-bit unsigned integer into 2 bytes in little-endian byte order
 * and appends them to the destination vector.
 *
 * @param dest The destination byte vector to append to
 * @param value The uint16_t value to serialize
 */
inline void append_uint16_le(std::vector<uint8_t>& dest, uint16_t value) {
    dest.push_back(value & 0xFF);
    dest.push_back((value >> 8) & 0xFF);
}

/**
 * @brief Appends a uint32_t value to a byte vector in big-endian format
 *
 * Serializes a 32-bit unsigned integer into 4 bytes in big-endian byte order
 * and appends them to the destination vector.
 *
 * @param dest The destination byte vector to append to
 * @param value The uint32_t value to serialize
 */
inline void append_uint32_be(std::vector<uint8_t>& dest, uint32_t value) {
    dest.push_back((value >> 24) & 0xFF);
    dest.push_back((value >> 16) & 0xFF);
    dest.push_back((value >> 8) & 0xFF);
    dest.push_back(value & 0xFF);
}

/**
 * @brief Reads a single uint8_t value from a byte vector with bounds check
 *
 * @param src The source byte vector to read from
 * @param offset The offset in the source vector to read from (default: 0)
 * @return The uint8_t value, or 0 if offset is out of bounds
 */
inline uint8_t read_uint8(const std::vector<uint8_t>& src, size_t offset = 0) {
    if (src.size() < offset + 1) {
        return 0;
    }
    return src[offset];
}

/**
 * @brief Reads a uint16_t value from a byte vector in big-endian format
 *
 * Deserializes a 16-bit unsigned integer from 2 bytes in big-endian byte order
 * starting at the specified offset in the source vector.
 *
 * @param src The source byte vector to read from
 * @param offset The offset in the source vector to start reading (default: 0)
 * @return The deserialized uint16_t value, or 0 if insufficient bytes
 */
inline uint16_t read_uint16_be(const std::vector<uint8_t>& src, size_t offset = 0) {
    if (src.size() < offset + 2) {
        return 0;
    }
    return (static_cast<uint16_t>(src[offset]) << 8) |
           static_cast<uint16_t>(src[offset + 1]);
}

/**
 * @brief Reads a uint32_t value from a byte vector in little-endian format
 *
 * Deserializes a 32-bit unsigned integer from 4 bytes in little-endian byte order
 * starting at the specified offset in the source vector.
 *
 * @param src The source byte vector to read from
 * @param offset The offset in the source vector to start reading (default: 0)
 * @return The deserialized uint32_t value, or 0 if insufficient bytes
 */
inline uint32_t read_uint32_le(const std::vector<uint8_t>& src, size_t offset = 0) {
    if (src.size() < offset + 4) {
        return 0;
    }
    return static_cast<uint32_t>(src[offset]) |
           (static_cast<uint32_t>(src[offset + 1]) << 8) |
           (static_cast<uint32_t>(src[offset + 2]) << 16) |
           (static_cast<uint32_t>(src[offset + 3]) << 24);
}

/**
 * @brief Reads a uint32_t value from a byte vector in big-endian format
 *
 * Deserializes a 32-bit unsigned integer from 4 bytes in big-endian byte order
 * starting at the specified offset in the source vector.
 *
 * @param src The source byte vector to read from
 * @param offset The offset in the source vector to start reading (default: 0)
 * @return The deserialized uint32_t value, or 0 if insufficient bytes
 */
inline uint32_t read_uint32_be(const std::vector<uint8_t>& src, size_t offset = 0) {
    if (src.size() < offset + 4) {
        return 0;
    }
    return (static_cast<uint32_t>(src[offset]) << 24) |
           (static_cast<uint32_t>(src[offset + 1]) << 16) |
           (static_cast<uint32_t>(src[offset + 2]) << 8) |
           static_cast<uint32_t>(src[offset + 3]);
}

} // namespace serialization
