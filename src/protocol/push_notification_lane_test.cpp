/**
 * @file push_notification_lane_test.cpp
 * @brief Tests for unified push notification lane detection
 * 
 * Validates that push notification opcodes are correctly matched by the
 * unified matches_opcode() lambda for both legacy 8-bit and stateless
 * 16-bit mirror-mapped opcodes, ensuring m_protocol_lane is used rather
 * than hardcoded lane values.
 * 
 * Test scenarios:
 * - Legacy 8-bit push opcodes (0xD9, 0xDA) match via matches_opcode()
 * - Stateless 16-bit push opcodes (0xD0D9, 0xD0DA) match via matches_opcode()
 * - Both formats route through unified handler with correct lane
 */

#include "miner_opcodes.hpp"
#include "protocol_lane.hpp"
#include "protocol/push_notification_handler.hpp"
#include "protocol/mining_template_interface.hpp"
#include "protocol/solo.hpp"
#include "protocol/height_tracker.hpp"
#include "mining/client_block.h"
#include "spdlog/spdlog.h"
#include "spdlog/sinks/null_sink.h"
#include <iostream>
#include <cstdint>
#include <gtest/gtest.h>

using namespace nexusminer;
namespace MinerLLP = nexusminer::LLP;

/**
 * Simulates the matches_opcode() lambda from solo.cpp process_messages():
 *   auto matches_opcode = [&packet](uint16_t legacy_opcode) {
 *       if (packet.m_is_uint16_opcode) {
 *           return packet.m_header == MinerLLP::MirrorOpcode(static_cast<uint8_t>(legacy_opcode));
 *       }
 *       return packet.m_header == legacy_opcode;
 *   };
 */
bool simulated_matches_opcode(uint16_t packet_header, bool is_uint16_opcode, uint16_t legacy_opcode) {
    if (is_uint16_opcode) {
        return packet_header == MinerLLP::MirrorOpcode(static_cast<uint8_t>(legacy_opcode));
    }
    return packet_header == legacy_opcode;
}

/**
 * Simulates the matches_stateless_opcode() lambda from solo.cpp:
 *   auto matches_stateless_opcode = [&packet](uint16_t legacy_opcode) {
 *       return packet.m_is_uint16_opcode &&
 *           packet.m_header == MinerLLP::MirrorOpcode(static_cast<uint8_t>(legacy_opcode));
 *   };
 */
bool simulated_matches_stateless_opcode(uint16_t packet_header, bool is_uint16_opcode, uint16_t legacy_opcode) {
    return is_uint16_opcode &&
        packet_header == MinerLLP::MirrorOpcode(static_cast<uint8_t>(legacy_opcode));
}

std::vector<uint8_t> create_mock_template(uint32_t height, uint32_t nBits = 0x1d00ffff,
                                          uint8_t channel = 2) {
    std::vector<uint8_t> data(216, 0);

    size_t offset = 0;
    auto write_u32_be = [&](uint32_t value) {
        data[offset++] = (value >> 24) & 0xFF;
        data[offset++] = (value >> 16) & 0xFF;
        data[offset++] = (value >> 8) & 0xFF;
        data[offset++] = value & 0xFF;
    };

    auto write_u64_be = [&](uint64_t value) {
        data[offset++] = (value >> 56) & 0xFF;
        data[offset++] = (value >> 48) & 0xFF;
        data[offset++] = (value >> 40) & 0xFF;
        data[offset++] = (value >> 32) & 0xFF;
        data[offset++] = (value >> 24) & 0xFF;
        data[offset++] = (value >> 16) & 0xFF;
        data[offset++] = (value >> 8) & 0xFF;
        data[offset++] = value & 0xFF;
    };

    write_u32_be(7);
    offset += 128;
    for (int i = 0; i < 64; ++i) {
        data[offset++] = static_cast<uint8_t>(i + 1);
    }
    write_u32_be(static_cast<uint32_t>(channel));
    write_u32_be(height);
    write_u32_be(nBits);
    write_u64_be(0);

    return data;
}

network::Payload create_extended_push_payload(uint32_t unified_height,
                                              uint32_t channel_height,
                                              uint32_t difficulty,
                                              uint8_t prev_hash_fill)
{
    network::Payload payload(140, 0);
    auto write_u32_be = [&](size_t offset, uint32_t value) {
        payload[offset + 0] = static_cast<uint8_t>((value >> 24) & 0xFF);
        payload[offset + 1] = static_cast<uint8_t>((value >> 16) & 0xFF);
        payload[offset + 2] = static_cast<uint8_t>((value >> 8) & 0xFF);
        payload[offset + 3] = static_cast<uint8_t>(value & 0xFF);
    };

    write_u32_be(0, unified_height);
    write_u32_be(4, channel_height);
    write_u32_be(8, difficulty);
    for (size_t i = 12; i < payload.size(); ++i) {
        payload[i] = prev_hash_fill;
    }
    return payload;
}

network::Payload create_template_delivery_payload(uint32_t unified_height,
                                                  uint32_t channel_height,
                                                  uint32_t difficulty,
                                                  uint32_t block_height,
                                                  uint8_t channel = 2)
{
    network::Payload payload(12, 0);
    auto write_u32_be = [&](size_t offset, uint32_t value) {
        payload[offset + 0] = static_cast<uint8_t>((value >> 24) & 0xFF);
        payload[offset + 1] = static_cast<uint8_t>((value >> 16) & 0xFF);
        payload[offset + 2] = static_cast<uint8_t>((value >> 8) & 0xFF);
        payload[offset + 3] = static_cast<uint8_t>(value & 0xFF);
    };

    write_u32_be(0, unified_height);
    write_u32_be(4, channel_height);
    write_u32_be(8, difficulty);

    auto block = create_mock_template(block_height, difficulty, channel);
    payload.insert(payload.end(), block.begin(), block.end());
    return payload;
}
