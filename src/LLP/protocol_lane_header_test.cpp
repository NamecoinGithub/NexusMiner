/**
 * @file protocol_lane_header_test.cpp
 * @brief Unit tests for Protocol Lane Determination from PORT and Header Size
 *
 * Validates the relationship between:
 *   - Connection port → Protocol lane (LEGACY vs STATELESS)
 *   - Protocol lane → Header byte size (1-byte vs 2-byte)
 *   - Packet wire format (1-byte legacy header vs 2-byte stateless header)
 *   - Header-only vs data-bearing classification per lane
 *
 * Port-Lane-Header mapping:
 *   Port 8323  → LEGACY    → 1-byte header (uint8_t,  0x00-0xFF)
 *   Port 9323+ → STATELESS → 2-byte header (uint16_t, 0xD000-0xD0FF)
 */

#include "miner_opcodes.hpp"
#include "protocol_lane.hpp"
#include "packet.hpp"
#include <gtest/gtest.h>
#include <iostream>
#include <cstdint>

using namespace nexusminer;

// Fully qualified aliases to avoid ambiguity with global ::LLP namespace from block.hpp
namespace MinerLLP = nexusminer::LLP;

TEST(ProtocolLaneHeaderTest, PortToLaneDetermination) {
    // Legacy port
    EXPECT_TRUE(determine_lane_from_port(ProtocolPorts::LEGACY_PORT) == ProtocolLane::LEGACY)
        << "Port 8323 → LEGACY";

    // Stateless ports
    EXPECT_TRUE(determine_lane_from_port(ProtocolPorts::STATELESS_PORT) == ProtocolLane::STATELESS)
        << "Port 9323 → STATELESS";
    EXPECT_TRUE(determine_lane_from_port(9324) == ProtocolLane::STATELESS)
        << "Port 9324 → STATELESS";
    EXPECT_TRUE(determine_lane_from_port(10000) == ProtocolLane::STATELESS)
        << "Port 10000 → STATELESS";

    // Edge cases
    EXPECT_TRUE(determine_lane_from_port(0) == ProtocolLane::STATELESS)
        << "Port 0 → STATELESS (not legacy)";
    EXPECT_TRUE(determine_lane_from_port(8322) == ProtocolLane::STATELESS)
        << "Port 8322 → STATELESS (off-by-one low)";
    EXPECT_TRUE(determine_lane_from_port(8324) == ProtocolLane::STATELESS)
        << "Port 8324 → STATELESS (off-by-one high)";
}

TEST(ProtocolLaneHeaderTest, LaneToHeaderByteSizeViaPacketConstruction) {
    // Legacy lane: 1-byte header packets
    Packet legacy_pkt(static_cast<uint8_t>(MinerLLP::GET_BLOCK));
    EXPECT_TRUE(!legacy_pkt.m_is_uint16_opcode)
        << "Legacy Packet(uint8_t GET_BLOCK) → 1-byte header";
    EXPECT_TRUE(legacy_pkt.m_header == MinerLLP::GET_BLOCK)
        << "Legacy Packet header value == 129";

    // Stateless lane: 2-byte header packets
    Packet stateless_pkt(static_cast<uint16_t>(MinerLLP::StatelessMining::GET_BLOCK));
    EXPECT_TRUE(stateless_pkt.m_is_uint16_opcode)
        << "Stateless Packet(uint16_t 0xD081) → 2-byte header";
    EXPECT_TRUE(stateless_pkt.m_header == 0xD081)
        << "Stateless Packet header value == 0xD081";
}

TEST(ProtocolLaneHeaderTest, WireFormatHeaderBytes) {
    // Legacy: header-only GET_BLOCK (opcode 129) → 1 byte on wire
    Packet legacy_get_block(static_cast<uint8_t>(MinerLLP::GET_BLOCK));
    auto legacy_bytes = legacy_get_block.get_bytes();
    EXPECT_TRUE(legacy_bytes && legacy_bytes->size() == 1)
        << "Legacy GET_BLOCK wire: 1 byte total";
    EXPECT_TRUE(legacy_bytes && (*legacy_bytes)[0] == 0x81)
        << "Legacy GET_BLOCK wire: byte[0] == 0x81 (129)";

    // Stateless: header-only MINER_READY (0xD0D8) → 2 bytes on wire
    Packet stateless_ready(static_cast<uint16_t>(MinerLLP::StatelessMining::MINER_READY));
    auto stateless_bytes = stateless_ready.get_bytes();
    EXPECT_TRUE(stateless_bytes && stateless_bytes->size() == 2)
        << "Stateless MINER_READY wire: 2 bytes total";
    EXPECT_TRUE(stateless_bytes && (*stateless_bytes)[0] == 0xD0)
        << "Stateless MINER_READY wire: byte[0] == 0xD0";
    EXPECT_TRUE(stateless_bytes && (*stateless_bytes)[1] == 0xD8)
        << "Stateless MINER_READY wire: byte[1] == 0xD8";
}

TEST(ProtocolLaneHeaderTest, PortToLaneToHeaderToWireFormatChain) {
    // Scenario A: Legacy miner on port 8323
    {
        uint16_t port = ProtocolPorts::LEGACY_PORT;
        ProtocolLane lane = determine_lane_from_port(port);
        bool use_stateless = (lane == ProtocolLane::STATELESS);

        // Build GET_ROUND packet based on lane
        Packet pkt = use_stateless
            ? Packet(static_cast<uint16_t>(MinerLLP::MirrorOpcode(static_cast<uint8_t>(MinerLLP::GET_ROUND))))
            : Packet(static_cast<uint8_t>(MinerLLP::GET_ROUND));

        auto wire = pkt.get_bytes();
        EXPECT_TRUE(lane == ProtocolLane::LEGACY && !pkt.m_is_uint16_opcode)
            << "Port 8323: lane=LEGACY, 1-byte header";
        EXPECT_TRUE(wire && wire->size() == 1)
            << "Port 8323: GET_ROUND wire is 1 byte";
        EXPECT_TRUE(wire && (*wire)[0] == 133)
            << "Port 8323: GET_ROUND wire[0] == 0x85 (133)";
    }

    // Scenario B: Stateless miner on port 9323
    {
        uint16_t port = ProtocolPorts::STATELESS_PORT;
        ProtocolLane lane = determine_lane_from_port(port);
        bool use_stateless = (lane == ProtocolLane::STATELESS);

        // Build GET_ROUND packet based on lane
        Packet pkt = use_stateless
            ? Packet(static_cast<uint16_t>(MinerLLP::MirrorOpcode(static_cast<uint8_t>(MinerLLP::GET_ROUND))))
            : Packet(static_cast<uint8_t>(MinerLLP::GET_ROUND));

        auto wire = pkt.get_bytes();
        EXPECT_TRUE(lane == ProtocolLane::STATELESS && pkt.m_is_uint16_opcode)
            << "Port 9323: lane=STATELESS, 2-byte header";
        EXPECT_TRUE(wire && wire->size() == 2)
            << "Port 9323: GET_ROUND wire is 2 bytes";
        EXPECT_TRUE(wire && (*wire)[0] == 0xD0 && (*wire)[1] == 0x85)
            << "Port 9323: GET_ROUND wire[0:1] == 0xD085";
    }
}

TEST(ProtocolLaneHeaderTest, PushNotificationHeaderSizePerLane) {
    // Legacy push: PRIME_BLOCK_AVAILABLE (217 = 0xD9) → 1-byte header
    Packet legacy_prime(static_cast<uint8_t>(MinerLLP::PRIME_BLOCK_AVAILABLE));
    EXPECT_TRUE(!legacy_prime.m_is_uint16_opcode && legacy_prime.m_header == 217)
        << "Legacy PRIME_BLOCK_AVAILABLE: 1-byte header";

    // Stateless push: PRIME_BLOCK_AVAILABLE (0xD0D9) → 2-byte header
    Packet stateless_prime(static_cast<uint16_t>(MinerLLP::StatelessMining::PRIME_BLOCK_AVAILABLE));
    EXPECT_TRUE(stateless_prime.m_is_uint16_opcode && stateless_prime.m_header == 0xD0D9)
        << "Stateless PRIME_BLOCK_AVAILABLE: 2-byte header";

    // Legacy push: HASH_BLOCK_AVAILABLE (218 = 0xDA) → 1-byte header
    Packet legacy_hash(static_cast<uint8_t>(MinerLLP::HASH_BLOCK_AVAILABLE));
    EXPECT_TRUE(!legacy_hash.m_is_uint16_opcode && legacy_hash.m_header == 218)
        << "Legacy HASH_BLOCK_AVAILABLE: 1-byte header";

    // Stateless push: HASH_BLOCK_AVAILABLE (0xD0DA) → 2-byte header
    Packet stateless_hash(static_cast<uint16_t>(MinerLLP::StatelessMining::HASH_BLOCK_AVAILABLE));
    EXPECT_TRUE(stateless_hash.m_is_uint16_opcode && stateless_hash.m_header == 0xD0DA)
        << "Stateless HASH_BLOCK_AVAILABLE: 2-byte header";
}

TEST(ProtocolLaneHeaderTest, HeaderOnlyVsDataBearingPerLane) {
    // Legacy header-only opcodes
    EXPECT_TRUE(PacketConstants::is_legacy_header_only_opcode(MinerLLP::GET_BLOCK))
        << "Legacy GET_BLOCK (129): header-only";
    EXPECT_TRUE(PacketConstants::is_legacy_header_only_opcode(MinerLLP::GET_ROUND))
        << "Legacy GET_ROUND (133): header-only";
    EXPECT_TRUE(PacketConstants::is_legacy_header_only_opcode(MinerLLP::ACCEPT))
        << "Legacy ACCEPT (200): header-only";
    EXPECT_TRUE(PacketConstants::is_legacy_header_only_opcode(MinerLLP::MINER_READY))
        << "Legacy MINER_READY (216): header-only";
    EXPECT_TRUE(PacketConstants::is_legacy_header_only_opcode(MinerLLP::PING))
        << "Legacy PING (253): header-only";

    // Legacy data-bearing opcodes
    EXPECT_TRUE(!PacketConstants::is_legacy_header_only_opcode(MinerLLP::SUBMIT_BLOCK))
        << "Legacy SUBMIT_BLOCK (1): has payload";
    EXPECT_TRUE(!PacketConstants::is_legacy_header_only_opcode(MinerLLP::NEW_ROUND))
        << "Legacy NEW_ROUND (204): has payload";
    EXPECT_TRUE(!PacketConstants::is_legacy_header_only_opcode(MinerLLP::PRIME_BLOCK_AVAILABLE))
        << "Legacy PRIME_BLOCK_AVAILABLE (217): has payload";

    // Stateless header-only opcodes (mirror-mapped, same classification)
    EXPECT_TRUE(PacketConstants::is_stateless_header_only_opcode(MinerLLP::StatelessMining::MINER_READY))
        << "Stateless MINER_READY (0xD0D8): header-only";

    // Stateless data-bearing opcodes
    EXPECT_TRUE(!PacketConstants::is_stateless_header_only_opcode(MinerLLP::StatelessMining::GET_BLOCK))
        << "Stateless GET_BLOCK (0xD081): has payload (228-byte template push)";
    EXPECT_TRUE(!PacketConstants::is_stateless_header_only_opcode(MinerLLP::StatelessMining::SUBMIT_BLOCK))
        << "Stateless SUBMIT_BLOCK (0xD001): has payload";
    EXPECT_TRUE(!PacketConstants::is_stateless_header_only_opcode(MinerLLP::StatelessMining::PRIME_BLOCK_AVAILABLE))
        << "Stateless PRIME_BLOCK_AVAILABLE (0xD0D9): has payload";
}

TEST(ProtocolLaneHeaderTest, DataPacketWireFormatPerLane) {
    // Create a 12-byte payload (push notification size)
    network::Payload payload_data(12, 0xAB);

    // Legacy data packet: [header(1)][length(4)][data(12)] = 17 bytes
    // Note: Legacy data packets with header < 128 include length field
    Packet legacy_data(static_cast<uint8_t>(MinerLLP::SUBMIT_BLOCK), payload_data);
    auto legacy_wire = legacy_data.get_bytes();
    EXPECT_TRUE(legacy_wire && legacy_wire->size() == 17)
        << "Legacy SUBMIT_BLOCK+12b: wire = 17 bytes (1+4+12)";
    EXPECT_TRUE(legacy_wire && (*legacy_wire)[0] == 0x01)
        << "Legacy SUBMIT_BLOCK+12b: wire[0] = 0x01 (1-byte header)";

    // Stateless data packet: [header(2)][length(4)][data(12)] = 18 bytes
    Packet stateless_data(static_cast<uint16_t>(MinerLLP::StatelessMining::SUBMIT_BLOCK), payload_data);
    auto stateless_wire = stateless_data.get_bytes();
    EXPECT_TRUE(stateless_wire && stateless_wire->size() == 18)
        << "Stateless SUBMIT_BLOCK+12b: wire = 18 bytes (2+4+12)";
    EXPECT_TRUE(stateless_wire && (*stateless_wire)[0] == 0xD0 && (*stateless_wire)[1] == 0x01)
        << "Stateless SUBMIT_BLOCK+12b: wire[0:1] = 0xD001 (2-byte header)";
}

TEST(ProtocolLaneHeaderTest, LaneNameStrings) {
    EXPECT_TRUE(std::string(get_lane_name(ProtocolLane::LEGACY)) == "Legacy")
        << "LEGACY → \"Legacy\"";
    EXPECT_TRUE(std::string(get_lane_name(ProtocolLane::STATELESS)) == "Stateless")
        << "STATELESS → \"Stateless\"";
    EXPECT_TRUE(std::string(get_lane_name(ProtocolLane::UNKNOWN)) == "Unknown")
        << "UNKNOWN → \"Unknown\"";
}

TEST(ProtocolLaneHeaderTest, MirrorMappingRoundTrip) {
    uint8_t key_opcodes[] = {
        MinerLLP::SUBMIT_BLOCK, MinerLLP::SET_CHANNEL, MinerLLP::GET_BLOCK,
        MinerLLP::GET_ROUND, MinerLLP::MINER_READY,
        MinerLLP::PRIME_BLOCK_AVAILABLE, MinerLLP::HASH_BLOCK_AVAILABLE
    };
    const char* names[] = {
        "SUBMIT_BLOCK", "SET_CHANNEL", "GET_BLOCK",
        "GET_ROUND", "MINER_READY",
        "PRIME_BLOCK_AVAILABLE", "HASH_BLOCK_AVAILABLE"
    };

    bool all_roundtrip = true;
    for (size_t i = 0; i < sizeof(key_opcodes); ++i) {
        uint16_t mirrored = MinerLLP::MirrorOpcode(key_opcodes[i]);
        uint8_t unmirrored = MinerLLP::UnmirrorOpcode(mirrored);
        if (unmirrored != key_opcodes[i]) {
            std::cout << "  [FAIL] Round-trip failed for " << names[i] << std::endl;
            all_roundtrip = false;
        }
        if (!MinerLLP::IsStatelessOpcode(mirrored)) {
            std::cout << "  [FAIL] MirrorOpcode(" << names[i] << ") not in stateless range" << std::endl;
            all_roundtrip = false;
        }
    }
    EXPECT_TRUE(all_roundtrip)
        << "All key opcodes survive mirror/unmirror round-trip";
}
