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
#include <iostream>
#include <cassert>
#include <cstdint>

using namespace nexusminer;

// Fully qualified aliases to avoid ambiguity with global ::LLP namespace from block.hpp
namespace MinerLLP = nexusminer::LLP;

// Test statistics
static int tests_run = 0;
static int tests_passed = 0;
static int tests_failed = 0;

void print_test_result(const char* name, bool passed) {
    tests_run++;
    if (passed) {
        tests_passed++;
        std::cout << "  [PASS] " << name << std::endl;
    } else {
        tests_failed++;
        std::cout << "  [FAIL] " << name << std::endl;
    }
}

int main()
{
    std::cout << "========================================" << std::endl;
    std::cout << "Protocol Lane & Header Size Tests" << std::endl;
    std::cout << "========================================" << std::endl;

    // ====================================================================
    // Test 1: Port → Lane determination
    // ====================================================================
    std::cout << "\nTest 1: Port → Lane determination" << std::endl;
    {
        // Legacy port
        print_test_result("Port 8323 → LEGACY",
            determine_lane_from_port(ProtocolPorts::LEGACY_PORT) == ProtocolLane::LEGACY);

        // Stateless ports
        print_test_result("Port 9323 → STATELESS",
            determine_lane_from_port(ProtocolPorts::STATELESS_PORT) == ProtocolLane::STATELESS);
        print_test_result("Port 9324 → STATELESS",
            determine_lane_from_port(9324) == ProtocolLane::STATELESS);
        print_test_result("Port 10000 → STATELESS",
            determine_lane_from_port(10000) == ProtocolLane::STATELESS);
        
        // Edge cases
        print_test_result("Port 0 → STATELESS (not legacy)",
            determine_lane_from_port(0) == ProtocolLane::STATELESS);
        print_test_result("Port 8322 → STATELESS (off-by-one low)",
            determine_lane_from_port(8322) == ProtocolLane::STATELESS);
        print_test_result("Port 8324 → STATELESS (off-by-one high)",
            determine_lane_from_port(8324) == ProtocolLane::STATELESS);
    }

    // ====================================================================
    // Test 2: Lane → Header byte size (1-byte legacy vs 2-byte stateless)
    // ====================================================================
    std::cout << "\nTest 2: Lane → Header byte size via Packet construction" << std::endl;
    {
        // Legacy lane: 1-byte header packets
        Packet legacy_pkt(static_cast<uint8_t>(MinerLLP::GET_BLOCK));
        print_test_result("Legacy Packet(uint8_t GET_BLOCK) → 1-byte header",
            !legacy_pkt.m_is_uint16_opcode);
        print_test_result("Legacy Packet header value == 129",
            legacy_pkt.m_header == MinerLLP::GET_BLOCK);

        // Stateless lane: 2-byte header packets
        Packet stateless_pkt(static_cast<uint16_t>(MinerLLP::StatelessMining::GET_BLOCK));
        print_test_result("Stateless Packet(uint16_t 0xD081) → 2-byte header",
            stateless_pkt.m_is_uint16_opcode);
        print_test_result("Stateless Packet header value == 0xD081",
            stateless_pkt.m_header == 0xD081);
    }

    // ====================================================================
    // Test 3: Wire format verification (1-byte vs 2-byte on the wire)
    // ====================================================================
    std::cout << "\nTest 3: Wire format header bytes" << std::endl;
    {
        // Legacy: header-only GET_BLOCK (opcode 129) → 1 byte on wire
        Packet legacy_get_block(static_cast<uint8_t>(MinerLLP::GET_BLOCK));
        auto legacy_bytes = legacy_get_block.get_bytes();
        print_test_result("Legacy GET_BLOCK wire: 1 byte total",
            legacy_bytes && legacy_bytes->size() == 1);
        print_test_result("Legacy GET_BLOCK wire: byte[0] == 0x81 (129)",
            legacy_bytes && (*legacy_bytes)[0] == 0x81);

        // Stateless: header-only MINER_READY (0xD0D8) → 2 bytes on wire
        Packet stateless_ready(static_cast<uint16_t>(MinerLLP::StatelessMining::MINER_READY));
        auto stateless_bytes = stateless_ready.get_bytes();
        print_test_result("Stateless MINER_READY wire: 2 bytes total",
            stateless_bytes && stateless_bytes->size() == 2);
        print_test_result("Stateless MINER_READY wire: byte[0] == 0xD0",
            stateless_bytes && (*stateless_bytes)[0] == 0xD0);
        print_test_result("Stateless MINER_READY wire: byte[1] == 0xD8",
            stateless_bytes && (*stateless_bytes)[1] == 0xD8);
    }

    // ====================================================================
    // Test 4: Full port → lane → header size → wire format chain
    // ====================================================================
    std::cout << "\nTest 4: Port → Lane → Header → Wire format chain" << std::endl;
    {
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
            print_test_result("Port 8323: lane=LEGACY, 1-byte header",
                lane == ProtocolLane::LEGACY && !pkt.m_is_uint16_opcode);
            print_test_result("Port 8323: GET_ROUND wire is 1 byte",
                wire && wire->size() == 1);
            print_test_result("Port 8323: GET_ROUND wire[0] == 0x85 (133)",
                wire && (*wire)[0] == 133);
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
            print_test_result("Port 9323: lane=STATELESS, 2-byte header",
                lane == ProtocolLane::STATELESS && pkt.m_is_uint16_opcode);
            print_test_result("Port 9323: GET_ROUND wire is 2 bytes",
                wire && wire->size() == 2);
            print_test_result("Port 9323: GET_ROUND wire[0:1] == 0xD085",
                wire && (*wire)[0] == 0xD0 && (*wire)[1] == 0x85);
        }
    }

    // ====================================================================
    // Test 5: Push notification opcodes: port determines header size
    // ====================================================================
    std::cout << "\nTest 5: Push notification header size per lane" << std::endl;
    {
        // Legacy push: PRIME_BLOCK_AVAILABLE (217 = 0xD9) → 1-byte header
        Packet legacy_prime(static_cast<uint8_t>(MinerLLP::PRIME_BLOCK_AVAILABLE));
        print_test_result("Legacy PRIME_BLOCK_AVAILABLE: 1-byte header",
            !legacy_prime.m_is_uint16_opcode && legacy_prime.m_header == 217);
        
        // Stateless push: PRIME_BLOCK_AVAILABLE (0xD0D9) → 2-byte header
        Packet stateless_prime(static_cast<uint16_t>(MinerLLP::StatelessMining::PRIME_BLOCK_AVAILABLE));
        print_test_result("Stateless PRIME_BLOCK_AVAILABLE: 2-byte header",
            stateless_prime.m_is_uint16_opcode && stateless_prime.m_header == 0xD0D9);
        
        // Legacy push: HASH_BLOCK_AVAILABLE (218 = 0xDA) → 1-byte header
        Packet legacy_hash(static_cast<uint8_t>(MinerLLP::HASH_BLOCK_AVAILABLE));
        print_test_result("Legacy HASH_BLOCK_AVAILABLE: 1-byte header",
            !legacy_hash.m_is_uint16_opcode && legacy_hash.m_header == 218);
        
        // Stateless push: HASH_BLOCK_AVAILABLE (0xD0DA) → 2-byte header
        Packet stateless_hash(static_cast<uint16_t>(MinerLLP::StatelessMining::HASH_BLOCK_AVAILABLE));
        print_test_result("Stateless HASH_BLOCK_AVAILABLE: 2-byte header",
            stateless_hash.m_is_uint16_opcode && stateless_hash.m_header == 0xD0DA);
    }

    // ====================================================================
    // Test 6: Header-only classification per lane
    // ====================================================================
    std::cout << "\nTest 6: Header-only vs data-bearing per lane" << std::endl;
    {
        // Legacy header-only opcodes
        print_test_result("Legacy GET_BLOCK (129): header-only",
            PacketConstants::is_legacy_header_only_opcode(MinerLLP::GET_BLOCK));
        print_test_result("Legacy GET_ROUND (133): header-only",
            PacketConstants::is_legacy_header_only_opcode(MinerLLP::GET_ROUND));
        print_test_result("Legacy ACCEPT (200): header-only",
            PacketConstants::is_legacy_header_only_opcode(MinerLLP::ACCEPT));
        print_test_result("Legacy MINER_READY (216): header-only",
            PacketConstants::is_legacy_header_only_opcode(MinerLLP::MINER_READY));
        print_test_result("Legacy PING (253): header-only",
            PacketConstants::is_legacy_header_only_opcode(MinerLLP::PING));
        
        // Legacy data-bearing opcodes
        print_test_result("Legacy SUBMIT_BLOCK (1): has payload",
            !PacketConstants::is_legacy_header_only_opcode(MinerLLP::SUBMIT_BLOCK));
        print_test_result("Legacy NEW_ROUND (204): has payload",
            !PacketConstants::is_legacy_header_only_opcode(MinerLLP::NEW_ROUND));
        print_test_result("Legacy PRIME_BLOCK_AVAILABLE (217): has payload",
            !PacketConstants::is_legacy_header_only_opcode(MinerLLP::PRIME_BLOCK_AVAILABLE));
        
        // Stateless header-only opcodes (mirror-mapped, same classification)
        print_test_result("Stateless MINER_READY (0xD0D8): header-only",
            PacketConstants::is_stateless_header_only_opcode(MinerLLP::StatelessMining::MINER_READY));
        
        // Stateless data-bearing opcodes
        print_test_result("Stateless GET_BLOCK (0xD081): has payload (228-byte template push)",
            !PacketConstants::is_stateless_header_only_opcode(MinerLLP::StatelessMining::GET_BLOCK));
        print_test_result("Stateless SUBMIT_BLOCK (0xD001): has payload",
            !PacketConstants::is_stateless_header_only_opcode(MinerLLP::StatelessMining::SUBMIT_BLOCK));
        print_test_result("Stateless PRIME_BLOCK_AVAILABLE (0xD0D9): has payload",
            !PacketConstants::is_stateless_header_only_opcode(MinerLLP::StatelessMining::PRIME_BLOCK_AVAILABLE));
    }

    // ====================================================================
    // Test 7: Data packet wire format: legacy 1+4+N vs stateless 2+4+N
    // ====================================================================
    std::cout << "\nTest 7: Data packet wire format per lane" << std::endl;
    {
        // Create a 12-byte payload (push notification size)
        network::Payload payload_data(12, 0xAB);
        
        // Legacy data packet: [header(1)][length(4)][data(12)] = 17 bytes
        // Note: Legacy data packets with header < 128 include length field
        Packet legacy_data(static_cast<uint8_t>(MinerLLP::SUBMIT_BLOCK), payload_data);
        auto legacy_wire = legacy_data.get_bytes();
        print_test_result("Legacy SUBMIT_BLOCK+12b: wire = 17 bytes (1+4+12)",
            legacy_wire && legacy_wire->size() == 17);
        print_test_result("Legacy SUBMIT_BLOCK+12b: wire[0] = 0x01 (1-byte header)",
            legacy_wire && (*legacy_wire)[0] == 0x01);
        
        // Stateless data packet: [header(2)][length(4)][data(12)] = 18 bytes
        Packet stateless_data(static_cast<uint16_t>(MinerLLP::StatelessMining::SUBMIT_BLOCK), payload_data);
        auto stateless_wire = stateless_data.get_bytes();
        print_test_result("Stateless SUBMIT_BLOCK+12b: wire = 18 bytes (2+4+12)",
            stateless_wire && stateless_wire->size() == 18);
        print_test_result("Stateless SUBMIT_BLOCK+12b: wire[0:1] = 0xD001 (2-byte header)",
            stateless_wire && (*stateless_wire)[0] == 0xD0 && (*stateless_wire)[1] == 0x01);
    }

    // ====================================================================
    // Test 8: Lane name strings
    // ====================================================================
    std::cout << "\nTest 8: Lane name strings" << std::endl;
    {
        print_test_result("LEGACY → \"Legacy\"",
            std::string(get_lane_name(ProtocolLane::LEGACY)) == "Legacy");
        print_test_result("STATELESS → \"Stateless\"",
            std::string(get_lane_name(ProtocolLane::STATELESS)) == "Stateless");
        print_test_result("UNKNOWN → \"Unknown\"",
            std::string(get_lane_name(ProtocolLane::UNKNOWN)) == "Unknown");
    }

    // ====================================================================
    // Test 9: Mirror-mapping round-trip for all key opcodes
    // ====================================================================
    std::cout << "\nTest 9: Mirror-mapping round-trip per port" << std::endl;
    {
        uint8_t key_opcodes[] = {
            MinerLLP::SUBMIT_BLOCK, MinerLLP::SET_CHANNEL, MinerLLP::GET_BLOCK,
            MinerLLP::GET_ROUND, MinerLLP::MINER_READY,
            MinerLLP::PRIME_BLOCK_AVAILABLE, MinerLLP::HASH_BLOCK_AVAILABLE,
            MinerLLP::MINER_AUTH_INIT, MinerLLP::MINER_AUTH_CHALLENGE,
            MinerLLP::MINER_AUTH_RESPONSE, MinerLLP::MINER_AUTH_RESULT,
            MinerLLP::SESSION_KEEPALIVE
        };
        const char* names[] = {
            "SUBMIT_BLOCK", "SET_CHANNEL", "GET_BLOCK",
            "GET_ROUND", "MINER_READY",
            "PRIME_BLOCK_AVAILABLE", "HASH_BLOCK_AVAILABLE",
            "MINER_AUTH_INIT", "MINER_AUTH_CHALLENGE",
            "MINER_AUTH_RESPONSE", "MINER_AUTH_RESULT",
            "SESSION_KEEPALIVE"
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
        print_test_result("All key opcodes survive mirror/unmirror round-trip", all_roundtrip);
    }

    // ====================================================================
    // Test 10: Auth/session mirror-mapped headers use 2-byte stateless format
    // ====================================================================
    std::cout << "\nTest 10: Auth/session mirror-mapped stateless headers" << std::endl;
    {
        Packet auth_init(static_cast<uint16_t>(MinerLLP::StatelessMining::MINER_AUTH_INIT));
        auto auth_init_wire = auth_init.get_bytes();
        print_test_result("STATELESS MINER_AUTH_INIT wire == [0xD0][0xCF]",
            auth_init_wire && auth_init_wire->size() == 2 &&
            (*auth_init_wire)[0] == 0xD0 && (*auth_init_wire)[1] == 0xCF);

        Packet auth_result(static_cast<uint16_t>(MinerLLP::StatelessMining::MINER_AUTH_RESULT));
        auto auth_result_wire = auth_result.get_bytes();
        print_test_result("STATELESS MINER_AUTH_RESULT wire == [0xD0][0xD2]",
            auth_result_wire && auth_result_wire->size() == 2 &&
            (*auth_result_wire)[0] == 0xD0 && (*auth_result_wire)[1] == 0xD2);

        Packet session_keepalive(static_cast<uint16_t>(MinerLLP::StatelessMining::SESSION_KEEPALIVE));
        auto keepalive_wire = session_keepalive.get_bytes();
        print_test_result("STATELESS SESSION_KEEPALIVE wire == [0xD0][0xD4]",
            keepalive_wire && keepalive_wire->size() == 2 &&
            (*keepalive_wire)[0] == 0xD0 && (*keepalive_wire)[1] == 0xD4);
    }

    // ====================================================================
    // Summary
    // ====================================================================
    std::cout << "\n========================================" << std::endl;
    std::cout << "Test Summary" << std::endl;
    std::cout << "========================================" << std::endl;
    std::cout << "Tests run:    " << tests_run << std::endl;
    std::cout << "Tests passed: " << tests_passed << std::endl;
    std::cout << "Tests failed: " << tests_failed << std::endl;
    std::cout << "Success rate: " << (tests_run > 0 ? (100 * tests_passed / tests_run) : 0) << "%" << std::endl;
    std::cout << "========================================" << std::endl;

    return tests_failed > 0 ? 1 : 0;
}
