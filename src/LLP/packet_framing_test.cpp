/**
 * @file packet_framing_test.cpp
 * @brief Unit test harness for LLP packet framing parser with TCP fragmentation
 * 
 * Tests the accumulator-based packet parser with various TCP fragmentation scenarios:
 * - Partial headers split across multiple receives
 * - Partial length fields split across receives
 * - Partial payload data split across receives
 * - Multiple packets arriving in single receive
 * - Malformed packet detection
 * 
 * Run this test to verify TCP stream handling robustness.
 */

#include "packet.hpp"
#include "protocol_lane.hpp"
#include <iostream>
#include <iomanip>
#include <vector>
#include <deque>
#include <sstream>
#include <gtest/gtest.h>

using namespace nexusminer;

void print_hex(const std::vector<uint8_t>& data, size_t max_bytes = 32) {
    std::ostringstream ss;
    ss << std::hex << std::setfill('0');
    for (size_t i = 0; i < std::min(data.size(), max_bytes); ++i) {
        if (i > 0) ss << " ";
        ss << std::setw(2) << static_cast<unsigned>(data[i]);
    }
    if (data.size() > max_bytes) {
        ss << "...";
    }
    std::cout << "    Data: " << ss.str() << " (" << data.size() << " bytes)" << std::endl;
}

/**
 * Simulates TCP receive accumulator behavior
 */
class TestAccumulator {
public:
    std::deque<uint8_t> buffer;
    
    void feed(const std::vector<uint8_t>& data) {
        buffer.insert(buffer.end(), data.begin(), data.end());
    }
    
    bool parse_one_packet(ProtocolLane lane, Packet& out_packet, ParseResult& out_result) {
        if (buffer.empty()) {
            return false;
        }
        
        // Create view for parsing
        std::vector<uint8_t> view(buffer.begin(), buffer.end());
        auto view_shared = std::make_shared<network::Payload>(std::move(view));
        
        std::size_t bytes_consumed = 0;
        out_packet = extract_packet_from_buffer_with_result(
            view_shared, bytes_consumed, 0, lane, out_result);
        
        if (out_result == ParseResult::SUCCESS) {
            // Remove consumed bytes
            buffer.erase(buffer.begin(), buffer.begin() + bytes_consumed);
            return true;
        } else if (out_result == ParseResult::MALFORMED) {
            buffer.clear(); // Simulate disconnect
            return false;
        }
        
        // NEED_MORE_DATA - keep buffer intact
        return false;
    }
    
    size_t size() const { return buffer.size(); }
    bool empty() const { return buffer.empty(); }
    void clear() { buffer.clear(); }
};

// ============================================================================
// Test Case 1: Complete packet in single receive
// ============================================================================
TEST(PacketFramingTest, test_complete_packet_single_receive) {
    std::cout << "\nTest 1: Complete packet in single receive" << std::endl;
    
    TestAccumulator acc;
    
    // Legacy packet: header=0x01, length=5, data="hello"
    std::vector<uint8_t> complete_packet = {
        0x01,                           // header
        0x00, 0x00, 0x00, 0x05,        // length = 5
        'h', 'e', 'l', 'l', 'o'        // data
    };
    
    acc.feed(complete_packet);
    
    Packet packet;
    ParseResult result;
    bool parsed = acc.parse_one_packet(ProtocolLane::LEGACY, packet, result);
    
    bool test_passed = parsed && 
                       (result == ParseResult::SUCCESS) &&
                       (packet.m_header == 0x01) &&
                       (packet.m_length == 5) &&
                       acc.empty();
    
    EXPECT_TRUE(test_passed) << "Complete packet parsed successfully";
}

// ============================================================================
// Test Case 2: Header + length split across receives
// ============================================================================
TEST(PacketFramingTest, test_header_fragmented) {
    std::cout << "\nTest 2: Header + length split across multiple receives" << std::endl;
    
    TestAccumulator acc;
    
    // First receive: header + first 2 bytes of length field (incomplete)
    acc.feed({0x02, 0x00, 0x00});
    
    Packet packet;
    ParseResult result;
    
    bool parsed1 = acc.parse_one_packet(ProtocolLane::LEGACY, packet, result);
    bool test1 = !parsed1 && (result == ParseResult::NEED_MORE_DATA) && (acc.size() == 3);
    EXPECT_TRUE(test1) << "Incomplete length field triggers NEED_MORE_DATA";
    
    // Second receive: rest of length + data
    acc.feed({0x00, 0x03, 'a', 'b', 'c'});
    
    bool parsed2 = acc.parse_one_packet(ProtocolLane::LEGACY, packet, result);
    bool test2 = parsed2 && 
                 (result == ParseResult::SUCCESS) &&
                 (packet.m_header == 0x02) &&
                 (packet.m_length == 3) &&
                 acc.empty();
    EXPECT_TRUE(test2) << "Complete packet after split length field";
}

// ============================================================================
// Test Case 3: Payload split across receives
// ============================================================================
TEST(PacketFramingTest, test_payload_fragmented) {
    std::cout << "\nTest 3: Payload split across multiple receives" << std::endl;
    
    TestAccumulator acc;
    
    // First receive: header + length
    acc.feed({0x03, 0x00, 0x00, 0x00, 0x0A}); // length = 10 bytes
    
    Packet packet;
    ParseResult result;
    
    bool parsed1 = acc.parse_one_packet(ProtocolLane::LEGACY, packet, result);
    bool test1 = !parsed1 && (result == ParseResult::NEED_MORE_DATA);
    EXPECT_TRUE(test1) << "Header+length without payload triggers NEED_MORE_DATA";
    
    // Second receive: first 5 bytes of payload
    acc.feed({'a', 'b', 'c', 'd', 'e'});
    
    bool parsed2 = acc.parse_one_packet(ProtocolLane::LEGACY, packet, result);
    bool test2 = !parsed2 && (result == ParseResult::NEED_MORE_DATA);
    EXPECT_TRUE(test2) << "Partial payload triggers NEED_MORE_DATA";
    
    // Third receive: remaining 5 bytes
    acc.feed({'f', 'g', 'h', 'i', 'j'});
    
    bool parsed3 = acc.parse_one_packet(ProtocolLane::LEGACY, packet, result);
    bool test3 = parsed3 && 
                 (result == ParseResult::SUCCESS) &&
                 (packet.m_length == 10) &&
                 acc.empty();
    EXPECT_TRUE(test3) << "Complete payload after fragmentation";
}

// ============================================================================
// Test Case 4: Multiple packets in single receive
// ============================================================================
TEST(PacketFramingTest, test_multiple_packets_single_receive) {
    std::cout << "\nTest 4: Multiple packets in single receive" << std::endl;
    
    TestAccumulator acc;
    
    // Two complete packets back-to-back
    std::vector<uint8_t> two_packets = {
        // Packet 1: header=0x04, length=3, data="xyz"
        0x04, 0x00, 0x00, 0x00, 0x03, 'x', 'y', 'z',
        // Packet 2: header=0x05, length=2, data="ab"
        0x05, 0x00, 0x00, 0x00, 0x02, 'a', 'b'
    };
    
    acc.feed(two_packets);
    
    // Parse first packet
    Packet packet1;
    ParseResult result1;
    bool parsed1 = acc.parse_one_packet(ProtocolLane::LEGACY, packet1, result1);
    bool test1 = parsed1 && (packet1.m_header == 0x04) && (packet1.m_length == 3);
    EXPECT_TRUE(test1) << "First packet parsed from batch";
    
    // Parse second packet
    Packet packet2;
    ParseResult result2;
    bool parsed2 = acc.parse_one_packet(ProtocolLane::LEGACY, packet2, result2);
    bool test2 = parsed2 && (packet2.m_header == 0x05) && (packet2.m_length == 2) && acc.empty();
    EXPECT_TRUE(test2) << "Second packet parsed from batch";
}

// ============================================================================
// Test Case 5: Stateless lane with 16-bit header fragmentation
// ============================================================================
TEST(PacketFramingTest, test_stateless_header_fragmented) {
    std::cout << "\nTest 5: Stateless lane - 16-bit header fragmented" << std::endl;
    
    TestAccumulator acc;
    
    // First receive: only first byte of 16-bit header
    acc.feed({0xD0});
    
    Packet packet;
    ParseResult result;
    
    bool parsed1 = acc.parse_one_packet(ProtocolLane::STATELESS, packet, result);
    bool test1 = !parsed1 && (result == ParseResult::NEED_MORE_DATA) && (acc.size() == 1);
    EXPECT_TRUE(test1) << "Partial 16-bit header triggers NEED_MORE_DATA";
    
    // Second receive: second byte of header + partial length
    acc.feed({0x01, 0x00, 0x00});
    
    bool parsed2 = acc.parse_one_packet(ProtocolLane::STATELESS, packet, result);
    bool test2 = !parsed2 && (result == ParseResult::NEED_MORE_DATA);
    EXPECT_TRUE(test2) << "Incomplete length field in stateless";
    
    // Third receive: complete length + data
    acc.feed({0x00, 0x04, 't', 'e', 's', 't'});
    
    bool parsed3 = acc.parse_one_packet(ProtocolLane::STATELESS, packet, result);
    bool test3 = parsed3 && 
                 (result == ParseResult::SUCCESS) &&
                 (packet.m_header == 0xD001) &&
                 (packet.m_length == 4) &&
                 acc.empty();
    EXPECT_TRUE(test3) << "Stateless packet after multiple receives";
}

// ============================================================================
// Test Case 6: Malformed packet - unreasonably large length
// ============================================================================
TEST(PacketFramingTest, test_malformed_huge_length) {
    std::cout << "\nTest 6: Malformed packet - unreasonably large length" << std::endl;
    
    TestAccumulator acc;
    
    // Packet with 100MB length (exceeds 10MB limit)
    std::vector<uint8_t> malformed = {
        0x10,                           // header
        0x06, 0x40, 0x00, 0x00         // length = 100MB
    };
    
    acc.feed(malformed);
    
    Packet packet;
    ParseResult result;
    bool parsed = acc.parse_one_packet(ProtocolLane::LEGACY, packet, result);
    
    bool test_passed = !parsed && 
                       (result == ParseResult::MALFORMED) &&
                       acc.empty(); // Buffer cleared on malformed
    
    EXPECT_TRUE(test_passed) << "Huge length detected as malformed";
}

// ============================================================================
// Test Case 7: Malformed - invalid stateless opcode
// ============================================================================
TEST(PacketFramingTest, test_malformed_invalid_stateless_opcode) {
    std::cout << "\nTest 7: Malformed - invalid stateless opcode" << std::endl;
    
    TestAccumulator acc;
    
    // Invalid opcode for stateless lane (not in 0xD000-0xD0FF range)
    std::vector<uint8_t> malformed = {
        0x00, 0x01,                    // header = 0x0001 (not stateless)
        0x00, 0x00, 0x00, 0x00         // length = 0
    };
    
    acc.feed(malformed);
    
    Packet packet;
    ParseResult result;
    bool parsed = acc.parse_one_packet(ProtocolLane::STATELESS, packet, result);
    
    bool test_passed = !parsed && 
                       (result == ParseResult::MALFORMED) &&
                       acc.empty();
    
    EXPECT_TRUE(test_passed) << "Invalid stateless opcode detected";
}

// ============================================================================
// Test Case 8: Complex scenario - mixed fragmentation and batching
// ============================================================================
TEST(PacketFramingTest, test_complex_mixed_scenario) {
    std::cout << "\nTest 8: Complex scenario - mixed fragmentation and batching" << std::endl;
    
    TestAccumulator acc;
    
    // Simulate realistic TCP stream:
    // Receive 1: Partial packet 1
    acc.feed({0x20, 0x00, 0x00});
    
    Packet packet;
    ParseResult result;
    bool parsed1 = acc.parse_one_packet(ProtocolLane::LEGACY, packet, result);
    bool test1 = !parsed1 && (result == ParseResult::NEED_MORE_DATA);
    EXPECT_TRUE(test1) << "Partial first packet";
    
    // Receive 2: Rest of packet 1 + complete packet 2 + partial packet 3
    acc.feed({
        0x00, 0x02, 'A', 'B',          // Complete packet 1
        0x21, 0x00, 0x00, 0x00, 0x01, 'X',  // Complete packet 2
        0x22, 0x00                     // Partial packet 3
    });
    
    // Parse packet 1
    bool parsed2 = acc.parse_one_packet(ProtocolLane::LEGACY, packet, result);
    bool test2 = parsed2 && (packet.m_header == 0x20) && (packet.m_length == 2);
    EXPECT_TRUE(test2) << "First packet completed";
    
    // Parse packet 2
    bool parsed3 = acc.parse_one_packet(ProtocolLane::LEGACY, packet, result);
    bool test3 = parsed3 && (packet.m_header == 0x21) && (packet.m_length == 1);
    EXPECT_TRUE(test3) << "Second packet completed";
    
    // Try to parse packet 3 (incomplete)
    bool parsed4 = acc.parse_one_packet(ProtocolLane::LEGACY, packet, result);
    bool test4 = !parsed4 && (result == ParseResult::NEED_MORE_DATA) && (acc.size() == 2);
    EXPECT_TRUE(test4) << "Third packet incomplete";
    
    // Receive 3: Complete packet 3
    acc.feed({0x00, 0x00, 0x03, 'a', 'b', 'c'});
    
    bool parsed5 = acc.parse_one_packet(ProtocolLane::LEGACY, packet, result);
    bool test5 = parsed5 && (packet.m_header == 0x22) && (packet.m_length == 3) && acc.empty();
    EXPECT_TRUE(test5) << "Third packet completed";
}

// ============================================================================
// Test Case 9: Byte-by-byte feeding (extreme fragmentation)
// ============================================================================
TEST(PacketFramingTest, test_byte_by_byte_feeding) {
    std::cout << "\nTest 9: Extreme fragmentation - byte-by-byte feeding" << std::endl;
    
    TestAccumulator acc;
    
    // Build a packet byte by byte
    // Start with at least 2 bytes to avoid header-only packet interpretation
    std::vector<uint8_t> complete_packet = {
        0x30, 0x00, 0x00, 0x00, 0x05, 'h', 'e', 'l', 'l', 'o'
    };
    
    Packet packet;
    ParseResult result;
    
    // Feed first two bytes together (header + start of length)
    acc.feed({complete_packet[0], complete_packet[1]});
    bool parsed0 = acc.parse_one_packet(ProtocolLane::LEGACY, packet, result);
    if (parsed0 || result != ParseResult::NEED_MORE_DATA) {
        EXPECT_TRUE(false) << "Byte-by-byte feeding - initial state";
        return;
    }
    
    // Feed remaining bytes one at a time
    for (size_t i = 2; i < complete_packet.size() - 1; ++i) {
        acc.feed({complete_packet[i]});
        bool parsed = acc.parse_one_packet(ProtocolLane::LEGACY, packet, result);
        
        if (parsed || result != ParseResult::NEED_MORE_DATA) {
            EXPECT_TRUE(false) << "Byte-by-byte feeding - intermediate";
            return;
        }
    }
    
    // Feed last byte
    acc.feed({complete_packet.back()});
    bool parsed = acc.parse_one_packet(ProtocolLane::LEGACY, packet, result);
    
    bool test_passed = parsed && 
                       (result == ParseResult::SUCCESS) &&
                       (packet.m_header == 0x30) &&
                       (packet.m_length == 5) &&
                       acc.empty();
    
    EXPECT_TRUE(test_passed) << "Byte-by-byte feeding completes successfully";
}

// ============================================================================
// Test Case 10: Zero-length payload
// ============================================================================
TEST(PacketFramingTest, test_zero_length_payload) {
    std::cout << "\nTest 10: Zero-length payload packet" << std::endl;
    
    TestAccumulator acc;
    
    // Packet with zero-length payload
    std::vector<uint8_t> zero_packet = {
        0x40, 0x00, 0x00, 0x00, 0x00   // header + length=0
    };
    
    acc.feed(zero_packet);
    
    Packet packet;
    ParseResult result;
    bool parsed = acc.parse_one_packet(ProtocolLane::LEGACY, packet, result);
    
    bool test_passed = parsed && 
                       (result == ParseResult::SUCCESS) &&
                       (packet.m_header == 0x40) &&
                       (packet.m_length == 0) &&
                       acc.empty();
    
    EXPECT_TRUE(test_passed) << "Zero-length payload handled correctly";
}

// ============================================================================
// Test Case 11: Push notification packets (PRIME_BLOCK_AVAILABLE / HASH_BLOCK_AVAILABLE)
// These carry 12-byte payloads on the legacy lane and must be parsed correctly
// ============================================================================
TEST(PacketFramingTest, test_push_notification_legacy_lane) {
    std::cout << "\nTest 11: Push notification packets on legacy lane (12-byte and 148-byte payloads)" << std::endl;
    
    TestAccumulator acc;
    Packet packet;
    ParseResult result;
    
    // PRIME_BLOCK_AVAILABLE (217 = 0xD9) with 12-byte payload
    // Payload: unified_height(4) + prime_height(4) + difficulty(4)
    std::vector<uint8_t> prime_notification = {
        217,                                // header = PRIME_BLOCK_AVAILABLE
        0x00, 0x00, 0x00, 0x0C,            // length = 12
        0x00, 0x01, 0x00, 0x00,            // unified_height = 65536
        0x00, 0x00, 0xFF, 0x00,            // prime_height = 65280
        0x00, 0x00, 0x00, 0x1E             // difficulty = 30
    };
    
    acc.feed(prime_notification);
    bool parsed1 = acc.parse_one_packet(ProtocolLane::LEGACY, packet, result);
    
    bool test1 = parsed1 &&
                 (result == ParseResult::SUCCESS) &&
                 (packet.m_header == 217) &&
                 (packet.m_length == 12) &&
                 (packet.m_data && packet.m_data->size() == 12) &&
                 acc.empty();
    EXPECT_TRUE(test1) << "PRIME_BLOCK_AVAILABLE (217) with 12-byte payload";
    
    // Verify is_auth_packet() returns true for PRIME_BLOCK_AVAILABLE
    Packet prime_pkt(static_cast<uint8_t>(217));
    bool test1b = prime_pkt.is_auth_packet();
    EXPECT_TRUE(test1b) << "is_auth_packet() returns true for PRIME_BLOCK_AVAILABLE (217)";
    
    // HASH_BLOCK_AVAILABLE (218 = 0xDA) with 12-byte payload
    std::vector<uint8_t> hash_notification = {
        218,                                // header = HASH_BLOCK_AVAILABLE
        0x00, 0x00, 0x00, 0x0C,            // length = 12
        0x00, 0x02, 0x00, 0x00,            // unified_height = 131072
        0x00, 0x01, 0x00, 0x00,            // hash_height = 65536
        0x00, 0x00, 0x00, 0x20             // difficulty = 32
    };
    
    acc.feed(hash_notification);
    bool parsed2 = acc.parse_one_packet(ProtocolLane::LEGACY, packet, result);
    
    bool test2 = parsed2 &&
                 (result == ParseResult::SUCCESS) &&
                 (packet.m_header == 218) &&
                 (packet.m_length == 12) &&
                 (packet.m_data && packet.m_data->size() == 12) &&
                 acc.empty();
    EXPECT_TRUE(test2) << "HASH_BLOCK_AVAILABLE (218) with 12-byte payload";
    
    // Verify is_auth_packet() returns true for HASH_BLOCK_AVAILABLE
    Packet hash_pkt(static_cast<uint8_t>(218));
    bool test2b = hash_pkt.is_auth_packet();
    EXPECT_TRUE(test2b) << "is_auth_packet() returns true for HASH_BLOCK_AVAILABLE (218)";

    // PRIME_BLOCK_AVAILABLE (217 = 0xD9) with 148-byte full-picture payload
    // Layout: unified(4) + prime(4) + difficulty(4) + hash_height(4) + stake_height(4) + hashBestChain(128)
    std::vector<uint8_t> prime_notification_148(5 + 148, 0x00);  // 1-byte header + 4-byte length + 148-byte payload
    prime_notification_148[0] = 217;                              // header = PRIME_BLOCK_AVAILABLE
    prime_notification_148[1] = 0x00;
    prime_notification_148[2] = 0x00;
    prime_notification_148[3] = 0x00;
    prime_notification_148[4] = 148;                             // length = 148
    // [0-3]  unified_height = 6500000
    prime_notification_148[5]  = 0x00; prime_notification_148[6]  = 0x63;
    prime_notification_148[7]  = 0x4E; prime_notification_148[8]  = 0xA0;
    // [4-7]  prime_height = 2300000
    prime_notification_148[9]  = 0x00; prime_notification_148[10] = 0x23;
    prime_notification_148[11] = 0x12; prime_notification_148[12] = 0x60;
    // [8-11] difficulty = 0x0422E6FC
    prime_notification_148[13] = 0x04; prime_notification_148[14] = 0x22;
    prime_notification_148[15] = 0xE6; prime_notification_148[16] = 0xFC;
    // [12-15] hash_height = 900000
    prime_notification_148[17] = 0x00; prime_notification_148[18] = 0x0D;
    prime_notification_148[19] = 0xBB; prime_notification_148[20] = 0xA0;
    // [16-19] stake_height = 400000
    prime_notification_148[21] = 0x00; prime_notification_148[22] = 0x06;
    prime_notification_148[23] = 0x1A; prime_notification_148[24] = 0x80;
    // [20-147] hashBestChain: fill with 0xAB pattern for recognizability
    for (int i = 25; i < 5 + 148; ++i) {
        prime_notification_148[i] = 0xAB;
    }

    acc.feed(prime_notification_148);
    bool parsed3 = acc.parse_one_packet(ProtocolLane::LEGACY, packet, result);

    bool test3 = parsed3 &&
                 (result == ParseResult::SUCCESS) &&
                 (packet.m_header == 217) &&
                 (packet.m_length == 148) &&
                 (packet.m_data && packet.m_data->size() == 148) &&
                 acc.empty();
    EXPECT_TRUE(test3) << "PRIME_BLOCK_AVAILABLE (217) with 148-byte full-picture payload";

    // HASH_BLOCK_AVAILABLE (218 = 0xDA) with 148-byte full-picture payload
    std::vector<uint8_t> hash_notification_148(5 + 148, 0x00);
    hash_notification_148[0] = 218;                              // header = HASH_BLOCK_AVAILABLE
    hash_notification_148[1] = 0x00;
    hash_notification_148[2] = 0x00;
    hash_notification_148[3] = 0x00;
    hash_notification_148[4] = 148;                             // length = 148
    // fill payload bytes with distinct sentinel values
    for (int i = 5; i < 5 + 148; ++i) {
        hash_notification_148[i] = static_cast<uint8_t>((i - 5) & 0xFF);
    }

    acc.feed(hash_notification_148);
    bool parsed4 = acc.parse_one_packet(ProtocolLane::LEGACY, packet, result);

    bool test4 = parsed4 &&
                 (result == ParseResult::SUCCESS) &&
                 (packet.m_header == 218) &&
                 (packet.m_length == 148) &&
                 (packet.m_data && packet.m_data->size() == 148) &&
                 acc.empty();
    EXPECT_TRUE(test4) << "HASH_BLOCK_AVAILABLE (218) with 148-byte full-picture payload";
}

// ============================================================================
// Test Case 12: is_auth_packet() covers full 206-218 range
// ============================================================================
TEST(PacketFramingTest, test_is_auth_packet_full_range) {
    std::cout << "\nTest 12: is_auth_packet() covers full 206-218 range" << std::endl;
    
    // All opcodes 206-218 should return true
    for (uint16_t opcode = 206; opcode <= 218; ++opcode) {
        Packet pkt(static_cast<uint8_t>(opcode));
        bool in_range = pkt.is_auth_packet();
        std::string name = "is_auth_packet() returns true for opcode " + std::to_string(opcode);
        EXPECT_TRUE(in_range) << name;
    }
    
    // Opcodes just outside the range should return false
    Packet below(static_cast<uint8_t>(205));
    EXPECT_TRUE(!below.is_auth_packet()) << "is_auth_packet() returns false for opcode 205";
    
    Packet above(static_cast<uint8_t>(219));
    EXPECT_TRUE(!above.is_auth_packet()) << "is_auth_packet() returns false for opcode 219";
}

// ============================================================================
// Test Case 13: MINER_READY (216) is header-only and validates correctly
// ============================================================================
TEST(PacketFramingTest, test_miner_ready_header_only) {
    std::cout << "\nTest 13: MINER_READY (216) is header-only and validates correctly" << std::endl;
    
    // MINER_READY is header-only (no payload)
    Packet ready_pkt(static_cast<uint8_t>(216));
    
    // Should be in is_auth_packet() range
    bool test1 = ready_pkt.is_auth_packet();
    EXPECT_TRUE(test1) << "MINER_READY (216) is in is_auth_packet() range";
    
    // Should still validate as valid (header-only request)
    bool test2 = ready_pkt.is_valid();
    EXPECT_TRUE(test2) << "MINER_READY (216) with m_length=0 validates as valid";
}

// ============================================================================
// Test Case 14: Legacy data packet single-byte fragmentation
// When only 1 byte of a data packet (opcode < 128) arrives, it should NOT
// be treated as a header-only packet - NEED_MORE_DATA should be returned
// ============================================================================
TEST(PacketFramingTest, test_legacy_data_packet_single_byte) {
    std::cout << "\nTest 14: Legacy data packet single-byte fragmentation" << std::endl;
    
    TestAccumulator acc;
    Packet packet;
    ParseResult result;
    
    // Feed only 1 byte of a BLOCK_DATA (opcode 0) packet
    acc.feed({0x00});
    
    bool parsed1 = acc.parse_one_packet(ProtocolLane::LEGACY, packet, result);
    bool test1 = !parsed1 && (result == ParseResult::NEED_MORE_DATA) && (acc.size() == 1);
    EXPECT_TRUE(test1) << "Single byte of BLOCK_DATA triggers NEED_MORE_DATA";
    
    // Feed remaining bytes (length + payload)
    acc.feed({0x00, 0x00, 0x00, 0x05, 'h', 'e', 'l', 'l', 'o'});
    
    bool parsed2 = acc.parse_one_packet(ProtocolLane::LEGACY, packet, result);
    bool test2 = parsed2 && 
                 (result == ParseResult::SUCCESS) &&
                 (packet.m_header == 0x00) &&
                 (packet.m_length == 5) &&
                 acc.empty();
    EXPECT_TRUE(test2) << "Complete BLOCK_DATA after fragmented single byte";
    
    // Test with SUBMIT_BLOCK (opcode 1) - also a data packet
    acc.feed({0x01});
    
    bool parsed3 = acc.parse_one_packet(ProtocolLane::LEGACY, packet, result);
    bool test3 = !parsed3 && (result == ParseResult::NEED_MORE_DATA) && (acc.size() == 1);
    EXPECT_TRUE(test3) << "Single byte of SUBMIT_BLOCK triggers NEED_MORE_DATA";
    
    acc.feed({0x00, 0x00, 0x00, 0x03, 'a', 'b', 'c'});
    
    bool parsed4 = acc.parse_one_packet(ProtocolLane::LEGACY, packet, result);
    bool test4 = parsed4 && 
                 (result == ParseResult::SUCCESS) &&
                 (packet.m_header == 0x01) &&
                 (packet.m_length == 3) &&
                 acc.empty();
    EXPECT_TRUE(test4) << "Complete SUBMIT_BLOCK after fragmented single byte";
}

// ============================================================================
// Test Case 15: Legacy header-only opcode single-byte
// When a header-only opcode (>= 128, not auth) arrives as 1 byte,
// it should be treated as a complete packet
// ============================================================================
TEST(PacketFramingTest, test_legacy_header_only_single_byte) {
    std::cout << "\nTest 15: Legacy header-only opcode single-byte" << std::endl;
    
    TestAccumulator acc;
    Packet packet;
    ParseResult result;
    
    // GET_BLOCK (129) is header-only
    acc.feed({129});
    
    bool parsed1 = acc.parse_one_packet(ProtocolLane::LEGACY, packet, result);
    bool test1 = parsed1 && 
                 (result == ParseResult::SUCCESS) &&
                 (packet.m_header == 129) &&
                 (packet.m_length == 0) &&
                 acc.empty();
    EXPECT_TRUE(test1) << "GET_BLOCK (129) header-only packet parsed immediately";
    
    // NEW_ROUND (204) has payload (12 bytes) - NOT header-only
    acc.feed({204});
    
    bool parsed2 = acc.parse_one_packet(ProtocolLane::LEGACY, packet, result);
    bool test2 = !parsed2 && (result == ParseResult::NEED_MORE_DATA) && (acc.size() == 1);
    EXPECT_TRUE(test2) << "NEW_ROUND (204) single byte triggers NEED_MORE_DATA (has payload)";
    acc.clear();
    
    // PING (253) is header-only
    acc.feed({253});
    
    bool parsed3 = acc.parse_one_packet(ProtocolLane::LEGACY, packet, result);
    bool test3 = parsed3 && 
                 (result == ParseResult::SUCCESS) &&
                 (packet.m_header == 253) &&
                 (packet.m_length == 0) &&
                 acc.empty();
    EXPECT_TRUE(test3) << "PING (253) header-only packet parsed immediately";
    
    // MINER_READY (216) is header-only even though it's in auth range
    acc.feed({216});
    
    bool parsed4 = acc.parse_one_packet(ProtocolLane::LEGACY, packet, result);
    bool test4 = parsed4 && 
                 (result == ParseResult::SUCCESS) &&
                 (packet.m_header == 216) &&
                 (packet.m_length == 0) &&
                 acc.empty();
    EXPECT_TRUE(test4) << "MINER_READY (216) header-only packet parsed immediately";
}

// ============================================================================
// Test Case 16: Legacy auth packet single-byte fragmentation
// Auth packets (206-218, except MINER_READY) always have payload,
// so a single byte should trigger NEED_MORE_DATA
// ============================================================================
TEST(PacketFramingTest, test_legacy_auth_packet_single_byte) {
    std::cout << "\nTest 16: Legacy auth packet single-byte fragmentation" << std::endl;
    
    TestAccumulator acc;
    Packet packet;
    ParseResult result;
    
    // MINER_AUTH_CHALLENGE (208) - has payload
    acc.feed({208});
    
    bool parsed1 = acc.parse_one_packet(ProtocolLane::LEGACY, packet, result);
    bool test1 = !parsed1 && (result == ParseResult::NEED_MORE_DATA) && (acc.size() == 1);
    EXPECT_TRUE(test1) << "Single byte of MINER_AUTH_CHALLENGE triggers NEED_MORE_DATA";
    
    // Complete the packet
    acc.feed({0x00, 0x00, 0x00, 0x04, 0xAA, 0xBB, 0xCC, 0xDD});
    
    bool parsed2 = acc.parse_one_packet(ProtocolLane::LEGACY, packet, result);
    bool test2 = parsed2 && 
                 (result == ParseResult::SUCCESS) &&
                 (packet.m_header == 208) &&
                 (packet.m_length == 4) &&
                 acc.empty();
    EXPECT_TRUE(test2) << "Complete MINER_AUTH_CHALLENGE after single byte";
}

// ============================================================================
// Test Case 17: Stateless data packet two-byte fragmentation
// When only 2 bytes of a stateless data packet arrive, NEED_MORE_DATA
// should be returned (not treated as header-only)
// ============================================================================
TEST(PacketFramingTest, test_stateless_data_packet_two_byte) {
    std::cout << "\nTest 17: Stateless data packet two-byte fragmentation" << std::endl;
    
    TestAccumulator acc;
    Packet packet;
    ParseResult result;
    
    // STATELESS_SUBMIT_BLOCK (0xD001) - has payload, only 2 bytes arrive
    acc.feed({0xD0, 0x01});
    
    bool parsed1 = acc.parse_one_packet(ProtocolLane::STATELESS, packet, result);
    bool test1 = !parsed1 && (result == ParseResult::NEED_MORE_DATA) && (acc.size() == 2);
    EXPECT_TRUE(test1) << "Two bytes of STATELESS_SUBMIT_BLOCK triggers NEED_MORE_DATA";
    
    // Complete the packet
    acc.feed({0x00, 0x00, 0x00, 0x03, 'x', 'y', 'z'});
    
    bool parsed2 = acc.parse_one_packet(ProtocolLane::STATELESS, packet, result);
    bool test2 = parsed2 && 
                 (result == ParseResult::SUCCESS) &&
                 (packet.m_header == 0xD001) &&
                 (packet.m_length == 3) &&
                 acc.empty();
    EXPECT_TRUE(test2) << "Complete STATELESS_SUBMIT_BLOCK after fragmentation";
}

// ============================================================================
// Test Case 18: Stateless header-only opcode two-byte
// When a stateless header-only opcode arrives as 2 bytes, it should be
// treated as a complete packet.
// NOTE: GET_BLOCK (0xD081) is NOT header-only on stateless (template push).
// ============================================================================
TEST(PacketFramingTest, test_stateless_header_only_two_byte) {
    std::cout << "\nTest 18: Stateless header-only opcode two-byte" << std::endl;
    
    TestAccumulator acc;
    Packet packet;
    ParseResult result;
    
    // STATELESS_GET_BLOCK (0xD081) is NOT header-only on stateless lane
    // (node sends 228-byte template push via this opcode)
    acc.feed({0xD0, 0x81});
    
    bool parsed1 = acc.parse_one_packet(ProtocolLane::STATELESS, packet, result);
    bool test1 = !parsed1 && 
                 (result == ParseResult::NEED_MORE_DATA) &&
                 (acc.size() == 2);
    EXPECT_TRUE(test1) << "STATELESS_GET_BLOCK (0xD081) is NOT header-only (needs payload)";
    acc.clear();
    
    // STATELESS MINER_READY (0xD0D8) is header-only
    acc.feed({0xD0, 0xD8});
    
    bool parsed2 = acc.parse_one_packet(ProtocolLane::STATELESS, packet, result);
    bool test2 = parsed2 && 
                 (result == ParseResult::SUCCESS) &&
                 (packet.m_header == 0xD0D8) &&
                 (packet.m_length == 0) &&
                 acc.empty();
    EXPECT_TRUE(test2) << "STATELESS_MINER_READY (0xD0D8) header-only parsed immediately";
}

// ============================================================================
// Test Case 19: NEW_ROUND (204) with 12-byte payload
// NEW_ROUND carries payload: [unified_height][channel_height][difficulty]
// ============================================================================
TEST(PacketFramingTest, test_new_round_with_payload) {
    std::cout << "\nTest 19: NEW_ROUND (204) with 12-byte payload" << std::endl;
    
    TestAccumulator acc;
    Packet packet;
    ParseResult result;
    
    // NEW_ROUND (204) with 12-byte payload: height=6500000, channel=6499900, difficulty=0x1E00FFFF
    std::vector<uint8_t> new_round_packet = {
        204,                                // header (NEW_ROUND)
        0x00, 0x00, 0x00, 0x0C,           // length = 12
        0x00, 0x63, 0x32, 0x20,           // unified_height = 6500000 (big-endian)
        0x00, 0x63, 0x31, 0xBC,           // channel_height = 6499900 (big-endian)
        0x1E, 0x00, 0xFF, 0xFF            // difficulty = 0x1E00FFFF (big-endian)
    };
    
    acc.feed(new_round_packet);
    
    bool parsed = acc.parse_one_packet(ProtocolLane::LEGACY, packet, result);
    bool test1 = parsed && 
                 (result == ParseResult::SUCCESS) &&
                 (packet.m_header == 204) &&
                 (packet.m_length == 12) &&
                 (packet.m_data != nullptr) &&
                 (packet.m_data->size() == 12) &&
                 acc.empty();
    EXPECT_TRUE(test1) << "NEW_ROUND 12-byte payload parsed correctly";
    
    // NEW_ROUND single byte should trigger NEED_MORE_DATA (not treated as header-only)
    acc.feed({204});
    
    bool parsed2 = acc.parse_one_packet(ProtocolLane::LEGACY, packet, result);
    bool test2 = !parsed2 && (result == ParseResult::NEED_MORE_DATA) && (acc.size() == 1);
    EXPECT_TRUE(test2) << "NEW_ROUND single byte triggers NEED_MORE_DATA";
    acc.clear();
}

// ============================================================================
// Test Case 20: OLD_ROUND (205) with 12-byte payload
// OLD_ROUND carries payload: [unified_height][channel_height][difficulty]
// ============================================================================
TEST(PacketFramingTest, test_old_round_with_payload) {
    std::cout << "\nTest 20: OLD_ROUND (205) with 12-byte payload" << std::endl;
    
    TestAccumulator acc;
    Packet packet;
    ParseResult result;
    
    // OLD_ROUND (205) with 12-byte payload
    std::vector<uint8_t> old_round_packet = {
        205,                                // header (OLD_ROUND)
        0x00, 0x00, 0x00, 0x0C,           // length = 12
        0x00, 0x63, 0x32, 0x20,           // unified_height = 6500000 (big-endian)
        0x00, 0x63, 0x31, 0xBC,           // channel_height = 6499900 (big-endian)
        0x1E, 0x00, 0xFF, 0xFF            // difficulty = 0x1E00FFFF (big-endian)
    };
    
    acc.feed(old_round_packet);
    
    bool parsed = acc.parse_one_packet(ProtocolLane::LEGACY, packet, result);
    bool test1 = parsed && 
                 (result == ParseResult::SUCCESS) &&
                 (packet.m_header == 205) &&
                 (packet.m_length == 12) &&
                 (packet.m_data != nullptr) &&
                 (packet.m_data->size() == 12) &&
                 acc.empty();
    EXPECT_TRUE(test1) << "OLD_ROUND 12-byte payload parsed correctly";
    
    // OLD_ROUND single byte should trigger NEED_MORE_DATA
    acc.feed({205});
    
    bool parsed2 = acc.parse_one_packet(ProtocolLane::LEGACY, packet, result);
    bool test2 = !parsed2 && (result == ParseResult::NEED_MORE_DATA) && (acc.size() == 1);
    EXPECT_TRUE(test2) << "OLD_ROUND single byte triggers NEED_MORE_DATA";
    acc.clear();
}

// ============================================================================
// Test Case 21: NEW_ROUND/OLD_ROUND with legacy 16-byte payload
// Legacy lane accepts 16-byte format: [unified][prime][hash][stake]
// ============================================================================
TEST(PacketFramingTest, test_round_legacy_16byte_payload) {
    std::cout << "\nTest 21: NEW_ROUND/OLD_ROUND with legacy 16-byte payload" << std::endl;
    
    TestAccumulator acc;
    Packet packet;
    ParseResult result;
    
    // NEW_ROUND with 16-byte legacy payload
    std::vector<uint8_t> new_round_16 = {
        204,                                // header (NEW_ROUND)
        0x00, 0x00, 0x00, 0x10,           // length = 16
        0x00, 0x63, 0x32, 0x20,           // unified_height (big-endian)
        0x00, 0x63, 0x31, 0x00,           // prime_height (big-endian)
        0x00, 0x63, 0x31, 0x50,           // hash_height (big-endian)
        0x00, 0x63, 0x30, 0xA0            // stake_height (big-endian)
    };
    
    acc.feed(new_round_16);
    
    bool parsed = acc.parse_one_packet(ProtocolLane::LEGACY, packet, result);
    bool test1 = parsed && 
                 (result == ParseResult::SUCCESS) &&
                 (packet.m_header == 204) &&
                 (packet.m_length == 16) &&
                 (packet.m_data != nullptr) &&
                 (packet.m_data->size() == 16) &&
                 acc.empty();
    EXPECT_TRUE(test1) << "NEW_ROUND 16-byte legacy payload parsed correctly";
}

// ============================================================================
// Test Case 22: ACCEPT/REJECT still header-only (regression check)
// Ensure the fix doesn't break ACCEPT (200) and REJECT (201) classification
// ============================================================================
TEST(PacketFramingTest, test_accept_reject_still_header_only) {
    std::cout << "\nTest 22: ACCEPT/REJECT still header-only (regression check)" << std::endl;
    
    TestAccumulator acc;
    Packet packet;
    ParseResult result;
    
    // ACCEPT (200) should still be header-only
    acc.feed({200});
    
    bool parsed1 = acc.parse_one_packet(ProtocolLane::LEGACY, packet, result);
    bool test1 = parsed1 && 
                 (result == ParseResult::SUCCESS) &&
                 (packet.m_header == 200) &&
                 (packet.m_length == 0) &&
                 acc.empty();
    EXPECT_TRUE(test1) << "ACCEPT (200) still header-only";
    
    // REJECT (201) should still be header-only
    acc.feed({201});
    
    bool parsed2 = acc.parse_one_packet(ProtocolLane::LEGACY, packet, result);
    bool test2 = parsed2 && 
                 (result == ParseResult::SUCCESS) &&
                 (packet.m_header == 201) &&
                 (packet.m_length == 0) &&
                 acc.empty();
    EXPECT_TRUE(test2) << "REJECT (201) still header-only";
    
    // COINBASE_SET (202) should still be header-only
    acc.feed({202});
    
    bool parsed3 = acc.parse_one_packet(ProtocolLane::LEGACY, packet, result);
    bool test3 = parsed3 && 
                 (result == ParseResult::SUCCESS) &&
                 (packet.m_header == 202) &&
                 (packet.m_length == 0) &&
                 acc.empty();
    EXPECT_TRUE(test3) << "COINBASE_SET (202) still header-only";
    
    // COINBASE_FAIL (203) should still be header-only
    acc.feed({203});
    
    bool parsed4 = acc.parse_one_packet(ProtocolLane::LEGACY, packet, result);
    bool test4 = parsed4 && 
                 (result == ParseResult::SUCCESS) &&
                 (packet.m_header == 203) &&
                 (packet.m_length == 0) &&
                 acc.empty();
    EXPECT_TRUE(test4) << "COINBASE_FAIL (203) still header-only";
}

// ============================================================================
// Test Case 23: Stateless GET_BLOCK (0xD081) with 228-byte payload
// On stateless lane, GET_BLOCK is a template push with 228-byte payload
// ============================================================================
TEST(PacketFramingTest, test_stateless_get_block_with_payload) {
    std::cout << "\nTest 23: Stateless GET_BLOCK (0xD081) with 228-byte payload" << std::endl;
    
    TestAccumulator acc;
    Packet packet;
    ParseResult result;
    
    // Build a complete STATELESS_GET_BLOCK (0xD081) with 228-byte payload
    // Wire format: [0xD0][0x81][00 00 00 E4][228 bytes]
    std::vector<uint8_t> get_block_packet;
    get_block_packet.push_back(0xD0);  // header MSB
    get_block_packet.push_back(0x81);  // header LSB
    get_block_packet.push_back(0x00);  // length MSB
    get_block_packet.push_back(0x00);
    get_block_packet.push_back(0x00);
    get_block_packet.push_back(0xE4);  // length LSB = 228
    // 228 bytes of payload (simulated template data)
    for (int i = 0; i < 228; ++i) {
        get_block_packet.push_back(static_cast<uint8_t>(i));
    }
    
    acc.feed(get_block_packet);
    
    bool parsed = acc.parse_one_packet(ProtocolLane::STATELESS, packet, result);
    bool test1 = parsed &&
                 (result == ParseResult::SUCCESS) &&
                 (packet.m_header == 0xD081) &&
                 (packet.m_length == 228) &&
                 (packet.m_data != nullptr) &&
                 (packet.m_data->size() == 228) &&
                 acc.empty();
    EXPECT_TRUE(test1) << "STATELESS_GET_BLOCK (0xD081) with 228-byte payload parsed correctly";
    
    // Verify first few bytes of payload
    if (packet.m_data && packet.m_data->size() >= 4) {
        bool data_correct = ((*packet.m_data)[0] == 0x00) &&
                           ((*packet.m_data)[1] == 0x01) &&
                           ((*packet.m_data)[2] == 0x02) &&
                           ((*packet.m_data)[3] == 0x03);
        EXPECT_TRUE(data_correct) << "STATELESS_GET_BLOCK payload data verified";
    } else {
        EXPECT_TRUE(false) << "STATELESS_GET_BLOCK payload data verified";
    }
}

// ============================================================================
// Test Case 23b: Stateless GET_BLOCK (0xD081) with zero-length payload
// Node can send GET_BLOCK with length=0 (no template available yet)
// ============================================================================
TEST(PacketFramingTest, test_stateless_get_block_zero_length) {
    std::cout << "\nTest 23b: Stateless GET_BLOCK (0xD081) with zero-length payload" << std::endl;
    
    TestAccumulator acc;
    Packet packet;
    ParseResult result;
    
    // Build STATELESS_GET_BLOCK (0xD081) with length=0
    // Wire format: [0xD0][0x81][00 00 00 00]
    std::vector<uint8_t> get_block_packet = {
        0xD0, 0x81,                    // header = 0xD081
        0x00, 0x00, 0x00, 0x00         // length = 0
    };
    
    acc.feed(get_block_packet);
    
    bool parsed = acc.parse_one_packet(ProtocolLane::STATELESS, packet, result);
    bool test1 = parsed &&
                 (result == ParseResult::SUCCESS) &&
                 (packet.m_header == 0xD081) &&
                 (packet.m_length == 0) &&
                 acc.empty();
    EXPECT_TRUE(test1) << "STATELESS_GET_BLOCK (0xD081) with length=0 parsed correctly";
}

// ============================================================================
// Test Case 23c: Stateless BLOCK_DATA (0xD000) with 216-byte payload
// Node responds to GET_BLOCK with BLOCK_DATA containing 216-byte block template
// ============================================================================
TEST(PacketFramingTest, test_stateless_block_data_with_payload) {
    std::cout << "\nTest 23c: Stateless BLOCK_DATA (0xD000) with 216-byte payload" << std::endl;
    
    TestAccumulator acc;
    Packet packet;
    ParseResult result;
    
    // Build a complete STATELESS_BLOCK_DATA (0xD000) with 216-byte payload
    // Wire format: [0xD0][0x00][00 00 00 D8][216 bytes]
    std::vector<uint8_t> block_data_packet;
    block_data_packet.push_back(0xD0);  // header MSB
    block_data_packet.push_back(0x00);  // header LSB
    block_data_packet.push_back(0x00);  // length MSB
    block_data_packet.push_back(0x00);
    block_data_packet.push_back(0x00);
    block_data_packet.push_back(0xD8);  // length LSB = 216
    // 216 bytes of payload (simulated block template)
    for (int i = 0; i < 216; ++i) {
        block_data_packet.push_back(static_cast<uint8_t>(i));
    }
    
    acc.feed(block_data_packet);
    
    bool parsed = acc.parse_one_packet(ProtocolLane::STATELESS, packet, result);
    bool test1 = parsed &&
                 (result == ParseResult::SUCCESS) &&
                 (packet.m_header == 0xD000) &&
                 (packet.m_is_uint16_opcode) &&
                 (packet.m_length == 216) &&
                 (packet.m_data != nullptr) &&
                 (packet.m_data->size() == 216) &&
                 acc.empty();
    EXPECT_TRUE(test1) << "STATELESS_BLOCK_DATA (0xD000) with 216-byte payload parsed correctly";
    
    // Verify first few bytes of payload
    if (packet.m_data && packet.m_data->size() >= 4) {
        bool data_correct = ((*packet.m_data)[0] == 0x00) &&
                           ((*packet.m_data)[1] == 0x01) &&
                           ((*packet.m_data)[2] == 0x02) &&
                           ((*packet.m_data)[3] == 0x03);
        EXPECT_TRUE(data_correct) << "STATELESS_BLOCK_DATA payload data verified";
    } else {
        EXPECT_TRUE(false) << "STATELESS_BLOCK_DATA payload data verified";
    }
    
    // Verify opcode matches the StatelessMining::BLOCK_DATA constant
    bool opcode_test = (packet.m_header == nexusminer::LLP::StatelessMining::BLOCK_DATA);
    EXPECT_TRUE(opcode_test) << "STATELESS_BLOCK_DATA header matches StatelessMining::BLOCK_DATA";
}

// ============================================================================
// Test Case 24: Stateless auth opcodes (mirror-mapped) with payload
// Auth opcodes 0xD0CE, 0xD0D0, 0xD0D2 should parse as 2-byte headers with payload
// ============================================================================
TEST(PacketFramingTest, test_stateless_auth_opcodes_with_payload) {
    std::cout << "\nTest 24: Stateless auth opcodes (mirror-mapped) with payload" << std::endl;
    
    TestAccumulator acc;
    Packet packet;
    ParseResult result;
    
    // CHANNEL_ACK (0xD0CE = mirror of 206) with 1-byte payload
    std::vector<uint8_t> channel_ack = {
        0xD0, 0xCE,                    // header = 0xD0CE
        0x00, 0x00, 0x00, 0x01,        // length = 1
        0x02                           // channel = 2 (Hash)
    };
    
    acc.feed(channel_ack);
    bool parsed1 = acc.parse_one_packet(ProtocolLane::STATELESS, packet, result);
    bool test1 = parsed1 &&
                 (result == ParseResult::SUCCESS) &&
                 (packet.m_header == 0xD0CE) &&
                 (packet.m_length == 1) &&
                 (packet.m_data != nullptr) &&
                 acc.empty();
    EXPECT_TRUE(test1) << "CHANNEL_ACK (0xD0CE) parsed with payload";
    
    // MINER_AUTH_CHALLENGE (0xD0D0 = mirror of 208) with 34-byte nonce payload
    std::vector<uint8_t> auth_challenge;
    auth_challenge.push_back(0xD0);  // header MSB
    auth_challenge.push_back(0xD0);  // header LSB (mirror of 208)
    auth_challenge.push_back(0x00);  // length
    auth_challenge.push_back(0x00);
    auth_challenge.push_back(0x00);
    auth_challenge.push_back(0x22);  // length = 34
    // 34 bytes of nonce data
    for (int i = 0; i < 34; ++i) {
        auth_challenge.push_back(static_cast<uint8_t>(0xAA + i));
    }
    
    acc.feed(auth_challenge);
    bool parsed2 = acc.parse_one_packet(ProtocolLane::STATELESS, packet, result);
    bool test2 = parsed2 &&
                 (result == ParseResult::SUCCESS) &&
                 (packet.m_header == 0xD0D0) &&
                 (packet.m_length == 34) &&
                 (packet.m_data != nullptr) &&
                 acc.empty();
    EXPECT_TRUE(test2) << "MINER_AUTH_CHALLENGE (0xD0D0) parsed with payload";
    
    // MINER_AUTH_RESULT (0xD0D2 = mirror of 210) with 5-byte payload
    std::vector<uint8_t> auth_result = {
        0xD0, 0xD2,                    // header = 0xD0D2
        0x00, 0x00, 0x00, 0x05,        // length = 5
        0x01,                          // status = success
        0x12, 0x34, 0x56, 0x78         // session_id (LE)
    };
    
    acc.feed(auth_result);
    bool parsed3 = acc.parse_one_packet(ProtocolLane::STATELESS, packet, result);
    bool test3 = parsed3 &&
                 (result == ParseResult::SUCCESS) &&
                 (packet.m_header == 0xD0D2) &&
                 (packet.m_length == 5) &&
                 (packet.m_data != nullptr) &&
                 acc.empty();
    EXPECT_TRUE(test3) << "MINER_AUTH_RESULT (0xD0D2) parsed with payload";
}

// ============================================================================
// Test Case 25: Legacy auth opcode 208 (0xD0) parses correctly (NOT rejected)
// Byte 0xD0 on legacy lane is MINER_AUTH_CHALLENGE and must NOT be rejected
// ============================================================================
TEST(PacketFramingTest, test_legacy_auth_opcode_208_not_rejected) {
    std::cout << "\nTest 25: Legacy auth opcode 208 (0xD0) not rejected" << std::endl;
    
    TestAccumulator acc;
    Packet packet;
    ParseResult result;
    
    // MINER_AUTH_CHALLENGE (208 = 0xD0) with 34-byte nonce payload on legacy lane
    std::vector<uint8_t> auth_challenge;
    auth_challenge.push_back(208);     // header = 0xD0 (MINER_AUTH_CHALLENGE)
    auth_challenge.push_back(0x00);    // length
    auth_challenge.push_back(0x00);
    auth_challenge.push_back(0x00);
    auth_challenge.push_back(0x22);    // length = 34
    for (int i = 0; i < 34; ++i) {
        auth_challenge.push_back(static_cast<uint8_t>(0xBB + i));
    }
    
    acc.feed(auth_challenge);
    bool parsed = acc.parse_one_packet(ProtocolLane::LEGACY, packet, result);
    bool test1 = parsed &&
                 (result == ParseResult::SUCCESS) &&
                 (packet.m_header == 208) &&
                 (packet.m_length == 34) &&
                 (packet.m_data != nullptr) &&
                 (packet.m_data->size() == 34) &&
                 acc.empty();
    EXPECT_TRUE(test1) << "Legacy MINER_AUTH_CHALLENGE (208/0xD0) parsed correctly (NOT rejected)";
    
    // Also verify MINER_AUTH_INIT (207) on legacy lane
    std::vector<uint8_t> auth_init = {
        207,                           // header = MINER_AUTH_INIT
        0x00, 0x00, 0x00, 0x04,       // length = 4
        0x01, 0x02, 0x03, 0x04        // payload
    };
    
    acc.feed(auth_init);
    bool parsed2 = acc.parse_one_packet(ProtocolLane::LEGACY, packet, result);
    bool test2 = parsed2 &&
                 (result == ParseResult::SUCCESS) &&
                 (packet.m_header == 207) &&
                 (packet.m_length == 4) &&
                 acc.empty();
    EXPECT_TRUE(test2) << "Legacy MINER_AUTH_INIT (207) parsed correctly";
    
    // Also verify MINER_AUTH_RESULT (210) on legacy lane
    std::vector<uint8_t> auth_result = {
        210,                           // header = MINER_AUTH_RESULT
        0x00, 0x00, 0x00, 0x05,       // length = 5
        0x01,                          // status = success
        0x12, 0x34, 0x56, 0x78        // session_id
    };
    
    acc.feed(auth_result);
    bool parsed3 = acc.parse_one_packet(ProtocolLane::LEGACY, packet, result);
    bool test3 = parsed3 &&
                 (result == ParseResult::SUCCESS) &&
                 (packet.m_header == 210) &&
                 (packet.m_length == 5) &&
                 acc.empty();
    EXPECT_TRUE(test3) << "Legacy MINER_AUTH_RESULT (210) parsed correctly";
}

// ============================================================================
// Main test runner
// ============================================================================
