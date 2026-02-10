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
#include <cassert>
#include <vector>
#include <deque>
#include <sstream>

using namespace nexusminer;

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
void test_complete_packet_single_receive() {
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
    
    print_test_result("Complete packet parsed successfully", test_passed);
}

// ============================================================================
// Test Case 2: Header + length split across receives
// ============================================================================
void test_header_fragmented() {
    std::cout << "\nTest 2: Header + length split across multiple receives" << std::endl;
    
    TestAccumulator acc;
    
    // First receive: header + first 2 bytes of length field (incomplete)
    acc.feed({0x02, 0x00, 0x00});
    
    Packet packet;
    ParseResult result;
    
    bool parsed1 = acc.parse_one_packet(ProtocolLane::LEGACY, packet, result);
    bool test1 = !parsed1 && (result == ParseResult::NEED_MORE_DATA) && (acc.size() == 3);
    print_test_result("Incomplete length field triggers NEED_MORE_DATA", test1);
    
    // Second receive: rest of length + data
    acc.feed({0x00, 0x03, 'a', 'b', 'c'});
    
    bool parsed2 = acc.parse_one_packet(ProtocolLane::LEGACY, packet, result);
    bool test2 = parsed2 && 
                 (result == ParseResult::SUCCESS) &&
                 (packet.m_header == 0x02) &&
                 (packet.m_length == 3) &&
                 acc.empty();
    print_test_result("Complete packet after split length field", test2);
}

// ============================================================================
// Test Case 3: Payload split across receives
// ============================================================================
void test_payload_fragmented() {
    std::cout << "\nTest 3: Payload split across multiple receives" << std::endl;
    
    TestAccumulator acc;
    
    // First receive: header + length
    acc.feed({0x03, 0x00, 0x00, 0x00, 0x0A}); // length = 10 bytes
    
    Packet packet;
    ParseResult result;
    
    bool parsed1 = acc.parse_one_packet(ProtocolLane::LEGACY, packet, result);
    bool test1 = !parsed1 && (result == ParseResult::NEED_MORE_DATA);
    print_test_result("Header+length without payload triggers NEED_MORE_DATA", test1);
    
    // Second receive: first 5 bytes of payload
    acc.feed({'a', 'b', 'c', 'd', 'e'});
    
    bool parsed2 = acc.parse_one_packet(ProtocolLane::LEGACY, packet, result);
    bool test2 = !parsed2 && (result == ParseResult::NEED_MORE_DATA);
    print_test_result("Partial payload triggers NEED_MORE_DATA", test2);
    
    // Third receive: remaining 5 bytes
    acc.feed({'f', 'g', 'h', 'i', 'j'});
    
    bool parsed3 = acc.parse_one_packet(ProtocolLane::LEGACY, packet, result);
    bool test3 = parsed3 && 
                 (result == ParseResult::SUCCESS) &&
                 (packet.m_length == 10) &&
                 acc.empty();
    print_test_result("Complete payload after fragmentation", test3);
}

// ============================================================================
// Test Case 4: Multiple packets in single receive
// ============================================================================
void test_multiple_packets_single_receive() {
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
    print_test_result("First packet parsed from batch", test1);
    
    // Parse second packet
    Packet packet2;
    ParseResult result2;
    bool parsed2 = acc.parse_one_packet(ProtocolLane::LEGACY, packet2, result2);
    bool test2 = parsed2 && (packet2.m_header == 0x05) && (packet2.m_length == 2) && acc.empty();
    print_test_result("Second packet parsed from batch", test2);
}

// ============================================================================
// Test Case 5: Stateless lane with 16-bit header fragmentation
// ============================================================================
void test_stateless_header_fragmented() {
    std::cout << "\nTest 5: Stateless lane - 16-bit header fragmented" << std::endl;
    
    TestAccumulator acc;
    
    // First receive: only first byte of 16-bit header
    acc.feed({0xD0});
    
    Packet packet;
    ParseResult result;
    
    bool parsed1 = acc.parse_one_packet(ProtocolLane::STATELESS, packet, result);
    bool test1 = !parsed1 && (result == ParseResult::NEED_MORE_DATA) && (acc.size() == 1);
    print_test_result("Partial 16-bit header triggers NEED_MORE_DATA", test1);
    
    // Second receive: second byte of header + partial length
    acc.feed({0x01, 0x00, 0x00});
    
    bool parsed2 = acc.parse_one_packet(ProtocolLane::STATELESS, packet, result);
    bool test2 = !parsed2 && (result == ParseResult::NEED_MORE_DATA);
    print_test_result("Incomplete length field in stateless", test2);
    
    // Third receive: complete length + data
    acc.feed({0x00, 0x04, 't', 'e', 's', 't'});
    
    bool parsed3 = acc.parse_one_packet(ProtocolLane::STATELESS, packet, result);
    bool test3 = parsed3 && 
                 (result == ParseResult::SUCCESS) &&
                 (packet.m_header == 0xD001) &&
                 (packet.m_length == 4) &&
                 acc.empty();
    print_test_result("Stateless packet after multiple receives", test3);
}

// ============================================================================
// Test Case 6: Malformed packet - unreasonably large length
// ============================================================================
void test_malformed_huge_length() {
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
    
    print_test_result("Huge length detected as malformed", test_passed);
}

// ============================================================================
// Test Case 7: Malformed - invalid stateless opcode
// ============================================================================
void test_malformed_invalid_stateless_opcode() {
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
    
    print_test_result("Invalid stateless opcode detected", test_passed);
}

// ============================================================================
// Test Case 8: Complex scenario - mixed fragmentation and batching
// ============================================================================
void test_complex_mixed_scenario() {
    std::cout << "\nTest 8: Complex scenario - mixed fragmentation and batching" << std::endl;
    
    TestAccumulator acc;
    
    // Simulate realistic TCP stream:
    // Receive 1: Partial packet 1
    acc.feed({0x20, 0x00, 0x00});
    
    Packet packet;
    ParseResult result;
    bool parsed1 = acc.parse_one_packet(ProtocolLane::LEGACY, packet, result);
    bool test1 = !parsed1 && (result == ParseResult::NEED_MORE_DATA);
    print_test_result("Partial first packet", test1);
    
    // Receive 2: Rest of packet 1 + complete packet 2 + partial packet 3
    acc.feed({
        0x00, 0x02, 'A', 'B',          // Complete packet 1
        0x21, 0x00, 0x00, 0x00, 0x01, 'X',  // Complete packet 2
        0x22, 0x00                     // Partial packet 3
    });
    
    // Parse packet 1
    bool parsed2 = acc.parse_one_packet(ProtocolLane::LEGACY, packet, result);
    bool test2 = parsed2 && (packet.m_header == 0x20) && (packet.m_length == 2);
    print_test_result("First packet completed", test2);
    
    // Parse packet 2
    bool parsed3 = acc.parse_one_packet(ProtocolLane::LEGACY, packet, result);
    bool test3 = parsed3 && (packet.m_header == 0x21) && (packet.m_length == 1);
    print_test_result("Second packet completed", test3);
    
    // Try to parse packet 3 (incomplete)
    bool parsed4 = acc.parse_one_packet(ProtocolLane::LEGACY, packet, result);
    bool test4 = !parsed4 && (result == ParseResult::NEED_MORE_DATA) && (acc.size() == 2);
    print_test_result("Third packet incomplete", test4);
    
    // Receive 3: Complete packet 3
    acc.feed({0x00, 0x00, 0x03, 'a', 'b', 'c'});
    
    bool parsed5 = acc.parse_one_packet(ProtocolLane::LEGACY, packet, result);
    bool test5 = parsed5 && (packet.m_header == 0x22) && (packet.m_length == 3) && acc.empty();
    print_test_result("Third packet completed", test5);
}

// ============================================================================
// Test Case 9: Byte-by-byte feeding (extreme fragmentation)
// ============================================================================
void test_byte_by_byte_feeding() {
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
        print_test_result("Byte-by-byte feeding - initial state", false);
        return;
    }
    
    // Feed remaining bytes one at a time
    for (size_t i = 2; i < complete_packet.size() - 1; ++i) {
        acc.feed({complete_packet[i]});
        bool parsed = acc.parse_one_packet(ProtocolLane::LEGACY, packet, result);
        
        if (parsed || result != ParseResult::NEED_MORE_DATA) {
            print_test_result("Byte-by-byte feeding - intermediate", false);
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
    
    print_test_result("Byte-by-byte feeding completes successfully", test_passed);
}

// ============================================================================
// Test Case 10: Zero-length payload
// ============================================================================
void test_zero_length_payload() {
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
    
    print_test_result("Zero-length payload handled correctly", test_passed);
}

// ============================================================================
// Test Case 11: Push notification packets (PRIME_BLOCK_AVAILABLE / HASH_BLOCK_AVAILABLE)
// These carry 12-byte payloads on the legacy lane and must be parsed correctly
// ============================================================================
void test_push_notification_legacy_lane() {
    std::cout << "\nTest 11: Push notification packets on legacy lane (12-byte payload)" << std::endl;
    
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
    print_test_result("PRIME_BLOCK_AVAILABLE (217) with 12-byte payload", test1);
    
    // Verify is_auth_packet() returns true for PRIME_BLOCK_AVAILABLE
    Packet prime_pkt(static_cast<uint8_t>(217));
    bool test1b = prime_pkt.is_auth_packet();
    print_test_result("is_auth_packet() returns true for PRIME_BLOCK_AVAILABLE (217)", test1b);
    
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
    print_test_result("HASH_BLOCK_AVAILABLE (218) with 12-byte payload", test2);
    
    // Verify is_auth_packet() returns true for HASH_BLOCK_AVAILABLE
    Packet hash_pkt(static_cast<uint8_t>(218));
    bool test2b = hash_pkt.is_auth_packet();
    print_test_result("is_auth_packet() returns true for HASH_BLOCK_AVAILABLE (218)", test2b);
}

// ============================================================================
// Test Case 12: is_auth_packet() covers full 206-218 range
// ============================================================================
void test_is_auth_packet_full_range() {
    std::cout << "\nTest 12: is_auth_packet() covers full 206-218 range" << std::endl;
    
    // All opcodes 206-218 should return true
    for (uint16_t opcode = 206; opcode <= 218; ++opcode) {
        Packet pkt(static_cast<uint8_t>(opcode));
        bool in_range = pkt.is_auth_packet();
        std::string name = "is_auth_packet() returns true for opcode " + std::to_string(opcode);
        print_test_result(name.c_str(), in_range);
    }
    
    // Opcodes just outside the range should return false
    Packet below(static_cast<uint8_t>(205));
    print_test_result("is_auth_packet() returns false for opcode 205", !below.is_auth_packet());
    
    Packet above(static_cast<uint8_t>(219));
    print_test_result("is_auth_packet() returns false for opcode 219", !above.is_auth_packet());
}

// ============================================================================
// Test Case 13: MINER_READY (216) is header-only and validates correctly
// ============================================================================
void test_miner_ready_header_only() {
    std::cout << "\nTest 13: MINER_READY (216) is header-only and validates correctly" << std::endl;
    
    // MINER_READY is header-only (no payload)
    Packet ready_pkt(static_cast<uint8_t>(216));
    
    // Should be in is_auth_packet() range
    bool test1 = ready_pkt.is_auth_packet();
    print_test_result("MINER_READY (216) is in is_auth_packet() range", test1);
    
    // Should still validate as valid (header-only request)
    bool test2 = ready_pkt.is_valid();
    print_test_result("MINER_READY (216) with m_length=0 validates as valid", test2);
}

// ============================================================================
// Test Case 14: Legacy data packet single-byte fragmentation
// When only 1 byte of a data packet (opcode < 128) arrives, it should NOT
// be treated as a header-only packet - NEED_MORE_DATA should be returned
// ============================================================================
void test_legacy_data_packet_single_byte() {
    std::cout << "\nTest 14: Legacy data packet single-byte fragmentation" << std::endl;
    
    TestAccumulator acc;
    Packet packet;
    ParseResult result;
    
    // Feed only 1 byte of a BLOCK_DATA (opcode 0) packet
    acc.feed({0x00});
    
    bool parsed1 = acc.parse_one_packet(ProtocolLane::LEGACY, packet, result);
    bool test1 = !parsed1 && (result == ParseResult::NEED_MORE_DATA) && (acc.size() == 1);
    print_test_result("Single byte of BLOCK_DATA triggers NEED_MORE_DATA", test1);
    
    // Feed remaining bytes (length + payload)
    acc.feed({0x00, 0x00, 0x00, 0x05, 'h', 'e', 'l', 'l', 'o'});
    
    bool parsed2 = acc.parse_one_packet(ProtocolLane::LEGACY, packet, result);
    bool test2 = parsed2 && 
                 (result == ParseResult::SUCCESS) &&
                 (packet.m_header == 0x00) &&
                 (packet.m_length == 5) &&
                 acc.empty();
    print_test_result("Complete BLOCK_DATA after fragmented single byte", test2);
    
    // Test with SUBMIT_BLOCK (opcode 1) - also a data packet
    acc.feed({0x01});
    
    bool parsed3 = acc.parse_one_packet(ProtocolLane::LEGACY, packet, result);
    bool test3 = !parsed3 && (result == ParseResult::NEED_MORE_DATA) && (acc.size() == 1);
    print_test_result("Single byte of SUBMIT_BLOCK triggers NEED_MORE_DATA", test3);
    
    acc.feed({0x00, 0x00, 0x00, 0x03, 'a', 'b', 'c'});
    
    bool parsed4 = acc.parse_one_packet(ProtocolLane::LEGACY, packet, result);
    bool test4 = parsed4 && 
                 (result == ParseResult::SUCCESS) &&
                 (packet.m_header == 0x01) &&
                 (packet.m_length == 3) &&
                 acc.empty();
    print_test_result("Complete SUBMIT_BLOCK after fragmented single byte", test4);
}

// ============================================================================
// Test Case 15: Legacy header-only opcode single-byte
// When a header-only opcode (>= 128, not auth) arrives as 1 byte,
// it should be treated as a complete packet
// ============================================================================
void test_legacy_header_only_single_byte() {
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
    print_test_result("GET_BLOCK (129) header-only packet parsed immediately", test1);
    
    // NEW_ROUND (204) has payload (12 bytes) - NOT header-only
    acc.feed({204});
    
    bool parsed2 = acc.parse_one_packet(ProtocolLane::LEGACY, packet, result);
    bool test2 = !parsed2 && (result == ParseResult::NEED_MORE_DATA) && (acc.size() == 1);
    print_test_result("NEW_ROUND (204) single byte triggers NEED_MORE_DATA (has payload)", test2);
    acc.clear();
    
    // PING (253) is header-only
    acc.feed({253});
    
    bool parsed3 = acc.parse_one_packet(ProtocolLane::LEGACY, packet, result);
    bool test3 = parsed3 && 
                 (result == ParseResult::SUCCESS) &&
                 (packet.m_header == 253) &&
                 (packet.m_length == 0) &&
                 acc.empty();
    print_test_result("PING (253) header-only packet parsed immediately", test3);
    
    // MINER_READY (216) is header-only even though it's in auth range
    acc.feed({216});
    
    bool parsed4 = acc.parse_one_packet(ProtocolLane::LEGACY, packet, result);
    bool test4 = parsed4 && 
                 (result == ParseResult::SUCCESS) &&
                 (packet.m_header == 216) &&
                 (packet.m_length == 0) &&
                 acc.empty();
    print_test_result("MINER_READY (216) header-only packet parsed immediately", test4);
}

// ============================================================================
// Test Case 16: MINER_AUTH_CHALLENGE (208 = 0xD0) rejected on legacy lane
// Byte 0xD0 on legacy lane is treated as cross-lane stateless framing.
// Auth opcodes that start with 0xD0 are only valid on stateless lane.
// ============================================================================
void test_legacy_auth_challenge_rejected() {
    std::cout << "\nTest 16: MINER_AUTH_CHALLENGE (0xD0) rejected on legacy lane" << std::endl;
    
    TestAccumulator acc;
    Packet packet;
    ParseResult result;
    
    // MINER_AUTH_CHALLENGE (208 = 0xD0) single byte - need more data to confirm
    acc.feed({208});
    
    bool parsed1 = acc.parse_one_packet(ProtocolLane::LEGACY, packet, result);
    bool test1 = !parsed1 && (result == ParseResult::NEED_MORE_DATA) && (acc.size() == 1);
    print_test_result("Single byte 0xD0 triggers NEED_MORE_DATA (need second byte)", test1);
    
    // After second byte arrives, cross-lane detection triggers MALFORMED
    acc.feed({0x00, 0x00, 0x00, 0x04, 0xAA, 0xBB, 0xCC, 0xDD});
    
    bool parsed2 = acc.parse_one_packet(ProtocolLane::LEGACY, packet, result);
    bool test2 = !parsed2 && (result == ParseResult::MALFORMED) && acc.empty();
    print_test_result("0xD0xx on legacy lane detected as MALFORMED (cross-lane)", test2);
}

// ============================================================================
// Test Case 17: Stateless data packet two-byte fragmentation
// When only 2 bytes of a stateless data packet arrive, NEED_MORE_DATA
// should be returned (not treated as header-only)
// ============================================================================
void test_stateless_data_packet_two_byte() {
    std::cout << "\nTest 17: Stateless data packet two-byte fragmentation" << std::endl;
    
    TestAccumulator acc;
    Packet packet;
    ParseResult result;
    
    // STATELESS_SUBMIT_BLOCK (0xD001) - has payload, only 2 bytes arrive
    acc.feed({0xD0, 0x01});
    
    bool parsed1 = acc.parse_one_packet(ProtocolLane::STATELESS, packet, result);
    bool test1 = !parsed1 && (result == ParseResult::NEED_MORE_DATA) && (acc.size() == 2);
    print_test_result("Two bytes of STATELESS_SUBMIT_BLOCK triggers NEED_MORE_DATA", test1);
    
    // Complete the packet
    acc.feed({0x00, 0x00, 0x00, 0x03, 'x', 'y', 'z'});
    
    bool parsed2 = acc.parse_one_packet(ProtocolLane::STATELESS, packet, result);
    bool test2 = parsed2 && 
                 (result == ParseResult::SUCCESS) &&
                 (packet.m_header == 0xD001) &&
                 (packet.m_length == 3) &&
                 acc.empty();
    print_test_result("Complete STATELESS_SUBMIT_BLOCK after fragmentation", test2);
}

// ============================================================================
// Test Case 18: Stateless header-only opcode two-byte
// When a stateless header-only opcode arrives as 2 bytes, it should be
// treated as a complete packet
// ============================================================================
void test_stateless_header_only_two_byte() {
    std::cout << "\nTest 18: Stateless header-only opcode two-byte" << std::endl;
    
    TestAccumulator acc;
    Packet packet;
    ParseResult result;
    
    // STATELESS_GET_BLOCK (0xD081) is header-only
    acc.feed({0xD0, 0x81});
    
    bool parsed1 = acc.parse_one_packet(ProtocolLane::STATELESS, packet, result);
    bool test1 = parsed1 && 
                 (result == ParseResult::SUCCESS) &&
                 (packet.m_header == 0xD081) &&
                 (packet.m_length == 0) &&
                 acc.empty();
    print_test_result("STATELESS_GET_BLOCK (0xD081) header-only parsed immediately", test1);
    
    // STATELESS MINER_READY (0xD0D8) is header-only
    acc.feed({0xD0, 0xD8});
    
    bool parsed2 = acc.parse_one_packet(ProtocolLane::STATELESS, packet, result);
    bool test2 = parsed2 && 
                 (result == ParseResult::SUCCESS) &&
                 (packet.m_header == 0xD0D8) &&
                 (packet.m_length == 0) &&
                 acc.empty();
    print_test_result("STATELESS_MINER_READY (0xD0D8) header-only parsed immediately", test2);
}

// ============================================================================
// Test Case 19: NEW_ROUND (204) with 12-byte payload
// NEW_ROUND carries payload: [unified_height][channel_height][difficulty]
// ============================================================================
void test_new_round_with_payload() {
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
    print_test_result("NEW_ROUND 12-byte payload parsed correctly", test1);
    
    // NEW_ROUND single byte should trigger NEED_MORE_DATA (not treated as header-only)
    acc.feed({204});
    
    bool parsed2 = acc.parse_one_packet(ProtocolLane::LEGACY, packet, result);
    bool test2 = !parsed2 && (result == ParseResult::NEED_MORE_DATA) && (acc.size() == 1);
    print_test_result("NEW_ROUND single byte triggers NEED_MORE_DATA", test2);
    acc.clear();
}

// ============================================================================
// Test Case 20: OLD_ROUND (205) with 12-byte payload
// OLD_ROUND carries payload: [unified_height][channel_height][difficulty]
// ============================================================================
void test_old_round_with_payload() {
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
    print_test_result("OLD_ROUND 12-byte payload parsed correctly", test1);
    
    // OLD_ROUND single byte should trigger NEED_MORE_DATA
    acc.feed({205});
    
    bool parsed2 = acc.parse_one_packet(ProtocolLane::LEGACY, packet, result);
    bool test2 = !parsed2 && (result == ParseResult::NEED_MORE_DATA) && (acc.size() == 1);
    print_test_result("OLD_ROUND single byte triggers NEED_MORE_DATA", test2);
    acc.clear();
}

// ============================================================================
// Test Case 21: NEW_ROUND/OLD_ROUND with legacy 16-byte payload
// Legacy lane accepts 16-byte format: [unified][prime][hash][stake]
// ============================================================================
void test_round_legacy_16byte_payload() {
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
    print_test_result("NEW_ROUND 16-byte legacy payload parsed correctly", test1);
}

// ============================================================================
// Test Case 22: ACCEPT/REJECT still header-only (regression check)
// Ensure the fix doesn't break ACCEPT (200) and REJECT (201) classification
// ============================================================================
void test_accept_reject_still_header_only() {
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
    print_test_result("ACCEPT (200) still header-only", test1);
    
    // REJECT (201) should still be header-only
    acc.feed({201});
    
    bool parsed2 = acc.parse_one_packet(ProtocolLane::LEGACY, packet, result);
    bool test2 = parsed2 && 
                 (result == ParseResult::SUCCESS) &&
                 (packet.m_header == 201) &&
                 (packet.m_length == 0) &&
                 acc.empty();
    print_test_result("REJECT (201) still header-only", test2);
    
    // COINBASE_SET (202) should still be header-only
    acc.feed({202});
    
    bool parsed3 = acc.parse_one_packet(ProtocolLane::LEGACY, packet, result);
    bool test3 = parsed3 && 
                 (result == ParseResult::SUCCESS) &&
                 (packet.m_header == 202) &&
                 (packet.m_length == 0) &&
                 acc.empty();
    print_test_result("COINBASE_SET (202) still header-only", test3);
    
    // COINBASE_FAIL (203) should still be header-only
    acc.feed({203});
    
    bool parsed4 = acc.parse_one_packet(ProtocolLane::LEGACY, packet, result);
    bool test4 = parsed4 && 
                 (result == ParseResult::SUCCESS) &&
                 (packet.m_header == 203) &&
                 (packet.m_length == 0) &&
                 acc.empty();
    print_test_result("COINBASE_FAIL (203) still header-only", test4);
}

// ============================================================================
// Test Case 23: Cross-lane detection - stateless bytes on legacy lane
// Sending stateless framing (0xD0xx 2-byte headers) to a legacy port
// should cause MALFORMED disconnect, not desync
// ============================================================================
void test_cross_lane_stateless_on_legacy() {
    std::cout << "\nTest 23: Cross-lane detection - stateless bytes on legacy lane" << std::endl;
    
    TestAccumulator acc;
    Packet packet;
    ParseResult result;
    
    // Stateless GET_BLOCK (0xD081) sent to legacy port
    acc.feed({0xD0, 0x81});
    
    bool parsed1 = acc.parse_one_packet(ProtocolLane::LEGACY, packet, result);
    bool test1 = !parsed1 && (result == ParseResult::MALFORMED) && acc.empty();
    print_test_result("Stateless GET_BLOCK (0xD081) on legacy lane → MALFORMED", test1);
    
    // Stateless SUBMIT_BLOCK (0xD001) with payload sent to legacy port
    acc.feed({0xD0, 0x01, 0x00, 0x00, 0x00, 0x04, 't', 'e', 's', 't'});
    
    bool parsed2 = acc.parse_one_packet(ProtocolLane::LEGACY, packet, result);
    bool test2 = !parsed2 && (result == ParseResult::MALFORMED) && acc.empty();
    print_test_result("Stateless SUBMIT_BLOCK (0xD001) on legacy lane → MALFORMED", test2);
    
    // Stateless MINER_READY (0xD0D8) sent to legacy port
    acc.feed({0xD0, 0xD8});
    
    bool parsed3 = acc.parse_one_packet(ProtocolLane::LEGACY, packet, result);
    bool test3 = !parsed3 && (result == ParseResult::MALFORMED) && acc.empty();
    print_test_result("Stateless MINER_READY (0xD0D8) on legacy lane → MALFORMED", test3);
    
    // Confirm: 0xD0 single byte triggers NEED_MORE_DATA (not immediate MALFORMED)
    acc.feed({0xD0});
    
    bool parsed4 = acc.parse_one_packet(ProtocolLane::LEGACY, packet, result);
    bool test4 = !parsed4 && (result == ParseResult::NEED_MORE_DATA) && (acc.size() == 1);
    print_test_result("Single 0xD0 byte on legacy lane → NEED_MORE_DATA", test4);
    acc.clear();
}

// ============================================================================
// Test Case 24: Cross-lane detection - legacy bytes on stateless lane
// Sending legacy framing (1-byte headers) to a stateless port
// should cause MALFORMED disconnect
// ============================================================================
void test_cross_lane_legacy_on_stateless() {
    std::cout << "\nTest 24: Cross-lane detection - legacy bytes on stateless lane" << std::endl;
    
    TestAccumulator acc;
    Packet packet;
    ParseResult result;
    
    // Legacy GET_BLOCK (0x81) sent to stateless port
    // As a 2-byte stateless header, 0x8100 is NOT in 0xD000-0xD0FF range → MALFORMED
    acc.feed({0x81, 0x00});
    
    bool parsed1 = acc.parse_one_packet(ProtocolLane::STATELESS, packet, result);
    bool test1 = !parsed1 && (result == ParseResult::MALFORMED) && acc.empty();
    print_test_result("Legacy GET_BLOCK (0x81) on stateless lane → MALFORMED", test1);
    
    // Legacy SUBMIT_BLOCK data packet on stateless port
    acc.feed({0x01, 0x00, 0x00, 0x00, 0x03, 'a', 'b', 'c'});
    
    bool parsed2 = acc.parse_one_packet(ProtocolLane::STATELESS, packet, result);
    bool test2 = !parsed2 && (result == ParseResult::MALFORMED) && acc.empty();
    print_test_result("Legacy SUBMIT_BLOCK (0x01) on stateless lane → MALFORMED", test2);
    
    // Legacy ACCEPT (0xC8) on stateless port
    acc.feed({0xC8, 0x00});
    
    bool parsed3 = acc.parse_one_packet(ProtocolLane::STATELESS, packet, result);
    bool test3 = !parsed3 && (result == ParseResult::MALFORMED) && acc.empty();
    print_test_result("Legacy ACCEPT (0xC8) on stateless lane → MALFORMED", test3);
}

// ============================================================================
// Test Case 25: TX lane enforcement - get_bytes(ProtocolLane)
// Ensures packets are only serialized when they match the lane format
// ============================================================================
void test_tx_lane_enforcement() {
    std::cout << "\nTest 25: TX lane enforcement - get_bytes(ProtocolLane)" << std::endl;
    
    // Legacy packet (uint8 opcode)
    Packet legacy_pkt(static_cast<uint8_t>(Packet::GET_BLOCK));
    
    // Legacy packet on LEGACY lane → OK
    auto bytes1 = legacy_pkt.get_bytes(ProtocolLane::LEGACY);
    print_test_result("Legacy packet on LEGACY lane → bytes returned",
        bytes1 && bytes1->size() > 0);
    
    // Legacy packet on STATELESS lane → rejected
    auto bytes2 = legacy_pkt.get_bytes(ProtocolLane::STATELESS);
    print_test_result("Legacy packet on STATELESS lane → rejected (empty)",
        !bytes2 || bytes2->empty());
    
    // Legacy packet on UNKNOWN lane → rejected
    auto bytes3 = legacy_pkt.get_bytes(ProtocolLane::UNKNOWN);
    print_test_result("Legacy packet on UNKNOWN lane → rejected (empty)",
        !bytes3 || bytes3->empty());
    
    // Stateless packet (uint16 opcode)
    Packet stateless_pkt(static_cast<uint16_t>(Packet::STATELESS_GET_BLOCK));
    
    // Stateless packet on STATELESS lane → OK
    auto bytes4 = stateless_pkt.get_bytes(ProtocolLane::STATELESS);
    print_test_result("Stateless packet on STATELESS lane → bytes returned",
        bytes4 && bytes4->size() > 0);
    
    // Stateless packet on LEGACY lane → rejected
    auto bytes5 = stateless_pkt.get_bytes(ProtocolLane::LEGACY);
    print_test_result("Stateless packet on LEGACY lane → rejected (empty)",
        !bytes5 || bytes5->empty());
    
    // Stateless packet on UNKNOWN lane → rejected
    auto bytes6 = stateless_pkt.get_bytes(ProtocolLane::UNKNOWN);
    print_test_result("Stateless packet on UNKNOWN lane → rejected (empty)",
        !bytes6 || bytes6->empty());
    
    // Data packet TX enforcement
    network::Payload payload_data(12, 0xAB);
    
    Packet legacy_data(static_cast<uint8_t>(Packet::SUBMIT_BLOCK), payload_data);
    auto bytes7 = legacy_data.get_bytes(ProtocolLane::LEGACY);
    print_test_result("Legacy data packet on LEGACY lane → bytes returned",
        bytes7 && bytes7->size() == 17);  // 1 + 4 + 12
    
    auto bytes8 = legacy_data.get_bytes(ProtocolLane::STATELESS);
    print_test_result("Legacy data packet on STATELESS lane → rejected",
        !bytes8 || bytes8->empty());
    
    Packet stateless_data(static_cast<uint16_t>(Packet::STATELESS_SUBMIT_BLOCK), payload_data);
    auto bytes9 = stateless_data.get_bytes(ProtocolLane::STATELESS);
    print_test_result("Stateless data packet on STATELESS lane → bytes returned",
        bytes9 && bytes9->size() == 18);  // 2 + 4 + 12
    
    auto bytes10 = stateless_data.get_bytes(ProtocolLane::LEGACY);
    print_test_result("Stateless data packet on LEGACY lane → rejected",
        !bytes10 || bytes10->empty());
}

// ============================================================================
// Test Case 26: Correct-lane parsing OK (regression check)
// Ensure normal packets on their correct lane still parse successfully
// ============================================================================
void test_correct_lane_parses_ok() {
    std::cout << "\nTest 26: Correct-lane parsing OK (regression check)" << std::endl;
    
    TestAccumulator acc;
    Packet packet;
    ParseResult result;
    
    // Legacy ACCEPT (200) on legacy lane → OK
    acc.feed({200});
    bool parsed1 = acc.parse_one_packet(ProtocolLane::LEGACY, packet, result);
    print_test_result("Legacy ACCEPT on legacy lane → SUCCESS",
        parsed1 && result == ParseResult::SUCCESS && packet.m_header == 200);
    
    // Legacy CHANNEL_ACK (206 = 0xCE) on legacy lane → OK (not 0xD0)
    acc.feed({206, 0x00, 0x00, 0x00, 0x01, 0xFF});
    bool parsed2 = acc.parse_one_packet(ProtocolLane::LEGACY, packet, result);
    print_test_result("Legacy CHANNEL_ACK (206) on legacy lane → SUCCESS",
        parsed2 && result == ParseResult::SUCCESS && packet.m_header == 206);
    
    // Legacy MINER_AUTH_INIT (207 = 0xCF) on legacy lane → OK (not 0xD0)
    acc.feed({207, 0x00, 0x00, 0x00, 0x02, 0xAA, 0xBB});
    bool parsed3 = acc.parse_one_packet(ProtocolLane::LEGACY, packet, result);
    print_test_result("Legacy MINER_AUTH_INIT (207) on legacy lane → SUCCESS",
        parsed3 && result == ParseResult::SUCCESS && packet.m_header == 207);
    
    // Legacy MINER_AUTH_RESPONSE (209 = 0xD1) on legacy lane → OK (not 0xD0)
    acc.feed({209, 0x00, 0x00, 0x00, 0x02, 0xCC, 0xDD});
    bool parsed4 = acc.parse_one_packet(ProtocolLane::LEGACY, packet, result);
    print_test_result("Legacy MINER_AUTH_RESPONSE (209) on legacy lane → SUCCESS",
        parsed4 && result == ParseResult::SUCCESS && packet.m_header == 209);
    
    // Stateless GET_BLOCK (0xD081) on stateless lane → OK
    acc.feed({0xD0, 0x81});
    bool parsed5 = acc.parse_one_packet(ProtocolLane::STATELESS, packet, result);
    print_test_result("Stateless GET_BLOCK (0xD081) on stateless lane → SUCCESS",
        parsed5 && result == ParseResult::SUCCESS && packet.m_header == 0xD081);
    
    // Stateless SUBMIT_BLOCK (0xD001) with payload on stateless lane → OK
    acc.feed({0xD0, 0x01, 0x00, 0x00, 0x00, 0x03, 'x', 'y', 'z'});
    bool parsed6 = acc.parse_one_packet(ProtocolLane::STATELESS, packet, result);
    print_test_result("Stateless SUBMIT_BLOCK (0xD001) on stateless lane → SUCCESS",
        parsed6 && result == ParseResult::SUCCESS && packet.m_header == 0xD001);
}

// ============================================================================
// Main test runner
// ============================================================================
int main() {
    std::cout << "========================================" << std::endl;
    std::cout << "LLP Packet Framing Test Suite" << std::endl;
    std::cout << "Testing TCP fragmentation handling" << std::endl;
    std::cout << "========================================" << std::endl;
    
    test_complete_packet_single_receive();
    test_header_fragmented();
    test_payload_fragmented();
    test_multiple_packets_single_receive();
    test_stateless_header_fragmented();
    test_malformed_huge_length();
    test_malformed_invalid_stateless_opcode();
    test_complex_mixed_scenario();
    test_byte_by_byte_feeding();
    test_zero_length_payload();
    test_push_notification_legacy_lane();
    test_is_auth_packet_full_range();
    test_miner_ready_header_only();
    test_legacy_data_packet_single_byte();
    test_legacy_header_only_single_byte();
    test_legacy_auth_challenge_rejected();
    test_stateless_data_packet_two_byte();
    test_stateless_header_only_two_byte();
    test_new_round_with_payload();
    test_old_round_with_payload();
    test_round_legacy_16byte_payload();
    test_accept_reject_still_header_only();
    test_cross_lane_stateless_on_legacy();
    test_cross_lane_legacy_on_stateless();
    test_tx_lane_enforcement();
    test_correct_lane_parses_ok();
    
    std::cout << "\n========================================" << std::endl;
    std::cout << "Test Summary" << std::endl;
    std::cout << "========================================" << std::endl;
    std::cout << "Tests run:    " << tests_run << std::endl;
    std::cout << "Tests passed: " << tests_passed << std::endl;
    std::cout << "Tests failed: " << tests_failed << std::endl;
    std::cout << "Success rate: " << (tests_run > 0 ? (100 * tests_passed / tests_run) : 0) << "%" << std::endl;
    std::cout << "========================================" << std::endl;
    
    return (tests_failed == 0) ? 0 : 1;
}
