/**
 * @file session_start_parser_test.cpp
 * @brief Unit tests for SESSION_START packet parser
 *
 * Tests parsing of SESSION_START packets in various configurations:
 *  1. Minimum valid packet (success + session_id + timeout, 9 bytes)
 *  2. Full packet: success + session_id + timeout + genesis (41 bytes)
 *  3. Invalid: null data pointer
 *  4. Invalid: insufficient data (< 9 bytes)
 *  5. Invalid: partial genesis hash (10-40 bytes)
 *  6. Excess data (> 41 bytes, should parse successfully)
 *  7. Success byte validation
 *  8. Session ID parsing (little-endian)
 *  9. Timeout value parsing (little-endian)
 * 10. Keepalive interval calculation
 */

#include "protocol/session_start_parser.hpp"
#include <iostream>
#include <vector>
#include <cstring>
#include <gtest/gtest.h>

using namespace nexusminer::protocol;

// Helper: Create test packet with success byte, session_id, and timeout
std::vector<uint8_t> make_session_start_packet(uint8_t success, uint32_t session_id, uint32_t timeout) {
    std::vector<uint8_t> packet(9);
    // Success byte (offset 0)
    packet[0] = success;
    // Session ID (4 bytes LE, offset 1-4)
    packet[1] = session_id & 0xFF;
    packet[2] = (session_id >> 8) & 0xFF;
    packet[3] = (session_id >> 16) & 0xFF;
    packet[4] = (session_id >> 24) & 0xFF;
    // Timeout (4 bytes LE, offset 5-8)
    packet[5] = timeout & 0xFF;
    packet[6] = (timeout >> 8) & 0xFF;
    packet[7] = (timeout >> 16) & 0xFF;
    packet[8] = (timeout >> 24) & 0xFF;
    return packet;
}

// Helper: Append 32-byte field
void append_32bytes(std::vector<uint8_t>& packet, uint8_t fill_value) {
    for (int i = 0; i < 32; ++i) {
        packet.push_back(fill_value);
    }
}

// ============================================================================
// Test 1: Minimum valid packet (success + session_id + timeout, 9 bytes)
// ============================================================================
TEST(SessionStartParserTest, test_minimum_valid_packet) {
    std::cout << "\nTest 1: Minimum valid packet (9 bytes: success+session_id+timeout)\n";

    // Create packet: [success=0x01][session_id=0x12345678][timeout=3600 seconds (1 hour)]
    auto packet = make_session_start_packet(0x01, 0x12345678, 3600);

    auto result = parse_session_start(packet);
    bool ok = result.has_value() &&
              result->success == 0x01 &&
              result->session_id == 0x12345678 &&
              result->timeout_seconds == 3600 &&
              !result->has_genesis_hash();

    EXPECT_TRUE(ok) << "Parse 9-byte minimum packet";
}

// ============================================================================
// Test 2: Full packet (success + session_id + timeout + genesis, 41 bytes)
// ============================================================================
TEST(SessionStartParserTest, test_full_packet) {
    std::cout << "\nTest 2: Full packet (41 bytes: success+session_id+timeout+genesis)\n";

    // Create packet: [success=0x01][session_id=0xABCDEF01][timeout=86400 (24 hours)] + [32-byte genesis]
    auto packet = make_session_start_packet(0x01, 0xABCDEF01, 86400);
    append_32bytes(packet, 0xEF);  // Genesis hash

    auto result = parse_session_start(packet);
    bool ok = result.has_value() &&
              result->success == 0x01 &&
              result->session_id == 0xABCDEF01 &&
              result->timeout_seconds == 86400 &&
              result->has_genesis_hash() &&
              result->genesis_hash->size() == 32 &&
              (*result->genesis_hash)[0] == 0xEF;

    EXPECT_TRUE(ok) << "Parse 41-byte full packet";
}

// ============================================================================
// Test 3: Invalid - null data pointer
// ============================================================================
TEST(SessionStartParserTest, test_null_data_pointer) {
    std::cout << "\nTest 3: Invalid - null data pointer\n";

    auto result = parse_session_start(nullptr, 9);
    bool ok = !result.has_value();

    EXPECT_TRUE(ok) << "Reject null data pointer";
}

// ============================================================================
// Test 4: Invalid - insufficient data (< 9 bytes)
// ============================================================================
TEST(SessionStartParserTest, test_insufficient_data) {
    std::cout << "\nTest 4: Invalid - insufficient data\n";

    // Test 0 bytes
    std::vector<uint8_t> empty;
    auto result1 = parse_session_start(empty);
    bool ok1 = !result1.has_value();
    EXPECT_TRUE(ok1) << "Reject 0-byte packet";

    // Test 1 byte
    std::vector<uint8_t> one_byte = {0x01};
    auto result2 = parse_session_start(one_byte);
    bool ok2 = !result2.has_value();
    EXPECT_TRUE(ok2) << "Reject 1-byte packet";

    // Test 8 bytes (one short of minimum)
    std::vector<uint8_t> eight_bytes = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
    auto result3 = parse_session_start(eight_bytes);
    bool ok3 = !result3.has_value();
    EXPECT_TRUE(ok3) << "Reject 8-byte packet";
}

// ============================================================================
// Test 5: Invalid - partial genesis hash (10-40 bytes)
// ============================================================================
TEST(SessionStartParserTest, test_partial_genesis_hash) {
    std::cout << "\nTest 5: Invalid - partial genesis hash\n";

    // Test 10 bytes (9-byte minimum + 1 byte of genesis)
    auto packet1 = make_session_start_packet(0x01, 0x1000, 1000);
    packet1.push_back(0xDD);        // 1 byte of genesis
    auto result1 = parse_session_start(packet1);
    bool ok1 = !result1.has_value();
    EXPECT_TRUE(ok1) << "Reject 10-byte packet (partial genesis)";

    // Test 25 bytes (9-byte minimum + 16 bytes of genesis)
    auto packet2 = make_session_start_packet(0x01, 0x2000, 2000);
    for (int i = 0; i < 16; ++i) packet2.push_back(0xEE);
    auto result2 = parse_session_start(packet2);
    bool ok2 = !result2.has_value();
    EXPECT_TRUE(ok2) << "Reject 25-byte packet (partial genesis)";

    // Test 40 bytes (9-byte minimum + 31 bytes of genesis)
    auto packet3 = make_session_start_packet(0x01, 0x3000, 3000);
    for (int i = 0; i < 31; ++i) packet3.push_back(0xFF);
    auto result3 = parse_session_start(packet3);
    bool ok3 = !result3.has_value();
    EXPECT_TRUE(ok3) << "Reject 40-byte packet (partial genesis)";
}

// ============================================================================
// Test 6: Excess data (> 41 bytes, should parse successfully and ignore extra)
// ============================================================================
TEST(SessionStartParserTest, test_excess_data) {
    std::cout << "\nTest 6: Excess data (> 41 bytes)\n";

    // Create 73-byte packet (41 valid + 32 excess)
    auto packet = make_session_start_packet(0x01, 0x5000, 5000);
    append_32bytes(packet, 0x22);  // Genesis hash
    for (int i = 0; i < 32; ++i) packet.push_back(0x99);  // Excess data

    auto result = parse_session_start(packet);
    bool ok = result.has_value() &&
              result->success == 0x01 &&
              result->session_id == 0x5000 &&
              result->timeout_seconds == 5000 &&
              result->has_genesis_hash();

    EXPECT_TRUE(ok) << "Parse 73-byte packet (ignore excess)";
}

// ============================================================================
// Test 7: Success byte validation
// ============================================================================
TEST(SessionStartParserTest, test_success_byte) {
    std::cout << "\nTest 7: Success byte validation\n";

    // Test success=0x01 (valid)
    auto packet1 = make_session_start_packet(0x01, 0x1234, 1000);
    auto result1 = parse_session_start(packet1);
    bool ok1 = result1.has_value() && result1->success == 0x01;
    EXPECT_TRUE(ok1) << "Parse with success=0x01";

    // Test success=0x00 (should still parse, validation happens elsewhere)
    auto packet2 = make_session_start_packet(0x00, 0x5678, 2000);
    auto result2 = parse_session_start(packet2);
    bool ok2 = result2.has_value() && result2->success == 0x00;
    EXPECT_TRUE(ok2) << "Parse with success=0x00";

    // Test success=0xFF (should still parse, validation happens elsewhere)
    auto packet3 = make_session_start_packet(0xFF, 0xABCD, 3000);
    auto result3 = parse_session_start(packet3);
    bool ok3 = result3.has_value() && result3->success == 0xFF;
    EXPECT_TRUE(ok3) << "Parse with success=0xFF";
}

// ============================================================================
// Test 8: Session ID parsing (little-endian)
// ============================================================================
TEST(SessionStartParserTest, test_session_id_endianness) {
    std::cout << "\nTest 8: Session ID parsing (little-endian)\n";

    // Test 1: 0x12345678 in little-endian → [0x78, 0x56, 0x34, 0x12]
    auto packet1 = make_session_start_packet(0x01, 0x12345678, 1000);
    auto result1 = parse_session_start(packet1);
    bool ok1 = result1.has_value() && result1->session_id == 0x12345678;
    EXPECT_TRUE(ok1) << "Parse session_id 0x12345678 (LE)";

    // Test 2: 0x00000001 → [0x01, 0x00, 0x00, 0x00]
    auto packet2 = make_session_start_packet(0x01, 0x00000001, 2000);
    auto result2 = parse_session_start(packet2);
    bool ok2 = result2.has_value() && result2->session_id == 1;
    EXPECT_TRUE(ok2) << "Parse session_id 1 (LE)";

    // Test 3: 0xFFFFFFFF → [0xFF, 0xFF, 0xFF, 0xFF]
    auto packet3 = make_session_start_packet(0x01, 0xFFFFFFFF, 3000);
    auto result3 = parse_session_start(packet3);
    bool ok3 = result3.has_value() && result3->session_id == 0xFFFFFFFF;
    EXPECT_TRUE(ok3) << "Parse session_id max uint32 (LE)";
}

// ============================================================================
// Test 9: Timeout value parsing (little-endian)
// ============================================================================
TEST(SessionStartParserTest, test_timeout_endianness) {
    std::cout << "\nTest 9: Timeout value parsing (little-endian)\n";

    // Test 1: 0x12345678 in little-endian → timeout at offset 5-8
    auto packet1 = make_session_start_packet(0x01, 0x1111, 0x12345678);
    auto result1 = parse_session_start(packet1);
    bool ok1 = result1.has_value() && result1->timeout_seconds == 0x12345678;
    EXPECT_TRUE(ok1) << "Parse timeout 0x12345678 (LE)";

    // Test 2: 0x00000001 → 1 second
    auto packet2 = make_session_start_packet(0x01, 0x2222, 1);
    auto result2 = parse_session_start(packet2);
    bool ok2 = result2.has_value() && result2->timeout_seconds == 1;
    EXPECT_TRUE(ok2) << "Parse 1 second timeout (LE)";

    // Test 3: 0xFFFFFFFF → max uint32
    auto packet3 = make_session_start_packet(0x01, 0x3333, 0xFFFFFFFF);
    auto result3 = parse_session_start(packet3);
    bool ok3 = result3.has_value() && result3->timeout_seconds == 0xFFFFFFFF;
    EXPECT_TRUE(ok3) << "Parse max uint32 timeout (LE)";
}

// ============================================================================
// Test 10: Keepalive interval calculation
// ============================================================================
TEST(SessionStartParserTest, test_keepalive_calculation) {
    std::cout << "\nTest 10: Keepalive interval calculation\n";

    // Test 1: 86400 seconds (24 hours) with safety=2 → 12 hours
    uint16_t hours1 = calculate_keepalive_hours(86400, 2);
    bool ok1 = (hours1 == 12);
    EXPECT_TRUE(ok1) << "24h timeout → 12h keepalive (safety=2)";

    // Test 2: 43200 seconds (12 hours) with safety=2 → 6 hours
    uint16_t hours2 = calculate_keepalive_hours(43200, 2);
    bool ok2 = (hours2 == 6);
    EXPECT_TRUE(ok2) << "12h timeout → 6h keepalive (safety=2)";

    // Test 3: 3600 seconds (1 hour) with safety=2 → 1 hour (minimum)
    uint16_t hours3 = calculate_keepalive_hours(3600, 2);
    bool ok3 = (hours3 == 1);
    EXPECT_TRUE(ok3) << "1h timeout → 1h keepalive (minimum)";

    // Test 4: 0 seconds → 1 hour (minimum)
    uint16_t hours4 = calculate_keepalive_hours(0, 2);
    bool ok4 = (hours4 == 1);
    EXPECT_TRUE(ok4) << "0s timeout → 1h keepalive (minimum)";

    // Test 5: 7200 seconds (2 hours) with safety=2 → 1 hour
    uint16_t hours5 = calculate_keepalive_hours(7200, 2);
    bool ok5 = (hours5 == 1);
    EXPECT_TRUE(ok5) << "2h timeout → 1h keepalive (safety=2)";
}

// ============================================================================
// Main
// ============================================================================
