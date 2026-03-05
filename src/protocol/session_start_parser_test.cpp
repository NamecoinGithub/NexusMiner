/**
 * @file session_start_parser_test.cpp
 * @brief Unit tests for SESSION_START packet parser
 *
 * Tests parsing of SESSION_START packets in various configurations:
 *  1. Minimum valid packet (timeout only, 4 bytes)
 *  2. Timeout + session key (36 bytes)
 *  3. Full packet: timeout + session key + genesis (68 bytes)
 *  4. Invalid: null data pointer
 *  5. Invalid: insufficient data (< 4 bytes)
 *  6. Invalid: partial session key (5-35 bytes)
 *  7. Invalid: partial genesis hash (37-67 bytes)
 *  8. Excess data (> 68 bytes, should parse successfully)
 *  9. Timeout value parsing (little-endian)
 * 10. Keepalive interval calculation
 */

#include "protocol/session_start_parser.hpp"
#include <iostream>
#include <cassert>
#include <vector>
#include <cstring>

using namespace nexusminer::protocol;

// Test statistics
static int tests_run = 0;
static int tests_passed = 0;
static int tests_failed = 0;

void print_test_result(const char* name, bool passed) {
    tests_run++;
    if (passed) {
        tests_passed++;
        std::cout << "  [PASS] " << name << "\n";
    } else {
        tests_failed++;
        std::cout << "  [FAIL] " << name << "\n";
    }
}

// Helper: Create test packet with timeout
std::vector<uint8_t> make_timeout_packet(uint32_t timeout) {
    std::vector<uint8_t> packet(4);
    packet[0] = timeout & 0xFF;
    packet[1] = (timeout >> 8) & 0xFF;
    packet[2] = (timeout >> 16) & 0xFF;
    packet[3] = (timeout >> 24) & 0xFF;
    return packet;
}

// Helper: Append 32-byte field
void append_32bytes(std::vector<uint8_t>& packet, uint8_t fill_value) {
    for (int i = 0; i < 32; ++i) {
        packet.push_back(fill_value);
    }
}

// ============================================================================
// Test 1: Minimum valid packet (timeout only, 4 bytes)
// ============================================================================
void test_minimum_valid_packet() {
    std::cout << "\nTest 1: Minimum valid packet (timeout only)\n";

    // Create packet: [timeout=3600 seconds (1 hour)]
    auto packet = make_timeout_packet(3600);

    auto result = parse_session_start(packet);
    bool ok = result.has_value() &&
              result->timeout_seconds == 3600 &&
              !result->has_session_key() &&
              !result->has_genesis_hash();

    print_test_result("Parse 4-byte timeout-only packet", ok);
}

// ============================================================================
// Test 2: Timeout + session key (36 bytes)
// ============================================================================
void test_timeout_plus_session_key() {
    std::cout << "\nTest 2: Timeout + session key (36 bytes)\n";

    // Create packet: [timeout=7200] + [32-byte session key]
    auto packet = make_timeout_packet(7200);
    append_32bytes(packet, 0xAB);  // Session key filled with 0xAB

    auto result = parse_session_start(packet);
    bool ok = result.has_value() &&
              result->timeout_seconds == 7200 &&
              result->has_session_key() &&
              result->session_key->size() == 32 &&
              (*result->session_key)[0] == 0xAB &&
              !result->has_genesis_hash();

    print_test_result("Parse 36-byte packet with session key", ok);
}

// ============================================================================
// Test 3: Full packet (timeout + session key + genesis, 68 bytes)
// ============================================================================
void test_full_packet() {
    std::cout << "\nTest 3: Full packet (timeout + key + genesis)\n";

    // Create packet: [timeout=86400] + [32-byte key] + [32-byte genesis]
    auto packet = make_timeout_packet(86400);  // 24 hours
    append_32bytes(packet, 0xCD);  // Session key
    append_32bytes(packet, 0xEF);  // Genesis hash

    auto result = parse_session_start(packet);
    bool ok = result.has_value() &&
              result->timeout_seconds == 86400 &&
              result->has_session_key() &&
              result->session_key->size() == 32 &&
              (*result->session_key)[0] == 0xCD &&
              result->has_genesis_hash() &&
              result->genesis_hash->size() == 32 &&
              (*result->genesis_hash)[0] == 0xEF;

    print_test_result("Parse 68-byte full packet", ok);
}

// ============================================================================
// Test 4: Invalid - null data pointer
// ============================================================================
void test_null_data_pointer() {
    std::cout << "\nTest 4: Invalid - null data pointer\n";

    auto result = parse_session_start(nullptr, 4);
    bool ok = !result.has_value();

    print_test_result("Reject null data pointer", ok);
}

// ============================================================================
// Test 5: Invalid - insufficient data (< 4 bytes)
// ============================================================================
void test_insufficient_data() {
    std::cout << "\nTest 5: Invalid - insufficient data\n";

    // Test 0 bytes
    std::vector<uint8_t> empty;
    auto result1 = parse_session_start(empty);
    bool ok1 = !result1.has_value();
    print_test_result("Reject 0-byte packet", ok1);

    // Test 1 byte
    std::vector<uint8_t> one_byte = {0x01};
    auto result2 = parse_session_start(one_byte);
    bool ok2 = !result2.has_value();
    print_test_result("Reject 1-byte packet", ok2);

    // Test 3 bytes
    std::vector<uint8_t> three_bytes = {0x01, 0x02, 0x03};
    auto result3 = parse_session_start(three_bytes);
    bool ok3 = !result3.has_value();
    print_test_result("Reject 3-byte packet", ok3);
}

// ============================================================================
// Test 6: Invalid - partial session key (5-35 bytes)
// ============================================================================
void test_partial_session_key() {
    std::cout << "\nTest 6: Invalid - partial session key\n";

    // Test 5 bytes (timeout + 1 byte of key)
    auto packet1 = make_timeout_packet(1000);
    packet1.push_back(0xAA);
    auto result1 = parse_session_start(packet1);
    bool ok1 = !result1.has_value();
    print_test_result("Reject 5-byte packet (partial key)", ok1);

    // Test 20 bytes (timeout + 16 bytes of key)
    auto packet2 = make_timeout_packet(1000);
    for (int i = 0; i < 16; ++i) packet2.push_back(0xBB);
    auto result2 = parse_session_start(packet2);
    bool ok2 = !result2.has_value();
    print_test_result("Reject 20-byte packet (partial key)", ok2);

    // Test 35 bytes (timeout + 31 bytes of key)
    auto packet3 = make_timeout_packet(1000);
    for (int i = 0; i < 31; ++i) packet3.push_back(0xCC);
    auto result3 = parse_session_start(packet3);
    bool ok3 = !result3.has_value();
    print_test_result("Reject 35-byte packet (partial key)", ok3);
}

// ============================================================================
// Test 7: Invalid - partial genesis hash (37-67 bytes)
// ============================================================================
void test_partial_genesis_hash() {
    std::cout << "\nTest 7: Invalid - partial genesis hash\n";

    // Test 37 bytes (timeout + full key + 1 byte of genesis)
    auto packet1 = make_timeout_packet(1000);
    append_32bytes(packet1, 0xAA);  // Full session key
    packet1.push_back(0xDD);        // 1 byte of genesis
    auto result1 = parse_session_start(packet1);
    bool ok1 = !result1.has_value();
    print_test_result("Reject 37-byte packet (partial genesis)", ok1);

    // Test 50 bytes (timeout + full key + 14 bytes of genesis)
    auto packet2 = make_timeout_packet(1000);
    append_32bytes(packet2, 0xBB);
    for (int i = 0; i < 14; ++i) packet2.push_back(0xEE);
    auto result2 = parse_session_start(packet2);
    bool ok2 = !result2.has_value();
    print_test_result("Reject 50-byte packet (partial genesis)", ok2);

    // Test 67 bytes (timeout + full key + 31 bytes of genesis)
    auto packet3 = make_timeout_packet(1000);
    append_32bytes(packet3, 0xCC);
    for (int i = 0; i < 31; ++i) packet3.push_back(0xFF);
    auto result3 = parse_session_start(packet3);
    bool ok3 = !result3.has_value();
    print_test_result("Reject 67-byte packet (partial genesis)", ok3);
}

// ============================================================================
// Test 8: Excess data (> 68 bytes, should parse successfully and ignore extra)
// ============================================================================
void test_excess_data() {
    std::cout << "\nTest 8: Excess data (> 68 bytes)\n";

    // Create 100-byte packet (68 valid + 32 excess)
    auto packet = make_timeout_packet(5000);
    append_32bytes(packet, 0x11);  // Session key
    append_32bytes(packet, 0x22);  // Genesis hash
    for (int i = 0; i < 32; ++i) packet.push_back(0x99);  // Excess data

    auto result = parse_session_start(packet);
    bool ok = result.has_value() &&
              result->timeout_seconds == 5000 &&
              result->has_session_key() &&
              result->has_genesis_hash();

    print_test_result("Parse 100-byte packet (ignore excess)", ok);
}

// ============================================================================
// Test 9: Timeout value parsing (little-endian)
// ============================================================================
void test_timeout_endianness() {
    std::cout << "\nTest 9: Timeout value parsing (little-endian)\n";

    // Test 1: 0x12345678 in little-endian → [0x78, 0x56, 0x34, 0x12]
    std::vector<uint8_t> packet1 = {0x78, 0x56, 0x34, 0x12};
    auto result1 = parse_session_start(packet1);
    bool ok1 = result1.has_value() && result1->timeout_seconds == 0x12345678;
    print_test_result("Parse 0x12345678 (LE)", ok1);

    // Test 2: 0x00000001 → [0x01, 0x00, 0x00, 0x00]
    std::vector<uint8_t> packet2 = {0x01, 0x00, 0x00, 0x00};
    auto result2 = parse_session_start(packet2);
    bool ok2 = result2.has_value() && result2->timeout_seconds == 1;
    print_test_result("Parse 1 second timeout (LE)", ok2);

    // Test 3: 0xFFFFFFFF → [0xFF, 0xFF, 0xFF, 0xFF]
    std::vector<uint8_t> packet3 = {0xFF, 0xFF, 0xFF, 0xFF};
    auto result3 = parse_session_start(packet3);
    bool ok3 = result3.has_value() && result3->timeout_seconds == 0xFFFFFFFF;
    print_test_result("Parse max uint32 timeout (LE)", ok3);
}

// ============================================================================
// Test 10: Keepalive interval calculation
// ============================================================================
void test_keepalive_calculation() {
    std::cout << "\nTest 10: Keepalive interval calculation\n";

    // Test 1: 86400 seconds (24 hours) with safety=2 → 12 hours
    uint16_t hours1 = calculate_keepalive_hours(86400, 2);
    bool ok1 = (hours1 == 12);
    print_test_result("24h timeout → 12h keepalive (safety=2)", ok1);

    // Test 2: 43200 seconds (12 hours) with safety=2 → 6 hours
    uint16_t hours2 = calculate_keepalive_hours(43200, 2);
    bool ok2 = (hours2 == 6);
    print_test_result("12h timeout → 6h keepalive (safety=2)", ok2);

    // Test 3: 3600 seconds (1 hour) with safety=2 → 1 hour (minimum)
    uint16_t hours3 = calculate_keepalive_hours(3600, 2);
    bool ok3 = (hours3 == 1);
    print_test_result("1h timeout → 1h keepalive (minimum)", ok3);

    // Test 4: 0 seconds → 1 hour (minimum)
    uint16_t hours4 = calculate_keepalive_hours(0, 2);
    bool ok4 = (hours4 == 1);
    print_test_result("0s timeout → 1h keepalive (minimum)", ok4);

    // Test 5: 7200 seconds (2 hours) with safety=2 → 1 hour
    uint16_t hours5 = calculate_keepalive_hours(7200, 2);
    bool ok5 = (hours5 == 1);
    print_test_result("2h timeout → 1h keepalive (safety=2)", ok5);
}

// ============================================================================
// Main
// ============================================================================
int main() {
    std::cout << "============================================================\n";
    std::cout << "SESSION_START Parser Unit Tests\n";
    std::cout << "============================================================\n";

    test_minimum_valid_packet();
    test_timeout_plus_session_key();
    test_full_packet();
    test_null_data_pointer();
    test_insufficient_data();
    test_partial_session_key();
    test_partial_genesis_hash();
    test_excess_data();
    test_timeout_endianness();
    test_keepalive_calculation();

    std::cout << "\n============================================================\n";
    std::cout << "Test Summary:\n";
    std::cout << "  Total:  " << tests_run << "\n";
    std::cout << "  Passed: " << tests_passed << "\n";
    std::cout << "  Failed: " << tests_failed << "\n";
    std::cout << "============================================================\n";

    return (tests_failed == 0) ? 0 : 1;
}
