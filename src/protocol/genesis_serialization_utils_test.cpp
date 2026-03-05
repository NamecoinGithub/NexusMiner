/*__________________________________________________________________________________________

            Hash(BEGIN(Satoshi[2010]), END(Sunny[2012])) == Videlicet[2014]++

            (c) Copyright The Nexus Developers 2014 - 2023

            Distributed under the MIT software license, see the accompanying
            file COPYING or http://www.opensource.org/licenses/mit-license.php.

            "ad vocem populi" - To the Voice of the People

____________________________________________________________________________________________*/

/**
 * Unit tests for genesis_utils.hpp and serialization_helpers.hpp
 * These utilities were extracted to eliminate duplication between solo.cpp and session_manager.cpp
 */

#include "protocol/genesis_utils.hpp"
#include "protocol/serialization_helpers.hpp"
#include <iostream>
#include <iomanip>
#include <vector>
#include <cassert>

// Simple test framework
int test_count = 0;
int pass_count = 0;

void test_assert(bool condition, const char* test_name) {
    test_count++;
    if (condition) {
        std::cout << "  [PASS] " << test_name << std::endl;
        pass_count++;
    } else {
        std::cout << "  [FAIL] " << test_name << std::endl;
    }
}

void test_genesis_validation() {
    std::cout << "\nTest 1: Genesis validation - empty vector" << std::endl;
    {
        std::vector<uint8_t> empty;
        test_assert(!genesis_utils::is_valid_genesis(empty), "Empty genesis is invalid");
    }

    std::cout << "\nTest 2: Genesis validation - all zeros" << std::endl;
    {
        std::vector<uint8_t> all_zeros(32, 0);
        test_assert(!genesis_utils::is_valid_genesis(all_zeros), "All-zero genesis is invalid");
    }

    std::cout << "\nTest 3: Genesis validation - single non-zero byte" << std::endl;
    {
        std::vector<uint8_t> genesis(32, 0);
        genesis[0] = 1;
        test_assert(genesis_utils::is_valid_genesis(genesis), "Genesis with first byte non-zero is valid");
    }

    std::cout << "\nTest 4: Genesis validation - last byte non-zero" << std::endl;
    {
        std::vector<uint8_t> genesis(32, 0);
        genesis[31] = 0xFF;
        test_assert(genesis_utils::is_valid_genesis(genesis), "Genesis with last byte non-zero is valid");
    }

    std::cout << "\nTest 5: Genesis validation - typical genesis hash" << std::endl;
    {
        std::vector<uint8_t> genesis = {
            0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
            0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
            0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00
        };
        test_assert(genesis_utils::is_valid_genesis(genesis), "Typical genesis hash is valid");
    }
}

void test_serialization_helpers() {
    std::cout << "\nTest 6: append_uint32_le - basic serialization" << std::endl;
    {
        std::vector<uint8_t> data;
        serialization::append_uint32_le(data, 0x12345678);
        test_assert(data.size() == 4, "uint32 produces 4 bytes");
        test_assert(data[0] == 0x78, "Byte 0 is LSB (0x78)");
        test_assert(data[1] == 0x56, "Byte 1 is second byte (0x56)");
        test_assert(data[2] == 0x34, "Byte 2 is third byte (0x34)");
        test_assert(data[3] == 0x12, "Byte 3 is MSB (0x12)");
    }

    std::cout << "\nTest 7: append_uint32_le - zero value" << std::endl;
    {
        std::vector<uint8_t> data;
        serialization::append_uint32_le(data, 0);
        test_assert(data.size() == 4, "uint32 zero produces 4 bytes");
        test_assert(data[0] == 0 && data[1] == 0 && data[2] == 0 && data[3] == 0,
                   "All bytes are zero");
    }

    std::cout << "\nTest 8: append_uint32_le - max value" << std::endl;
    {
        std::vector<uint8_t> data;
        serialization::append_uint32_le(data, 0xFFFFFFFF);
        test_assert(data.size() == 4, "uint32 max produces 4 bytes");
        test_assert(data[0] == 0xFF && data[1] == 0xFF && data[2] == 0xFF && data[3] == 0xFF,
                   "All bytes are 0xFF");
    }

    std::cout << "\nTest 9: append_uint64_le - basic serialization" << std::endl;
    {
        std::vector<uint8_t> data;
        serialization::append_uint64_le(data, 0x0123456789ABCDEF);
        test_assert(data.size() == 8, "uint64 produces 8 bytes");
        test_assert(data[0] == 0xEF, "Byte 0 is LSB (0xEF)");
        test_assert(data[7] == 0x01, "Byte 7 is MSB (0x01)");
    }

    std::cout << "\nTest 10: read_uint32_le - basic deserialization" << std::endl;
    {
        std::vector<uint8_t> data = {0x78, 0x56, 0x34, 0x12};
        uint32_t value = serialization::read_uint32_le(data);
        test_assert(value == 0x12345678, "Reads correct uint32 value");
    }

    std::cout << "\nTest 11: read_uint32_le - with offset" << std::endl;
    {
        std::vector<uint8_t> data = {0xFF, 0xFF, 0x78, 0x56, 0x34, 0x12};
        uint32_t value = serialization::read_uint32_le(data, 2);
        test_assert(value == 0x12345678, "Reads correct uint32 value with offset");
    }

    std::cout << "\nTest 12: read_uint32_le - insufficient data" << std::endl;
    {
        std::vector<uint8_t> data = {0x78, 0x56};
        uint32_t value = serialization::read_uint32_le(data);
        test_assert(value == 0, "Returns 0 for insufficient data");
    }

    std::cout << "\nTest 13: round-trip append/read uint32" << std::endl;
    {
        std::vector<uint8_t> data;
        uint32_t original = 0xDEADBEEF;
        serialization::append_uint32_le(data, original);
        uint32_t decoded = serialization::read_uint32_le(data);
        test_assert(decoded == original, "Round-trip preserves value");
    }

    std::cout << "\nTest 14: multiple appends" << std::endl;
    {
        std::vector<uint8_t> data;
        serialization::append_uint32_le(data, 0x11111111);
        serialization::append_uint32_le(data, 0x22222222);
        test_assert(data.size() == 8, "Two uint32s produce 8 bytes");
        test_assert(serialization::read_uint32_le(data, 0) == 0x11111111, "First value correct");
        test_assert(serialization::read_uint32_le(data, 4) == 0x22222222, "Second value correct");
    }
}

int main() {
    std::cout << "========================================" << std::endl;
    std::cout << "Genesis & Serialization Utils Tests" << std::endl;
    std::cout << "========================================" << std::endl;

    test_genesis_validation();
    test_serialization_helpers();

    std::cout << "\n========================================" << std::endl;
    std::cout << "Test Summary" << std::endl;
    std::cout << "========================================" << std::endl;
    std::cout << "Tests run:    " << test_count << std::endl;
    std::cout << "Tests passed: " << pass_count << std::endl;
    std::cout << "Tests failed: " << (test_count - pass_count) << std::endl;
    std::cout << "Success rate: " << (100 * pass_count / test_count) << "%" << std::endl;
    std::cout << "========================================" << std::endl;

    return (pass_count == test_count) ? 0 : 1;
}
