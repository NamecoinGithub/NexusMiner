/**
 * Simple test to verify LLP Packet encoding for header-only request packets
 * This tests the fix for "payload is null or empty" errors in stateless mining.
 */

#include <iostream>
#include <iomanip>
#include <vector>
#include <memory>
#include "src/LLP/packet.hpp"
#include "src/LLP/miner_opcodes.hpp"

using namespace nexusminer;

void print_payload(const char* name, network::Shared_payload payload) {
    std::cout << name << ": ";
    if (!payload) {
        std::cout << "NULL" << std::endl;
        return;
    }
    if (payload->empty()) {
        std::cout << "EMPTY" << std::endl;
        return;
    }
    std::cout << "size=" << payload->size() << " bytes, data=[";
    for (size_t i = 0; i < payload->size(); i++) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') 
                  << static_cast<int>((*payload)[i]);
        if (i < payload->size() - 1) std::cout << " ";
    }
    std::cout << "]" << std::dec << std::endl;
}

int main() {
    std::cout << "=== LLP Packet Encoding Test ===" << std::endl << std::endl;
    
    // Test 1: GET_BLOCK (header-only request packet)
    std::cout << "Test 1: GET_BLOCK (129) - Header-only request packet" << std::endl;
    {
        Packet packet{ Packet::GET_BLOCK };
        std::cout << "  header = " << static_cast<int>(packet.m_header) 
                  << " (0x" << std::hex << static_cast<int>(packet.m_header) << std::dec << ")" << std::endl;
        std::cout << "  length = " << packet.m_length << std::endl;
        std::cout << "  is_valid() = " << (packet.is_valid() ? "TRUE" : "FALSE") << std::endl;
        
        auto payload = packet.get_bytes();
        std::cout << "  ";
        print_payload("get_bytes()", payload);
        
        if (packet.is_valid() && payload && payload->size() == 1 && (*payload)[0] == 129) {
            std::cout << "  ✓ PASS: Encoded as single-byte header (0x81)" << std::endl;
        } else {
            std::cout << "  ✗ FAIL: Expected 1-byte payload [81]" << std::endl;
        }
    }
    std::cout << std::endl;
    
    // Test 2: GET_HEIGHT (header-only request packet)
    std::cout << "Test 2: GET_HEIGHT (130) - Header-only request packet" << std::endl;
    {
        Packet packet{ Packet::GET_HEIGHT };
        std::cout << "  header = " << static_cast<int>(packet.m_header) 
                  << " (0x" << std::hex << static_cast<int>(packet.m_header) << std::dec << ")" << std::endl;
        std::cout << "  length = " << packet.m_length << std::endl;
        std::cout << "  is_valid() = " << (packet.is_valid() ? "TRUE" : "FALSE") << std::endl;
        
        auto payload = packet.get_bytes();
        std::cout << "  ";
        print_payload("get_bytes()", payload);
        
        if (packet.is_valid() && payload && payload->size() == 1 && (*payload)[0] == 130) {
            std::cout << "  ✓ PASS: Encoded as single-byte header (0x82)" << std::endl;
        } else {
            std::cout << "  ✗ FAIL: Expected 1-byte payload [82]" << std::endl;
        }
    }
    std::cout << std::endl;
    
    // Test 3: PING (header-only request packet)
    std::cout << "Test 3: PING (253) - Header-only request packet" << std::endl;
    {
        Packet packet{ Packet::PING };
        std::cout << "  header = " << static_cast<int>(packet.m_header) 
                  << " (0x" << std::hex << static_cast<int>(packet.m_header) << std::dec << ")" << std::endl;
        std::cout << "  length = " << packet.m_length << std::endl;
        std::cout << "  is_valid() = " << (packet.is_valid() ? "TRUE" : "FALSE") << std::endl;
        
        auto payload = packet.get_bytes();
        std::cout << "  ";
        print_payload("get_bytes()", payload);
        
        if (packet.is_valid() && payload && payload->size() == 1 && (*payload)[0] == 253) {
            std::cout << "  ✓ PASS: Encoded as single-byte header (0xfd)" << std::endl;
        } else {
            std::cout << "  ✗ FAIL: Expected 1-byte payload [fd]" << std::endl;
        }
    }
    std::cout << std::endl;
    
    // Test 4: SET_CHANNEL (data packet with 1-byte payload)
    std::cout << "Test 4: SET_CHANNEL (3) - Data packet with 1-byte payload" << std::endl;
    {
        std::vector<uint8_t> channel_data{2};  // Hash channel
        Packet packet{ Packet::SET_CHANNEL, std::make_shared<network::Payload>(channel_data) };
        std::cout << "  header = " << static_cast<int>(packet.m_header) 
                  << " (0x" << std::hex << static_cast<int>(packet.m_header) << std::dec << ")" << std::endl;
        std::cout << "  length = " << packet.m_length << std::endl;
        std::cout << "  is_valid() = " << (packet.is_valid() ? "TRUE" : "FALSE") << std::endl;
        
        auto payload = packet.get_bytes();
        std::cout << "  ";
        print_payload("get_bytes()", payload);
        
        // Should be: [header(1)] [length(4)] [data(1)] = 6 bytes total
        // [03] [00 00 00 01] [02]
        if (packet.is_valid() && payload && payload->size() == 6) {
            std::cout << "  ✓ PASS: Encoded as data packet [header][length][payload]" << std::endl;
        } else {
            std::cout << "  ✗ FAIL: Expected 6-byte payload" << std::endl;
        }
    }
    std::cout << std::endl;
    
    // Test 5: BLOCK_DATA (data packet header < 128)
    std::cout << "Test 5: BLOCK_DATA (0) - Data packet" << std::endl;
    {
        std::vector<uint8_t> block_data(10, 0xAA);  // 10 bytes of dummy data
        Packet packet{ Packet::BLOCK_DATA, std::make_shared<network::Payload>(block_data) };
        std::cout << "  header = " << static_cast<int>(packet.m_header) 
                  << " (0x" << std::hex << static_cast<int>(packet.m_header) << std::dec << ")" << std::endl;
        std::cout << "  length = " << packet.m_length << std::endl;
        std::cout << "  is_valid() = " << (packet.is_valid() ? "TRUE" : "FALSE") << std::endl;
        
        auto payload = packet.get_bytes();
        std::cout << "  ";
        print_payload("get_bytes()", payload);
        
        // Should be: [header(1)] [length(4)] [data(10)] = 15 bytes total
        if (packet.is_valid() && payload && payload->size() == 15) {
            std::cout << "  ✓ PASS: Encoded as data packet [header][length][payload]" << std::endl;
        } else {
            std::cout << "  ✗ FAIL: Expected 15-byte payload" << std::endl;
        }
    }
    std::cout << std::endl;
    
    // Test 6: Edge case - header < 128 with length = 0 (should be INVALID)
    std::cout << "Test 6: Data packet header with length=0 (should be INVALID)" << std::endl;
    {
        Packet packet{ 50 };  // Header 50 < 128, but no data (length will be 0)
        std::cout << "  header = " << static_cast<int>(packet.m_header) << std::endl;
        std::cout << "  length = " << packet.m_length << std::endl;
        std::cout << "  is_valid() = " << (packet.is_valid() ? "TRUE" : "FALSE") << std::endl;
        
        auto payload = packet.get_bytes();
        std::cout << "  ";
        print_payload("get_bytes()", payload);
        
        if (!packet.is_valid() && (!payload || payload->empty())) {
            std::cout << "  ✓ PASS: Correctly rejected as invalid (header < 128 requires length > 0)" << std::endl;
        } else {
            std::cout << "  ✗ FAIL: Should be invalid" << std::endl;
        }
    }
    std::cout << std::endl;
    
    std::cout << "=== Test Complete ===" << std::endl;
    
    return 0;
}
