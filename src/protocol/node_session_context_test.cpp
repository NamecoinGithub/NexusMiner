#include "protocol/node_session_context.hpp"
#include <cassert>
#include <iostream>

using namespace nexusminer::protocol;

void test_session_lifecycle() {
    std::cout << "Testing session lifecycle..." << std::endl;

    auto session_manager = std::make_shared<SessionManager>(24, nullptr);
    NodeSessionContext context(session_manager);

    // Initially no session
    assert(context.get_session_id() == 0);
    assert(!context.is_authenticated());
    assert(!context.is_active());
    assert(context.get_state() == SessionManager::SessionState::DISCONNECTED);

    // Start a session
    context.start_session(12345);
    assert(context.get_session_id() == 12345);
    assert(context.is_authenticated());
    assert(context.is_active());

    // End session
    context.end_session();
    assert(context.get_session_id() == 0);
    assert(!context.is_authenticated());

    std::cout << "Session lifecycle test passed!" << std::endl;
}

void test_session_constants() {
    std::cout << "Testing session constants accessors..." << std::endl;

    assert(NodeSessionContext::get_keepalive_safety_divisor() == 2);
    assert(NodeSessionContext::get_max_session_auth_retries() == 10);
    assert(NodeSessionContext::get_base_session_retry_ms() == 1000);
    assert(NodeSessionContext::get_max_session_retry_ms() == 60000);

    std::cout << "Session constants test passed!" << std::endl;
}

void test_parse_session_start() {
    std::cout << "Testing parse_session_start..." << std::endl;

    // Valid SESSION_START packet (minimal: 9 bytes)
    std::vector<uint8_t> packet = {
        0x01,                    // success
        0x39, 0x30, 0x00, 0x00,  // session_id = 12345 (LE)
        0x10, 0x0E, 0x00, 0x00   // timeout = 3600 seconds (LE)
    };

    uint32_t session_id = 0;
    uint32_t timeout = 0;
    std::vector<uint8_t> genesis;

    bool result = NodeSessionContext::parse_session_start(packet, session_id, timeout, genesis);
    assert(result);
    assert(session_id == 12345);
    assert(timeout == 3600);
    assert(genesis.empty());

    // Valid SESSION_START with genesis (41 bytes)
    std::vector<uint8_t> packet_with_genesis = {
        0x01,                    // success
        0x39, 0x30, 0x00, 0x00,  // session_id = 12345 (LE)
        0x10, 0x0E, 0x00, 0x00   // timeout = 3600 seconds (LE)
    };
    // Add 32 bytes of genesis
    for (int i = 0; i < 32; ++i) {
        packet_with_genesis.push_back(static_cast<uint8_t>(i));
    }

    genesis.clear();
    result = NodeSessionContext::parse_session_start(packet_with_genesis, session_id, timeout, genesis);
    assert(result);
    assert(session_id == 12345);
    assert(timeout == 3600);
    assert(genesis.size() == 32);
    for (int i = 0; i < 32; ++i) {
        assert(genesis[i] == static_cast<uint8_t>(i));
    }

    // Invalid packet (too short)
    std::vector<uint8_t> short_packet = {0x01, 0x39, 0x30};
    result = NodeSessionContext::parse_session_start(short_packet, session_id, timeout, genesis);
    assert(!result);

    // Invalid packet (success = 0)
    std::vector<uint8_t> failed_packet = {
        0x00,                    // success = 0 (failed)
        0x39, 0x30, 0x00, 0x00,
        0x10, 0x0E, 0x00, 0x00
    };
    result = NodeSessionContext::parse_session_start(failed_packet, session_id, timeout, genesis);
    assert(!result);

    std::cout << "parse_session_start test passed!" << std::endl;
}

void test_keepalive_interval() {
    std::cout << "Testing keepalive interval..." << std::endl;

    auto session_manager = std::make_shared<SessionManager>(24, nullptr);
    NodeSessionContext context(session_manager);

    assert(context.get_keepalive_interval() == 24);

    context.set_keepalive_interval(12);
    assert(context.get_keepalive_interval() == 12);

    std::cout << "Keepalive interval test passed!" << std::endl;
}

void test_tritium_genesis() {
    std::cout << "Testing Tritium genesis..." << std::endl;

    auto session_manager = std::make_shared<SessionManager>(24, nullptr);
    NodeSessionContext context(session_manager);

    std::vector<uint8_t> genesis(32, 0xAB);
    context.set_tritium_genesis(genesis);

    auto retrieved = context.get_tritium_genesis();
    assert(retrieved.size() == 32);
    for (size_t i = 0; i < 32; ++i) {
        assert(retrieved[i] == 0xAB);
    }

    std::cout << "Tritium genesis test passed!" << std::endl;
}

void test_session_manager_access() {
    std::cout << "Testing session manager access..." << std::endl;

    auto session_manager = std::make_shared<SessionManager>(24, nullptr);
    NodeSessionContext context(session_manager);

    assert(context.get_session_manager() == session_manager);

    std::cout << "Session manager access test passed!" << std::endl;
}

int main() {
    std::cout << "Running NodeSessionContext unit tests..." << std::endl;

    try {
        test_session_lifecycle();
        test_session_constants();
        test_parse_session_start();
        test_keepalive_interval();
        test_tritium_genesis();
        test_session_manager_access();

        std::cout << "\nAll NodeSessionContext tests passed!" << std::endl;
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "Test failed with exception: " << e.what() << std::endl;
        return 1;
    }
}
