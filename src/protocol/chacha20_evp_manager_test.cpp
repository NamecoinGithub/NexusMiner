/**
 * @file chacha20_evp_manager_test.cpp
 * @brief Unit tests for ChaCha20EVPManager
 *
 * Validates:
 *   - register_session() → encrypt_packet() → decrypt_packet() round-trip
 *   - remove_session() causes subsequent encrypt_packet() to return success=false
 *   - prune_expired_sessions() retains live sessions and removes expired ones
 *   - Wrong key (MITM simulation) causes decrypt to fail
 *   - configure() / is_evp_active() / is_tls_active() mode gate
 */

#include "protocol/chacha20_evp_manager.hpp"
#include <iostream>
#include <cassert>
#include <cstdint>
#include <vector>
#include <string>

#include <spdlog/spdlog.h>
#include <spdlog/sinks/null_sink.h>

using namespace nexusminer::protocol;

// ──────────────────────────────────────────────────────────────────────────────
// Test statistics
// ──────────────────────────────────────────────────────────────────────────────
static int tests_run    = 0;
static int tests_passed = 0;
static int tests_failed = 0;

static void print_test_result(const char* name, bool passed)
{
    ++tests_run;
    if (passed) {
        ++tests_passed;
        std::cout << "  [PASS] " << name << "\n";
    } else {
        ++tests_failed;
        std::cout << "  [FAIL] " << name << "\n";
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Helpers
// ──────────────────────────────────────────────────────────────────────────────

static std::vector<uint8_t> make_key(uint8_t seed = 0x42)
{
    return std::vector<uint8_t>(32, seed);
}

static std::vector<uint8_t> make_plaintext(size_t n = 64)
{
    std::vector<uint8_t> pt(n);
    for (size_t i = 0; i < n; ++i)
        pt[i] = static_cast<uint8_t>(i & 0xFF);
    return pt;
}

static std::string make_fingerprint(const std::vector<uint8_t>& key)
{
    static const char* HEX = "0123456789abcdef";
    std::string out;
    out.reserve(16);
    for (int i = 0; i < 8 && i < (int)key.size(); ++i) {
        out.push_back(HEX[(key[i] >> 4) & 0x0F]);
        out.push_back(HEX[ key[i]       & 0x0F]);
    }
    return out;
}

// ──────────────────────────────────────────────────────────────────────────────
// Reset singleton between tests by re-configuring to EVP (default).
// lock_mode() is a one-way latch; we don't call it in unit tests.
// ──────────────────────────────────────────────────────────────────────────────
static void reset_evp_manager_to_evp()
{
    // Force EVP mode. This will succeed as long as the mode isn't locked.
    // In unit tests we never call lock_mode() so configure() always works.
    ChaCha20EVPManager::Get().configure(EncryptionMode::EVP);
}

// ──────────────────────────────────────────────────────────────────────────────
// Test 1: register → encrypt → decrypt round-trip produces original plaintext
// ──────────────────────────────────────────────────────────────────────────────
static void test_round_trip()
{
    std::cout << "\nTest 1: register_session + encrypt_packet + decrypt_packet round-trip\n";

    reset_evp_manager_to_evp();

    const uint32_t sid = 0xDEADBEEF;
    const auto key = make_key(0x11);
    const std::string fp = make_fingerprint(key);
    const auto plaintext = make_plaintext(128);
    const std::vector<uint8_t> aad = { 0xD0, 0xD4 };  // mock SESSION_KEEPALIVE opcode

    ChaCha20EVPManager::Get().register_session(sid, key, fp);
    print_test_result("has_session_key after register", ChaCha20EVPManager::Get().has_session_key(sid));

    auto enc = ChaCha20EVPManager::Get().encrypt_packet(sid, plaintext, aad);
    print_test_result("encrypt_packet succeeds", enc.success);
    print_test_result("encrypted payload non-empty", !enc.data.empty());
    // Wire format: [nonce(12)][ciphertext+tag(N+16)] — must be larger than plaintext
    print_test_result("wire payload larger than plaintext", enc.data.size() > plaintext.size());

    auto dec = ChaCha20EVPManager::Get().decrypt_packet(sid, enc.data, aad);
    print_test_result("decrypt_packet succeeds", dec.success);
    print_test_result("decrypted data matches original plaintext", dec.data == plaintext);

    // Cleanup
    ChaCha20EVPManager::Get().remove_session(sid);
}

// ──────────────────────────────────────────────────────────────────────────────
// Test 2: remove_session() causes subsequent encrypt_packet() to fail
// ──────────────────────────────────────────────────────────────────────────────
static void test_remove_session_blocks_encrypt()
{
    std::cout << "\nTest 2: remove_session causes encrypt_packet to fail\n";

    reset_evp_manager_to_evp();

    const uint32_t sid = 0xAABBCCDD;
    const auto key = make_key(0x22);
    ChaCha20EVPManager::Get().register_session(sid, key, make_fingerprint(key));

    // Sanity: encrypt works before removal
    auto enc_before = ChaCha20EVPManager::Get().encrypt_packet(sid, make_plaintext(32), {});
    print_test_result("encrypt succeeds before remove_session", enc_before.success);

    ChaCha20EVPManager::Get().remove_session(sid);
    print_test_result("has_session_key false after remove_session",
                      !ChaCha20EVPManager::Get().has_session_key(sid));

    auto enc_after = ChaCha20EVPManager::Get().encrypt_packet(sid, make_plaintext(32), {});
    print_test_result("encrypt_packet fails after remove_session", !enc_after.success);
}

// ──────────────────────────────────────────────────────────────────────────────
// Test 3: prune_expired_sessions retains live sessions and removes expired ones
// ──────────────────────────────────────────────────────────────────────────────
static void test_prune_expired_sessions()
{
    std::cout << "\nTest 3: prune_expired_sessions retains live and removes expired\n";

    reset_evp_manager_to_evp();

    // Register three sessions
    const uint32_t live_sid   = 0x1111;
    const uint32_t live_sid2  = 0x2222;
    const uint32_t dead_sid   = 0x3333;

    ChaCha20EVPManager::Get().register_session(live_sid,  make_key(0x01), "fp_live1");
    ChaCha20EVPManager::Get().register_session(live_sid2, make_key(0x02), "fp_live2");
    ChaCha20EVPManager::Get().register_session(dead_sid,  make_key(0x03), "fp_dead");

    print_test_result("live_sid registered",  ChaCha20EVPManager::Get().has_session_key(live_sid));
    print_test_result("live_sid2 registered", ChaCha20EVPManager::Get().has_session_key(live_sid2));
    print_test_result("dead_sid registered",  ChaCha20EVPManager::Get().has_session_key(dead_sid));

    // Prune: only live_sid and live_sid2 survive
    std::vector<uint32_t> live_set = { live_sid, live_sid2 };
    uint32_t pruned = ChaCha20EVPManager::Get().prune_expired_sessions(live_set);

    print_test_result("pruned count == 1", pruned == 1);
    print_test_result("live_sid retained",  ChaCha20EVPManager::Get().has_session_key(live_sid));
    print_test_result("live_sid2 retained", ChaCha20EVPManager::Get().has_session_key(live_sid2));
    print_test_result("dead_sid removed",   !ChaCha20EVPManager::Get().has_session_key(dead_sid));

    // Prune with empty live set removes everything
    pruned = ChaCha20EVPManager::Get().prune_expired_sessions({});
    print_test_result("prune with empty set removes all (pruned==2)", pruned == 2);
    print_test_result("live_sid removed after empty prune",  !ChaCha20EVPManager::Get().has_session_key(live_sid));
    print_test_result("live_sid2 removed after empty prune", !ChaCha20EVPManager::Get().has_session_key(live_sid2));
}

// ──────────────────────────────────────────────────────────────────────────────
// Test 4: Wrong key (MITM simulation) causes decrypt_packet to fail
// ──────────────────────────────────────────────────────────────────────────────
static void test_wrong_key_mitm_simulation()
{
    std::cout << "\nTest 4: MITM simulation — wrong key causes decrypt_packet to fail\n";

    reset_evp_manager_to_evp();

    const uint32_t sender_sid   = 0xFACE0001;
    const uint32_t attacker_sid = 0xFACE0002;

    const auto legitimate_key = make_key(0xAA);
    const auto attacker_key   = make_key(0xBB);  // different key

    ChaCha20EVPManager::Get().register_session(sender_sid,   legitimate_key, "fp_legit");
    ChaCha20EVPManager::Get().register_session(attacker_sid, attacker_key,   "fp_mitm");

    const auto plaintext = make_plaintext(96);
    const std::vector<uint8_t> aad = { 0xD0, 0xDB };  // mock SESSION_STATUS opcode

    // Legitimate sender encrypts
    auto enc = ChaCha20EVPManager::Get().encrypt_packet(sender_sid, plaintext, aad);
    print_test_result("legitimate encrypt succeeds", enc.success);

    // Legitimate receiver decrypts with correct key → should succeed
    auto dec_ok = ChaCha20EVPManager::Get().decrypt_packet(sender_sid, enc.data, aad);
    print_test_result("decrypt with correct key succeeds", dec_ok.success);
    print_test_result("decrypted plaintext matches", dec_ok.data == plaintext);

    // MITM uses attacker's registered key to decrypt → should FAIL (tag mismatch)
    auto dec_mitm = ChaCha20EVPManager::Get().decrypt_packet(attacker_sid, enc.data, aad);
    print_test_result("decrypt with wrong key (MITM) FAILS", !dec_mitm.success);

    // Cleanup
    ChaCha20EVPManager::Get().remove_session(sender_sid);
    ChaCha20EVPManager::Get().remove_session(attacker_sid);
}

// ──────────────────────────────────────────────────────────────────────────────
// Test 5: Mode gate — TLS mode disables EVP encrypt/decrypt
// ──────────────────────────────────────────────────────────────────────────────
static void test_mode_gate()
{
    std::cout << "\nTest 5: mode gate — TLS mode returns plaintext pass-through\n";

    // Switch to TLS
    bool ok = ChaCha20EVPManager::Get().configure(EncryptionMode::TLS);
    print_test_result("configure(TLS) returns true", ok);
    print_test_result("is_tls_active() == true",  ChaCha20EVPManager::Get().is_tls_active());
    print_test_result("is_evp_active() == false", !ChaCha20EVPManager::Get().is_evp_active());

    // In TLS mode, encrypt_packet is a pass-through (returns plaintext unchanged)
    const uint32_t sid = 0xCAFE0001;
    ChaCha20EVPManager::Get().register_session(sid, make_key(0x55), "fp_tls_test");

    const auto pt = make_plaintext(48);
    auto enc = ChaCha20EVPManager::Get().encrypt_packet(sid, pt, {});
    print_test_result("encrypt_packet in TLS mode succeeds (pass-through)", enc.success);
    print_test_result("TLS mode: returned data == plaintext (pass-through)", enc.data == pt);

    auto dec = ChaCha20EVPManager::Get().decrypt_packet(sid, pt, {});
    print_test_result("decrypt_packet in TLS mode succeeds (pass-through)", dec.success);
    print_test_result("TLS mode: returned data == input (pass-through)", dec.data == pt);

    ChaCha20EVPManager::Get().remove_session(sid);

    // Restore EVP for subsequent tests
    reset_evp_manager_to_evp();
}

// ──────────────────────────────────────────────────────────────────────────────
// Test 6: session_count reflects registrations and removals
// ──────────────────────────────────────────────────────────────────────────────
static void test_session_count()
{
    std::cout << "\nTest 6: session_count reflects register / remove\n";

    reset_evp_manager_to_evp();
    // Ensure clean state
    ChaCha20EVPManager::Get().prune_expired_sessions({});

    const uint32_t sid_a = 0x1A;
    const uint32_t sid_b = 0x2B;

    ChaCha20EVPManager::Get().register_session(sid_a, make_key(0x10), "fp_a");
    print_test_result("session_count == 1 after first register",
                      ChaCha20EVPManager::Get().session_count() == 1);

    ChaCha20EVPManager::Get().register_session(sid_b, make_key(0x20), "fp_b");
    print_test_result("session_count == 2 after second register",
                      ChaCha20EVPManager::Get().session_count() == 2);

    // Re-registering the same session should not increment count
    ChaCha20EVPManager::Get().register_session(sid_a, make_key(0x11), "fp_a2");
    print_test_result("session_count still 2 after re-register of same session",
                      ChaCha20EVPManager::Get().session_count() == 2);

    ChaCha20EVPManager::Get().remove_session(sid_a);
    print_test_result("session_count == 1 after remove",
                      ChaCha20EVPManager::Get().session_count() == 1);

    ChaCha20EVPManager::Get().remove_session(sid_b);
    print_test_result("session_count == 0 after removing all",
                      ChaCha20EVPManager::Get().session_count() == 0);
}

// ──────────────────────────────────────────────────────────────────────────────
// main
// ──────────────────────────────────────────────────────────────────────────────
int main()
{
    // Suppress log output during tests
    auto null_sink = std::make_shared<spdlog::sinks::null_sink_mt>();
    spdlog::set_default_logger(std::make_shared<spdlog::logger>("logger", null_sink));

    std::cout << "============================================================\n";
    std::cout << "ChaCha20EVPManager Unit Tests\n";
    std::cout << "============================================================\n";

    test_round_trip();
    test_remove_session_blocks_encrypt();
    test_prune_expired_sessions();
    test_wrong_key_mitm_simulation();
    test_mode_gate();
    test_session_count();

    std::cout << "\n============================================================\n";
    std::cout << "Results: " << tests_passed << "/" << tests_run << " passed";
    if (tests_failed > 0)
        std::cout << " (" << tests_failed << " FAILED)";
    std::cout << "\n============================================================\n";

    return (tests_failed == 0) ? 0 : 1;
}
