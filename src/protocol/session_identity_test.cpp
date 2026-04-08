/**
 * @file session_identity_test.cpp
 * @brief Unit tests for the SessionIdentity value object.
 *
 * Tests cover construction, validation, comparison (matches/same_miner/full_match),
 * fingerprint/diagnostics output, copy semantics, and edge cases.
 */

#include "protocol/session_identity.hpp"
#include <LLC/hash/SK.h>
#include <cassert>
#include <cstring>
#include <iostream>
#include <vector>
#include <string>
#include <sstream>

using nexusminer::protocol::SessionIdentity;
using nexusminer::ProtocolLane;

namespace {

// ── Helpers ──────────────────────────────────────────────────────────────

/// Create a vector filled with a repeating byte value.
std::vector<uint8_t> make_bytes(size_t size, uint8_t fill)
{
    return std::vector<uint8_t>(size, fill);
}

/// Convenience: build a valid SessionIdentity with default test values.
SessionIdentity make_valid_identity(
    uint32_t session_id = 0x548c90d3,
    uint64_t session_epoch = 2,
    ProtocolLane lane = ProtocolLane::STATELESS)
{
    return SessionIdentity(
        session_id,
        session_epoch,
        make_bytes(32, 0xAA),  // genesis
        make_bytes(32, 0xBB),  // chacha20 key
        make_bytes(32, 0xCC),  // pre-computed SK256 pubkey hash (32 bytes)
        lane);
}

// ── Tests ────────────────────────────────────────────────────────────────

void test_default_construction()
{
    SessionIdentity id;
    assert(!id.is_valid());
    assert(id.is_empty());
    assert(!id.has_crypto_context());
    assert(id.session_id() == 0);
    assert(id.session_epoch() == 0);
    assert(id.genesis_hash().empty());
    assert(id.chacha20_key().empty());
    assert(id.falcon_pubkey_hash().empty());
    assert(id.lane() == ProtocolLane::UNKNOWN);
    std::cout << "  PASS: default_construction\n";
}

void test_valid_construction()
{
    auto id = make_valid_identity();
    assert(id.is_valid());
    assert(!id.is_empty());
    assert(id.has_crypto_context());
    assert(id.session_id() == 0x548c90d3);
    assert(id.session_epoch() == 2);
    assert(id.genesis_hash().size() == 32);
    assert(id.chacha20_key().size() == 32);
    assert(id.falcon_pubkey_hash().size() == 32);  // SK256 produces 32 bytes
    assert(id.lane() == ProtocolLane::STATELESS);
    std::cout << "  PASS: valid_construction\n";
}

void test_is_valid_requires_nonzero_session_id()
{
    auto id = SessionIdentity(
        0,  // zero session_id
        2,
        make_bytes(32, 0xAA),
        make_bytes(32, 0xBB),
        make_bytes(32, 0xCC),  // pre-computed pubkey hash
        ProtocolLane::STATELESS);
    assert(!id.is_valid());
    assert(!id.is_empty());  // not empty — has epoch=2, but invalid since session_id==0
    std::cout << "  PASS: is_valid_requires_nonzero_session_id\n";
}

void test_is_valid_requires_nonzero_epoch()
{
    auto id = SessionIdentity(
        0x1234,
        0,  // zero epoch
        make_bytes(32, 0xAA),
        make_bytes(32, 0xBB),
        make_bytes(32, 0xCC),  // pre-computed pubkey hash
        ProtocolLane::STATELESS);
    assert(!id.is_valid());
    std::cout << "  PASS: is_valid_requires_nonzero_epoch\n";
}

void test_has_crypto_context()
{
    // With both key and genesis
    auto id_full = make_valid_identity();
    assert(id_full.has_crypto_context());

    // Without chacha20 key
    auto id_no_key = SessionIdentity(
        0x1234, 1,
        make_bytes(32, 0xAA),
        {},  // empty key
        make_bytes(32, 0xCC),  // pre-computed pubkey hash
        ProtocolLane::STATELESS);
    assert(!id_no_key.has_crypto_context());

    // Without genesis
    auto id_no_genesis = SessionIdentity(
        0x1234, 1,
        {},  // empty genesis
        make_bytes(32, 0xBB),
        make_bytes(32, 0xCC),  // pre-computed pubkey hash
        ProtocolLane::STATELESS);
    assert(!id_no_genesis.has_crypto_context());

    std::cout << "  PASS: has_crypto_context\n";
}

void test_matches_same_session()
{
    auto id1 = make_valid_identity(0x1111, 5);
    auto id2 = make_valid_identity(0x1111, 5);
    assert(id1.matches(id2));
    assert(id2.matches(id1));
    std::cout << "  PASS: matches_same_session\n";
}

void test_matches_different_session_id()
{
    auto id1 = make_valid_identity(0x1111, 5);
    auto id2 = make_valid_identity(0x2222, 5);
    assert(!id1.matches(id2));
    std::cout << "  PASS: matches_different_session_id\n";
}

void test_matches_different_epoch()
{
    auto id1 = make_valid_identity(0x1111, 5);
    auto id2 = make_valid_identity(0x1111, 6);
    assert(!id1.matches(id2));
    std::cout << "  PASS: matches_different_epoch\n";
}

void test_same_miner_same_pubkey()
{
    // Same SK256 pubkey hash → same miner identity
    auto pubkey_hash = make_bytes(32, 0xDD);
    auto id1 = SessionIdentity(0x1111, 1, {}, {}, pubkey_hash, ProtocolLane::STATELESS);
    auto id2 = SessionIdentity(0x2222, 2, {}, {}, pubkey_hash, ProtocolLane::STATELESS);
    // Different sessions but same miner identity
    assert(id1.same_miner(id2));
    assert(id2.same_miner(id1));
    std::cout << "  PASS: same_miner_same_pubkey\n";
}

void test_same_miner_different_pubkey()
{
    // Different SK256 pubkey hashes → different miner identities
    auto id1 = SessionIdentity(0x1111, 1, {}, {}, make_bytes(32, 0xDD), ProtocolLane::STATELESS);
    auto id2 = SessionIdentity(0x1111, 1, {}, {}, make_bytes(32, 0xEE), ProtocolLane::STATELESS);
    assert(!id1.same_miner(id2));
    std::cout << "  PASS: same_miner_different_pubkey\n";
}

void test_same_miner_empty_pubkey()
{
    auto id1 = SessionIdentity(0x1111, 1, {}, {}, {}, ProtocolLane::STATELESS);
    auto id2 = SessionIdentity(0x2222, 2, {}, {}, {}, ProtocolLane::STATELESS);
    // Both have empty pubkey — same_miner should return false (no identity to compare)
    assert(!id1.same_miner(id2));
    std::cout << "  PASS: same_miner_empty_pubkey\n";
}

void test_full_match()
{
    auto genesis = make_bytes(32, 0xAA);
    auto key = make_bytes(32, 0xBB);
    auto pubkey_hash = make_bytes(32, 0xCC);  // pre-computed SK256

    auto id1 = SessionIdentity(0x1111, 1, genesis, key, pubkey_hash, ProtocolLane::STATELESS);
    auto id2 = SessionIdentity(0x1111, 1, genesis, key, pubkey_hash, ProtocolLane::STATELESS);
    assert(id1.full_match(id2));

    // Different lane breaks full match
    auto id3 = SessionIdentity(0x1111, 1, genesis, key, pubkey_hash, ProtocolLane::LEGACY);
    assert(!id1.full_match(id3));

    // Different key breaks full match
    auto id4 = SessionIdentity(0x1111, 1, genesis, make_bytes(32, 0xFF), pubkey_hash, ProtocolLane::STATELESS);
    assert(!id1.full_match(id4));

    std::cout << "  PASS: full_match\n";
}

void test_fingerprint_format()
{
    auto id = make_valid_identity(0x548c90d3, 2);
    auto fp = id.fingerprint();
    // Should contain "sid=0x548c90d3/e2"
    assert(fp.find("sid=0x548c90d3/e2") != std::string::npos);
    std::cout << "  PASS: fingerprint_format (\"" << fp << "\")\n";
}

void test_fingerprint_default_identity()
{
    SessionIdentity id;
    auto fp = id.fingerprint();
    assert(fp.find("sid=0x00000000/e0") != std::string::npos);
    std::cout << "  PASS: fingerprint_default_identity\n";
}

void test_diagnostics_contains_fields()
{
    auto id = make_valid_identity(0xDEADBEEF, 42);
    auto diag = id.diagnostics();
    assert(diag.find("SessionIdentity{") != std::string::npos);
    assert(diag.find("deadbeef") != std::string::npos);
    assert(diag.find("epoch=42") != std::string::npos);
    assert(diag.find("valid=yes") != std::string::npos);
    std::cout << "  PASS: diagnostics_contains_fields\n";
}

void test_diagnostics_invalid_identity()
{
    SessionIdentity id;
    auto diag = id.diagnostics();
    assert(diag.find("valid=no") != std::string::npos);
    assert(diag.find("(empty)") != std::string::npos);
    std::cout << "  PASS: diagnostics_invalid_identity\n";
}

void test_equality_operator()
{
    auto id1 = make_valid_identity(0x1111, 1);
    auto id2 = make_valid_identity(0x1111, 1);
    auto id3 = make_valid_identity(0x2222, 1);

    assert(id1 == id2);
    assert(!(id1 != id2));
    assert(id1 != id3);
    assert(!(id1 == id3));
    std::cout << "  PASS: equality_operator\n";
}

void test_copy_semantics()
{
    auto id1 = make_valid_identity(0xAAAA, 10);

    // Copy construction
    auto id2 = id1;
    assert(id2 == id1);
    assert(id2.session_id() == 0xAAAA);
    assert(id2.session_epoch() == 10);

    // Copy assignment
    SessionIdentity id3;
    id3 = id1;
    assert(id3 == id1);

    // Original is unmodified
    assert(id1.session_id() == 0xAAAA);

    std::cout << "  PASS: copy_semantics\n";
}

void test_move_semantics()
{
    auto id1 = make_valid_identity(0xBBBB, 20);
    auto genesis_copy = id1.genesis_hash();

    // Move construction
    auto id2 = std::move(id1);
    assert(id2.session_id() == 0xBBBB);
    assert(id2.session_epoch() == 20);
    assert(id2.genesis_hash() == genesis_copy);
    assert(id2.is_valid());

    std::cout << "  PASS: move_semantics\n";
}

void test_sk256_pubkey_hash_size()
{
    // SK256 produces 32-byte hashes regardless of input pubkey size.
    // The caller pre-computes SK256(pubkey).GetBytes() for Falcon-512 (897 bytes)
    // or Falcon-1024 (1793 bytes) — both produce 32-byte hashes.
    auto hash_512 = make_bytes(32, 0xDD);   // simulated SK256 of Falcon-512 pubkey
    auto hash_1024 = make_bytes(32, 0xEE);  // simulated SK256 of Falcon-1024 pubkey

    auto id_512 = SessionIdentity(0x1234, 1, {}, {}, hash_512, ProtocolLane::STATELESS);
    auto id_1024 = SessionIdentity(0x1234, 1, {}, {}, hash_1024, ProtocolLane::STATELESS);

    assert(id_512.falcon_pubkey_hash().size() == 32);
    assert(id_1024.falcon_pubkey_hash().size() == 32);

    // Different hashes → different miners
    assert(!id_512.same_miner(id_1024));
    // Same hash → same miner
    auto id_512b = SessionIdentity(0x5678, 2, {}, {}, hash_512, ProtocolLane::STATELESS);
    assert(id_512.same_miner(id_512b));

    std::cout << "  PASS: sk256_pubkey_hash_size\n";
}

void test_pubkey_hash_deterministic()
{
    // Same pre-computed SK256 hash always produces the same identity
    auto pubkey_hash = make_bytes(32, 0xCC);
    auto id1 = SessionIdentity(0x1111, 1, {}, {}, pubkey_hash, ProtocolLane::STATELESS);
    auto id2 = SessionIdentity(0x2222, 2, {}, {}, pubkey_hash, ProtocolLane::STATELESS);
    // Same pubkey hash regardless of other fields
    assert(id1.falcon_pubkey_hash() == id2.falcon_pubkey_hash());
    std::cout << "  PASS: pubkey_hash_deterministic\n";
}

void test_matches_ignores_crypto_context()
{
    auto id1 = SessionIdentity(0x1111, 1,
        make_bytes(32, 0xAA), make_bytes(32, 0xBB),
        make_bytes(32, 0xCC), ProtocolLane::STATELESS);
    auto id2 = SessionIdentity(0x1111, 1,
        make_bytes(32, 0xFF), make_bytes(32, 0xEE),
        make_bytes(32, 0xDD), ProtocolLane::LEGACY);
    // matches() only checks session_id + epoch
    assert(id1.matches(id2));
    // but full_match() catches the differences
    assert(!id1.full_match(id2));
    std::cout << "  PASS: matches_ignores_crypto_context\n";
}

void test_default_identity_matches_itself()
{
    SessionIdentity id1;
    SessionIdentity id2;
    // Two empty identities technically match (both 0/0)
    assert(id1.matches(id2));
    // But neither is valid
    assert(!id1.is_valid());
    std::cout << "  PASS: default_identity_matches_itself\n";
}

void test_lane_variations()
{
    auto id_unknown = make_valid_identity(0x1111, 1);
    // Construct with different lanes to confirm lane is stored correctly
    auto id_legacy = SessionIdentity(0x1111, 1, {}, {}, {}, ProtocolLane::LEGACY);
    auto id_stateless = SessionIdentity(0x1111, 1, {}, {}, {}, ProtocolLane::STATELESS);

    assert(id_legacy.lane() == ProtocolLane::LEGACY);
    assert(id_stateless.lane() == ProtocolLane::STATELESS);
    // matches() doesn't check lane
    assert(id_legacy.matches(id_stateless));
    // full_match fails on lane difference
    assert(!id_legacy.full_match(id_stateless));
    std::cout << "  PASS: lane_variations\n";
}

void test_sk256_node_compatible_hash()
{
    // Verify that LLC::SK256(pubkey) produces the correct 32-byte hash
    // matching NODE-side hashKeyID used for miner identity.

    // Falcon-512 pubkey: LOGN=9, 897 bytes (9 + 2^(LOGN-1) = 9 + 2^8 = 9 + 256 = ... see falcon_keygen.h)
    auto pubkey_512 = make_bytes(897, 0xCC);
    auto hash_512 = LLC::SK256(pubkey_512).GetBytes();
    assert(hash_512.size() == 32);

    // Falcon-1024 pubkey: LOGN=10, 1793 bytes
    auto pubkey_1024 = make_bytes(1793, 0xCC);
    auto hash_1024 = LLC::SK256(pubkey_1024).GetBytes();
    assert(hash_1024.size() == 32);

    // Different pubkeys → different hashes
    assert(hash_512 != hash_1024);

    // Same pubkey → same hash (deterministic)
    auto hash_512b = LLC::SK256(pubkey_512).GetBytes();
    assert(hash_512 == hash_512b);

    // Build identities with the real SK256 hashes
    auto id_512 = SessionIdentity(0x1111, 1, {}, {}, hash_512, ProtocolLane::STATELESS);
    auto id_1024 = SessionIdentity(0x2222, 2, {}, {}, hash_1024, ProtocolLane::STATELESS);
    assert(!id_512.same_miner(id_1024));  // different keys → different miners

    auto id_512b = SessionIdentity(0x3333, 3, {}, {}, hash_512, ProtocolLane::STATELESS);
    assert(id_512.same_miner(id_512b));   // same key → same miner

    std::cout << "  PASS: sk256_node_compatible_hash\n";
}

} // namespace

int main()
{
    std::cout << "=== SessionIdentity Tests ===\n";

    test_default_construction();
    test_valid_construction();
    test_is_valid_requires_nonzero_session_id();
    test_is_valid_requires_nonzero_epoch();
    test_has_crypto_context();
    test_matches_same_session();
    test_matches_different_session_id();
    test_matches_different_epoch();
    test_same_miner_same_pubkey();
    test_same_miner_different_pubkey();
    test_same_miner_empty_pubkey();
    test_full_match();
    test_fingerprint_format();
    test_fingerprint_default_identity();
    test_diagnostics_contains_fields();
    test_diagnostics_invalid_identity();
    test_equality_operator();
    test_copy_semantics();
    test_move_semantics();
    test_sk256_pubkey_hash_size();
    test_pubkey_hash_deterministic();
    test_matches_ignores_crypto_context();
    test_default_identity_matches_itself();
    test_lane_variations();
    test_sk256_node_compatible_hash();

    std::cout << "\n=== All SessionIdentity tests passed! ===\n";
    return 0;
}
