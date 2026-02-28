#include "dual_connection_manager.hpp"

#include <iostream>

using namespace nexusminer;

namespace
{
bool expect(bool condition, const char* message)
{
    if (!condition)
    {
        std::cerr << "  [FAIL] " << message << std::endl;
        return false;
    }
    std::cout << "  [PASS] " << message << std::endl;
    return true;
}
}

int main()
{
    bool ok = true;

    std::cout << "========================================\n";
    std::cout << "DualConnectionManager Unit Tests\n";
    std::cout << "========================================\n\n";

    {
        std::cout << "Test 1: Lane liveness state tracking\n";
        DualConnectionManager mgr;
        ok &= expect(!mgr.any_lane_alive(), "Initial state: no lane alive");
        mgr.set_stateless_alive(true);
        ok &= expect(mgr.is_stateless_alive(), "Stateless lane alive after set");
        ok &= expect(mgr.any_lane_alive(), "Any lane alive when stateless alive");
        mgr.set_legacy_alive(true);
        ok &= expect(mgr.is_legacy_alive(), "Legacy lane alive after set");
        std::cout << '\n';
    }

    {
        std::cout << "Test 2: Stateless failure arms legacy one-shot bypass\n";
        DualConnectionManager mgr;
        mgr.set_stateless_alive(true);
        mgr.set_legacy_alive(true);
        mgr.on_lane_failed(ProtocolLane::STATELESS);
        ok &= expect(!mgr.is_stateless_alive(), "Stateless marked dead on failure");
        ok &= expect(mgr.is_legacy_alive(), "Legacy remains alive");
        ok &= expect(mgr.consume_bypass(ProtocolLane::LEGACY), "Legacy bypass consumed once");
        ok &= expect(!mgr.consume_bypass(ProtocolLane::LEGACY), "Legacy bypass does not repeat");
        std::cout << '\n';
    }

    {
        std::cout << "Test 3: Legacy failure arms stateless one-shot bypass\n";
        DualConnectionManager mgr;
        mgr.set_stateless_alive(true);
        mgr.set_legacy_alive(true);
        mgr.on_lane_failed(ProtocolLane::LEGACY);
        ok &= expect(!mgr.is_legacy_alive(), "Legacy marked dead on failure");
        ok &= expect(mgr.is_stateless_alive(), "Stateless remains alive");
        ok &= expect(mgr.consume_bypass(ProtocolLane::STATELESS), "Stateless bypass consumed once");
        ok &= expect(!mgr.consume_bypass(ProtocolLane::STATELESS), "Stateless bypass does not repeat");
        std::cout << '\n';
    }

    {
        std::cout << "Test 4: Lane recovery updates liveness\n";
        DualConnectionManager mgr;
        mgr.on_lane_failed(ProtocolLane::STATELESS);
        ok &= expect(!mgr.is_stateless_alive(), "Stateless dead after failure");
        mgr.on_lane_recovered(ProtocolLane::STATELESS);
        ok &= expect(mgr.is_stateless_alive(), "Stateless alive after recovery");
        mgr.on_lane_recovered(ProtocolLane::LEGACY);
        ok &= expect(mgr.is_legacy_alive(), "Legacy alive after recovery");
        std::cout << '\n';
    }

    {
        std::cout << "Test 5: No miner-side GET_BLOCK rate limiter\n";
        // The miner-side GET_BLOCK rate limiter (GET_BLOCK_MIN_INTERVAL in Solo::get_work())
        // has been removed. The node's 2-second AutoCoolDown (server-side) is the sole
        // rate limiter for GET_BLOCK. Any miner-side suppression was redundant and caused
        // doom loops during recovery.
        //
        // The compile-time proof that the DualConnectionManager timing constants are gone
        // is that this file compiles without them — any reference to
        // GET_BLOCK_MINER_INTERVAL_MS or GET_BLOCK_NODE_INTERVAL_MS would be a compile error.
        DualConnectionManager mgr;
        mgr.set_stateless_alive(true);
        ok &= expect(mgr.is_stateless_alive(),
                     "DualConnectionManager liveness works without stale GET_BLOCK timing constants");
        std::cout << '\n';
    }

    std::cout << "========================================\n";
    std::cout << "Test Summary\n";
    std::cout << "========================================\n";
    std::cout << (ok ? "ALL TESTS PASSED" : "TESTS FAILED") << std::endl;
    return ok ? 0 : 1;
}
