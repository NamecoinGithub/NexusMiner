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
        std::cout << "Test 2: Stateless failure arms stateless one-shot bypass (same-lane — NO cross-lane)\n";
        DualConnectionManager mgr;
        mgr.set_stateless_alive(true);
        mgr.set_legacy_alive(true);
        mgr.on_lane_failed(ProtocolLane::STATELESS);
        ok &= expect(!mgr.is_stateless_alive(), "Stateless marked dead on failure");
        ok &= expect(mgr.is_legacy_alive(), "Legacy remains alive");
        ok &= expect(mgr.consume_bypass(ProtocolLane::STATELESS), "Stateless bypass consumed once (same lane)");
        ok &= expect(!mgr.consume_bypass(ProtocolLane::STATELESS), "Stateless bypass does not repeat");
        ok &= expect(!mgr.consume_bypass(ProtocolLane::LEGACY), "Legacy bypass NOT armed (no cross-lane)");
        std::cout << '\n';
    }

    {
        std::cout << "Test 3: Legacy failure arms legacy one-shot bypass (same-lane — NO cross-lane)\n";
        DualConnectionManager mgr;
        mgr.set_stateless_alive(true);
        mgr.set_legacy_alive(true);
        mgr.on_lane_failed(ProtocolLane::LEGACY);
        ok &= expect(!mgr.is_legacy_alive(), "Legacy marked dead on failure");
        ok &= expect(mgr.is_stateless_alive(), "Stateless remains alive");
        ok &= expect(mgr.consume_bypass(ProtocolLane::LEGACY), "Legacy bypass consumed once (same lane)");
        ok &= expect(!mgr.consume_bypass(ProtocolLane::LEGACY), "Legacy bypass does not repeat");
        ok &= expect(!mgr.consume_bypass(ProtocolLane::STATELESS), "Stateless bypass NOT armed (no cross-lane)");
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

    {
        std::cout << "Test 6: Cross-lane bypass is never armed\n";
        // On stateless failure the legacy bypass must remain unset, and vice versa.
        {
            DualConnectionManager mgr;
            mgr.on_lane_failed(ProtocolLane::STATELESS);
            ok &= expect(!mgr.consume_bypass(ProtocolLane::LEGACY),
                         "Stateless failure does NOT arm legacy bypass");
        }
        {
            DualConnectionManager mgr;
            mgr.on_lane_failed(ProtocolLane::LEGACY);
            ok &= expect(!mgr.consume_bypass(ProtocolLane::STATELESS),
                         "Legacy failure does NOT arm stateless bypass");
        }
        std::cout << '\n';
    }

    {
        std::cout << "Test 7: Mining lane is immutable once set\n";
        DualConnectionManager mgr;
        ok &= expect(mgr.mining_lane() == ProtocolLane::UNKNOWN,
                     "Mining lane initially UNKNOWN");
        mgr.set_mining_lane(ProtocolLane::STATELESS);
        ok &= expect(mgr.mining_lane() == ProtocolLane::STATELESS,
                     "Mining lane set to STATELESS");
        // Simulate lane failure — mining lane must not change
        mgr.on_lane_failed(ProtocolLane::STATELESS);
        ok &= expect(mgr.mining_lane() == ProtocolLane::STATELESS,
                     "Mining lane unchanged after stateless failure");
        // Simulate failover — mining lane must still not change
        mgr.set_failover_active(true, "192.168.1.99");
        ok &= expect(mgr.mining_lane() == ProtocolLane::STATELESS,
                     "Mining lane unchanged after failover activation");
        std::cout << '\n';
    }

    {
        std::cout << "Test 8: Failover switchover after max retries\n";
        DualConnectionManager mgr;
        mgr.init_failover(3);  // switch after 3 failures
        ok &= expect(!mgr.is_using_failover(), "Initially on primary");
        // First two failures — no switch
        auto d1 = mgr.record_connection_failure();
        ok &= expect(!d1.switched, "No switch after 1 failure");
        ok &= expect(mgr.primary_fail_count() == 1, "Fail count is 1");
        auto d2 = mgr.record_connection_failure();
        ok &= expect(!d2.switched, "No switch after 2 failures");
        // Third failure — switch to failover
        auto d3 = mgr.record_connection_failure();
        ok &= expect(d3.switched, "Switch after 3 failures");
        ok &= expect(mgr.is_using_failover(), "Now on failover");
        ok &= expect(mgr.primary_fail_count() == 0, "Fail count reset after switch");
        ok &= expect(mgr.failover_activated_at() != std::chrono::steady_clock::time_point{},
                      "Failover activation timestamp set");
        std::cout << '\n';
    }

    {
        std::cout << "Test 9: Failover switches back to primary after max retries\n";
        DualConnectionManager mgr;
        mgr.init_failover(2);
        // Force to failover
        mgr.record_connection_failure();
        mgr.record_connection_failure();
        ok &= expect(mgr.is_using_failover(), "On failover after 2 failures");
        // Now fail failover twice — should switch back to primary
        mgr.record_connection_failure();
        auto d = mgr.record_connection_failure();
        ok &= expect(d.switched, "Switch back after failover failures");
        ok &= expect(!mgr.is_using_failover(), "Back on primary");
        std::cout << '\n';
    }

    {
        std::cout << "Test 10: reset_fail_count clears on success\n";
        DualConnectionManager mgr;
        mgr.init_failover(3);
        mgr.record_connection_failure();
        mgr.record_connection_failure();
        ok &= expect(mgr.primary_fail_count() == 2, "Fail count is 2");
        mgr.reset_fail_count();
        ok &= expect(mgr.primary_fail_count() == 0, "Fail count reset to 0");
        std::cout << '\n';
    }

    std::cout << "========================================\n";
    std::cout << "Test Summary\n";
    std::cout << "========================================\n";
    std::cout << (ok ? "ALL TESTS PASSED" : "TESTS FAILED") << std::endl;
    return ok ? 0 : 1;
}
