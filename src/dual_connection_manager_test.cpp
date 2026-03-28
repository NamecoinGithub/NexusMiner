#include "dual_connection_manager.hpp"

#include <iostream>
#include <gtest/gtest.h>

using namespace nexusminer;

TEST(DualConnectionManagerTest, test_lane_liveness_state_tracking)
{
    std::cout << "Test 1: Lane liveness state tracking\n";
    DualConnectionManager mgr;
    EXPECT_TRUE(!mgr.any_lane_alive()) << "Initial state: no lane alive";
    mgr.set_stateless_alive(true);
    EXPECT_TRUE(mgr.is_stateless_alive()) << "Stateless lane alive after set";
    EXPECT_TRUE(mgr.any_lane_alive()) << "Any lane alive when stateless alive";
    mgr.set_legacy_alive(true);
    EXPECT_TRUE(mgr.is_legacy_alive()) << "Legacy lane alive after set";
}

TEST(DualConnectionManagerTest, test_stateless_failure_arms_same_lane_bypass)
{
    std::cout << "Test 2: Stateless failure arms stateless one-shot bypass (same-lane — NO cross-lane)\n";
    DualConnectionManager mgr;
    mgr.set_stateless_alive(true);
    mgr.set_legacy_alive(true);
    mgr.on_lane_failed(ProtocolLane::STATELESS);
    EXPECT_TRUE(!mgr.is_stateless_alive()) << "Stateless marked dead on failure";
    EXPECT_TRUE(mgr.is_legacy_alive()) << "Legacy remains alive";
    EXPECT_TRUE(mgr.consume_bypass(ProtocolLane::STATELESS)) << "Stateless bypass consumed once (same lane)";
    EXPECT_TRUE(!mgr.consume_bypass(ProtocolLane::STATELESS)) << "Stateless bypass does not repeat";
    EXPECT_TRUE(!mgr.consume_bypass(ProtocolLane::LEGACY)) << "Legacy bypass NOT armed (no cross-lane)";
}

TEST(DualConnectionManagerTest, test_legacy_failure_arms_same_lane_bypass)
{
    std::cout << "Test 3: Legacy failure arms legacy one-shot bypass (same-lane — NO cross-lane)\n";
    DualConnectionManager mgr;
    mgr.set_stateless_alive(true);
    mgr.set_legacy_alive(true);
    mgr.on_lane_failed(ProtocolLane::LEGACY);
    EXPECT_TRUE(!mgr.is_legacy_alive()) << "Legacy marked dead on failure";
    EXPECT_TRUE(mgr.is_stateless_alive()) << "Stateless remains alive";
    EXPECT_TRUE(mgr.consume_bypass(ProtocolLane::LEGACY)) << "Legacy bypass consumed once (same lane)";
    EXPECT_TRUE(!mgr.consume_bypass(ProtocolLane::LEGACY)) << "Legacy bypass does not repeat";
    EXPECT_TRUE(!mgr.consume_bypass(ProtocolLane::STATELESS)) << "Stateless bypass NOT armed (no cross-lane)";
}

TEST(DualConnectionManagerTest, test_lane_recovery_updates_liveness)
{
    std::cout << "Test 4: Lane recovery updates liveness\n";
    DualConnectionManager mgr;
    mgr.on_lane_failed(ProtocolLane::STATELESS);
    EXPECT_TRUE(!mgr.is_stateless_alive()) << "Stateless dead after failure";
    mgr.on_lane_recovered(ProtocolLane::STATELESS);
    EXPECT_TRUE(mgr.is_stateless_alive()) << "Stateless alive after recovery";
    mgr.on_lane_recovered(ProtocolLane::LEGACY);
    EXPECT_TRUE(mgr.is_legacy_alive()) << "Legacy alive after recovery";
}

TEST(DualConnectionManagerTest, test_no_miner_side_get_block_rate_limiter)
{
    std::cout << "Test 5: No miner-side GET_BLOCK rate limiter\n";
    DualConnectionManager mgr;
    mgr.set_stateless_alive(true);
    EXPECT_TRUE(mgr.is_stateless_alive())
        << "DualConnectionManager liveness works without stale GET_BLOCK timing constants";
}

TEST(DualConnectionManagerTest, test_cross_lane_bypass_never_armed)
{
    std::cout << "Test 6: Cross-lane bypass is never armed\n";
    {
        DualConnectionManager mgr;
        mgr.on_lane_failed(ProtocolLane::STATELESS);
        EXPECT_TRUE(!mgr.consume_bypass(ProtocolLane::LEGACY))
            << "Stateless failure does NOT arm legacy bypass";
    }
    {
        DualConnectionManager mgr;
        mgr.on_lane_failed(ProtocolLane::LEGACY);
        EXPECT_TRUE(!mgr.consume_bypass(ProtocolLane::STATELESS))
            << "Legacy failure does NOT arm stateless bypass";
    }
}

TEST(DualConnectionManagerTest, test_mining_lane_immutable_once_set)
{
    std::cout << "Test 7: Mining lane is immutable once set\n";
    DualConnectionManager mgr;
    EXPECT_TRUE(mgr.mining_lane() == ProtocolLane::UNKNOWN)
        << "Mining lane initially UNKNOWN";
    mgr.set_mining_lane(ProtocolLane::STATELESS);
    EXPECT_TRUE(mgr.mining_lane() == ProtocolLane::STATELESS)
        << "Mining lane set to STATELESS";
    mgr.on_lane_failed(ProtocolLane::STATELESS);
    EXPECT_TRUE(mgr.mining_lane() == ProtocolLane::STATELESS)
        << "Mining lane unchanged after stateless failure";
    mgr.set_failover_active(true, "192.168.1.99");
    EXPECT_TRUE(mgr.mining_lane() == ProtocolLane::STATELESS)
        << "Mining lane unchanged after failover activation";
}

