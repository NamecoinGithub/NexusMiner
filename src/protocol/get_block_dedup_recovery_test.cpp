/**
 * @file get_block_dedup_recovery_test.cpp
 * @brief Unit tests for GET_BLOCK deduplication and empty BLOCK_DATA recovery
 *
 * Tests:
 *  1. GET_BLOCK deduplication within 100ms window
 *  2. GET_BLOCK allowed after deduplication window expires
 *  3. Multiple rapid GET_BLOCK requests deduplicated
 *  4. GET_BLOCK deduplication across push handler and Worker_manager
 *  5. Deduplication state can be reset
 *  6. Three successive GET_BLOCK calls with proper timing
 *  7. Verify packet format for GET_BLOCK
 *  8. Degraded forced retry sends within bounded interval
 *  9. Dedup still allows periodic forced retry in degraded mode
 * 10. request_work empty schedules delayed retry (no starvation)
 * 11. ⚡ Unified Tip-Anchor Changed — dedup reset allows fresh GET_BLOCK despite recent prior request
 * 12. New recovery epoch does not inherit stale GET_BLOCK suppression state; anti-flood preserved within epoch
 * 13. Anti-flood preserved — true duplicates in same epoch/state still suppressed
 * 14. Height-based dedup bypassed when no valid template exists
 */

#include "protocol/packet_builder.hpp"
#include "miner_opcodes.hpp"
#include <iostream>
#include <cstdint>
#include <chrono>
#include <thread>
#include <memory>
#include <deque>
#include <gtest/gtest.h>

using namespace nexusminer;
using namespace nexusminer::protocol;

// ============================================================================
// Mock GET_BLOCK deduplication logic (mirrors Solo::get_work)
// ============================================================================
class GetBlockDeduplicator {
public:
    GetBlockDeduplicator()
        : m_authenticated(true)
        , m_reward_bound(true)
        , m_protocol_lane(ProtocolLane::STATELESS)
        , m_last_get_block_transmitted_tp{}
        , m_get_block_call_count(0)
    {}

    // Simulates Solo::get_work() with deduplication logic
    network::Shared_payload get_work(bool bypass_dedup = false) {
        m_get_block_call_count++;

        if (!m_authenticated || !m_reward_bound) {
            return nullptr;
        }

        // GET_BLOCK deduplication guard (mirrors solo.cpp lines 546-556)
        auto now_tp = std::chrono::steady_clock::now();
        if (!bypass_dedup && m_last_get_block_transmitted_tp != std::chrono::steady_clock::time_point{}) {
            auto elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                now_tp - m_last_get_block_transmitted_tp).count();
            if (elapsed_ms < 100) {  // GET_BLOCK_DEDUP_MS = 100
                std::cout << "    [Dedup] Suppressing duplicate GET_BLOCK ("
                         << elapsed_ms << "ms since last)\n";
                return nullptr;  // Suppress duplicate
            }
        }

        // Build GET_BLOCK packet
        auto payload = PacketBuilder::build(m_protocol_lane, nexusminer::LLP::GET_BLOCK);

        if (payload && !payload->empty()) {
            m_last_get_block_transmitted_tp = now_tp;
            std::cout << "    [Transmitted] GET_BLOCK sent successfully\n";
        }

        return payload;
    }

    void reset_timestamp() {
        m_last_get_block_transmitted_tp = {};
    }

    int get_call_count() const { return m_get_block_call_count; }
    void reset_call_count() { m_get_block_call_count = 0; }

    std::chrono::steady_clock::time_point get_last_transmitted_tp() const {
        return m_last_get_block_transmitted_tp;
    }

private:
    bool m_authenticated;
    bool m_reward_bound;
    ProtocolLane m_protocol_lane;
    std::chrono::steady_clock::time_point m_last_get_block_transmitted_tp;
    int m_get_block_call_count;
};

class DegradedForcedRetryController {
public:
    bool degraded{true};
    bool authenticated{true};
    bool no_valid_template{true};
    bool request_work_empty_once{false};
    int sent_count{0};
    int scheduled_retry_count{0};
    std::deque<std::chrono::steady_clock::time_point> forced_send_timestamps;
    std::chrono::steady_clock::time_point next_due{};
    GetBlockDeduplicator dedup;

    bool tick(std::chrono::steady_clock::time_point now) {
        if (!(degraded && authenticated && no_valid_template)) {
            return false;
        }
        if (next_due != std::chrono::steady_clock::time_point{} && now < next_due) {
            return false;
        }
        while (!forced_send_timestamps.empty()) {
            auto age_s = std::chrono::duration_cast<std::chrono::seconds>(now - forced_send_timestamps.front()).count();
            if (age_s <= 60) break;
            forced_send_timestamps.pop_front();
        }
        if (forced_send_timestamps.size() >= 25) {
            return false;
        }

        if (request_work_empty_once) {
            request_work_empty_once = false;
            schedule_retry(now);
            return false;
        }

        auto payload = dedup.get_work(true);
        if (payload && !payload->empty()) {
            ++sent_count;
            forced_send_timestamps.push_back(now);
            schedule_retry(now);
            return true;
        }
        schedule_retry(now);
        return false;
    }

private:
    void schedule_retry(std::chrono::steady_clock::time_point now) {
        ++scheduled_retry_count;
        next_due = now + std::chrono::milliseconds(1000 + 125);
    }
};

// ============================================================================
// Test 1: GET_BLOCK deduplication within 100ms window
// ============================================================================
TEST(GetBlockDedupRecoveryTest, test_get_block_dedup_within_window) {
    std::cout << "\nTest 1: GET_BLOCK deduplication within 100ms window\n";

    GetBlockDeduplicator dedup;

    // First call should succeed
    auto payload1 = dedup.get_work();
    bool first_success = (payload1 != nullptr && !payload1->empty());

    // Second call within 100ms should be suppressed
    auto payload2 = dedup.get_work();
    bool second_suppressed = (payload2 == nullptr);

    // Third call within 100ms should also be suppressed
    auto payload3 = dedup.get_work();
    bool third_suppressed = (payload3 == nullptr);

    int call_count = dedup.get_call_count();
    bool correct_call_count = (call_count == 3);  // All 3 calls should be counted

    bool passed = first_success && second_suppressed && third_suppressed && correct_call_count;
    EXPECT_TRUE(passed) << "GET_BLOCK deduplication within 100ms";
}

// ============================================================================
// Test 2: GET_BLOCK allowed after deduplication window expires
// ============================================================================
TEST(GetBlockDedupRecoveryTest, test_get_block_after_window) {
    std::cout << "\nTest 2: GET_BLOCK allowed after deduplication window expires\n";

    GetBlockDeduplicator dedup;

    // First call should succeed
    auto payload1 = dedup.get_work();
    bool first_success = (payload1 != nullptr && !payload1->empty());

    // Wait for deduplication window to expire (110ms > 100ms)
    std::cout << "    [Wait] Sleeping for 110ms to expire dedup window...\n";
    std::this_thread::sleep_for(std::chrono::milliseconds(110));

    // Second call after window should succeed
    auto payload2 = dedup.get_work();
    bool second_success = (payload2 != nullptr && !payload2->empty());

    bool passed = first_success && second_success;
    EXPECT_TRUE(passed) << "GET_BLOCK allowed after dedup window expires";
}

// ============================================================================
// Test 3: Multiple rapid GET_BLOCK requests deduplicated
// ============================================================================
TEST(GetBlockDedupRecoveryTest, test_multiple_rapid_requests) {
    std::cout << "\nTest 3: Multiple rapid GET_BLOCK requests deduplicated\n";

    GetBlockDeduplicator dedup;

    int successful_transmissions = 0;
    int suppressed_transmissions = 0;

    // First request should succeed
    auto payload = dedup.get_work();
    if (payload && !payload->empty()) {
        successful_transmissions++;
    }

    // Rapid-fire 9 more requests within 100ms
    for (int i = 0; i < 9; i++) {
        payload = dedup.get_work();
        if (payload && !payload->empty()) {
            successful_transmissions++;
        } else {
            suppressed_transmissions++;
        }
    }

    std::cout << "    [Stats] Successful: " << successful_transmissions
              << ", Suppressed: " << suppressed_transmissions << "\n";

    bool passed = (successful_transmissions == 1) && (suppressed_transmissions == 9);
    EXPECT_TRUE(passed) << "Multiple rapid requests deduplicated correctly";
}

// ============================================================================
// Test 4: GET_BLOCK deduplication across push handler and Worker_manager
// ============================================================================
TEST(GetBlockDedupRecoveryTest, test_dedup_across_callers) {
    std::cout << "\nTest 4: GET_BLOCK deduplication across callers\n";

    GetBlockDeduplicator dedup;

    // Simulate push handler call
    std::cout << "    [Push Handler] Requesting GET_BLOCK...\n";
    auto payload1 = dedup.get_work();
    bool push_success = (payload1 != nullptr && !payload1->empty());

    // Simulate Worker_manager call immediately after (within 100ms)
    std::cout << "    [Worker Manager] Requesting GET_BLOCK...\n";
    auto payload2 = dedup.get_work();
    bool worker_suppressed = (payload2 == nullptr);

    bool passed = push_success && worker_suppressed;
    EXPECT_TRUE(passed) << "Deduplication works across different callers";
}

// ============================================================================
// Test 5: Deduplication resets after timestamp reset
// ============================================================================
TEST(GetBlockDedupRecoveryTest, test_dedup_reset) {
    std::cout << "\nTest 5: Deduplication state can be reset\n";

    GetBlockDeduplicator dedup;

    // First call succeeds
    auto payload1 = dedup.get_work();
    bool first_success = (payload1 != nullptr && !payload1->empty());

    // Second call within window is suppressed
    auto payload2 = dedup.get_work();
    bool second_suppressed = (payload2 == nullptr);

    // Reset timestamp (simulating recovery completion)
    dedup.reset_timestamp();

    // Third call after reset should succeed
    auto payload3 = dedup.get_work();
    bool third_success = (payload3 != nullptr && !payload3->empty());

    bool passed = first_success && second_suppressed && third_success;
    EXPECT_TRUE(passed) << "Deduplication state resets correctly";
}

// ============================================================================
// Test 6: Three successive GET_BLOCK calls with proper timing
// ============================================================================
TEST(GetBlockDedupRecoveryTest, test_three_successive_calls) {
    std::cout << "\nTest 6: Three successive GET_BLOCK calls with proper timing\n";

    GetBlockDeduplicator dedup;

    // First call
    auto payload1 = dedup.get_work();
    bool first_success = (payload1 != nullptr && !payload1->empty());
    auto first_tp = dedup.get_last_transmitted_tp();

    // Wait 110ms
    std::this_thread::sleep_for(std::chrono::milliseconds(110));

    // Second call
    auto payload2 = dedup.get_work();
    bool second_success = (payload2 != nullptr && !payload2->empty());
    auto second_tp = dedup.get_last_transmitted_tp();

    // Wait 110ms
    std::this_thread::sleep_for(std::chrono::milliseconds(110));

    // Third call
    auto payload3 = dedup.get_work();
    bool third_success = (payload3 != nullptr && !payload3->empty());
    auto third_tp = dedup.get_last_transmitted_tp();

    // Verify timestamps are advancing
    bool timestamps_advance = (first_tp < second_tp) && (second_tp < third_tp);

    bool passed = first_success && second_success && third_success && timestamps_advance;
    EXPECT_TRUE(passed) << "Three successive calls with proper timing";
}

// ============================================================================
// Test 7: Verify packet format
// ============================================================================
TEST(GetBlockDedupRecoveryTest, test_packet_format) {
    std::cout << "\nTest 7: Verify GET_BLOCK packet format\n";

    GetBlockDeduplicator dedup;
    auto payload = dedup.get_work();

    bool valid_payload = (payload != nullptr && !payload->empty());

    // Stateless GET_BLOCK should be 2 bytes: [0xD0][0x81]
    bool correct_size = valid_payload && (payload->size() == 2);
    bool correct_header = correct_size &&
                         ((*payload)[0] == 0xD0) &&
                         ((*payload)[1] == 0x81);

    if (valid_payload) {
        std::cout << "    [Packet] Size: " << payload->size() << " bytes\n";
        std::cout << "    [Packet] Content: 0x";
        for (size_t i = 0; i < payload->size(); i++) {
            printf("%02X", (*payload)[i]);
        }
        std::cout << "\n";
    }

    bool passed = valid_payload && correct_size && correct_header;
    EXPECT_TRUE(passed) << "GET_BLOCK packet format correct";
}

// ============================================================================
// Test 8: Degraded forced retry sends within bounded interval
// ============================================================================
TEST(GetBlockDedupRecoveryTest, test_degraded_forced_retry_sends_within_interval) {
    std::cout << "\nTest 8: Degraded forced retry sends within bounded interval\n";
    DegradedForcedRetryController controller;
    auto now = std::chrono::steady_clock::now();

    bool first_sent = controller.tick(now);
    EXPECT_TRUE(first_sent) << "Forced retry sends immediately on degraded tick";

    bool second_sent_too_early = controller.tick(now + std::chrono::milliseconds(50));
    EXPECT_TRUE(!second_sent_too_early) << "Second retry before interval is suppressed";

    bool third_sent = controller.tick(now + std::chrono::milliseconds(1200));
    EXPECT_TRUE(third_sent) << "Forced retry sends again after interval";
}

// ============================================================================
// Test 9: Dedup window cannot starve degraded forced retry lane
// ============================================================================
TEST(GetBlockDedupRecoveryTest, test_dedup_still_allows_periodic_forced_retry) {
    std::cout << "\nTest 9: Dedup still allows periodic forced retry in degraded mode\n";
    DegradedForcedRetryController controller;
    auto now = std::chrono::steady_clock::now();

    bool first_sent = controller.tick(now);
    bool immediate_retry = controller.tick(now + std::chrono::milliseconds(10));  // interval gate
    bool second_sent = controller.tick(now + std::chrono::milliseconds(1200));

    EXPECT_TRUE(first_sent) << "First forced send succeeds";
    EXPECT_TRUE(!immediate_retry) << "Immediate retry is suppressed by local interval";
    EXPECT_TRUE(second_sent) << "Periodic forced retry succeeds after interval despite dedup";
}

// ============================================================================
// Test 10: request_work empty schedules delayed retry (no starvation)
// ============================================================================
TEST(GetBlockDedupRecoveryTest, test_request_work_empty_delayed_retry_path) {
    std::cout << "\nTest 10: request_work empty triggers delayed retry path\n";
    DegradedForcedRetryController controller;
    controller.request_work_empty_once = true;
    auto now = std::chrono::steady_clock::now();

    bool first_sent = controller.tick(now);
    EXPECT_TRUE(!first_sent) << "Initial empty work does not send";
    EXPECT_TRUE(controller.scheduled_retry_count == 1) << "Empty work schedules retry token";

    bool retry_sent = controller.tick(now + std::chrono::milliseconds(1200));
    EXPECT_TRUE(retry_sent) << "Delayed retry sends GET_BLOCK";
    EXPECT_TRUE(controller.sent_count >= 1) << "No starvation after empty work transient";
}

// ============================================================================
// Test 11: Same-height tip-anchor change: dedup reset allows fresh GET_BLOCK
//
// Simulates the Unified Tip-Anchor Changed path: the canonical prev hash
// changes at the same channel height.  The old dedup timestamp refers to
// a request for the wrong canonical state and must not suppress the new one.
// ============================================================================
TEST(GetBlockDedupRecoveryTest, test_tip_anchor_change_resets_dedup_allows_fresh_get_block) {
    std::cout << "\nTest 11: ⚡ Unified Tip-Anchor Changed — dedup reset allows fresh GET_BLOCK\n";

    GetBlockDeduplicator dedup;

    // First GET_BLOCK succeeds (current canonical tip-anchor, epoch 1)
    auto payload1 = dedup.get_work();
    bool first_success = (payload1 != nullptr && !payload1->empty());
    EXPECT_TRUE(first_success) << "Initial GET_BLOCK for first tip-anchor succeeds";

    // Immediate second request within 100ms is suppressed (same epoch, no tip change)
    auto payload_dup = dedup.get_work();
    bool dup_suppressed = (payload_dup == nullptr);
    EXPECT_TRUE(dup_suppressed) << "Immediate duplicate within same epoch is suppressed";

    // ⚡ Unified Tip-Anchor Changed — simulate recovery epoch reset:
    // reset_get_block_dedup_state() clears the dedup timestamp so the new canonical
    // tip-anchor's GET_BLOCK is not blocked by the old request's timestamp.
    dedup.reset_timestamp();  // mirrors Solo::reset_get_block_dedup_state()

    // Request for new canonical tip-anchor must succeed immediately despite
    // being within 100ms of the previous request.
    auto payload_recovery = dedup.get_work();
    bool recovery_allowed = (payload_recovery != nullptr && !payload_recovery->empty());
    EXPECT_TRUE(recovery_allowed) << "GET_BLOCK after tip-anchor change succeeds (not suppressed)";
}

// ============================================================================
// Test 12: New recovery epoch does not inherit stale dedup suppression state
//
// Confirms that once the dedup state is reset at recovery epoch boundary,
// subsequent rapid-fire requests in the *new* epoch are correctly deduplicated
// again (anti-flood preserved) while the first request is allowed through.
// ============================================================================
TEST(GetBlockDedupRecoveryTest, test_new_recovery_epoch_does_not_inherit_stale_dedup) {
    std::cout << "\nTest 12: New recovery epoch — anti-flood preserved within epoch\n";

    GetBlockDeduplicator dedup;
    auto now = std::chrono::steady_clock::now();

    // Epoch 1: first request succeeds
    auto p1 = dedup.get_work();
    bool epoch1_first_ok = (p1 != nullptr && !p1->empty());
    EXPECT_TRUE(epoch1_first_ok) << "Epoch 1 first GET_BLOCK succeeds";

    // Epoch 1: second rapid request is suppressed
    auto p2 = dedup.get_work();
    bool epoch1_second_suppressed = (p2 == nullptr);
    EXPECT_TRUE(epoch1_second_suppressed) << "Epoch 1 second rapid request suppressed (anti-flood)";

    // ⚡ Recovery epoch transition (Unified Tip-Anchor Changed or degraded recovery begin)
    dedup.reset_timestamp();  // mirrors Solo::reset_get_block_dedup_state()

    // Epoch 2: first request after reset succeeds (new canonical state)
    auto p3 = dedup.get_work();
    bool epoch2_first_ok = (p3 != nullptr && !p3->empty());
    EXPECT_TRUE(epoch2_first_ok) << "Epoch 2 first GET_BLOCK after reset succeeds";

    // Epoch 2: second rapid request within same epoch is still suppressed (anti-flood preserved)
    auto p4 = dedup.get_work();
    bool epoch2_second_suppressed = (p4 == nullptr);
    EXPECT_TRUE(epoch2_second_suppressed) << "Epoch 2 anti-flood still active — rapid duplicate suppressed";

    // Verify call count is as expected
    bool correct_count = (dedup.get_call_count() == 4);
    EXPECT_TRUE(correct_count) << "All 4 calls tracked regardless of suppression";
}

// ============================================================================
// Test 13: Anti-flood preserved — true duplicates in same epoch still suppressed
//
// Verifies that the dedup reset mechanism does not disable flood protection:
// within a single recovery epoch, rapid duplicate requests are still suppressed.
// ============================================================================
TEST(GetBlockDedupRecoveryTest, test_anti_flood_preserved_within_same_epoch) {
    std::cout << "\nTest 13: Anti-flood preserved for true duplicates (same epoch/state)\n";

    GetBlockDeduplicator dedup;

    // Send first request — should succeed
    auto p1 = dedup.get_work();
    bool first_ok = (p1 != nullptr && !p1->empty());

    // Fire 5 rapid duplicates — all must be suppressed
    int suppressed = 0;
    for (int i = 0; i < 5; i++) {
        auto p = dedup.get_work();
        if (!p || p->empty()) suppressed++;
    }

    bool flood_blocked = (suppressed == 5);
    EXPECT_TRUE(first_ok) << "First request in epoch succeeds";
    EXPECT_TRUE(flood_blocked) << "5 rapid true duplicates are all suppressed";

    // After dedup window, one more request should succeed
    std::this_thread::sleep_for(std::chrono::milliseconds(110));
    auto p_after = dedup.get_work();
    bool after_window_ok = (p_after != nullptr && !p_after->empty());
    EXPECT_TRUE(after_window_ok) << "After dedup window, next request succeeds again";
}

// ============================================================================
// Test 14: Height-based dedup bypassed when no valid template exists
//
// Verifies that the height-based dedup guard does NOT suppress GET_BLOCK when
// no valid template is held, even if (unified, channel) heights are unchanged
// since the last transmission.  The guard must only suppress redundant
// refreshes of an already-valid template.
// ============================================================================

// Minimal mock of the height-based dedup condition added in solo.cpp,
// isolated from the time-based rapid-burst guard.
struct HeightDeduplicator {
    bool has_valid_template{false};
    uint32_t last_unified{0};
    uint32_t last_channel{0};
    uint32_t cur_unified{100};
    uint32_t cur_channel{50};

    // Returns true when the GET_BLOCK would be transmitted (not suppressed).
    // Mirrors the solo.cpp height-based dedup condition exactly:
    //   suppress only when heights unchanged AND a valid template exists.
    bool would_send() {
        if (last_unified > 0 &&
            cur_unified == last_unified &&
            cur_channel == last_channel &&
            has_valid_template)
        {
            return false;  // suppressed — redundant refresh of valid template
        }
        last_unified = cur_unified;
        last_channel = cur_channel;
        return true;
    }
};

TEST(GetBlockDedupRecoveryTest, test_height_dedup_bypassed_when_no_valid_template) {
    std::cout << "\nTest 14: Height-based dedup bypassed when no valid template\n";

    HeightDeduplicator dedup;

    // First request: no prior heights recorded, always passes.
    dedup.has_valid_template = false;
    bool first_ok = dedup.would_send();
    EXPECT_TRUE(first_ok) << "Initial GET_BLOCK succeeds (no prior heights)";
    // Heights are now recorded as (100, 50).

    // Same heights, valid template present → guard fires, request suppressed.
    dedup.has_valid_template = true;
    bool suppressed_with_template = !dedup.would_send();
    EXPECT_TRUE(suppressed_with_template) << "Same heights with valid template → suppressed";

    // Same heights, NO valid template → guard bypassed, request allowed.
    dedup.has_valid_template = false;
    bool allowed_no_template = dedup.would_send();
    EXPECT_TRUE(allowed_no_template) << "Same heights without valid template → allowed (bypass)";

    // Heights advance, valid template present → height change unblocks guard.
    dedup.has_valid_template = true;
    dedup.cur_unified = 101;
    bool allowed_new_height = dedup.would_send();
    EXPECT_TRUE(allowed_new_height) << "New height with valid template → allowed (height changed)";
}

// ============================================================================
// Main Test Runner
// ============================================================================
