/**
 * @file legacy_lane_node_bug_detector_test.cpp
 * @brief Unit tests for LegacyLaneNodeBugDetector
 *
 * See docs/diagnostics/legacy-lane-node-bug.md for the bug being detected.
 */

#include "protocol/legacy_lane_node_bug_detector.hpp"

#include <chrono>
#include <iostream>

using namespace nexusminer::protocol;
using namespace std::chrono_literals;

namespace {

int tests_run    = 0;
int tests_passed = 0;
int tests_failed = 0;

void record(const char* name, bool ok)
{
    ++tests_run;
    if (ok) { ++tests_passed; std::cout << "  [PASS] " << name << "\n"; }
    else    { ++tests_failed; std::cout << "  [FAIL] " << name << "\n"; }
}

using TP = LegacyLaneNodeBugDetector::TimePoint;
TP base = LegacyLaneNodeBugDetector::Clock::now();
TP at(std::int64_t ms_offset) { return base + std::chrono::milliseconds(ms_offset); }

// =========================================================================
// Test 1: Default thresholds — two phantom rejections within 5s trip.
// This matches the screenshot pattern exactly (BLOCK_REJECTED 0xc9 fired
// twice in the same millisecond on a LEGACY connection).
// =========================================================================
void test_default_two_within_window_trips()
{
    std::cout << "\nTest 1: default thresholds — 2 rejections in window trip\n";
    LegacyLaneNodeBugDetector det;
    bool first  = det.observe_phantom_rejection(at(0));
    bool second = det.observe_phantom_rejection(at(1));
    record("first observation does not trip",       !first);
    record("second observation trips",               second);
    record("tripped() reflects state",               det.tripped());
}

// =========================================================================
// Test 2: One-shot semantics — subsequent observations after trip return
// false (so the caller logs the error exactly once per connection).
// =========================================================================
void test_one_shot_after_trip()
{
    std::cout << "\nTest 2: one-shot semantics after trip\n";
    LegacyLaneNodeBugDetector det;
    det.observe_phantom_rejection(at(0));
    det.observe_phantom_rejection(at(1));   // trips
    bool third  = det.observe_phantom_rejection(at(2));
    bool fourth = det.observe_phantom_rejection(at(3));
    record("third observation does not re-trip",   !third);
    record("fourth observation does not re-trip",  !fourth);
}

// =========================================================================
// Test 3: Sliding window — events outside the window are pruned and do
// not contribute to the threshold.
// =========================================================================
void test_window_prunes_old_events()
{
    std::cout << "\nTest 3: sliding window prunes old events\n";
    LegacyLaneNodeBugDetector det;     // 5000ms window
    bool a = det.observe_phantom_rejection(at(0));        // first
    bool b = det.observe_phantom_rejection(at(10000));    // 10s later — first is pruned
    record("first observation does not trip",  !a);
    record("delayed second does not trip "
           "(first was outside window)",        !b);
    record("tripped() is still false",          !det.tripped());
}

// =========================================================================
// Test 4: Custom threshold — 3 rejections required.
// =========================================================================
void test_custom_threshold()
{
    std::cout << "\nTest 4: custom threshold of 3\n";
    LegacyLaneNodeBugDetector det(3, 5000ms);
    bool a = det.observe_phantom_rejection(at(0));
    bool b = det.observe_phantom_rejection(at(100));
    bool c = det.observe_phantom_rejection(at(200));
    record("first does not trip",  !a);
    record("second does not trip", !b);
    record("third trips",           c);
    record("threshold() exposed",   det.threshold() == 3u);
    record("window() exposed",      det.window() == 5000ms);
}

// =========================================================================
// Test 5: reset() returns the detector to the initial state.
// =========================================================================
void test_reset()
{
    std::cout << "\nTest 5: reset() clears events and tripped flag\n";
    LegacyLaneNodeBugDetector det;
    det.observe_phantom_rejection(at(0));
    det.observe_phantom_rejection(at(1));   // trips
    record("tripped before reset", det.tripped());
    det.reset();
    record("not tripped after reset",                !det.tripped());
    record("pending_count zero after reset",         det.pending_count() == 0u);
    bool first  = det.observe_phantom_rejection(at(100));
    bool second = det.observe_phantom_rejection(at(101));
    record("can re-trip after reset", !first && second);
}

// =========================================================================
// Test 6: Constructor guards — zero threshold/window fall back to defaults.
// =========================================================================
void test_constructor_guards()
{
    std::cout << "\nTest 6: constructor guards reject degenerate inputs\n";
    LegacyLaneNodeBugDetector det_zero_threshold(0, 1000ms);
    LegacyLaneNodeBugDetector det_zero_window(2, 0ms);
    record("zero threshold falls back to default",
           det_zero_threshold.threshold() == LegacyLaneNodeBugDetector::kDefaultThreshold);
    record("zero window falls back to default",
           det_zero_window.window() ==
               std::chrono::milliseconds(LegacyLaneNodeBugDetector::kDefaultWindowMs));
}

} // namespace

int main()
{
    std::cout << "=========================================================\n";
    std::cout << "LegacyLaneNodeBugDetector unit tests\n";
    std::cout << "=========================================================\n";

    test_default_two_within_window_trips();
    test_one_shot_after_trip();
    test_window_prunes_old_events();
    test_custom_threshold();
    test_reset();
    test_constructor_guards();

    std::cout << "\n---------------------------------------------------------\n";
    std::cout << "Run:    " << tests_run << "\n";
    std::cout << "Passed: " << tests_passed << "\n";
    std::cout << "Failed: " << tests_failed << "\n";
    std::cout << "---------------------------------------------------------\n";

    return tests_failed == 0 ? 0 : 1;
}
