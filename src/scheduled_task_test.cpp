/**
 * @file scheduled_task_test.cpp
 * @brief Unit tests for ScheduledTask — reusable timer abstraction.
 *
 * Tests:
 *  1. One-shot fires exactly once after delay
 *  2. Repeating fires multiple times
 *  3. cancel() prevents pending one-shot from firing
 *  4. cancel() stops repeating cycle
 *  5. Rescheduling cancels previous task
 *  6. Generation increments on cancel
 *  7. is_pending() reflects state correctly
 *  8. Destruction cancels pending task
 *  9. Callback can call cancel() (self-cancel)
 * 10. schedule_once accepts seconds duration
 */

#include "Util/include/scheduled_task.hpp"

#include <asio/io_context.hpp>
#include <iostream>
#include <cassert>
#include <chrono>
#include <string>

using namespace nexusminer::util;

static int tests_run    = 0;
static int tests_passed = 0;
static int tests_failed = 0;

static void print_result(const char* name, bool passed)
{
    ++tests_run;
    if (passed) {
        ++tests_passed;
        std::cout << "  [PASS] " << name << '\n';
    } else {
        ++tests_failed;
        std::cout << "  [FAIL] " << name << '\n';
    }
}

// Helper: run the io_context until all handlers complete, with a safety timeout.
static void run_for(asio::io_context& io, std::chrono::milliseconds ms)
{
    io.restart();
    io.run_for(ms);
}

// ── Test 1: One-shot fires exactly once ──────────────────────────────────────
static void test_one_shot_fires()
{
    std::cout << "\nTest 1: One-shot fires exactly once\n";
    asio::io_context io;
    ScheduledTask task(io);

    int fire_count = 0;
    task.schedule_once(std::chrono::milliseconds(10), [&]{ ++fire_count; });

    print_result("is_pending after schedule", task.is_pending());
    run_for(io, std::chrono::milliseconds(100));
    print_result("fired exactly once", fire_count == 1);
    print_result("not pending after fire", !task.is_pending());
}

// ── Test 2: Repeating fires multiple times ───────────────────────────────────
static void test_repeating_fires()
{
    std::cout << "\nTest 2: Repeating fires multiple times\n";
    asio::io_context io;
    ScheduledTask task(io);

    int fire_count = 0;
    task.schedule_repeating(std::chrono::milliseconds(10), [&]{ ++fire_count; });

    run_for(io, std::chrono::milliseconds(100));
    task.cancel();  // stop for determinism
    print_result("fired more than once", fire_count > 1);
    print_result("not pending after cancel", !task.is_pending());
}

// ── Test 3: cancel() prevents pending one-shot ───────────────────────────────
static void test_cancel_one_shot()
{
    std::cout << "\nTest 3: cancel() prevents pending one-shot\n";
    asio::io_context io;
    ScheduledTask task(io);

    int fire_count = 0;
    task.schedule_once(std::chrono::milliseconds(50), [&]{ ++fire_count; });
    task.cancel();

    run_for(io, std::chrono::milliseconds(100));
    print_result("callback did not fire", fire_count == 0);
    print_result("not pending", !task.is_pending());
}

// ── Test 4: cancel() stops repeating cycle ───────────────────────────────────
static void test_cancel_repeating()
{
    std::cout << "\nTest 4: cancel() stops repeating cycle\n";
    asio::io_context io;
    ScheduledTask task(io);

    int fire_count = 0;
    task.schedule_repeating(std::chrono::milliseconds(10), [&]{ ++fire_count; });

    // Let it fire a couple of times, then cancel
    run_for(io, std::chrono::milliseconds(50));
    int count_at_cancel = fire_count;
    task.cancel();
    run_for(io, std::chrono::milliseconds(100));

    print_result("fired before cancel", count_at_cancel > 0);
    print_result("no more fires after cancel", fire_count == count_at_cancel);
}

// ── Test 5: Rescheduling cancels previous task ───────────────────────────────
static void test_reschedule()
{
    std::cout << "\nTest 5: Rescheduling cancels previous task\n";
    asio::io_context io;
    ScheduledTask task(io);

    int first_count = 0;
    int second_count = 0;

    task.schedule_once(std::chrono::milliseconds(50), [&]{ ++first_count; });
    // Immediately reschedule — first should be cancelled
    task.schedule_once(std::chrono::milliseconds(10), [&]{ ++second_count; });

    run_for(io, std::chrono::milliseconds(100));
    print_result("first callback cancelled", first_count == 0);
    print_result("second callback fired", second_count == 1);
}

// ── Test 6: Generation increments on cancel ──────────────────────────────────
static void test_generation()
{
    std::cout << "\nTest 6: Generation increments on cancel\n";
    asio::io_context io;
    ScheduledTask task(io);

    auto g0 = task.generation();
    print_result("initial generation is 0", g0 == 0);

    task.schedule_once(std::chrono::milliseconds(10), []{});
    auto g1 = task.generation();
    // schedule_once calls cancel() (+1) then increments for the new callback (+1)
    print_result("generation advanced on schedule", g1 > g0);

    task.cancel();
    auto g2 = task.generation();
    print_result("generation incremented on cancel", g2 > g1);
}

// ── Test 7: is_pending() reflects state ──────────────────────────────────────
static void test_pending_state()
{
    std::cout << "\nTest 7: is_pending() reflects state\n";
    asio::io_context io;
    ScheduledTask task(io);

    print_result("not pending initially", !task.is_pending());

    task.schedule_once(std::chrono::milliseconds(10), []{});
    print_result("pending after schedule", task.is_pending());

    task.cancel();
    print_result("not pending after cancel", !task.is_pending());
}

// ── Test 8: Destruction cancels pending task ─────────────────────────────────
static void test_destruction_cancels()
{
    std::cout << "\nTest 8: Destruction cancels pending task\n";
    asio::io_context io;
    int fire_count = 0;

    {
        ScheduledTask task(io);
        task.schedule_once(std::chrono::milliseconds(50), [&]{ ++fire_count; });
    }
    // task destroyed here — timer should be cancelled

    run_for(io, std::chrono::milliseconds(100));
    print_result("callback did not fire after destruction", fire_count == 0);
}

// ── Test 9: Callback can call cancel() (self-cancel) ─────────────────────────
static void test_self_cancel()
{
    std::cout << "\nTest 9: Callback can call cancel() (self-cancel in repeating)\n";
    asio::io_context io;
    ScheduledTask task(io);

    int fire_count = 0;
    task.schedule_repeating(std::chrono::milliseconds(10), [&]{
        ++fire_count;
        if (fire_count >= 3) {
            task.cancel();
        }
    });

    run_for(io, std::chrono::milliseconds(200));
    print_result("stopped after self-cancel", fire_count == 3);
    print_result("not pending after self-cancel", !task.is_pending());
}

// ── Test 10: schedule_once accepts seconds duration ──────────────────────────
static void test_seconds_duration()
{
    std::cout << "\nTest 10: schedule_once accepts std::chrono::seconds\n";
    asio::io_context io;
    ScheduledTask task(io);

    int fire_count = 0;
    // This tests that the template accepts std::chrono::seconds
    task.schedule_once(std::chrono::seconds(0), [&]{ ++fire_count; });

    run_for(io, std::chrono::milliseconds(50));
    print_result("fired with seconds duration", fire_count == 1);
}

// ── main ─────────────────────────────────────────────────────────────────────
int main()
{
    std::cout << "=== ScheduledTask unit tests ===\n";

    test_one_shot_fires();
    test_repeating_fires();
    test_cancel_one_shot();
    test_cancel_repeating();
    test_reschedule();
    test_generation();
    test_pending_state();
    test_destruction_cancels();
    test_self_cancel();
    test_seconds_duration();

    std::cout << "\n========================================\n";
    std::cout << "Total: " << tests_run
              << "  Passed: " << tests_passed
              << "  Failed: " << tests_failed << '\n';
    std::cout << "========================================\n";

    return tests_failed == 0 ? 0 : 1;
}
