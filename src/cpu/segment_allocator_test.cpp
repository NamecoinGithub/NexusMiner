// Tests for cpu::Segment_allocator — Stone 3 pluggable per-segment cursor.

#include "cpu/prime/segment_allocator.hpp"

#include <spdlog/sinks/null_sink.h>
#include <spdlog/spdlog.h>

#include <cstdint>
#include <iostream>
#include <memory>
#include <string>

namespace
{
int tests_run = 0;
int tests_failed = 0;

void print_result(const char* name, bool passed)
{
    ++tests_run;
    std::cout << (passed ? "  [PASS] " : "  [FAIL] ") << name << '\n';
    if (!passed)
        ++tests_failed;
}

void test_per_worker_reset_then_three_advances()
{
    constexpr std::uint64_t S = 1024;
    constexpr std::uint64_t N = 12345;
    nexusminer::cpu::Per_worker_segment_allocator alloc{S};
    alloc.reset(N);

    const auto a = alloc.next_segment_start();
    const auto b = alloc.next_segment_start();
    const auto c = alloc.next_segment_start();

    print_result("Per_worker reset(N) → next_segment_start() returns N",   a == N);
    print_result("Per_worker second next_segment_start() returns N + S",   b == N + S);
    print_result("Per_worker third  next_segment_start() returns N + 2S",  c == N + 2 * S);
}

void test_per_worker_current_is_pre_advance_cursor()
{
    constexpr std::uint64_t S = 256;
    nexusminer::cpu::Per_worker_segment_allocator alloc{S};
    alloc.reset(0);

    const auto current_before = alloc.current();
    const auto handed_out = alloc.next_segment_start();
    const auto current_after = alloc.current();

    print_result("current() returns the cursor BEFORE the next next_segment_start() advances it",
                 current_before == handed_out);
    print_result("current() advances by segment_size after next_segment_start()",
                 current_after == current_before + S);
}

void verify_factory_yields_per_worker_semantics(const std::string& engine_mode)
{
    constexpr std::uint64_t S = 4096;
    auto alloc = nexusminer::cpu::make_segment_allocator_for_engine_mode(engine_mode, S);

    const std::string label = "make_segment_allocator_for_engine_mode(\"" + engine_mode + "\", S)";

    print_result((label + " returns non-null").c_str(), alloc != nullptr);
    if (!alloc)
        return;

    alloc->reset(0);
    const auto a = alloc->next_segment_start();
    const auto b = alloc->next_segment_start();
    const auto c = alloc->next_segment_start();

    print_result((label + " yields per-worker semantics: 0, S, 2S").c_str(),
                 a == 0 && b == S && c == 2 * S);
}

void test_factory_workers_mode()  { verify_factory_yields_per_worker_semantics("workers"); }
void test_factory_engine_mode()   { verify_factory_yields_per_worker_semantics("engine");  }
void test_factory_garbage_mode()  { verify_factory_yields_per_worker_semantics("garbage"); }
void test_factory_empty_mode()    { verify_factory_yields_per_worker_semantics("");        }
} // namespace

int main()
{
    // The factory may emit warn-level logs for non-canonical engine modes; the
    // logger lookup tolerates a missing "logger" but we register a null sink
    // so the warn path is exercised cleanly under test.
    if (!spdlog::get("logger"))
    {
        spdlog::create<spdlog::sinks::null_sink_mt>("logger");
    }

    std::cout << "Running cpu::Segment_allocator tests...\n";
    test_per_worker_reset_then_three_advances();
    test_per_worker_current_is_pre_advance_cursor();
    test_factory_workers_mode();
    test_factory_engine_mode();
    test_factory_garbage_mode();
    test_factory_empty_mode();

    std::cout << "\nResult: " << (tests_run - tests_failed) << "/" << tests_run << " passed\n";
    return tests_failed == 0 ? 0 : 1;
}
