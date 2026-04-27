// Stone 6 — PrimeMiningEngine pool sieve thread tests.
//
// Covers the scenarios enumerated in the Stone 6 spec:
//   1. Pool spawns and joins cleanly with no template ever published.
//   2. Pool spawns and joins cleanly when one template is published, and
//      segments_processed advances.
//   3. Heavy template churn advances segments_discarded_epoch_changed.
//   4. candidates_dispatched accuracy via the test seam (every segment
//      forces a candidate hit; dispatch count == segment count).
//   5. Explicit pool_threads config value is honoured exactly.
//   6. pool_threads == 0 derives from hardware concurrency clamped to
//      pool_threads_max_cap.
//   7. segments_skipped_consumed advances after the engine session is
//      marked consumed and pool threads observe it.
//   8. Destruction during heavy publish + heavy candidate dispatch joins
//      cleanly within a bounded timeout.
//   9. Same-base-hash republish: pool threads do NOT discard work
//      (segments_discarded_epoch_changed only advances when the cursor was
//      actually reset by the engine consumer).
//
// All tests use the cfg.pool_segment_test_hook seam to avoid standing up
// the (slow) Sieving_prime_table singleton and to deterministically force
// candidate hits.  The real sieve+validate pipeline is exercised by
// existing tests (chain_sieve_test, sieving_prime_table_test,
// prime_validation_test); Stone 6 tests target the engine bookkeeping.

#include "cpu/prime/prime_mining_engine.hpp"
#include "cpu/prime/segment_allocator.hpp"
#include "worker/template_feed.hpp"
#include "worker.hpp"
#include "block.hpp"

#include <asio.hpp>
#include <spdlog/sinks/null_sink.h>
#include <spdlog/spdlog.h>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <iostream>
#include <memory>
#include <thread>

using namespace nexusminer;
using namespace nexusminer::cpu;
using namespace std::chrono_literals;

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

constexpr std::uint64_t kSegmentSize = 4096;
constexpr std::uint64_t kStartingNonce = 0x1234'0000'0000ULL;
constexpr std::uint32_t kRepWorkerId = 7;

Engine_config base_cfg(std::shared_ptr<asio::io_context> io,
                       std::uint32_t pool_threads = 2)
{
    Engine_config cfg;
    cfg.segment_size = kSegmentSize;
    cfg.channel_starting_nonce = kStartingNonce;
    cfg.internal_id_for_solution = kRepWorkerId;
    cfg.io_context = std::move(io);
    cfg.pool_threads = pool_threads;
    return cfg;
}

std::shared_ptr<WorkPackage> make_work_package(std::uint32_t nbits,
                                               const boost::multiprecision::uint1024_t& base_hash,
                                               std::uint32_t height = 0)
{
    ::LLP::CBlock block;
    block.nVersion = 4;
    block.nChannel = 2;
    block.nHeight = height;
    block.nBits = nbits;
    block.nNonce = 0;
    auto wp = std::make_shared<WorkPackage>(block, nbits);
    wp->set_prime_base_hash(base_hash);
    return wp;
}

std::shared_ptr<TemplateEpoch> make_epoch(std::shared_ptr<WorkPackage> wp,
                                          Worker::Block_found_handler on_found = {})
{
    auto epoch = std::make_shared<TemplateEpoch>();
    epoch->work_package = std::move(wp);
    epoch->on_found = std::move(on_found);
    return epoch;
}

// Wait until a polled predicate becomes true or the timeout elapses.  Returns
// the final predicate value.  Cleaner than ad-hoc sleep loops in each test
// body and keeps the asserts crisp.
template <typename P>
bool wait_until(P pred, std::chrono::milliseconds timeout)
{
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    while (std::chrono::steady_clock::now() < deadline)
    {
        if (pred()) return true;
        std::this_thread::sleep_for(2ms);
    }
    return pred();
}

// ─────────────────────────────────────────────────────────────────────────────

void test_pool_spawns_and_joins_no_publish()
{
    auto io = std::make_shared<asio::io_context>();
    auto feed = std::make_shared<WorkerTemplateFeed>();

    auto start = std::chrono::steady_clock::now();
    {
        PrimeMiningEngine engine{base_cfg(io, /*pool_threads=*/3), feed};
        print_result("pool_thread_count == 3 when explicitly configured",
                     engine.pool_thread_count() == 3);
        // Give the pool threads time to actually enter their park loop so we
        // are exercising the shutdown-wakes-parked-pool path, not just a
        // race-free spawn-then-shutdown.
        std::this_thread::sleep_for(80ms);
        print_result("pool_threads_running reaches the spawned count",
                     engine.pool_threads_running() == 3);
    }
    const auto elapsed_ms =
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - start).count();
    print_result("Pool destruction joins within 1s with no publish",
                 elapsed_ms < 1000);
}

void test_pool_processes_segments_after_one_publish()
{
    auto io = std::make_shared<asio::io_context>();
    auto feed = std::make_shared<WorkerTemplateFeed>();
    auto cfg = base_cfg(io, /*pool_threads=*/2);
    // Hook returns "no candidates" so we just measure raw segment throughput.
    cfg.pool_segment_test_hook = [](const EngineSession&, std::uint64_t,
                                    std::uint32_t) {
        Engine_config::Pool_segment_test_outcome out;
        out.candidates_to_dispatch = 0;
        return out;
    };
    PrimeMiningEngine engine{cfg, feed};

    feed->publish(make_epoch(make_work_package(0x1c00ffffu, boost::multiprecision::uint1024_t{"0xab"})));
    const auto p1 = engine.wait_for_sessions_published_after(0, 2s);
    print_result("Single publish observed by consumer", p1 == 1);

    const bool advanced = wait_until([&]() {
        return engine.segments_processed() >= 50;
    }, 1s);
    print_result("Pool segments_processed advances past 50 within 1s", advanced);
    print_result("No segments discarded on a quiescent template",
                 engine.segments_discarded_epoch_changed() == 0);
    print_result("No segments skipped (session not consumed)",
                 engine.segments_skipped_consumed() == 0);
}

void test_pool_dispatches_one_candidate_per_segment()
{
    // Test seam forces every segment to report a candidate.  The engine
    // increments m_candidates_dispatched once per reported candidate AND
    // m_segments_processed once per segment.  Assert the two are equal
    // (modulo a brief snapshot race we'll handle by sampling both atomically
    // at the same instant and accepting near-equality).
    auto io = std::make_shared<asio::io_context>();
    auto feed = std::make_shared<WorkerTemplateFeed>();
    auto cfg = base_cfg(io, /*pool_threads=*/1);
    cfg.pool_segment_test_hook = [](const EngineSession&, std::uint64_t,
                                    std::uint32_t) {
        Engine_config::Pool_segment_test_outcome out;
        out.candidates_to_dispatch = 1;
        return out;
    };
    PrimeMiningEngine engine{cfg, feed};

    bool found_block_called = false;
    auto on_found = [&](std::uint32_t id, std::unique_ptr<Block_data>&& bd) {
        if (id == kRepWorkerId && bd) found_block_called = true;
    };
    feed->publish(make_epoch(make_work_package(0x1c00ffffu, boost::multiprecision::uint1024_t{"0xab"}), on_found));
    engine.wait_for_sessions_published_after(0, 2s);

    const bool dispatched_some = wait_until([&]() {
        return engine.candidates_dispatched() >= 20;
    }, 1s);
    print_result("Pool dispatches >=20 candidates within 1s (test seam)",
                 dispatched_some);

    // Single-thread pool with hook returning exactly 1 candidate per segment:
    // candidates_dispatched and segments_processed must be equal at every
    // instant where they are read together.  Take both in one tight
    // sequence; allow at most a 1-step delta because the two counters are
    // bumped on consecutive instructions inside the loop body.
    const auto seg = engine.segments_processed();
    const auto cand = engine.candidates_dispatched();
    const auto delta = (seg > cand) ? (seg - cand) : (cand - seg);
    print_result("candidates_dispatched matches segments_processed (±1)",
                 delta <= 1);

    // Drain the io_context queue so we can verify the post actually
    // reached the user callback (proves the dispatch path, not just the
    // counter).  poll() runs ready handlers without blocking.
    const auto handlers_run = io->poll();
    print_result("io_context received posted on_found handlers",
                 handlers_run > 0 || found_block_called);
}

void test_pool_skips_consumed_session()
{
    auto io = std::make_shared<asio::io_context>();
    auto feed = std::make_shared<WorkerTemplateFeed>();
    auto cfg = base_cfg(io, /*pool_threads=*/2);
    cfg.pool_segment_test_hook = [](const EngineSession&, std::uint64_t,
                                    std::uint32_t) {
        Engine_config::Pool_segment_test_outcome out;
        out.candidates_to_dispatch = 0;
        return out;
    };
    PrimeMiningEngine engine{cfg, feed};

    feed->publish(make_epoch(make_work_package(0x1c00ffffu, boost::multiprecision::uint1024_t{"0xab"})));
    engine.wait_for_sessions_published_after(0, 2s);

    // Wait until the pool has processed at least one segment, then mark the
    // session consumed externally.  Pool threads must observe the flag and
    // stop accumulating segments_processed (modulo at most one in-flight
    // segment per pool thread).
    wait_until([&]() { return engine.segments_processed() >= 5; }, 1s);

    auto session = engine.current_session();
    print_result("current_session non-null before mark_consumed",
                 session != nullptr);
    if (session) session->mark_consumed();

    // Wait until pool threads notice the consumed flag and start advancing
    // m_segments_skipped_consumed.
    const bool noticed = wait_until([&]() {
        return engine.segments_skipped_consumed() >= 2;
    }, 1s);
    print_result("Pool threads advance segments_skipped_consumed after consume",
                 noticed);

    const auto seg_after_consume = engine.segments_processed();
    std::this_thread::sleep_for(100ms);
    const auto seg_settled = engine.segments_processed();
    // After consume, segments_processed should NOT keep growing
    // significantly (one in-flight per pool thread is acceptable).
    print_result("segments_processed stops growing past in-flight slack",
                 (seg_settled - seg_after_consume) <= cfg.pool_threads);
}

void test_pool_discards_on_different_base_republish()
{
    // Heavy churn: republish many distinct base_hashes back-to-back.  The
    // pool MUST observe at least some discards because a fraction of pool
    // segments will straddle a cursor reset.  Slow the segment work via
    // simulated_segment_latency so the race window is reliable.
    auto io = std::make_shared<asio::io_context>();
    auto feed = std::make_shared<WorkerTemplateFeed>();
    auto cfg = base_cfg(io, /*pool_threads=*/4);
    cfg.pool_segment_test_hook = [](const EngineSession&, std::uint64_t,
                                    std::uint32_t) {
        Engine_config::Pool_segment_test_outcome out;
        out.simulated_segment_latency = 5ms;
        return out;
    };
    PrimeMiningEngine engine{cfg, feed};

    std::uint64_t last_seen = 0;
    for (int i = 0; i < 20; ++i)
    {
        boost::multiprecision::uint1024_t h{i + 1};  // distinct base each time
        feed->publish(make_epoch(make_work_package(0x1c00ffffu, h, i)));
        last_seen = engine.wait_for_sessions_published_after(last_seen, 1s);
        std::this_thread::sleep_for(10ms);
    }

    // Wait briefly for pending in-flight segments to either commit or
    // discard before sampling the counter.
    std::this_thread::sleep_for(50ms);

    const auto discarded = engine.segments_discarded_epoch_changed();
    print_result("Heavy different-base churn produces >0 segment discards",
                 discarded > 0);
    print_result("allocator_resets advanced for every different-base publish",
                 engine.allocator_resets() == 20);
}

void test_pool_does_not_discard_on_same_base_republish()
{
    // The cursor is preserved across same-base republishes (Stone 5).  Pool
    // threads MUST therefore not discard their in-flight segment when the
    // session changes due to a same-base republish — the work is still
    // valid for the same proof-hash space.
    auto io = std::make_shared<asio::io_context>();
    auto feed = std::make_shared<WorkerTemplateFeed>();
    auto cfg = base_cfg(io, /*pool_threads=*/4);
    cfg.pool_segment_test_hook = [](const EngineSession&, std::uint64_t,
                                    std::uint32_t) {
        Engine_config::Pool_segment_test_outcome out;
        out.simulated_segment_latency = 5ms;
        return out;
    };
    PrimeMiningEngine engine{cfg, feed};

    boost::multiprecision::uint1024_t same_base{"0xfeedfacecafebeef"};
    std::uint64_t last_seen = 0;
    for (int i = 0; i < 20; ++i)
    {
        feed->publish(make_epoch(make_work_package(0x1c00ffffu, same_base, i)));
        last_seen = engine.wait_for_sessions_published_after(last_seen, 1s);
        std::this_thread::sleep_for(10ms);
    }
    std::this_thread::sleep_for(50ms);

    print_result("Same-base churn: same_base_short_circuits == publishes - 1",
                 engine.same_base_short_circuits() == 19);
    print_result("Same-base churn: only one allocator reset (the first)",
                 engine.allocator_resets() == 1);
    // Critical Stone 6 invariant: pool work is NOT discarded across
    // same-base republishes because the cursor was not reset.
    print_result("Same-base churn: zero segments discarded by the pool",
                 engine.segments_discarded_epoch_changed() == 0);
    print_result("Same-base churn: pool processed >=10 segments",
                 engine.segments_processed() >= 10);
}

void test_pool_thread_count_explicit_value()
{
    auto io = std::make_shared<asio::io_context>();
    auto feed = std::make_shared<WorkerTemplateFeed>();
    PrimeMiningEngine engine{base_cfg(io, /*pool_threads=*/1), feed};
    print_result("Explicit pool_threads=1 produces pool_thread_count==1",
                 engine.pool_thread_count() == 1);
}

void test_pool_thread_count_auto_capped()
{
    auto io = std::make_shared<asio::io_context>();
    auto feed = std::make_shared<WorkerTemplateFeed>();
    auto cfg = base_cfg(io, /*pool_threads=*/0);  // 0 => auto-derive
    cfg.pool_threads_max_cap = 2;                  // assert the cap is honoured
    PrimeMiningEngine engine{cfg, feed};
    print_result("Auto-derived pool_thread_count is clamped to max_cap",
                 engine.pool_thread_count() == 2);
}

void test_pool_session_only_mode_when_no_io_context()
{
    auto feed = std::make_shared<WorkerTemplateFeed>();
    Engine_config cfg;
    cfg.segment_size = kSegmentSize;
    cfg.channel_starting_nonce = kStartingNonce;
    cfg.pool_threads = 4;  // ignored when io_context is null
    PrimeMiningEngine engine{cfg, feed};
    print_result("No io_context => session-only mode (zero pool threads)",
                 engine.pool_thread_count() == 0);
    print_result("Session-only mode reports zero pool threads running",
                 engine.pool_threads_running() == 0);
}

void test_destruction_under_load_joins_within_bounded_timeout()
{
    // Heavy publish + heavy candidate dispatch + non-trivial per-segment
    // work, then immediate destruction.  Must join within 5 s.
    auto io = std::make_shared<asio::io_context>();
    auto feed = std::make_shared<WorkerTemplateFeed>();
    auto cfg = base_cfg(io, /*pool_threads=*/4);
    cfg.pool_segment_test_hook = [](const EngineSession&, std::uint64_t,
                                    std::uint32_t) {
        Engine_config::Pool_segment_test_outcome out;
        out.candidates_to_dispatch = 1;
        out.simulated_segment_latency = 2ms;
        return out;
    };

    auto start = std::chrono::steady_clock::now();
    {
        PrimeMiningEngine engine{cfg, feed};
        // Drive churn from a side thread while the main thread waits a moment,
        // then drops the engine out of scope mid-grind.
        std::atomic<bool> stop_pub{false};
        std::thread publisher{[&]() {
            std::uint64_t i = 0;
            while (!stop_pub.load()) {
                boost::multiprecision::uint1024_t h{i++ + 1};
                feed->publish(make_epoch(make_work_package(0x1c00ffffu, h)));
                std::this_thread::sleep_for(1ms);
            }
        }};
        std::this_thread::sleep_for(150ms);
        stop_pub.store(true);
        publisher.join();
        // Engine destructor runs here.
    }
    const auto elapsed_ms =
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - start).count();
    print_result("Heavy-load destruction joins all threads within 5s",
                 elapsed_ms < 5000);
}

} // namespace

int main()
{
    if (!spdlog::get("logger")) {
        spdlog::create<spdlog::sinks::null_sink_mt>("logger");
    }

    std::cout << "Running cpu::PrimeMiningEngine pool tests...\n";

    test_pool_spawns_and_joins_no_publish();
    test_pool_processes_segments_after_one_publish();
    test_pool_dispatches_one_candidate_per_segment();
    test_pool_skips_consumed_session();
    test_pool_discards_on_different_base_republish();
    test_pool_does_not_discard_on_same_base_republish();
    test_pool_thread_count_explicit_value();
    test_pool_thread_count_auto_capped();
    test_pool_session_only_mode_when_no_io_context();
    test_destruction_under_load_joins_within_bounded_timeout();

    std::cout << "\nResult: " << (tests_run - tests_failed) << "/" << tests_run << " passed\n";
    return tests_failed == 0 ? 0 : 1;
}
