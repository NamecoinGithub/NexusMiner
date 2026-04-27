// Stone 6 — PrimeMiningEngine pool sieve threads tests.
//
// Covers:
//   * Lifecycle: pool threads spawn and join cleanly with no template
//     ever published.
//   * One-template advances: segments_processed counter advances after
//     a single publish.
//   * Heavy churn: rapid republishes drive
//     segments_discarded_epoch_changed > 0.
//   * Candidates dispatched: forced-candidate seam yields candidates_dispatched
//     equal to the number of segments processed before the session is consumed.
//   * Explicit pool_threads count is honored as-is.
//   * pool_threads == 0 auto-derives within the auto-cap.
//   * segments_skipped_consumed advances after the session is consumed.
//   * Destruction during heavy publish + heavy candidate dispatch joins
//     cleanly within a 5s bound.
//   * Same-base-hash republish does NOT discard work
//     (segments_discarded_epoch_changed only advances on actual base change).
//
// The tests use the Engine_config::test_skip_sieve and
// test_force_candidate_per_segment seams so they don't depend on the actual
// prime distribution of an arbitrary base hash.  The full sieve pipeline
// is exercised in production paths (Stone 7) and by the existing
// chain_sieve_test / prime_validation_test targets.

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
    if (!passed) ++tests_failed;
}

constexpr std::uint64_t kSegmentSize = 4096;
constexpr std::uint64_t kStartingNonce = 0x1234'0000'0000ULL;
constexpr std::uint32_t kRepWorkerId = 7;

// RAII wrapper: an io_context with a work guard, run on a background thread,
// shut down cleanly on destruction.  Pool threads asio::post their found-block
// callbacks to this io_context.
struct Test_io_context
{
    std::shared_ptr<asio::io_context> ctx;
    asio::executor_work_guard<asio::io_context::executor_type> guard;
    std::thread runner;

    Test_io_context()
        : ctx{std::make_shared<asio::io_context>()}
        , guard{asio::make_work_guard(*ctx)}
        , runner{[this] { ctx->run(); }}
    {}

    ~Test_io_context()
    {
        guard.reset();
        ctx->stop();
        if (runner.joinable()) runner.join();
    }
};

Engine_config make_cfg(std::uint32_t pool_threads,
                       std::shared_ptr<asio::io_context> io,
                       bool force_candidate = false)
{
    Engine_config cfg;
    cfg.segment_size = kSegmentSize;
    cfg.channel_starting_nonce = kStartingNonce;
    cfg.internal_id_for_solution = kRepWorkerId;
    cfg.pool_threads = pool_threads;
    cfg.io_context = std::move(io);
    cfg.test_skip_sieve = true;
    cfg.test_force_candidate_per_segment = force_candidate;
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

// Wait until predicate() returns true OR the deadline expires.  Returns the
// final predicate value.  Used to avoid sleep-and-pray timing in tests.
template <typename Pred>
bool wait_until(std::chrono::milliseconds budget, Pred pred)
{
    const auto deadline = std::chrono::steady_clock::now() + budget;
    while (std::chrono::steady_clock::now() < deadline)
    {
        if (pred()) return true;
        std::this_thread::sleep_for(1ms);
    }
    return pred();
}

// ─────────────────────────────────────────────────────────────────────────────

void test_no_template_lifecycle()
{
    Test_io_context io;
    auto feed = std::make_shared<WorkerTemplateFeed>();
    {
        PrimeMiningEngine engine{make_cfg(2, io.ctx), feed};
        // Give pool threads a moment to actually park on m_pool_cv.
        const bool running = wait_until(500ms,
            [&] { return engine.pool_threads_running() == 2; });
        print_result("Pool threads start (count==2 with no template)", running);
        print_result("No-template: segments_processed == 0",
                     engine.segments_processed() == 0);
        print_result("No-template: candidates_dispatched == 0",
                     engine.candidates_dispatched() == 0);
        print_result("No-template: pool_threads_crashed == 0",
                     engine.pool_threads_crashed() == 0);
    }
    print_result("Destructor joins pool threads cleanly with no template", true);
}

void test_one_template_segments_advance()
{
    Test_io_context io;
    auto feed = std::make_shared<WorkerTemplateFeed>();
    PrimeMiningEngine engine{make_cfg(2, io.ctx), feed};

    boost::multiprecision::uint1024_t base{"0xabc"};
    feed->publish(make_epoch(make_work_package(0x1c00ffffu, base, 1)));
    engine.wait_for_sessions_published_after(0, 2s);

    const bool advanced = wait_until(2s, [&] {
        return engine.segments_processed() >= 8;
    });
    print_result("segments_processed advances after a publish", advanced);
    print_result("Pool did not crash", engine.pool_threads_crashed() == 0);
    print_result("No epoch-discards on a single stable template",
                 engine.segments_discarded_epoch_changed() == 0);
}

void test_heavy_churn_drives_discards()
{
    Test_io_context io;
    auto feed = std::make_shared<WorkerTemplateFeed>();
    PrimeMiningEngine engine{make_cfg(4, io.ctx), feed};

    // Publish many distinct base hashes back-to-back.  Each different base
    // forces an allocator reset on the consumer side; the post-segment
    // re-check on pool threads catches the base-hash change and increments
    // segments_discarded_epoch_changed.
    constexpr int kPublishes = 50;
    std::uint64_t last_seen = 0;
    for (int i = 0; i < kPublishes; ++i)
    {
        boost::multiprecision::uint1024_t base{i + 1};
        feed->publish(make_epoch(make_work_package(0x1c00ffffu, base, i)));
        last_seen = engine.wait_for_sessions_published_after(last_seen, 1s);
        std::this_thread::sleep_for(2ms);
    }

    // Give pool threads a beat to observe the final session and process.
    wait_until(1s, [&] { return engine.segments_processed() > 0; });

    print_result("Heavy churn: allocator_resets >= kPublishes",
                 engine.allocator_resets() >= static_cast<std::uint64_t>(kPublishes));
    print_result("Heavy churn: segments_discarded_epoch_changed > 0",
                 engine.segments_discarded_epoch_changed() > 0);
    print_result("Heavy churn: pool_threads_crashed == 0",
                 engine.pool_threads_crashed() == 0);
}

void test_candidates_dispatched_accuracy()
{
    Test_io_context io;
    std::atomic<int> on_found_calls{0};
    auto feed = std::make_shared<WorkerTemplateFeed>();
    PrimeMiningEngine engine{make_cfg(/*pool_threads=*/2, io.ctx,
                                      /*force_candidate=*/true), feed};

    boost::multiprecision::uint1024_t base{"0xfeed"};
    feed->publish(make_epoch(make_work_package(0x1c00ffffu, base, 42),
        [&](std::uint32_t /*id*/, std::unique_ptr<Block_data>&& bd) {
            (void)bd;
            on_found_calls.fetch_add(1, std::memory_order_relaxed);
        }));
    engine.wait_for_sessions_published_after(0, 2s);

    // With test_force_candidate_per_segment + single-found-block-wins, the
    // first segment any pool thread completes for this session marks the
    // session consumed; every subsequent pool-thread iteration observes the
    // consumed bit and idles.  So candidates_dispatched MUST equal exactly 1
    // per published session, regardless of pool thread count.
    const bool dispatched = wait_until(2s, [&] {
        return engine.candidates_dispatched() == 1;
    });
    print_result("Forced candidate: candidates_dispatched == 1 per session",
                 dispatched);

    // Wait for the io_context to drain the posted callback.
    const bool callback_fired = wait_until(2s, [&] {
        return on_found_calls.load() == 1;
    });
    print_result("Forced candidate: on_found callback fired exactly once",
                 callback_fired);

    print_result("Forced candidate: pool did not crash",
                 engine.pool_threads_crashed() == 0);
}

void test_explicit_pool_thread_count_honored()
{
    Test_io_context io;
    auto feed = std::make_shared<WorkerTemplateFeed>();
    PrimeMiningEngine engine{make_cfg(/*pool_threads=*/3, io.ctx), feed};
    print_result("Explicit pool_threads=3 honored",
                 engine.pool_thread_count() == 3);
    const bool running = wait_until(500ms,
        [&] { return engine.pool_threads_running() == 3; });
    print_result("3 pool threads actually running", running);
}

void test_auto_pool_thread_count_within_cap()
{
    Test_io_context io;
    auto feed = std::make_shared<WorkerTemplateFeed>();
    PrimeMiningEngine engine{make_cfg(/*pool_threads=*/0, io.ctx), feed};
    const auto count = engine.pool_thread_count();
    print_result("Auto pool count >= 1",
                 count >= 1);
    print_result("Auto pool count <= max auto cap",
                 count <= PrimeMiningEngine::pool_threads_max_auto_cap);
}

void test_skipped_consumed_advances()
{
    Test_io_context io;
    auto feed = std::make_shared<WorkerTemplateFeed>();
    PrimeMiningEngine engine{make_cfg(/*pool_threads=*/2, io.ctx,
                                      /*force_candidate=*/true), feed};

    boost::multiprecision::uint1024_t base{"0xc0ffee"};
    feed->publish(make_epoch(make_work_package(0x1c00ffffu, base, 1),
        [](std::uint32_t, std::unique_ptr<Block_data>&&) {}));
    engine.wait_for_sessions_published_after(0, 2s);

    // Wait for the candidate to be dispatched (session marked consumed).
    wait_until(2s, [&] { return engine.candidates_dispatched() == 1; });

    // After consumption, both pool threads should observe is_consumed() and
    // skip-park.  The idle path increments segments_skipped_consumed each
    // time a pool thread re-checks while the session is still consumed.
    const bool skipped = wait_until(2s, [&] {
        return engine.segments_skipped_consumed() > 0;
    });
    print_result("segments_skipped_consumed advances after session consumed",
                 skipped);
}

void test_destruction_during_heavy_churn()
{
    Test_io_context io;
    auto feed = std::make_shared<WorkerTemplateFeed>();
    auto cfg = make_cfg(/*pool_threads=*/4, io.ctx, /*force_candidate=*/true);

    auto start = std::chrono::steady_clock::now();
    {
        PrimeMiningEngine engine{cfg, feed};

        // Background publisher: hammer the feed with new templates while the
        // engine is mining and dispatching.  Each new template re-arms the
        // session (clears consumed) so candidates keep flowing.
        std::atomic<bool> stop{false};
        std::thread publisher([&] {
            int i = 1;
            while (!stop.load(std::memory_order_acquire))
            {
                boost::multiprecision::uint1024_t base{i++};
                feed->publish(make_epoch(make_work_package(0x1c00ffffu, base, i),
                    [](std::uint32_t, std::unique_ptr<Block_data>&&) {}));
                std::this_thread::sleep_for(500us);
            }
        });

        std::this_thread::sleep_for(200ms);
        stop.store(true, std::memory_order_release);
        publisher.join();
        // Engine destructor runs on scope exit.
    }
    const auto elapsed = std::chrono::steady_clock::now() - start;
    const auto elapsed_ms =
        std::chrono::duration_cast<std::chrono::milliseconds>(elapsed).count();
    print_result("Destruction during heavy churn joins within 5s",
                 elapsed_ms < 5000);
}

void test_same_base_republish_preserves_work()
{
    Test_io_context io;
    auto feed = std::make_shared<WorkerTemplateFeed>();
    PrimeMiningEngine engine{make_cfg(/*pool_threads=*/2, io.ctx), feed};

    boost::multiprecision::uint1024_t base{"0xbeef"};
    feed->publish(make_epoch(make_work_package(0x1c00ffffu, base, 1)));
    auto p1 = engine.wait_for_sessions_published_after(0, 2s);

    // Let pool threads do real work (no candidates because force=false).
    wait_until(500ms, [&] { return engine.segments_processed() >= 8; });
    const auto discards_before = engine.segments_discarded_epoch_changed();
    const auto resets_before = engine.allocator_resets();

    // Republish with SAME base_hash but a different height.  The engine
    // consumer must NOT reset the cursor; the pool-thread post-segment
    // re-check must NOT discard (base_hash matches).
    feed->publish(make_epoch(make_work_package(0x1c00ffffu, base, 2)));
    engine.wait_for_sessions_published_after(p1, 2s);

    // Let a few more segments drain so any spurious discards would surface.
    const auto baseline_segments = engine.segments_processed();
    wait_until(500ms, [&] {
        return engine.segments_processed() >= baseline_segments + 8;
    });

    print_result("Same-base republish: allocator_resets unchanged",
                 engine.allocator_resets() == resets_before);
    print_result("Same-base republish: same_base_short_circuits == 1",
                 engine.same_base_short_circuits() == 1);
    print_result("Same-base republish: no extra discards",
                 engine.segments_discarded_epoch_changed() == discards_before);
}

}  // namespace

int main()
{
    if (!spdlog::get("logger"))
    {
        spdlog::create<spdlog::sinks::null_sink_mt>("logger");
    }

    std::cout << "Running cpu::PrimeMiningEngine pool-thread tests...\n";

    test_no_template_lifecycle();
    test_one_template_segments_advance();
    test_heavy_churn_drives_discards();
    test_candidates_dispatched_accuracy();
    test_explicit_pool_thread_count_honored();
    test_auto_pool_thread_count_within_cap();
    test_skipped_consumed_advances();
    test_destruction_during_heavy_churn();
    test_same_base_republish_preserves_work();

    std::cout << "\nResult: " << (tests_run - tests_failed) << "/" << tests_run << " passed\n";
    return tests_failed == 0 ? 0 : 1;
}
