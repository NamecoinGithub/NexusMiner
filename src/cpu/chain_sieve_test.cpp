// Tests for cpu::Sieve invariants exposed by Stones 1 + 2:
//   * Singleton sharing of the sieving prime table across Sieve instances.
//   * Sieve::prepare(X) rounds up to a multiple of 30 and caches it.
//   * Sieve::test_chains() (no-arg) operates on the same cached sieve_start.

#include "cpu/prime/chain_sieve.hpp"
#include "cpu/prime/sieving_prime_table.hpp"

#include <boost/multiprecision/cpp_int.hpp>
#include <spdlog/sinks/null_sink.h>
#include <spdlog/spdlog.h>

#include <cstddef>
#include <iostream>

namespace
{
using boost_uint1024_t = boost::multiprecision::uint1024_t;

int tests_run = 0;
int tests_failed = 0;

void print_result(const char* name, bool passed)
{
    ++tests_run;
    std::cout << (passed ? "  [PASS] " : "  [FAIL] ") << name << '\n';
    if (!passed)
        ++tests_failed;
}

void test_sieve_instances_share_prime_table()
{
    const std::size_t size_before = nexusminer::cpu::Sieving_prime_table::instance().size();

    nexusminer::cpu::Sieve a;
    a.generate_sieving_primes();
    const std::size_t size_after_a = nexusminer::cpu::Sieving_prime_table::instance().size();

    nexusminer::cpu::Sieve b;
    b.generate_sieving_primes();
    const std::size_t size_after_b = nexusminer::cpu::Sieving_prime_table::instance().size();

    print_result("Singleton size unchanged across two Sieve constructions",
                 size_before == size_after_a && size_after_a == size_after_b);
    print_result("Shared prime table is non-empty", size_before > 0);
}

void test_prepare_rounds_up_to_multiple_of_30()
{
    nexusminer::cpu::Sieve s;
    s.generate_sieving_primes();

    // Pick a deliberately non-multiple-of-30 starting point.  prepare() must
    // round UP (set_sieve_start adds `30 - X%30`), so Y >= X and Y < X + 30.
    const boost_uint1024_t x = boost_uint1024_t{1} << 256;  // not a multiple of 30
    const boost_uint1024_t y = s.prepare(x);

    print_result("prepare(X) returns Y aligned to multiple of 30", (y % 30) == 0);
    print_result("prepare(X) returns Y >= X (rounded up, never down)", y >= x);
    print_result("prepare(X) rounds by less than one wheel (Y < X + 30)", y < x + 30);
    print_result("prepare(X) caches start: get_sieve_start() == Y", s.get_sieve_start() == y);
}

void test_prepare_is_idempotent_for_aligned_start()
{
    nexusminer::cpu::Sieve s;
    s.generate_sieving_primes();

    // Already a multiple of 30 — prepare must return it unchanged.
    const boost_uint1024_t aligned = boost_uint1024_t{30} * 100;
    const boost_uint1024_t y = s.prepare(aligned);
    print_result("prepare(X) is idempotent when X is already a multiple of 30", y == aligned);
}

void test_no_arg_test_chains_uses_cached_sieve_start()
{
    nexusminer::cpu::Sieve s;
    s.generate_sieving_primes();

    const boost_uint1024_t x = (boost_uint1024_t{1} << 200) + 7;
    const boost_uint1024_t y = s.prepare(x);

    // The no-arg test_chains() forwards to test_chains(m_sieve_start) — that
    // is the same value get_sieve_start() returns.  Both calls must operate
    // on the same start; with no chains opened, neither should crash or
    // surface long-chain candidates.
    s.test_chains();
    const auto starts_after_no_arg = s.m_long_chain_starts.size();

    s.test_chains(y);
    const auto starts_after_explicit = s.m_long_chain_starts.size();

    print_result("get_sieve_start() returns the value cached by prepare()",
                 s.get_sieve_start() == y);
    print_result("test_chains() (no-arg) and test_chains(Y) produce the same"
                 " m_long_chain_starts size on an unsieved instance",
                 starts_after_no_arg == starts_after_explicit);
}

// ─── Stone 6.9 — set_target_length / prepare(start, target) ──────────────────

void test_set_target_length_clamps_and_defaults()
{
    nexusminer::cpu::Sieve s;
    // Default after construction must match the legacy constant so any
    // caller that bypasses set_target_length sees the same behaviour as
    // before Stone 6.9.
    print_result("default get_target_length() == MIN_CHAIN_LENGTH (8)",
                 s.get_target_length() == nexusminer::mining::MIN_CHAIN_LENGTH);

    // Negative / zero → reset to the legacy default.
    s.set_target_length(-1);
    print_result("set_target_length(-1) restores the legacy default",
                 s.get_target_length() == nexusminer::mining::MIN_CHAIN_LENGTH);
    s.set_target_length(0);
    print_result("set_target_length(0)  restores the legacy default",
                 s.get_target_length() == nexusminer::mining::MIN_CHAIN_LENGTH);

    // 1 must clamp to 2 (a single-prime "chain" is meaningless to dispatch).
    s.set_target_length(1);
    print_result("set_target_length(1) clamps up to 2",
                 s.get_target_length() == 2);

    // Honoured values pass through unchanged.
    s.set_target_length(7);
    print_result("set_target_length(7) is honoured verbatim",
                 s.get_target_length() == 7);
    s.set_target_length(9);
    print_result("set_target_length(9) is honoured verbatim",
                 s.get_target_length() == 9);
}

void test_prepare_with_target_length_no_ordering_hazard()
{
    nexusminer::cpu::Sieve s;
    s.generate_sieving_primes();

    // The two-argument prepare() must apply target_length BEFORE
    // clear_chains so any chain opened by a subsequent find_chains() call
    // inherits the per-session target — there must be no
    // set-then-use ordering hazard for callers that use the bundled API.
    const boost_uint1024_t x = boost_uint1024_t{1} << 128;
    const boost_uint1024_t y = s.prepare(x, 7);

    print_result("prepare(X, 7) returns aligned start", (y % 30) == 0 && y >= x);
    print_result("prepare(X, 7) sets target_length to 7", s.get_target_length() == 7);

    // Re-call with a different target — second call must overwrite, not OR.
    s.prepare(x, 6);
    print_result("prepare(X, 6) overrides previous target", s.get_target_length() == 6);
}

// ─── Stone 6.9 — Chain::is_there_still_hope behaviour ────────────────────────

namespace {
using Chain = nexusminer::cpu::Chain;
using Status = nexusminer::cpu::Fermat_test_status;

// Build a Chain with a deterministic offset list and per-slot Fermat status.
// Offsets are in sieve units (multiples of 2 within the wheel) and stay
// inside the get_best_fermat_chain maxGap window unless a test specifically
// wants to step outside it.
Chain make_chain_with_statuses(const std::vector<int>& offsets,
                               const std::vector<Status>& statuses,
                               int min_chain_length)
{
    Chain c{0};
    // Chain::open() already pushed the first slot at offset 0.  Drop it so
    // tests can express the slot list explicitly.
    c.m_offsets.clear();
    c.m_untested_count = 0;
    c.m_prime_count = 0;
    c.m_min_chain_length = min_chain_length;
    for (std::size_t i = 0; i < offsets.size(); ++i)
    {
        Chain::Chain_offset slot{offsets[i]};
        slot.m_fermat_test_status = statuses[i];
        c.m_offsets.push_back(slot);
        if (statuses[i] == Status::untested) ++c.m_untested_count;
        else if (statuses[i] == Status::pass) ++c.m_prime_count;
    }
    return c;
}
} // namespace

void test_is_there_still_hope_returns_false_when_no_untested()
{
    // Even if the chain is "complete" with all primes, hope means "is more
    // testing useful?" — and there is none if every slot is decided.
    auto c = make_chain_with_statuses(
        {0, 2, 6, 8, 12, 18, 20, 26},
        {Status::pass, Status::pass, Status::pass, Status::pass,
         Status::pass, Status::pass, Status::pass, Status::pass},
        /*min*/ 7);
    print_result("is_there_still_hope() == false when m_untested_count == 0",
                 c.is_there_still_hope() == false);
}

void test_is_there_still_hope_keepalive_at_4_primes()
{
    // 4 primes already proven + lots of failures → totals predicate (b)
    // would return false (4+1=5 < target 7), but the keepalive must override
    // and keep us testing so the upper histogram buckets remain populated.
    auto c = make_chain_with_statuses(
        {0, 2, 6, 8, 12, 18, 20, 26},
        {Status::pass, Status::pass, Status::pass, Status::pass,
         Status::fail, Status::fail, Status::fail, Status::untested},
        /*min*/ 7);
    print_result("keepalive: 4 primes + remaining untested → hope=true even when totals < min",
                 c.is_there_still_hope() == true);
}

void test_is_there_still_hope_totals_prune()
{
    // 0 primes, 1 untested, target 7 → cannot possibly reach target even
    // assuming the last untested passes.  Must give up.
    auto c = make_chain_with_statuses(
        {0, 2, 6, 8, 12, 18, 20, 26},
        {Status::fail, Status::fail, Status::fail, Status::fail,
         Status::fail, Status::fail, Status::fail, Status::untested},
        /*min*/ 7);
    print_result("totals prune: prime_count + untested_count < min → hope=false",
                 c.is_there_still_hope() == false);
}

void test_is_there_still_hope_fast_path_no_failures()
{
    // No failures yet (mix of pass + untested only); upper bound = 7 == target.
    // Fast path (c) must accept this without doing the expensive Chain copy.
    // We can only observe the result, but the result must be true.
    auto c = make_chain_with_statuses(
        {0, 2, 6, 8, 12, 18, 20},
        {Status::pass, Status::untested, Status::untested, Status::untested,
         Status::untested, Status::untested, Status::untested},
        /*min*/ 7);
    print_result("fast path: no failures yet & upper_bound >= min → hope=true",
                 c.is_there_still_hope() == true);
}

void test_is_there_still_hope_fake_pass_walk_rejects_broken_chain()
{
    // The (d) "fake-pass walk" only differs from the (b) totals prune when
    // the gap between known passes — measured ACROSS intervening fails —
    // exceeds maxGap (=12).  Construct exactly that case: a 14-unit gap
    // produced by a single failed slot at offset 14, then 5 more
    // candidates packed within maxGap of each other.  Totals say
    // 1 prime + 5 untested = 6 ≥ target 6 (hope=true), but the longest
    // contiguous gap-bounded run after fake-passing every untested is only
    // 5, because the leading prime is stranded across the >maxGap break.
    auto c = make_chain_with_statuses(
        {0, 14, 16, 18, 20, 22, 24},
        {Status::pass, Status::fail, Status::untested, Status::untested,
         Status::untested, Status::untested, Status::untested},
        /*min*/ 6);
    print_result("fake-pass walk: stranded leading prime (gap 14 > maxGap) → hope=false",
                 c.is_there_still_hope() == false);

    // Same chain with target 5 — the right-hand 5×untested run is exactly
    // enough.  hope=true.
    auto c2 = make_chain_with_statuses(
        {0, 14, 16, 18, 20, 22, 24},
        {Status::pass, Status::fail, Status::untested, Status::untested,
         Status::untested, Status::untested, Status::untested},
        /*min*/ 5);
    print_result("fake-pass walk: same chain with target 5 → hope=true",
                 c2.is_there_still_hope() == true);
}

void test_slot_filter_slack_invariant()
{
    nexusminer::cpu::Sieve s;
    s.set_target_length(7);
    print_result("slot_filter_min() == target + kSlotFilterSlack at target=7",
                 s.slot_filter_min() == 7 + nexusminer::cpu::Sieve::kSlotFilterSlack);

    s.set_target_length(8);
    print_result("slot_filter_min() == target + kSlotFilterSlack at target=8",
                 s.slot_filter_min() == 8 + nexusminer::cpu::Sieve::kSlotFilterSlack);

    // Degenerate clamp: target=2 is the sieve floor; slot filter must
    // remain >= 2 + slack and must NEVER drop below 2 even if slack
    // hypothetically went negative in a future refactor.
    s.set_target_length(2);
    print_result("slot_filter_min() >= 2 even at minimum target",
                 s.slot_filter_min() >= 2);

    // Pin the constant value itself so any change is forced through code
    // review with this test failing.
    print_result("kSlotFilterSlack pinned to 1",
                 nexusminer::cpu::Sieve::kSlotFilterSlack == 1);
}
} // namespace

int main()
{
    // Sieve unconditionally invokes m_logger->info() in several paths; install
    // a null-sink logger so the test does not depend on any prior process
    // setup (Worker_prime/main register the real "logger" sink).
    if (!spdlog::get("logger"))
    {
        spdlog::create<spdlog::sinks::null_sink_mt>("logger");
    }

    std::cout << "Running cpu::Sieve / Sieving_prime_table interaction tests...\n";
    test_sieve_instances_share_prime_table();
    test_prepare_rounds_up_to_multiple_of_30();
    test_prepare_is_idempotent_for_aligned_start();
    test_no_arg_test_chains_uses_cached_sieve_start();
    test_set_target_length_clamps_and_defaults();
    test_prepare_with_target_length_no_ordering_hazard();
    test_is_there_still_hope_returns_false_when_no_untested();
    test_is_there_still_hope_keepalive_at_4_primes();
    test_is_there_still_hope_totals_prune();
    test_is_there_still_hope_fast_path_no_failures();
    test_is_there_still_hope_fake_pass_walk_rejects_broken_chain();
    test_slot_filter_slack_invariant();

    std::cout << "\nResult: " << (tests_run - tests_failed) << "/" << tests_run << " passed\n";
    return tests_failed == 0 ? 0 : 1;
}
