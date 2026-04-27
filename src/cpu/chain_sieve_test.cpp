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

    std::cout << "\nResult: " << (tests_run - tests_failed) << "/" << tests_run << " passed\n";
    return tests_failed == 0 ? 0 : 1;
}
