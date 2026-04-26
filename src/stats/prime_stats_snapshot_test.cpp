#include "stats/prime_stats_snapshot.hpp"
#include "stats/types.hpp"

#include <iostream>
#include <vector>

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

void test_copy_prime_histogram_clamps_and_zero_fills()
{
    const std::vector<std::uint32_t> histogram{1, 2, 3, 4, 5};
    const auto snapshot = nexusminer::stats::copy_prime_histogram(histogram);

    const bool passed = snapshot[0] == 1 &&
                        snapshot[1] == 2 &&
                        snapshot[2] == 3 &&
                        snapshot[3] == 4 &&
                        snapshot[4] == 5 &&
                        snapshot[5] == 0 &&
                        snapshot.back() == 0;
    print_result("Prime histogram snapshot copies values and zero-fills tail", passed);
}

void test_atomic_snapshot_keeps_immutable_previous_value()
{
    nexusminer::stats::Atomic_snapshot<nexusminer::stats::Prime> snapshot_store;

    nexusminer::stats::Prime first;
    first.m_range_searched = 11;
    first.m_chain_histogram[5] = 7;
    snapshot_store.store(first);
    auto first_snapshot = snapshot_store.load();

    nexusminer::stats::Prime second = first;
    second.m_range_searched = 42;
    second.m_chain_histogram[5] = 9;
    snapshot_store.store(second);
    auto second_snapshot = snapshot_store.load();

    const bool passed = first_snapshot->m_range_searched == 11 &&
                        first_snapshot->m_chain_histogram[5] == 7 &&
                        second_snapshot->m_range_searched == 42 &&
                        second_snapshot->m_chain_histogram[5] == 9;
    print_result("Atomic snapshot readers keep immutable published values", passed);
}
}

int main()
{
    test_copy_prime_histogram_clamps_and_zero_fills();
    test_atomic_snapshot_keeps_immutable_previous_value();

    if (tests_failed != 0)
    {
        std::cout << "\nprime_stats_snapshot_test: " << tests_failed << " of " << tests_run
                  << " test(s) failed.\n";
        return 1;
    }

    std::cout << "\nprime_stats_snapshot_test: all " << tests_run << " test(s) passed.\n";
    return 0;
}
