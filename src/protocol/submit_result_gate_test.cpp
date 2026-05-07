#include "protocol/submit_result_gate.hpp"

#include <iostream>

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

void test_gate_consumes_exactly_once()
{
    nexusminer::protocol::SubmitResultGate gate;

    const bool initially_not_pending = !gate.has_pending();
    const bool initial_consume_fails = !gate.consume_pending();

    gate.mark_pending();
    const bool pending_after_mark = gate.has_pending();
    const bool first_consume_succeeds = gate.consume_pending();
    const bool consumed_clears_pending = !gate.has_pending();
    const bool second_consume_fails = !gate.consume_pending();

    print_result("SubmitResultGate consumes one pending submit result exactly once",
                 initially_not_pending &&
                 initial_consume_fails &&
                 pending_after_mark &&
                 first_consume_succeeds &&
                 consumed_clears_pending &&
                 second_consume_fails);
}

void test_gate_clear_drops_pending_result()
{
    nexusminer::protocol::SubmitResultGate gate;
    gate.mark_pending();
    gate.clear();

    print_result("SubmitResultGate clear drops pending submit result",
                 !gate.has_pending() && !gate.consume_pending());
}

struct LegacyBlockResultHarness
{
    nexusminer::protocol::SubmitResultGate gate;
    int accepted{0};
    int rejected{0};
    int recovery_requests{0};

    bool accept_result()
    {
        if (!gate.consume_pending()) {
            return false;
        }
        ++accepted;
        return true;
    }

    bool reject_result()
    {
        if (!gate.consume_pending()) {
            ++recovery_requests;
            return false;
        }
        ++rejected;
        return true;
    }
};

void test_legacy_acceptance_results_are_idempotent()
{
    LegacyBlockResultHarness harness;
    harness.gate.mark_pending();

    const bool first_good_block_counted = harness.accept_result();
    const bool duplicate_good_block_ignored = !harness.accept_result();

    print_result("Legacy GOOD_BLOCK-style acceptance consumes pending submit once",
                 first_good_block_counted &&
                 duplicate_good_block_ignored &&
                 harness.accepted == 1 &&
                 harness.rejected == 0 &&
                 harness.recovery_requests == 0);
}

void test_legacy_orphan_results_require_pending_submit()
{
    LegacyBlockResultHarness harness;

    const bool stray_orphan_ignored = !harness.reject_result();
    harness.gate.mark_pending();
    const bool first_orphan_counted = harness.reject_result();
    const bool duplicate_orphan_ignored = !harness.reject_result();

    print_result("Legacy ORPHAN_BLOCK-style rejection requires and consumes pending submit",
                 stray_orphan_ignored &&
                 first_orphan_counted &&
                 duplicate_orphan_ignored &&
                 harness.accepted == 0 &&
                 harness.rejected == 1 &&
                 harness.recovery_requests == 2);
}

} // namespace

int main()
{
    test_gate_consumes_exactly_once();
    test_gate_clear_drops_pending_result();
    test_legacy_acceptance_results_are_idempotent();
    test_legacy_orphan_results_require_pending_submit();

    if (tests_failed != 0) {
        std::cout << "\nsubmit_result_gate_test: " << tests_failed << " of " << tests_run
                  << " test(s) failed.\n";
        return 1;
    }

    std::cout << "\nsubmit_result_gate_test: all " << tests_run << " test(s) passed.\n";
    return 0;
}
