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

} // namespace

int main()
{
    test_gate_consumes_exactly_once();
    test_gate_clear_drops_pending_result();

    if (tests_failed != 0) {
        std::cout << "\nsubmit_result_gate_test: " << tests_failed << " of " << tests_run
                  << " test(s) failed.\n";
        return 1;
    }

    std::cout << "\nsubmit_result_gate_test: all " << tests_run << " test(s) passed.\n";
    return 0;
}
