#include "worker/node_shutdown_policy.hpp"

#include <iostream>

namespace {

int tests_run = 0;
int tests_failed = 0;

void check(bool condition, const char* label)
{
    ++tests_run;
    if (condition) {
        std::cout << "  [PASS] " << label << '\n';
    } else {
        ++tests_failed;
        std::cout << "  [FAIL] " << label << '\n';
    }
}

void test_no_failover_full_stops()
{
    check(nexusminer::decide_node_shutdown_action(false) ==
              nexusminer::NodeShutdownAction::FULL_STOP,
          "NODE_SHUTDOWN with no failover selects FULL_STOP");
}

void test_failover_switches_to_standby()
{
    check(nexusminer::decide_node_shutdown_action(true) ==
              nexusminer::NodeShutdownAction::SWITCH_TO_STANDBY_NODE,
          "NODE_SHUTDOWN with failover selects standby-node switch");
}

} // namespace

int main()
{
    std::cout << "node_shutdown_policy_test\n";

    test_no_failover_full_stops();
    test_failover_switches_to_standby();

    if (tests_failed != 0) {
        std::cout << "\nnode_shutdown_policy_test: " << tests_failed
                  << " of " << tests_run << " test(s) failed.\n";
        return 1;
    }

    std::cout << "\nnode_shutdown_policy_test: all " << tests_run
              << " test(s) passed.\n";
    return 0;
}
