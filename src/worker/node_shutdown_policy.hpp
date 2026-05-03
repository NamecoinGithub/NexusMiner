#ifndef NEXUSMINER_WORKER_NODE_SHUTDOWN_POLICY_HPP
#define NEXUSMINER_WORKER_NODE_SHUTDOWN_POLICY_HPP

namespace nexusminer {

enum class NodeShutdownAction {
    FULL_STOP,
    SWITCH_TO_STANDBY_NODE
};

inline constexpr NodeShutdownAction decide_node_shutdown_action(bool has_failover_configured) noexcept
{
    return has_failover_configured
        ? NodeShutdownAction::SWITCH_TO_STANDBY_NODE
        : NodeShutdownAction::FULL_STOP;
}

} // namespace nexusminer

#endif // NEXUSMINER_WORKER_NODE_SHUTDOWN_POLICY_HPP
