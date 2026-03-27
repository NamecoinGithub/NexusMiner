#include "protocol/session_coordinator.hpp"
#include <sstream>
#include <iomanip>
#include <algorithm>

namespace nexusminer {
namespace protocol {

SessionCoordinator::SessionCoordinator(std::shared_ptr<spdlog::logger> logger)
    : m_logger(std::move(logger))
{
}

// ── Private static helper ─────────────────────────────────────────────────────

void SessionCoordinator::fire_notifications(
    const std::vector<StateChangeObserver>& observers,
    const std::vector<Notification>& notifications)
{
    for (const auto& n : notifications) {
        for (const auto& observer : observers) {
            observer(n.domain, n.old_val, n.new_val);
        }
    }
}

// ── Epoch management ──────────────────────────────────────────────────────────

SessionEpoch SessionCoordinator::session_epoch() const
{
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_session_epoch;
}

SessionEpoch SessionCoordinator::advance_session_epoch(const char* reason)
{
    uint64_t old_val, new_val;
    std::vector<StateChangeObserver> obs;

    {
        std::lock_guard<std::mutex> lock(m_mutex);
        old_val = m_session_epoch.get();
        ++m_session_epoch.get();
        new_val = m_session_epoch.get();
        if (m_logger) {
            m_logger->info("[SessionCoordinator] session_epoch {} → {} ({})",
                           old_val, new_val, reason ? reason : "");
        }
        obs = m_observers;
    }

    fire_notifications(obs, {{DOMAIN_SESSION_EPOCH, old_val, new_val}});
    return SessionEpoch{new_val};
}

uint64_t SessionCoordinator::recovery_epoch() const
{
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_recovery_epoch;
}

uint64_t SessionCoordinator::advance_recovery_epoch(const char* reason)
{
    uint64_t old_val, new_val;
    std::vector<StateChangeObserver> obs;

    {
        std::lock_guard<std::mutex> lock(m_mutex);
        old_val = m_recovery_epoch;
        ++m_recovery_epoch;
        new_val = m_recovery_epoch;
        if (m_logger) {
            m_logger->info("[SessionCoordinator] recovery_epoch {} → {} ({})",
                           old_val, new_val, reason ? reason : "");
        }
        obs = m_observers;
    }

    fire_notifications(obs, {{DOMAIN_RECOVERY_EPOCH, old_val, new_val}});
    return new_val;
}

uint64_t SessionCoordinator::global_epoch() const
{
    std::lock_guard<std::mutex> lock(m_mutex);
    return std::max(m_session_epoch.get(), m_recovery_epoch);
}

// ── Session identity ──────────────────────────────────────────────────────────

SessionId SessionCoordinator::session_id() const
{
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_session_id;
}

void SessionCoordinator::set_session_id(SessionId id, const char* reason)
{
    uint64_t old_val, new_val;
    std::vector<StateChangeObserver> obs;

    {
        std::lock_guard<std::mutex> lock(m_mutex);
        old_val = m_session_id.get();
        new_val = id.get();
        m_session_id = id;
        if (m_logger && old_val != new_val) {
            m_logger->info("[SessionCoordinator] session_id 0x{:08x} → 0x{:08x} ({})",
                           old_val, id.get(), reason ? reason : "");
        }
        obs = m_observers;
    }

    fire_notifications(obs, {{DOMAIN_SESSION_ID, old_val, new_val}});
}

bool SessionCoordinator::is_authenticated() const
{
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_authenticated;
}

void SessionCoordinator::set_authenticated(bool auth, const char* reason)
{
    uint64_t old_val, new_val;
    std::vector<StateChangeObserver> obs;

    {
        std::lock_guard<std::mutex> lock(m_mutex);
        old_val = m_authenticated ? 1u : 0u;
        new_val = auth ? 1u : 0u;
        m_authenticated = auth;
        if (m_logger && old_val != new_val) {
            m_logger->info("[SessionCoordinator] authenticated {} → {} ({})",
                           old_val, new_val, reason ? reason : "");
        }
        obs = m_observers;
    }

    fire_notifications(obs, {{DOMAIN_AUTHENTICATED, old_val, new_val}});
}

bool SessionCoordinator::is_reward_bound() const
{
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_reward_bound;
}

void SessionCoordinator::set_reward_bound(bool bound, const char* reason)
{
    uint64_t old_val, new_val;
    std::vector<StateChangeObserver> obs;

    {
        std::lock_guard<std::mutex> lock(m_mutex);
        old_val = m_reward_bound ? 1u : 0u;
        new_val = bound ? 1u : 0u;
        m_reward_bound = bound;
        if (m_logger && old_val != new_val) {
            m_logger->info("[SessionCoordinator] reward_bound {} → {} ({})",
                           old_val, new_val, reason ? reason : "");
        }
        obs = m_observers;
    }

    fire_notifications(obs, {{DOMAIN_REWARD_BOUND, old_val, new_val}});
}

bool SessionCoordinator::is_subscribed_to_notifications() const
{
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_subscribed_to_notifications;
}

void SessionCoordinator::set_subscribed_to_notifications(bool subscribed, const char* reason)
{
    uint64_t old_val, new_val;
    std::vector<StateChangeObserver> obs;

    {
        std::lock_guard<std::mutex> lock(m_mutex);
        old_val = m_subscribed_to_notifications ? 1u : 0u;
        new_val = subscribed ? 1u : 0u;
        m_subscribed_to_notifications = subscribed;
        if (m_logger && old_val != new_val) {
            m_logger->info("[SessionCoordinator] subscribed_to_notifications {} → {} ({})",
                           old_val, new_val, reason ? reason : "");
        }
        obs = m_observers;
    }

    fire_notifications(obs, {{DOMAIN_SUBSCRIBED, old_val, new_val}});
}

bool SessionCoordinator::has_pending_push_after_auth() const
{
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_pending_push_after_auth;
}

void SessionCoordinator::set_pending_push_after_auth(bool pending, const char* reason)
{
    uint64_t old_val, new_val;
    std::vector<StateChangeObserver> obs;

    {
        std::lock_guard<std::mutex> lock(m_mutex);
        old_val = m_pending_push_after_auth ? 1u : 0u;
        new_val = pending ? 1u : 0u;
        m_pending_push_after_auth = pending;
        if (m_logger && old_val != new_val) {
            m_logger->info("[SessionCoordinator] pending_push_after_auth {} → {} ({})",
                           old_val, new_val, reason ? reason : "");
        }
        obs = m_observers;
    }

    fire_notifications(obs, {{DOMAIN_PENDING_PUSH, old_val, new_val}});
}

// ── Composite queries ─────────────────────────────────────────────────────────

bool SessionCoordinator::can_request_get_block() const
{
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_authenticated;
}

bool SessionCoordinator::can_submit() const
{
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_authenticated && m_reward_bound;
}

bool SessionCoordinator::is_session_active() const
{
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_authenticated && !m_session_id.is_default();
}

// ── Bulk operations ───────────────────────────────────────────────────────────

void SessionCoordinator::clear_for_disconnect(const char* reason)
{
    std::vector<Notification> events;
    std::vector<StateChangeObserver> obs;

    {
        std::lock_guard<std::mutex> lock(m_mutex);
        // EPOCHS ARE NEVER CLEARED — preserves monotonicity across disconnects
        const SessionId old_session_id   = m_session_id;
        const bool     old_authenticated = m_authenticated;
        const bool     old_reward_bound  = m_reward_bound;

        m_session_id.clear();
        m_authenticated               = false;
        m_reward_bound                = false;
        m_subscribed_to_notifications = false;
        m_pending_push_after_auth     = false;

        if (m_logger) {
            m_logger->info("[SessionCoordinator] clear_for_disconnect ({}): "
                           "session_id 0x{:08x}→0, authenticated {}→false, reward_bound {}→false; "
                           "session_epoch={} recovery_epoch={} (preserved)",
                           reason ? reason : "",
                           old_session_id.get(), old_authenticated, old_reward_bound,
                           m_session_epoch.get(), m_recovery_epoch);
        }
        if (!old_session_id.is_default()) {
            events.push_back({DOMAIN_SESSION_ID, old_session_id.get(), 0});
        }
        if (old_authenticated) {
            events.push_back({DOMAIN_AUTHENTICATED, 1, 0});
        }
        if (old_reward_bound) {
            events.push_back({DOMAIN_REWARD_BOUND, 1, 0});
        }
        obs = m_observers;
    }

    fire_notifications(obs, events);
}

void SessionCoordinator::commit_authenticated(SessionId new_session_id, const char* reason)
{
    std::vector<Notification> events;
    std::vector<StateChangeObserver> obs;

    {
        std::lock_guard<std::mutex> lock(m_mutex);
        const uint64_t old_epoch      = m_session_epoch.get();
        const SessionId old_session_id = m_session_id;

        ++m_session_epoch.get();
        m_session_id    = new_session_id;
        m_authenticated = true;

        if (m_logger) {
            m_logger->info("[SessionCoordinator] commit_authenticated ({}): "
                           "session_epoch {}→{}, session_id 0x{:08x}→0x{:08x}",
                           reason ? reason : "",
                           old_epoch, m_session_epoch.get(),
                           old_session_id.get(), new_session_id.get());
        }
        events.push_back({DOMAIN_SESSION_EPOCH, old_epoch, m_session_epoch.get()});
        if (old_session_id != new_session_id) {
            events.push_back({DOMAIN_SESSION_ID, old_session_id.get(), new_session_id.get()});
        }
        events.push_back({DOMAIN_AUTHENTICATED, 0, 1});
        obs = m_observers;
    }

    fire_notifications(obs, events);
}

// ── Observer pattern ──────────────────────────────────────────────────────────

void SessionCoordinator::add_observer(StateChangeObserver observer)
{
    std::lock_guard<std::mutex> lock(m_mutex);
    m_observers.push_back(std::move(observer));
}

// ── Snapshot ─────────────────────────────────────────────────────────────────

SessionCoordinator::Snapshot SessionCoordinator::snapshot() const
{
    std::lock_guard<std::mutex> lock(m_mutex);
    Snapshot s;
    s.session_epoch               = m_session_epoch;
    s.recovery_epoch              = m_recovery_epoch;
    s.global_epoch                = std::max(m_session_epoch.get(), m_recovery_epoch);
    s.session_id                  = m_session_id;
    s.authenticated               = m_authenticated;
    s.reward_bound                = m_reward_bound;
    s.subscribed_to_notifications = m_subscribed_to_notifications;
    s.pending_push_after_auth     = m_pending_push_after_auth;
    return s;
}

std::string SessionCoordinator::diagnostics() const
{
    const auto snap = snapshot();
    std::ostringstream oss;
    oss << "SessionCoordinator{"
        << "session_epoch=" << snap.session_epoch.get()
        << " recovery_epoch=" << snap.recovery_epoch
        << " global_epoch=" << snap.global_epoch
        << " session_id=0x" << std::hex << std::setw(8) << std::setfill('0') << snap.session_id.get()
        << std::dec
        << " authenticated=" << snap.authenticated
        << " reward_bound=" << snap.reward_bound
        << " subscribed=" << snap.subscribed_to_notifications
        << " pending_push=" << snap.pending_push_after_auth
        << "}";
    return oss.str();
}

} // namespace protocol
} // namespace nexusminer
