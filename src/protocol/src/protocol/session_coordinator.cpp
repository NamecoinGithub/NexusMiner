#include "protocol/session_coordinator.hpp"
#include <sstream>
#include <iomanip>

namespace nexusminer {
namespace protocol {

SessionCoordinator::SessionCoordinator(std::shared_ptr<spdlog::logger> logger)
    : m_logger(std::move(logger))
{
}

// ── Epoch management ──────────────────────────────────────────────────────────

uint64_t SessionCoordinator::session_epoch() const
{
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_session_epoch;
}

uint64_t SessionCoordinator::advance_session_epoch(const char* reason)
{
    std::lock_guard<std::mutex> lock(m_mutex);
    const uint64_t old_val = m_session_epoch;
    ++m_session_epoch;
    if (m_logger) {
        m_logger->info("[SessionCoordinator] session_epoch {} → {} ({})",
                       old_val, m_session_epoch, reason ? reason : "");
    }
    notify_observers_locked(DOMAIN_SESSION_EPOCH, old_val, m_session_epoch);
    return m_session_epoch;
}

uint64_t SessionCoordinator::recovery_epoch() const
{
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_recovery_epoch;
}

uint64_t SessionCoordinator::advance_recovery_epoch(const char* reason)
{
    std::lock_guard<std::mutex> lock(m_mutex);
    const uint64_t old_val = m_recovery_epoch;
    ++m_recovery_epoch;
    if (m_logger) {
        m_logger->info("[SessionCoordinator] recovery_epoch {} → {} ({})",
                       old_val, m_recovery_epoch, reason ? reason : "");
    }
    notify_observers_locked(DOMAIN_RECOVERY_EPOCH, old_val, m_recovery_epoch);
    return m_recovery_epoch;
}

uint64_t SessionCoordinator::global_epoch() const
{
    std::lock_guard<std::mutex> lock(m_mutex);
    return (m_session_epoch > m_recovery_epoch) ? m_session_epoch : m_recovery_epoch;
}

// ── Session identity ──────────────────────────────────────────────────────────

uint32_t SessionCoordinator::session_id() const
{
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_session_id;
}

void SessionCoordinator::set_session_id(uint32_t id, const char* reason)
{
    std::lock_guard<std::mutex> lock(m_mutex);
    const uint64_t old_val = m_session_id;
    m_session_id = id;
    if (m_logger && old_val != id) {
        m_logger->info("[SessionCoordinator] session_id 0x{:08x} → 0x{:08x} ({})",
                       old_val, id, reason ? reason : "");
    }
    notify_observers_locked(DOMAIN_SESSION_ID, old_val, id);
}

bool SessionCoordinator::is_authenticated() const
{
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_authenticated;
}

void SessionCoordinator::set_authenticated(bool auth, const char* reason)
{
    std::lock_guard<std::mutex> lock(m_mutex);
    const uint64_t old_val = m_authenticated ? 1u : 0u;
    const uint64_t new_val = auth ? 1u : 0u;
    m_authenticated = auth;
    if (m_logger && old_val != new_val) {
        m_logger->info("[SessionCoordinator] authenticated {} → {} ({})",
                       old_val, new_val, reason ? reason : "");
    }
    notify_observers_locked(DOMAIN_AUTHENTICATED, old_val, new_val);
}

bool SessionCoordinator::is_reward_bound() const
{
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_reward_bound;
}

void SessionCoordinator::set_reward_bound(bool bound, const char* reason)
{
    std::lock_guard<std::mutex> lock(m_mutex);
    const uint64_t old_val = m_reward_bound ? 1u : 0u;
    const uint64_t new_val = bound ? 1u : 0u;
    m_reward_bound = bound;
    if (m_logger && old_val != new_val) {
        m_logger->info("[SessionCoordinator] reward_bound {} → {} ({})",
                       old_val, new_val, reason ? reason : "");
    }
    notify_observers_locked(DOMAIN_REWARD_BOUND, old_val, new_val);
}

bool SessionCoordinator::is_subscribed_to_notifications() const
{
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_subscribed_to_notifications;
}

void SessionCoordinator::set_subscribed_to_notifications(bool subscribed, const char* reason)
{
    std::lock_guard<std::mutex> lock(m_mutex);
    const uint64_t old_val = m_subscribed_to_notifications ? 1u : 0u;
    const uint64_t new_val = subscribed ? 1u : 0u;
    m_subscribed_to_notifications = subscribed;
    if (m_logger && old_val != new_val) {
        m_logger->info("[SessionCoordinator] subscribed_to_notifications {} → {} ({})",
                       old_val, new_val, reason ? reason : "");
    }
    notify_observers_locked(DOMAIN_SUBSCRIBED, old_val, new_val);
}

bool SessionCoordinator::has_pending_push_after_auth() const
{
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_pending_push_after_auth;
}

void SessionCoordinator::set_pending_push_after_auth(bool pending, const char* reason)
{
    std::lock_guard<std::mutex> lock(m_mutex);
    const uint64_t old_val = m_pending_push_after_auth ? 1u : 0u;
    const uint64_t new_val = pending ? 1u : 0u;
    m_pending_push_after_auth = pending;
    if (m_logger && old_val != new_val) {
        m_logger->info("[SessionCoordinator] pending_push_after_auth {} → {} ({})",
                       old_val, new_val, reason ? reason : "");
    }
    notify_observers_locked(DOMAIN_PENDING_PUSH, old_val, new_val);
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
    return m_authenticated && m_session_id != 0;
}

// ── Bulk operations ───────────────────────────────────────────────────────────

void SessionCoordinator::clear_for_disconnect(const char* reason)
{
    std::lock_guard<std::mutex> lock(m_mutex);
    // EPOCHS ARE NEVER CLEARED — preserves monotonicity across disconnects
    const uint32_t old_session_id   = m_session_id;
    const bool     old_authenticated = m_authenticated;
    const bool     old_reward_bound  = m_reward_bound;

    m_session_id                  = 0;
    m_authenticated               = false;
    m_reward_bound                = false;
    m_subscribed_to_notifications = false;
    m_pending_push_after_auth     = false;

    if (m_logger) {
        m_logger->info("[SessionCoordinator] clear_for_disconnect ({}): "
                       "session_id 0x{:08x}→0, authenticated {}→false, reward_bound {}→false; "
                       "session_epoch={} recovery_epoch={} (preserved)",
                       reason ? reason : "",
                       old_session_id, old_authenticated, old_reward_bound,
                       m_session_epoch, m_recovery_epoch);
    }
    if (old_session_id != 0) {
        notify_observers_locked(DOMAIN_SESSION_ID, old_session_id, 0);
    }
    if (old_authenticated) {
        notify_observers_locked(DOMAIN_AUTHENTICATED, 1, 0);
    }
    if (old_reward_bound) {
        notify_observers_locked(DOMAIN_REWARD_BOUND, 1, 0);
    }
}

void SessionCoordinator::commit_authenticated(uint32_t new_session_id, const char* reason)
{
    std::lock_guard<std::mutex> lock(m_mutex);
    const uint64_t old_epoch     = m_session_epoch;
    const uint32_t old_session_id = m_session_id;

    ++m_session_epoch;
    m_session_id    = new_session_id;
    m_authenticated = true;

    if (m_logger) {
        m_logger->info("[SessionCoordinator] commit_authenticated ({}): "
                       "session_epoch {}→{}, session_id 0x{:08x}→0x{:08x}",
                       reason ? reason : "",
                       old_epoch, m_session_epoch,
                       old_session_id, new_session_id);
    }
    notify_observers_locked(DOMAIN_SESSION_EPOCH, old_epoch, m_session_epoch);
    if (old_session_id != new_session_id) {
        notify_observers_locked(DOMAIN_SESSION_ID, old_session_id, new_session_id);
    }
    notify_observers_locked(DOMAIN_AUTHENTICATED, 0, 1);
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
    s.session_epoch              = m_session_epoch;
    s.recovery_epoch             = m_recovery_epoch;
    s.global_epoch               = (m_session_epoch > m_recovery_epoch) ? m_session_epoch : m_recovery_epoch;
    s.session_id                 = m_session_id;
    s.authenticated              = m_authenticated;
    s.reward_bound               = m_reward_bound;
    s.subscribed_to_notifications = m_subscribed_to_notifications;
    s.pending_push_after_auth    = m_pending_push_after_auth;
    return s;
}

std::string SessionCoordinator::diagnostics() const
{
    const auto snap = snapshot();
    std::ostringstream oss;
    oss << "SessionCoordinator{"
        << "session_epoch=" << snap.session_epoch
        << " recovery_epoch=" << snap.recovery_epoch
        << " global_epoch=" << snap.global_epoch
        << " session_id=0x" << std::hex << std::setw(8) << std::setfill('0') << snap.session_id
        << std::dec
        << " authenticated=" << snap.authenticated
        << " reward_bound=" << snap.reward_bound
        << " subscribed=" << snap.subscribed_to_notifications
        << " pending_push=" << snap.pending_push_after_auth
        << "}";
    return oss.str();
}

// ── Private helpers ───────────────────────────────────────────────────────────

void SessionCoordinator::notify_observers_locked(const char* domain, uint64_t old_val, uint64_t new_val)
{
    for (auto& observer : m_observers) {
        observer(domain, old_val, new_val);
    }
}

} // namespace protocol
} // namespace nexusminer
