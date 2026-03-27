#ifndef NEXUSMINER_PROTOCOL_SESSION_COORDINATOR_HPP
#define NEXUSMINER_PROTOCOL_SESSION_COORDINATOR_HPP

#include <cstdint>
#include <mutex>
#include <functional>
#include <vector>
#include <string>
#include <memory>
#include "spdlog/spdlog.h"

namespace nexusminer {
namespace protocol {

/**
 * SessionCoordinator — Single source of truth for all session identity state.
 *
 * Replaces the scattered independent copies of session_epoch, session_id,
 * authenticated, reward_bound, and recovery_epoch across SessionManager,
 * Solo, HeightTracker, MiningTemplateInterface, and Worker_manager.
 *
 * Key invariants:
 *   - session_epoch and recovery_epoch are MONOTONICALLY INCREASING (never reset to 0)
 *   - All reads/writes go through one mutex — no ordering ambiguity
 *   - Observers are notified synchronously on state changes
 *   - No component should cache these values locally
 */
class SessionCoordinator : public std::enable_shared_from_this<SessionCoordinator>
{
public:
    // ── Domain name constants (use these in observer comparisons for O(1) strcmp avoidance) ──
    static constexpr const char* DOMAIN_SESSION_EPOCH    = "session_epoch";
    static constexpr const char* DOMAIN_RECOVERY_EPOCH   = "recovery_epoch";
    static constexpr const char* DOMAIN_SESSION_ID        = "session_id";
    static constexpr const char* DOMAIN_AUTHENTICATED     = "authenticated";
    static constexpr const char* DOMAIN_REWARD_BOUND      = "reward_bound";
    static constexpr const char* DOMAIN_SUBSCRIBED        = "subscribed_to_notifications";
    static constexpr const char* DOMAIN_PENDING_PUSH      = "pending_push_after_auth";

    // ── Observer callback types ───────────────────────────────────────────────
    // domain: one of the DOMAIN_* constants above
    using StateChangeObserver = std::function<void(const char* domain, uint64_t old_val, uint64_t new_val)>;

    explicit SessionCoordinator(std::shared_ptr<spdlog::logger> logger = nullptr);

    // ── Epoch management (monotonically increasing, NEVER reset) ─────────────
    uint64_t session_epoch() const;
    uint64_t advance_session_epoch(const char* reason);

    uint64_t recovery_epoch() const;
    uint64_t advance_recovery_epoch(const char* reason);

    /// Global epoch = max(session_epoch, recovery_epoch)
    /// Any component can use this for staleness without knowing which domain advanced.
    uint64_t global_epoch() const;

    // ── Session identity (authoritative, replaces all cached copies) ──────────
    uint32_t session_id() const;
    void set_session_id(uint32_t id, const char* reason);

    bool is_authenticated() const;
    void set_authenticated(bool auth, const char* reason);

    bool is_reward_bound() const;
    void set_reward_bound(bool bound, const char* reason);

    // ── Push subscription state (previously only in Solo, no authoritative home) ──
    bool is_subscribed_to_notifications() const;
    void set_subscribed_to_notifications(bool subscribed, const char* reason);

    bool has_pending_push_after_auth() const;
    void set_pending_push_after_auth(bool pending, const char* reason);

    // ── Composite queries (replaces Solo's delegation-with-fallback pattern) ──
    bool can_request_get_block() const;   // authenticated
    bool can_submit() const;              // authenticated && reward_bound
    bool is_session_active() const;       // authenticated && session_id != 0

    // ── Bulk operations ───────────────────────────────────────────────────────
    /// Called on disconnect/reauth — clears transient state but PRESERVES epochs.
    /// session_id → 0, authenticated → false, reward_bound → false,
    /// subscribed → false, pending_push → false.
    /// Epochs are NEVER cleared.
    void clear_for_disconnect(const char* reason);

    /// Called on successful authentication — sets session_id, authenticated,
    /// advances session_epoch atomically in one lock acquisition.
    void commit_authenticated(uint32_t new_session_id, const char* reason);

    // ── Observer pattern ──────────────────────────────────────────────────────
    void add_observer(StateChangeObserver observer);

    // ── Snapshot (for diagnostics / logging) ─────────────────────────────────
    struct Snapshot {
        uint64_t session_epoch{0};
        uint64_t recovery_epoch{0};
        uint64_t global_epoch{0};
        uint32_t session_id{0};
        bool authenticated{false};
        bool reward_bound{false};
        bool subscribed_to_notifications{false};
        bool pending_push_after_auth{false};
    };
    Snapshot snapshot() const;

    /// Human-readable diagnostic dump for logging
    std::string diagnostics() const;

    // ── Pending notification helper (for fire-outside-lock pattern) ──────────
    struct Notification {
        const char* domain{nullptr};
        uint64_t old_val{0};
        uint64_t new_val{0};
    };

private:
    mutable std::mutex m_mutex;
    uint64_t m_session_epoch{0};
    uint64_t m_recovery_epoch{0};
    uint32_t m_session_id{0};
    bool m_authenticated{false};
    bool m_reward_bound{false};
    bool m_subscribed_to_notifications{false};
    bool m_pending_push_after_auth{false};

    std::vector<StateChangeObserver> m_observers;
    std::shared_ptr<spdlog::logger> m_logger;

    /// Fire a list of pre-captured notifications against a snapshot of observers.
    /// Must be called OUTSIDE m_mutex to avoid deadlocks with observer-side locks.
    static void fire_notifications(const std::vector<StateChangeObserver>& observers,
                                   const std::vector<Notification>& notifications);
};

} // namespace protocol
} // namespace nexusminer

#endif // NEXUSMINER_PROTOCOL_SESSION_COORDINATOR_HPP
