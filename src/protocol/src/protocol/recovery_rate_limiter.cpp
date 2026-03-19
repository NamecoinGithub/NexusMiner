#include "protocol/recovery_rate_limiter.hpp"

namespace protocol {

RecoveryRateLimiter::RecoveryRateLimiter()
    : m_min_interval_ms(15000),       // 15 seconds
      m_max_attempts_per_window(25),   // 25 attempts
      m_window_duration_ms(60000)      // 60 second window
{
}

bool RecoveryRateLimiter::allow_recovery_attempt() {
    auto now = std::chrono::steady_clock::now();

    // Check minimum interval
    if (m_last_attempt_at != std::chrono::steady_clock::time_point{}) {
        auto elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
            now - m_last_attempt_at).count();
        if (static_cast<uint64_t>(elapsed_ms) < m_min_interval_ms) {
            return false;  // Too soon since last attempt
        }
    }

    // Clean up expired timestamps from window
    cleanup_expired_timestamps();

    // Check sliding window limit
    if (m_attempt_timestamps.size() >= m_max_attempts_per_window) {
        return false;  // Too many attempts in window
    }

    return true;  // Allowed
}

void RecoveryRateLimiter::record_attempt() {
    auto now = std::chrono::steady_clock::now();
    m_last_attempt_at = now;
    m_attempt_timestamps.push_back(now);

    // Keep window size reasonable
    cleanup_expired_timestamps();
}

void RecoveryRateLimiter::reset() {
    m_last_attempt_at = {};
    m_attempt_timestamps.clear();
}

size_t RecoveryRateLimiter::get_attempts_in_window() const {
    return m_attempt_timestamps.size();
}

uint64_t RecoveryRateLimiter::get_time_until_next_attempt_ms() const {
    if (m_last_attempt_at == std::chrono::steady_clock::time_point{}) {
        return 0;  // No previous attempt, can attempt now
    }

    auto now = std::chrono::steady_clock::now();
    auto elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        now - m_last_attempt_at).count();

    if (static_cast<uint64_t>(elapsed_ms) >= m_min_interval_ms) {
        return 0;  // Enough time has passed
    }

    return m_min_interval_ms - static_cast<uint64_t>(elapsed_ms);
}

void RecoveryRateLimiter::cleanup_expired_timestamps() {
    auto now = std::chrono::steady_clock::now();
    auto window_start = now - std::chrono::milliseconds(m_window_duration_ms);

    // Remove timestamps older than window
    while (!m_attempt_timestamps.empty() &&
           m_attempt_timestamps.front() < window_start) {
        m_attempt_timestamps.pop_front();
    }
}

} // namespace protocol
