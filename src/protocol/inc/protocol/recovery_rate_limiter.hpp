#ifndef NEXUS_PROTOCOL_RECOVERY_RATE_LIMITER_HPP
#define NEXUS_PROTOCOL_RECOVERY_RATE_LIMITER_HPP

#include <chrono>
#include <cstdint>
#include <deque>

namespace protocol {

/**
 * Rate limiter for recovery attempts.
 *
 * Prevents flooding the node with GET_BLOCK requests during recovery.
 * Implements both:
 * 1. Minimum interval between attempts
 * 2. Maximum attempts per time window (sliding window)
 *
 * Thread-safety: NOT thread-safe. Caller must ensure serialization.
 */
class RecoveryRateLimiter {
public:
    /**
     * Constructor with default limits:
     * - Min interval: 15 seconds
     * - Max attempts: 25 per 60 seconds
     */
    RecoveryRateLimiter();

    /**
     * Check if a recovery attempt should be allowed.
     *
     * @return true if attempt should proceed, false if rate-limited
     */
    bool allow_recovery_attempt();

    /**
     * Record a recovery attempt (updates internal tracking)
     */
    void record_attempt();

    /**
     * Set minimum interval between attempts (milliseconds)
     */
    void set_min_interval_ms(uint64_t ms) { m_min_interval_ms = ms; }

    /**
     * Set maximum attempts per window
     */
    void set_max_attempts_per_window(uint64_t count) { m_max_attempts_per_window = count; }

    /**
     * Set sliding window duration (milliseconds)
     */
    void set_window_duration_ms(uint64_t ms) { m_window_duration_ms = ms; }

    /**
     * Reset rate limiter state (called on new recovery epoch)
     */
    void reset();

    /**
     * Get number of attempts in current window
     */
    size_t get_attempts_in_window() const;

    /**
     * Get time until next attempt allowed (milliseconds)
     */
    uint64_t get_time_until_next_attempt_ms() const;

private:
    uint64_t m_min_interval_ms;         // Minimum time between attempts
    uint64_t m_max_attempts_per_window; // Max attempts in sliding window
    uint64_t m_window_duration_ms;      // Sliding window duration

    std::chrono::steady_clock::time_point m_last_attempt_at{};
    std::deque<std::chrono::steady_clock::time_point> m_attempt_timestamps;

    // Remove expired timestamps from window
    void cleanup_expired_timestamps();
};

} // namespace protocol

#endif // NEXUS_PROTOCOL_RECOVERY_RATE_LIMITER_HPP
