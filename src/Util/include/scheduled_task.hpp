#ifndef NEXUSMINER_SCHEDULED_TASK_HPP
#define NEXUSMINER_SCHEDULED_TASK_HPP

#include <atomic>
#include <chrono>
#include <cstdint>
#include <functional>
#include <memory>

#include <asio/io_context.hpp>
#include <asio/steady_timer.hpp>

namespace nexusminer {
namespace util {

/**
 * @brief Reusable scheduled-task abstraction over asio::steady_timer.
 *
 * Unifies three independent timer patterns found in the codebase
 * (Worker_manager token-based, SessionManager generation-based, and
 * ColinAgent flag-based cancellation) into a single class with:
 *
 *  - Generation-based invalidation for safe, idempotent cancellation.
 *  - One-shot and repeating schedule modes.
 *  - Shared internal state so that in-flight callbacks never dereference
 *    a destroyed ScheduledTask (the shared state outlives the timer object).
 *
 * Thread-safety: schedule_once(), schedule_repeating(), and cancel() must
 * be called from the io_context thread (the same thread that processes
 * timer callbacks).  is_pending() and generation() may be read from any
 * thread (they use atomics).
 *
 * Example (one-shot):
 * @code
 *   ScheduledTask task(io_ctx);
 *   task.schedule_once(std::chrono::seconds(5), []{ std::cout << "fired!\n"; });
 *   // ...later...
 *   task.cancel();  // safe, idempotent
 * @endcode
 *
 * Example (repeating):
 * @code
 *   ScheduledTask task(io_ctx);
 *   task.schedule_repeating(std::chrono::seconds(60), []{ collect_stats(); });
 *   // task fires every 60s until cancel() or destruction
 * @endcode
 */
class ScheduledTask {
public:
    using Callback = std::function<void()>;

    /**
     * @brief Construct a ScheduledTask bound to the given io_context.
     * @param io_context  The ASIO io_context that drives the timer.
     */
    explicit ScheduledTask(asio::io_context& io_context)
        : m_state(std::make_shared<State>(io_context)) {}

    /**
     * @brief Destructor — cancels any pending task.
     */
    ~ScheduledTask() {
        if (m_state) cancel();
    }

    ScheduledTask(const ScheduledTask&)            = delete;
    ScheduledTask& operator=(const ScheduledTask&) = delete;
    ScheduledTask(ScheduledTask&&)                 = default;
    ScheduledTask& operator=(ScheduledTask&&)      = default;

    /**
     * @brief Schedule a one-shot callback after the specified delay.
     *
     * Any previously scheduled task is cancelled first.  The callback
     * is invoked exactly once unless cancel() is called before it fires.
     *
     * @tparam Rep     Arithmetic type representing the tick count.
     * @tparam Period  std::ratio representing the tick period.
     * @param delay     Duration to wait before invoking @p callback.
     * @param callback  Callable to invoke when the timer expires.
     */
    template <typename Rep, typename Period>
    void schedule_once(std::chrono::duration<Rep, Period> delay, Callback callback) {
        cancel();
        m_state->pending = true;
        const auto gen = ++m_state->generation;
        m_state->timer.expires_after(delay);
        m_state->timer.async_wait(
            [s = m_state, gen, cb = std::move(callback)](const asio::error_code& ec) {
                if (ec || gen != s->generation.load()) return;
                s->pending = false;
                cb();
            });
    }

    /**
     * @brief Schedule a repeating callback at a fixed interval.
     *
     * The callback fires once after each interval and then automatically
     * re-arms.  Any previously scheduled task is cancelled first.
     * The cycle continues until cancel() is called, the ScheduledTask
     * is destroyed, or the callback itself calls cancel().
     *
     * @tparam Rep     Arithmetic type representing the tick count.
     * @tparam Period  std::ratio representing the tick period.
     * @param interval  Duration between successive invocations.
     * @param callback  Callable to invoke each time the timer expires.
     */
    template <typename Rep, typename Period>
    void schedule_repeating(std::chrono::duration<Rep, Period> interval, Callback callback) {
        cancel();
        m_state->pending = true;
        const auto gen = ++m_state->generation;
        arm_repeating(m_state,
                      std::chrono::duration_cast<std::chrono::nanoseconds>(interval),
                      std::move(callback), gen);
    }

    /**
     * @brief Cancel any pending task.  Idempotent and safe to call at any time.
     *
     * Increments the internal generation counter so that any in-flight
     * callback observes the mismatch and silently returns.
     */
    void cancel() {
        m_state->pending = false;
        ++m_state->generation;
        m_state->timer.cancel();
    }

    /** @brief Returns true if a callback is currently scheduled. */
    bool is_pending() const { return m_state->pending.load(); }

    /** @brief Current generation counter (useful for diagnostics / logging). */
    uint64_t generation() const { return m_state->generation.load(); }

private:
    /** Shared mutable state that outlives the ScheduledTask object itself. */
    struct State {
        asio::steady_timer          timer;
        std::atomic<uint64_t>       generation{0};
        std::atomic_bool            pending{false};

        explicit State(asio::io_context& io) : timer(io) {}
    };

    /**
     * @brief Arm the repeating timer (static to avoid capturing `this`).
     *
     * The lambda captures a shared_ptr<State> instead of a raw pointer
     * to the ScheduledTask, so the callback remains safe even if the
     * ScheduledTask is destroyed between ticks.
     */
    static void arm_repeating(std::shared_ptr<State> s,
                              std::chrono::nanoseconds interval,
                              Callback callback,
                              uint64_t gen) {
        s->timer.expires_after(interval);
        s->timer.async_wait(
            [s, interval, cb = std::move(callback), gen]
            (const asio::error_code& ec) mutable {
                if (ec || gen != s->generation.load()) return;
                cb();
                if (gen == s->generation.load()) {
                    arm_repeating(std::move(s), interval, std::move(cb), gen);
                }
            });
    }

    std::shared_ptr<State> m_state;
};

} // namespace util
} // namespace nexusminer

#endif // NEXUSMINER_SCHEDULED_TASK_HPP
