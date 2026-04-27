#ifndef NEXUSMINER_WORKER_TEMPLATE_FEED_HPP
#define NEXUSMINER_WORKER_TEMPLATE_FEED_HPP

#include "worker/worker.hpp"

#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <memory>
#include <mutex>

namespace nexusminer {

// ─────────────────────────────────────────────────────────────────────────────
// Stone 4: Shared TemplateEpoch instead of N×set_block fanout
// ─────────────────────────────────────────────────────────────────────────────
// Each new template is published once into a shared, lock-free-readable slot
// instead of being pushed into N individual worker mutex/CV chains.  Workers
// observe new work by loading the latest TemplateEpoch from this feed at the
// natural rebind point in their mining loop (top of segment, end of nonce
// batch, etc.).  This decouples template-feed latency from worker count and
// removes the parent m_worker_mutex hold across N CV notifications, which is
// the same parent mutex the stats path holds.
//
// Publish-side semantics:
//   * Single-publisher (Worker_manager template handler).
//   * publish() advances a monotonic epoch_id, atomically swaps the slot, and
//     notify_all() on the shared CV so cold-start (waiting) workers wake up.
//
// Subscribe-side semantics:
//   * Many-reader.  load() is wait-free (relaxed semantics suffice for a
//     latest-wins handoff: the next load sees the next epoch).
//   * wait_for_epoch_after(last_seen, predicate) blocks until either a newer
//     epoch is published or predicate() returns true (used for shutdown
//     wake-up by the worker).
//
// This feed is *infrastructure* for Stones 5-7.  In this PR Worker_manager
// publishes for every template, but the existing per-worker
// set_block(WorkPackage, handler) shim is retained so unmigrated workers keep
// working unchanged.  The Worker_manager fanout that calls those shims now
// runs *outside* m_worker_mutex (snapshot-and-release), which already removes
// the stats-path contention called out in the Stone 4 brief.  Per-worker
// migrations to consume directly from this feed land in follow-up stones.
// ─────────────────────────────────────────────────────────────────────────────

struct TemplateEpoch
{
    // Monotonically increasing per-feed publish counter.  0 means "no epoch
    // has been published yet"; first real publish carries epoch_id == 1.
    std::uint64_t epoch_id{0};

    // Shared immutable work package (built once by Worker_manager).
    std::shared_ptr<WorkPackage> work_package;

    // Found-block callback shared across all workers consuming this epoch.
    // Captured once per template instead of re-captured per worker.
    Worker::Block_found_handler on_found;
};

class WorkerTemplateFeed
{
public:
    WorkerTemplateFeed() = default;

    WorkerTemplateFeed(const WorkerTemplateFeed&) = delete;
    WorkerTemplateFeed& operator=(const WorkerTemplateFeed&) = delete;
    WorkerTemplateFeed(WorkerTemplateFeed&&) = delete;
    WorkerTemplateFeed& operator=(WorkerTemplateFeed&&) = delete;

    // Publish a new TemplateEpoch.  The epoch_id field of `epoch` is
    // overwritten with the next monotonic value, so callers may pass in a
    // freshly-constructed shared_ptr without pre-filling epoch_id.
    //
    // Single-publisher only.  Returns the assigned epoch_id.
    std::uint64_t publish(std::shared_ptr<TemplateEpoch> epoch)
    {
        if (!epoch)
        {
            return m_latest_epoch_id.load(std::memory_order_acquire);
        }

        const std::uint64_t next_id = m_latest_epoch_id.load(std::memory_order_relaxed) + 1;
        epoch->epoch_id = next_id;

        // C++17 free-function atomic shared_ptr ops give us a wait-free
        // single-publisher / many-reader handoff without any shared mutex.
        // (Deprecated in C++20 but still supported; the project is C++17.)
        std::atomic_store_explicit(&m_slot,
                                   std::shared_ptr<const TemplateEpoch>(std::move(epoch)),
                                   std::memory_order_release);
        m_latest_epoch_id.store(next_id, std::memory_order_release);

        // Wake any worker waiting in wait_for_epoch_after().
        //
        // The empty critical section is intentional: the predicate
        // (m_latest_epoch_id) is updated above WITHOUT holding m_wake_mtx,
        // so a waiter that has just observed the old predicate value but has
        // not yet parked on m_wake_cv could otherwise miss the notify_all()
        // (classic lost-wakeup race).  Briefly acquiring m_wake_mtx here
        // serialises with the waiter's `cv.wait(lock, predicate)` block: by
        // the time we own the lock, the waiter is either (a) still in its
        // predicate re-evaluation under the same lock and will observe the
        // new id when we release, or (b) fully parked on the CV and will
        // be reached by the notify_all() below.
        {
            std::lock_guard<std::mutex> lock(m_wake_mtx);
        }
        m_wake_cv.notify_all();

        return next_id;
    }

    // Wait-free read of the latest published epoch.  Returns nullptr when
    // nothing has been published yet.
    std::shared_ptr<const TemplateEpoch> load() const
    {
        return std::atomic_load_explicit(&m_slot, std::memory_order_acquire);
    }

    // Latest epoch_id without dereferencing the slot (useful for fast-path
    // staleness checks in worker loops).  Returns 0 before any publish.
    std::uint64_t latest_epoch_id() const
    {
        return m_latest_epoch_id.load(std::memory_order_acquire);
    }

    // Block the caller until either:
    //   * a newer epoch than `last_seen` is published, OR
    //   * `wake_predicate()` returns true (e.g. worker shutdown signalled).
    //
    // Returns the latest epoch_id observed when the wait completes.
    template <typename Predicate>
    std::uint64_t wait_for_epoch_after(std::uint64_t last_seen, Predicate wake_predicate)
    {
        std::unique_lock<std::mutex> lock(m_wake_mtx);
        m_wake_cv.wait(lock, [&]() {
            return m_latest_epoch_id.load(std::memory_order_acquire) > last_seen
                || wake_predicate();
        });
        return m_latest_epoch_id.load(std::memory_order_acquire);
    }

    // Wake any waiters without publishing a new epoch.  Used by Worker_manager
    // during shutdown so workers blocked in wait_for_epoch_after() can re-
    // evaluate their wake_predicate (typically an m_shutdown flag).
    //
    // The empty critical section is intentional for the same reason as in
    // publish() — the wake_predicate is flipped by the caller WITHOUT holding
    // m_wake_mtx, so we briefly take the lock here to close the gap between
    // a waiter's predicate check and its park-on-CV (lost-wakeup race).
    void notify_wake()
    {
        {
            std::lock_guard<std::mutex> lock(m_wake_mtx);
        }
        m_wake_cv.notify_all();
    }

private:
    // Atomic slot updated via std::atomic_store on shared_ptr (C++17).
    std::shared_ptr<const TemplateEpoch> m_slot;

    // Mirrors m_slot->epoch_id for fast staleness checks without a shared_ptr
    // load.  Updated after the slot is stored so a reader that sees a newer
    // id is guaranteed to also see the corresponding slot.
    std::atomic<std::uint64_t> m_latest_epoch_id{0};

    // Cold-start / shutdown CV.  Hot-path readers do NOT touch this mutex —
    // they call load() / latest_epoch_id() which are wait-free.
    mutable std::mutex m_wake_mtx;
    std::condition_variable m_wake_cv;
};

}  // namespace nexusminer

#endif  // NEXUSMINER_WORKER_TEMPLATE_FEED_HPP
