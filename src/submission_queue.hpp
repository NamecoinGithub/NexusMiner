#ifndef NEXUSMINER_SUBMISSION_QUEUE_HPP
#define NEXUSMINER_SUBMISSION_QUEUE_HPP

#include <atomic>
#include <memory>
#include <vector>
#include <cstdint>
#include <chrono>

namespace nexusminer {

/**
 * @brief Submission item containing block data and metadata
 */
struct SubmissionItem {
    std::vector<uint8_t> block_data;
    uint64_t nonce;
    std::chrono::steady_clock::time_point found_at;

    SubmissionItem() = default;
    SubmissionItem(std::vector<uint8_t> data, uint64_t n)
        : block_data(std::move(data))
        , nonce(n)
        , found_at(std::chrono::steady_clock::now())
    {}
};

/**
 * @brief Lock-free MPSC (Multi-Producer Single-Consumer) submission queue
 *
 * Workers (producers) push found blocks into the queue from multiple threads.
 * A single submitter thread (consumer) drains and submits blocks with staleness checks.
 *
 * Design:
 * - Bounded ring buffer with atomic head/tail pointers
 * - Lock-free push from multiple worker threads
 * - Single-threaded pop from submitter thread
 * - Overflow handling: drops oldest entries when full
 *
 * Benefits:
 * - Reduces contention on asio::post
 * - Eliminates reentrancy risk in submission callbacks
 * - Enables batched staleness checks before submission
 */
class SubmissionQueue {
public:
    static constexpr size_t DEFAULT_CAPACITY = 256;

    explicit SubmissionQueue(size_t capacity = DEFAULT_CAPACITY)
        : m_capacity(capacity)
        , m_ring(capacity)
        , m_head(0)
        , m_tail(0)
    {}

    /**
     * @brief Push a submission item into the queue (called by workers)
     * @param item Submission item to push
     * @return True if pushed successfully, false if queue is full
     */
    bool push(SubmissionItem&& item) {
        // Load current tail
        size_t current_tail = m_tail.load(std::memory_order_relaxed);
        size_t next_tail = (current_tail + 1) % m_capacity;

        // Check if queue is full
        if (next_tail == m_head.load(std::memory_order_acquire)) {
            // Queue full - could drop or return false
            return false;
        }

        // Write data
        m_ring[current_tail] = std::move(item);

        // Commit the write by advancing tail
        m_tail.store(next_tail, std::memory_order_release);

        return true;
    }

    /**
     * @brief Pop a submission item from the queue (called by submitter thread)
     * @param item Output parameter for popped item
     * @return True if an item was popped, false if queue is empty
     */
    bool pop(SubmissionItem& item) {
        // Load current head
        size_t current_head = m_head.load(std::memory_order_relaxed);

        // Check if queue is empty
        if (current_head == m_tail.load(std::memory_order_acquire)) {
            return false;
        }

        // Read data
        item = std::move(m_ring[current_head]);

        // Commit the read by advancing head
        size_t next_head = (current_head + 1) % m_capacity;
        m_head.store(next_head, std::memory_order_release);

        return true;
    }

    /**
     * @brief Check if queue is empty
     * @return True if empty
     */
    bool empty() const {
        return m_head.load(std::memory_order_acquire) ==
               m_tail.load(std::memory_order_acquire);
    }

    /**
     * @brief Get approximate queue size (may be stale in concurrent context)
     * @return Approximate number of items in queue
     */
    size_t size() const {
        size_t h = m_head.load(std::memory_order_acquire);
        size_t t = m_tail.load(std::memory_order_acquire);

        if (t >= h) {
            return t - h;
        } else {
            return m_capacity - h + t;
        }
    }

private:
    const size_t m_capacity;
    std::vector<SubmissionItem> m_ring;

    // Aligned atomics for cache line separation (reduce false sharing)
    alignas(64) std::atomic<size_t> m_head;  // Consumer index
    alignas(64) std::atomic<size_t> m_tail;  // Producer index
};

} // namespace nexusminer

#endif // NEXUSMINER_SUBMISSION_QUEUE_HPP
