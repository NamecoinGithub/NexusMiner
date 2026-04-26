#ifndef NEXUSMINER_PRIME_STATS_SNAPSHOT_HPP
#define NEXUSMINER_PRIME_STATS_SNAPSHOT_HPP

#include <array>
#include <algorithm>
#include <atomic>
#include <cstdint>
#include <memory>
#include <mutex>
#include <utility>

namespace nexusminer {
namespace stats
{

inline constexpr std::size_t kPrimeHistogramBuckets = 11;
using Prime_histogram = std::array<std::uint32_t, kPrimeHistogramBuckets>;

template <typename Histogram>
Prime_histogram copy_prime_histogram(const Histogram& histogram)
{
    Prime_histogram snapshot{};
    const auto count = std::min(snapshot.size(), histogram.size());
    for (std::size_t i = 0; i < count; ++i)
    {
        snapshot[i] = histogram[i];
    }
    return snapshot;
}

template <typename Stats>
class Atomic_snapshot {
public:
    Atomic_snapshot()
        : m_snapshot(std::make_shared<const Stats>())
    {
    }

    void store(Stats snapshot)
    {
#if defined(__cpp_lib_atomic_shared_ptr) && __cpp_lib_atomic_shared_ptr >= 201711L
        m_snapshot.store(
            std::make_shared<const Stats>(std::move(snapshot)),
            std::memory_order_release);
#else
        std::scoped_lock lock(m_snapshot_mutex);
        m_snapshot = std::make_shared<const Stats>(std::move(snapshot));
#endif
    }

    std::shared_ptr<const Stats> load() const
    {
#if defined(__cpp_lib_atomic_shared_ptr) && __cpp_lib_atomic_shared_ptr >= 201711L
        return m_snapshot.load(std::memory_order_acquire);
#else
        std::scoped_lock lock(m_snapshot_mutex);
        return m_snapshot;
#endif
    }

private:
#if defined(__cpp_lib_atomic_shared_ptr) && __cpp_lib_atomic_shared_ptr >= 201711L
    std::atomic<std::shared_ptr<const Stats>> m_snapshot;
#else
    mutable std::mutex m_snapshot_mutex;
    std::shared_ptr<const Stats> m_snapshot;
#endif
};

}
}

#endif
