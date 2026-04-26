#ifndef NEXUSMINER_PRIME_STATS_SNAPSHOT_HPP
#define NEXUSMINER_PRIME_STATS_SNAPSHOT_HPP

#include <array>
#include <algorithm>
#include <atomic>
#include <cstdint>
#include <memory>
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
        std::atomic_store_explicit(
            &m_snapshot,
            std::make_shared<const Stats>(std::move(snapshot)),
            std::memory_order_release);
    }

    std::shared_ptr<const Stats> load() const
    {
        return std::atomic_load_explicit(&m_snapshot, std::memory_order_acquire);
    }

private:
    mutable std::shared_ptr<const Stats> m_snapshot;
};

}
}

#endif
