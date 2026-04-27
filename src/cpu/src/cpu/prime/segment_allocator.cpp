#include "segment_allocator.hpp"

#include <spdlog/spdlog.h>
#include <string>
#include <utility>

namespace nexusminer {
namespace cpu {

Per_worker_segment_allocator::Per_worker_segment_allocator(std::uint64_t segment_size)
    : m_segment_size{segment_size}
{
}

void Per_worker_segment_allocator::reset(std::uint64_t starting_nonce)
{
    m_cursor = starting_nonce;
}

std::uint64_t Per_worker_segment_allocator::next_segment_start()
{
    const std::uint64_t out = m_cursor;
    m_cursor += m_segment_size;
    return out;
}

std::unique_ptr<Segment_allocator>
make_segment_allocator_for_engine_mode(const std::string& engine_mode,
                                       std::uint64_t segment_size)
{
    if (engine_mode == "engine")
    {
        // Forward-compat: the cooperative engine path (Stones 5-7) is not yet
        // wired in.  Log once at construction and fall back to the per-worker
        // allocator so today's behaviour is preserved.
        if (auto logger = spdlog::get("logger"))
        {
            logger->warn("[cpu] engine_mode = \"engine\" is reserved for the upcoming "
                         "PrimeMiningEngine and is not yet active. Falling back to the "
                         "per-worker segment allocator.");
        }
    }
    else if (!engine_mode.empty() && engine_mode != "workers")
    {
        if (auto logger = spdlog::get("logger"))
        {
            logger->warn("[cpu] engine_mode = \"{}\" is not recognised; "
                         "expected \"workers\" or \"engine\". Falling back to "
                         "\"workers\".",
                         engine_mode);
        }
    }
    return std::make_unique<Per_worker_segment_allocator>(segment_size);
}

} // namespace cpu
} // namespace nexusminer
