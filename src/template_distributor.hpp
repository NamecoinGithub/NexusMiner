#ifndef NEXUSMINER_TEMPLATE_DISTRIBUTOR_HPP
#define NEXUSMINER_TEMPLATE_DISTRIBUTOR_HPP

#include <cstdint>
#include <memory>

namespace LLP { class CBlock; }

namespace nexusminer
{

class Worker_manager;
class Block_data;

/// Encapsulates the logic for receiving validated mining templates from the
/// protocol layer and distributing them to worker threads.
///
/// Extracted from the 280+ line template handler lambda in worker_manager.cpp
/// to improve readability and testability.  Accesses Worker_manager private
/// members via friendship.
class TemplateDistributor
{
public:
    /// Called when a validated template arrives from the protocol layer.
    /// Distributes the template to all workers, handles degraded-mode worker
    /// restart, recovery state clearing, and push resubscription.
    static void on_template_received(
        const ::LLP::CBlock& block,
        uint32_t nBits,
        std::shared_ptr<Worker_manager> mgr);

private:
    /// Block-found callback: validates the solution, performs staleness checks,
    /// prepares and submits the full block to the network.
    static void on_block_found(
        std::weak_ptr<Worker_manager> weak_mgr,
        std::uint32_t id,
        std::unique_ptr<Block_data>&& block_data);
};

} // namespace nexusminer

#endif // NEXUSMINER_TEMPLATE_DISTRIBUTOR_HPP
