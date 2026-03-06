#ifndef NEXUSMINER_WORKER_HPP
#define NEXUSMINER_WORKER_HPP

#include <memory>
#include <functional>
#include <algorithm>
#include "LLC/types/uint1024.h"
#include "block.hpp"
#include "hash/byte_utils.hpp"

namespace nexusminer {
namespace stats { class Collector; }

class Block_data
{
public:

	Block_data(const ::LLP::CBlock& block)
		:merkle_root{block.hashMerkleRoot}
		, previous_hash{block.hashPrevBlock}
		, nHeight {block.nHeight}
		, nVersion {block.nVersion}
		, nChannel {block.nChannel}
		, nBits {block.nBits}
		, nNonce{ block.nNonce }{}

	Block_data() {}

	std::vector<unsigned char> GetHeaderBytes(bool excludeNonce = false)
	{
		//convert header data to byte strings
		std::vector<unsigned char> blockHeightB = IntToBytes(nHeight, 4);
		std::vector<unsigned char> versionB = IntToBytes(nVersion, 4);
		std::vector<unsigned char> channelB = IntToBytes(nChannel, 4);
		std::vector<unsigned char> bitsB = IntToBytes(nBits, 4);
		std::vector<unsigned char> nonceB = IntToBytes(nNonce, 8);
		std::string merkleStr = merkle_root.GetHex();
		std::string hashPrevBlockStr = previous_hash.GetHex();
		std::vector<unsigned char> merkleB = HexStringToBytes(merkleStr);
		std::vector<unsigned char> prevHashB = HexStringToBytes(hashPrevBlockStr);
		reverse(merkleB.begin(), merkleB.end());
		reverse(prevHashB.begin(), prevHashB.end());

		//Concatenate the bytes
		std::vector<unsigned char> headerB = versionB;
		headerB.insert(headerB.end(), prevHashB.begin(), prevHashB.end());
		headerB.insert(headerB.end(), merkleB.begin(), merkleB.end());
		headerB.insert(headerB.end(), channelB.begin(), channelB.end());
		headerB.insert(headerB.end(), blockHeightB.begin(), blockHeightB.end());
		headerB.insert(headerB.end(), bitsB.begin(), bitsB.end());
		if (!excludeNonce)
		{
			headerB.insert(headerB.end(), nonceB.begin(), nonceB.end());
		}

		return headerB;

	}
	//The order of the block header data below matters for the cuda miner.  Be careful.
	uint32_t nVersion = 4;
    uint1024_t previous_hash;
	uint512_t merkle_root;
	uint32_t nChannel = 2;
	uint32_t nHeight = 2023276;
	uint32_t nBits = 0x7b032ed8;
	uint64_t nNonce = 21155560019;

	// Prime channel offsets (Cunningham chain offsets from ValidatePrimeCandidate).
	// Empty for Hash channel. Populated by worker_prime before firing the callback
	// so that worker_manager can include them in prepare_block_submission().
	std::vector<uint8_t> vOffsets;

};

/**
 * WorkPackage: Immutable shared work data for template distribution
 *
 * Created once per template by Worker_manager and shared across all workers
 * via std::shared_ptr. Eliminates repeated Block_data construction and
 * serialization per worker.
 *
 * Contains precomputed immutable data:
 * - Original CBlock from protocol layer
 * - nBits (difficulty target)
 * - Precomputed header bytes (208 or 216 bytes depending on nonce inclusion)
 *
 * Workers maintain per-worker mutable state (starting nonce, Block_data copy).
 */
class WorkPackage
{
public:
    WorkPackage(const ::LLP::CBlock& block, std::uint32_t nbits)
        : m_block{block}
        , m_nbits{nbits}
    {
        // Precompute header bytes once for all workers
        // Note: Block_data constructor copies from CBlock
        Block_data temp_block_data{block};
        m_header_bytes = temp_block_data.GetHeaderBytes();
    }

    // Immutable accessors
    const ::LLP::CBlock& get_block() const { return m_block; }
    std::uint32_t get_nbits() const { return m_nbits; }
    const std::vector<unsigned char>& get_header_bytes() const { return m_header_bytes; }

private:
    ::LLP::CBlock m_block;                      // Original block from protocol
    std::uint32_t m_nbits;                      // Difficulty target
    std::vector<unsigned char> m_header_bytes;  // Precomputed header (shared)
};

class Worker {
public:

	virtual ~Worker() = default;

    // A call to the BlockFoundHandler informs the user about a new found block.
    using Block_found_handler = std::function<void(std::uint32_t id, std::unique_ptr<Block_data>&& block)>;

    // Sets a new block (nexus data type) for the miner worker. The miner worker must reset the current work.
    // When  the worker finds a new block, the BlockFoundHandler has to be called with the found BlockData
    // DEPRECATED: Use set_block(shared_ptr<WorkPackage>, Block_found_handler) for better performance
    virtual void set_block(::LLP::CBlock block, std::uint32_t nbits, Block_found_handler result) = 0;

    // Optimized version: accepts shared WorkPackage to eliminate repeated block data construction
    // Default implementation delegates to legacy set_block() for backward compatibility
    virtual void set_block(std::shared_ptr<WorkPackage> work_package, Block_found_handler result)
    {
        // Default fallback: extract block and nbits from WorkPackage
        set_block(work_package->get_block(), work_package->get_nbits(), result);
    }

    // Returns true if the worker's mining thread is actively running (i.e. set_block() started it).
    // Implementations backed by an m_stop atomic should override this to return !m_stop.
    // The default returns true for async I/O workers (e.g. FPGA) that have no explicit stop flag.
    // NOTE: All thread-based worker subclasses MUST override this to return !m_stop so that
    // the workers_fed counter only counts threads that were actually started by set_block().
    virtual bool is_running() const { return true; }

    virtual void update_statistics(stats::Collector& stats_collector) = 0;
};

}


#endif
