#ifndef NEXUSMINER_BLOCK_HEADER_UTILS_HPP
#define NEXUSMINER_BLOCK_HEADER_UTILS_HPP

#include <vector>
#include "LLC/hash/SK.h"
#include "block.hpp"

#ifdef ui_type
#undef ui_type
#endif
#ifdef dec_unit_type
#undef dec_unit_type
#endif
#ifdef dec_bufr_type
#undef dec_bufr_type
#endif
#ifdef ptr_cast
#undef ptr_cast
#endif

namespace nexusminer {

/**
 * Extract the raw in-memory CBlock header span used by the node hashing code.
 * When exclude_nonce is true this returns nVersion..nBits (prime ProofHash span);
 * otherwise it returns nVersion..nNonce for full header hashing workers.
 */
inline std::vector<unsigned char> GetBlockHeaderBytes(const ::LLP::CBlock& block, bool exclude_nonce = false)
{
	const auto* begin = reinterpret_cast<const unsigned char*>(BEGIN(block.nVersion));
	const auto* end = exclude_nonce
		? reinterpret_cast<const unsigned char*>(END(block.nBits))
		: reinterpret_cast<const unsigned char*>(END(block.nNonce));
	return std::vector<unsigned char>(begin, end);
}

/**
 * Compute the prime-channel ProofHash exactly as the upstream node does:
 * LLC::SK1024 over the raw header bytes from nVersion through nBits, excluding nonce.
 * This uses BEGIN/END directly to mirror the node's Block::ProofHash() call site
 * rather than routing through GetBlockHeaderBytes() first, avoiding an
 * intermediate vector allocation while keeping the exact same span semantics.
 */
inline uint1024_t GetPrimeProofHash(const ::LLP::CBlock& block)
{
	return LLC::SK1024(BEGIN(block.nVersion), END(block.nBits));
}

} // namespace nexusminer

#endif
