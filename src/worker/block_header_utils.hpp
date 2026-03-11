#ifndef NEXUSMINER_BLOCK_HEADER_UTILS_HPP
#define NEXUSMINER_BLOCK_HEADER_UTILS_HPP

#include <vector>
#include "LLC/hash/SK.h"
#include "block.hpp"

namespace nexusminer {

inline std::vector<unsigned char> GetBlockHeaderBytes(const ::LLP::CBlock& block, bool exclude_nonce = false)
{
	const auto* begin = reinterpret_cast<const unsigned char*>(BEGIN(block.nVersion));
	const auto* end = exclude_nonce
		? reinterpret_cast<const unsigned char*>(END(block.nBits))
		: reinterpret_cast<const unsigned char*>(END(block.nNonce));
	return std::vector<unsigned char>(begin, end);
}

inline uint1024_t GetPrimeProofHash(const ::LLP::CBlock& block)
{
	return LLC::SK1024(BEGIN(block.nVersion), END(block.nBits));
}

} // namespace nexusminer

#endif
