#ifndef NEXUSMINER_MINING_CLIENT_BLOCK_H
#define NEXUSMINER_MINING_CLIENT_BLOCK_H

#include "LLC/types/uint1024.h"
#include <vector>
#include <cstdint>
#include <string>
#include <ctime>

namespace nexusminer {
namespace mining {

/**
 * @brief ClientBlock - CLIENT-SIDE equivalent of NODE's Block class
 * 
 * Represents a mining template received from the LLL-TAO node.
 * Contains only fields needed for mining (no consensus validation).
 * 
 * This mirrors NODE's TAO::Ledger::Block but is lightweight for client-side use.
 * Separates serializable template data from chain state (see ClientBlockState).
 * 
 * Architecture Alignment:
 *   NODE: TAO::Ledger::Block
 *   CLIENT: ClientBlock (this class)
 */
class ClientBlock
{
public:
    // Block header fields (serializable)
    uint32_t nVersion;              // Block version
    uint1024_t hashPrevBlock;       // Previous block hash (128 bytes)
    uint512_t hashMerkleRoot;       // Merkle root (64 bytes)
    uint32_t nChannel;              // Mining channel (1=Prime, 2=Hash, 3=Stake)
    uint32_t nHeight;               // Unified blockchain height
    uint32_t nBits;                 // Difficulty bits
    uint64_t nNonce;                // Mining nonce
    uint32_t nTime;                 // Block timestamp
    
    // Prime-specific fields
    std::vector<uint32_t> vOffsets; // Prime offsets (Prime channel only)
    
    // Block signature (for submission)
    std::vector<uint8_t> vchBlockSig;
    
    /**
     * @brief Default constructor - creates null block
     */
    ClientBlock()
        : nVersion(0)
        , hashPrevBlock(0)
        , hashMerkleRoot(0)
        , nChannel(0)
        , nHeight(0)
        , nBits(0)
        , nNonce(0)
        , nTime(0)
    {
    }
    
    /**
     * @brief Get block hash
     * @return Block hash (1024-bit)
     * @note This is a placeholder - actual mining uses SK1024 hash on NODE side
     */
    uint1024_t GetHash() const
    {
        // For CLIENT-SIDE, we don't compute actual hashes
        // The real hash verification happens on NODE side
        // Return the previous block hash as a placeholder identifier
        return hashPrevBlock;
    }
    
    /**
     * @brief Get mining channel
     * @return Channel number (1=Prime, 2=Hash, 3=Stake)
     */
    uint32_t GetChannel() const
    {
        return nChannel;
    }
    
    /**
     * @brief Check if block is null/empty
     * @return true if block is uninitialized
     */
    bool IsNull() const
    {
        return nVersion == 0 && nHeight == 0 && nChannel == 0;
    }
    
    /**
     * @brief Check if this is a Prime channel block
     * @return true if Prime channel (channel 1)
     */
    bool IsPrime() const
    {
        return nChannel == 1;
    }
    
    /**
     * @brief Check if this is a Hash channel block
     * @return true if Hash channel (channel 2)
     */
    bool IsHash() const
    {
        return nChannel == 2;
    }
    
    /**
     * @brief Get human-readable channel name
     * @return Channel name string
     */
    const char* GetChannelName() const
    {
        switch (nChannel) {
            case 1: return "PRIME";
            case 2: return "HASH";
            case 3: return "STAKE";
            default: return "UNKNOWN";
        }
    }
    
    /**
     * @brief Convert block to string for logging
     * @return Human-readable block description
     */
    std::string ToString() const
    {
        std::string str;
        str += "ClientBlock(";
        str += "channel=" + std::string(GetChannelName());
        str += ", height=" + std::to_string(nHeight);
        str += ", version=" + std::to_string(nVersion);
        str += ", bits=0x" + std::to_string(nBits);
        str += ", nonce=" + std::to_string(nNonce);
        str += ", time=" + std::to_string(nTime);
        str += ")";
        return str;
    }
};

} // namespace mining
} // namespace nexusminer

#endif // NEXUSMINER_MINING_CLIENT_BLOCK_H
