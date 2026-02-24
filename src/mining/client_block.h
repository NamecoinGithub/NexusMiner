#ifndef NEXUSMINER_MINING_CLIENT_BLOCK_H
#define NEXUSMINER_MINING_CLIENT_BLOCK_H

#include "LLC/types/uint1024.h"
#include <vector>
#include <cstdint>
#include <string>
#include <ctime>

namespace nexusminer {
namespace mining {

// Mining channel constants
constexpr uint32_t CHANNEL_PRIME = 1;
constexpr uint32_t CHANNEL_HASH = 2;
constexpr uint32_t CHANNEL_STAKE = 3;

// Template age timeout (seconds) - extended to match Prime block time and emergency timeout
constexpr uint64_t MAX_TEMPLATE_AGE_SECONDS = 600;

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
    uint1024_t hashPrevBlock;       // Hash of the best chain tip at template creation time.
                                    // MUST equal ChainState::hashBestChain at block acceptance.
                                    // This is the primary staleness anchor (StakeMinter pattern).
                                    // On any tip_moved notification, request a fresh template;
                                    // the new template's hashPrevBlock will reflect the new tip.
    uint512_t hashMerkleRoot;       // Merkle root (64 bytes)
    uint32_t nChannel;              // Mining channel (1=Prime, 2=Hash, 3=Stake)
    uint32_t nHeight;               // Channel target height: stateChannel.nChannelHeight + 1
                                    // Set by the node in CreateBlockForStatelessMining() / AddBlockData()
                                    // MUST be treated as READ-ONLY after deserialization from the 216-byte template.
                                    // This is the value Block::Accept() validates as the next channel sequence number.
                                    // It is NOT the unified blockchain height (which is tStateBest.nHeight).
                                    // It is NOT something the miner computes independently.
                                    // ProofHash() for Prime hashes nVersion..nBits (which includes nHeight),
                                    // so any mutation of this field after deserialization will break Prime mining.
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
     * @brief Get mining channel
     * @return Channel number (CHANNEL_PRIME, CHANNEL_HASH, or CHANNEL_STAKE)
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
     * @return true if Prime channel
     */
    bool IsPrime() const
    {
        return nChannel == CHANNEL_PRIME;
    }
    
    /**
     * @brief Check if this is a Hash channel block
     * @return true if Hash channel
     */
    bool IsHash() const
    {
        return nChannel == CHANNEL_HASH;
    }
    
    /**
     * @brief Get channel name as string (for logging/debugging)
     * @return Channel name string ("PRIME", "HASH", "STAKE", or "UNKNOWN")
     * @note Does NOT compute actual block hash - use GetPlaceholderHash() for identifier
     */
    const char* GetChannelName() const
    {
        switch (nChannel) {
            case CHANNEL_PRIME: return "PRIME";
            case CHANNEL_HASH: return "HASH";
            case CHANNEL_STAKE: return "STAKE";
            default: return "UNKNOWN";
        }
    }
    
    /**
     * @brief Get placeholder hash for identification
     * @return Previous block hash as identifier
     * @note This is NOT a real hash computation. Real hash verification happens on NODE.
     *       CLIENT-SIDE doesn't need to compute actual hashes.
     */
    uint1024_t GetPlaceholderHash() const
    {
        return hashPrevBlock;
    }
    
    /**
     * @brief Get block hash (legacy method - calls GetPlaceholderHash)
     * @deprecated Use GetPlaceholderHash() to make intent clear
     * @return Placeholder hash (previous block hash)
     */
    uint1024_t GetHash() const
    {
        return GetPlaceholderHash();
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
