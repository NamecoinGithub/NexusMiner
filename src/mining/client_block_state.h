#ifndef NEXUSMINER_MINING_CLIENT_BLOCK_STATE_H
#define NEXUSMINER_MINING_CLIENT_BLOCK_STATE_H

#include "client_block.h"
#include <ctime>
#include <string>

namespace nexusminer {
namespace mining {

/**
 * @brief ClientBlockState - CLIENT-SIDE equivalent of NODE's BlockState class
 * 
 * Extends ClientBlock with chain state information, specifically the channel height.
 * This mirrors NODE's separation of Block (serializable) vs BlockState (includes chain context).
 * 
 * Why separate nChannelHeight?
 * - ClientBlock is serializable template data (from node)
 * - nChannelHeight is NOT in the template, calculated from GET_ROUND response
 * - Mirrors NODE's Block/BlockState architecture
 * 
 * Architecture Alignment:
 *   NODE: TAO::Ledger::BlockState
 *   CLIENT: ClientBlockState (this class)
 */
class ClientBlockState : public ClientBlock
{
public:
    // Channel state (NOT in serialized block, from GET_ROUND)
    uint32_t nChannelHeight;        // Per-channel height from GET_ROUND response
    
    // Timestamp tracking
    uint64_t nCreationTime;         // Template creation timestamp (set by node or client)
    uint64_t nReceivedTime;         // Template received timestamp (set by client)
    
    /**
     * @brief Default constructor
     */
    ClientBlockState()
        : ClientBlock()
        , nChannelHeight(0)
        , nCreationTime(0)
        , nReceivedTime(0)
    {
    }
    
    /**
     * @brief Constructor from ClientBlock + channel height
     * @param block Base block template
     * @param channelHeight Channel-specific height from GET_ROUND
     */
    ClientBlockState(const ClientBlock& block, uint32_t channelHeight)
        : ClientBlock(block)
        , nChannelHeight(channelHeight)
        , nCreationTime(std::time(nullptr))
        , nReceivedTime(std::time(nullptr))
    {
    }
    
    /**
     * @brief Get age of template in seconds
     * @return Age since creation
     */
    uint64_t GetAge() const
    {
        if (nCreationTime == 0)
            return 0;
        
        uint64_t now = std::time(nullptr);
        if (now < nCreationTime)
            return 0;  // Clock skew protection
        
        return now - nCreationTime;
    }
    
    /**
     * @brief Get latency (time from creation to receipt)
     * @return Latency in seconds
     */
    uint64_t GetLatency() const
    {
        if (nCreationTime == 0 || nReceivedTime == 0)
            return 0;
        
        if (nReceivedTime < nCreationTime)
            return 0;  // Clock skew protection
        
        return nReceivedTime - nCreationTime;
    }
    
    /**
     * @brief Basic staleness check (age-based)
     * @return true if template is older than MAX_TEMPLATE_AGE_SECONDS
     * @note Use ClientChannelManager for complete validation with height checks
     */
    bool IsStale() const
    {
        return GetAge() > MAX_TEMPLATE_AGE_SECONDS;
    }
    
    /**
     * @brief Convert block state to string for logging
     * @return Human-readable description
     */
    std::string ToString() const
    {
        std::string str = ClientBlock::ToString();
        str += " + State(";
        str += "channelHeight=" + std::to_string(nChannelHeight);
        str += ", age=" + std::to_string(GetAge()) + "s";
        str += ", latency=" + std::to_string(GetLatency()) + "s";
        str += ")";
        return str;
    }
};

} // namespace mining
} // namespace nexusminer

#endif // NEXUSMINER_MINING_CLIENT_BLOCK_STATE_H
