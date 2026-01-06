#ifndef NEXUSMINER_MINING_CLIENT_CHANNEL_MANAGER_H
#define NEXUSMINER_MINING_CLIENT_CHANNEL_MANAGER_H

#include "client_block_state.h"
#include <atomic>
#include <memory>
#include <mutex>
#include <string>
#include <utility>

namespace nexusminer {
namespace mining {

/**
 * @brief ClientChannelManager - CLIENT-SIDE equivalent of NODE's ChannelStateManager
 * 
 * Manages channel-specific state for mining, tracking heights and detecting forks.
 * Validates templates using same logic as NODE's Block::Accept().
 * 
 * Key Features:
 * - Tracks unified + channel heights (from GET_ROUND)
 * - Detects forks (height regression)
 * - Validates templates (dual height check)
 * - Handles rollbacks (clears invalid templates)
 * 
 * Architecture Alignment:
 *   NODE: ChannelStateManager
 *   CLIENT: ClientChannelManager (this class)
 */
class ClientChannelManager
{
protected:
    const uint32_t m_nChannel;      // Channel number (1=Prime, 2=Hash)
    
    // Current node state (from GET_ROUND)
    std::atomic<uint32_t> m_nNodeUnifiedHeight;
    std::atomic<uint32_t> m_nNodeChannelHeight;
    
    // Previous state (for fork detection)
    std::atomic<uint32_t> m_nPrevUnifiedHeight;
    std::atomic<uint32_t> m_nPrevChannelHeight;
    
    // Fork detection
    std::atomic<bool> m_fForkDetected;
    
    // Current template (protected by mutex)
    std::unique_ptr<ClientBlockState> m_pCurrentTemplate;
    mutable std::mutex m_templateMutex;
    
public:
    /**
     * @brief Constructor
     * @param nChannel Channel number (1=Prime, 2=Hash)
     */
    explicit ClientChannelManager(uint32_t nChannel)
        : m_nChannel(nChannel)
        , m_nNodeUnifiedHeight(0)
        , m_nNodeChannelHeight(0)
        , m_nPrevUnifiedHeight(0)
        , m_nPrevChannelHeight(0)
        , m_fForkDetected(false)
        , m_pCurrentTemplate(nullptr)
    {
    }
    
    /**
     * @brief Virtual destructor
     */
    virtual ~ClientChannelManager() = default;
    
    // Disable copy/move
    ClientChannelManager(const ClientChannelManager&) = delete;
    ClientChannelManager& operator=(const ClientChannelManager&) = delete;
    ClientChannelManager(ClientChannelManager&&) = delete;
    ClientChannelManager& operator=(ClientChannelManager&&) = delete;
    
    /**
     * @brief Update from GET_ROUND response (CLIENT-SIDE equivalent of SyncWithBlockchain)
     * 
     * Called when GET_ROUND response is received from node.
     * Updates height tracking and detects forks via height regression.
     * 
     * @param nUnified Current unified blockchain height
     * @param nChannel Current channel-specific height
     */
    void UpdateFromGetRound(uint32_t nUnified, uint32_t nChannel)
    {
        uint32_t nPrevUnified = m_nNodeUnifiedHeight.load();
        uint32_t nPrevChannel = m_nNodeChannelHeight.load();
        
        // FORK DETECTION: Unified height regressed (same algorithm as NODE)
        if (nPrevUnified > 0 && nUnified < nPrevUnified)
        {
            // Height regression detected - blockchain rollback
            uint32_t nRollback = nPrevUnified - nUnified;
            m_fForkDetected.store(true);
            OnForkDetected(nPrevUnified, nUnified, nRollback);
        }
        
        // Update previous heights (for next comparison)
        m_nPrevUnifiedHeight.store(nPrevUnified);
        m_nPrevChannelHeight.store(nPrevChannel);
        
        // Update current heights
        m_nNodeUnifiedHeight.store(nUnified);
        m_nNodeChannelHeight.store(nChannel);
    }
    
    /**
     * @brief Validate template using dual height check (mirrors NODE's Block::Accept logic)
     * 
     * Checks:
     * 1. Unified height match (template.nHeight == nodeHeight + 1)
     * 2. Channel height match (template.nChannelHeight == nodeChannelHeight + 1)
     * 3. Age timeout (< 60 seconds)
     * 
     * @param pTemplate Template to validate
     * @return true if template is valid for mining
     */
    bool ValidateTemplate(const ClientBlockState* pTemplate) const
    {
        if (!pTemplate)
            return false;
        
        uint32_t nNodeUnified = m_nNodeUnifiedHeight.load();
        uint32_t nNodeChannel = m_nNodeChannelHeight.load();
        
        // Validate unified height (Block::Accept logic)
        // Template builds NEXT block, so height should be nodeHeight + 1
        if (pTemplate->nHeight != nNodeUnified + 1)
            return false;  // Stale or fork
        
        // Validate channel height (Block::Accept logic)
        // Template's channel height should be nodeChannelHeight + 1
        if (pTemplate->nChannelHeight != nNodeChannel + 1)
            return false;  // Channel advanced
        
        // Age timeout (MAX_TEMPLATE_AGE_SECONDS safety net)
        if (pTemplate->GetAge() > MAX_TEMPLATE_AGE_SECONDS)
            return false;  // Too old
        
        return true;  // FRESH
    }
    
    /**
     * @brief Set current template
     * @param pTemplate Template to set (ownership transferred)
     */
    void SetCurrentTemplate(std::unique_ptr<ClientBlockState> pTemplate)
    {
        std::lock_guard<std::mutex> lock(m_templateMutex);
        m_pCurrentTemplate = std::move(pTemplate);
    }
    
    /**
     * @brief Get current template (read-only)
     * @return Pointer to current template, nullptr if none
     */
    const ClientBlockState* GetCurrentTemplate() const
    {
        std::lock_guard<std::mutex> lock(m_templateMutex);
        return m_pCurrentTemplate.get();
    }
    
    /**
     * @brief Get mutable current template (for modifications)
     * @return Pointer to current template, nullptr if none
     */
    ClientBlockState* GetCurrentTemplate()
    {
        std::lock_guard<std::mutex> lock(m_templateMutex);
        return m_pCurrentTemplate.get();
    }
    
    /**
     * @brief Check if valid template exists
     * @return true if template exists
     */
    bool HasValidTemplate() const
    {
        std::lock_guard<std::mutex> lock(m_templateMutex);
        return m_pCurrentTemplate != nullptr;
    }
    
    /**
     * @brief Clear current template
     */
    void ClearTemplate()
    {
        std::lock_guard<std::mutex> lock(m_templateMutex);
        m_pCurrentTemplate.reset();
    }
    
    /**
     * @brief Get current node heights
     * @return Pair of (unified height, channel height)
     */
    std::pair<uint32_t, uint32_t> GetNodeHeights() const
    {
        return std::make_pair(
            m_nNodeUnifiedHeight.load(),
            m_nNodeChannelHeight.load()
        );
    }
    
    /**
     * @brief Get previous node heights (before last update)
     * @return Pair of (previous unified height, previous channel height)
     */
    std::pair<uint32_t, uint32_t> GetPreviousHeights() const
    {
        return std::make_pair(
            m_nPrevUnifiedHeight.load(),
            m_nPrevChannelHeight.load()
        );
    }
    
    /**
     * @brief Get expected heights for next block
     * @return Pair of (expected unified, expected channel)
     */
    std::pair<uint32_t, uint32_t> GetExpectedHeights() const
    {
        return std::make_pair(
            m_nNodeUnifiedHeight.load() + 1,
            m_nNodeChannelHeight.load() + 1
        );
    }
    
    /**
     * @brief Get channel number
     * @return Channel number
     */
    uint32_t GetChannel() const
    {
        return m_nChannel;
    }
    
    /**
     * @brief Get channel name
     * @return Human-readable channel name
     */
    virtual const char* GetChannelName() const
    {
        switch (m_nChannel) {
            case CHANNEL_PRIME: return "PRIME";
            case CHANNEL_HASH: return "HASH";
            case CHANNEL_STAKE: return "STAKE";
            default: return "UNKNOWN";
        }
    }
    
    /**
     * @brief Check if fork was detected
     * @return true if fork detected
     */
    bool IsForkDetected() const
    {
        return m_fForkDetected.load();
    }
    
    /**
     * @brief Clear fork flag
     */
    void ClearForkFlag()
    {
        m_fForkDetected.store(false);
    }
    
protected:
    /**
     * @brief Fork detection callback (virtual for subclass customization)
     * 
     * Called when height regression is detected. Default behavior clears template.
     * Subclasses can override for custom fork handling.
     * 
     * @param nPrevHeight Previous unified height
     * @param nNewHeight New (regressed) unified height
     * @param nRollback Number of blocks rolled back
     */
    virtual void OnForkDetected(uint32_t nPrevHeight, uint32_t nNewHeight, uint32_t nRollback)
    {
        // Log fork detection
        // Note: Can't log here directly as we don't have logger access
        // Logging should be done by the calling code
        
        // Clear invalid template
        ClearTemplate();
    }
};

/**
 * @brief PrimeClientManager - Prime channel (CHANNEL_PRIME) manager
 * 
 * Architecture Alignment:
 *   NODE: PrimeStateManager
 *   CLIENT: PrimeClientManager (this class)
 */
class PrimeClientManager : public ClientChannelManager
{
public:
    PrimeClientManager() 
        : ClientChannelManager(CHANNEL_PRIME) 
    {
    }
    
    const char* GetChannelName() const override 
    { 
        return "PRIME"; 
    }
};

/**
 * @brief HashClientManager - Hash channel (CHANNEL_HASH) manager
 * 
 * Architecture Alignment:
 *   NODE: HashStateManager
 *   CLIENT: HashClientManager (this class)
 */
class HashClientManager : public ClientChannelManager
{
public:
    HashClientManager() 
        : ClientChannelManager(CHANNEL_HASH) 
    {
    }
    
    const char* GetChannelName() const override 
    { 
        return "HASH"; 
    }
};

} // namespace mining
} // namespace nexusminer

#endif // NEXUSMINER_MINING_CLIENT_CHANNEL_MANAGER_H
